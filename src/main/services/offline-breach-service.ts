import { createHash } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import { lstat, open, rm, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';

export const OFFLINE_BREACH_SOURCE_FORMAT = 'sha1-count-v1' as const;
export const OFFLINE_BREACH_INDEX_VERSION = 1 as const;

const INDEX_MAGIC = Buffer.from('KRYBRCH1', 'ascii');
const INDEX_ALGORITHM_SHA1 = 1;
const INDEX_HEADER_BYTES = 64;
const INDEX_RECORD_BYTES = 24;
const INDEX_PREFIX_COUNT = 65_537;
const INDEX_PREFIX_BYTES = INDEX_PREFIX_COUNT * 8;
const INDEX_RECORDS_OFFSET = INDEX_HEADER_BYTES + INDEX_PREFIX_BYTES;
const INDEX_SOURCE_SHA256_OFFSET = 24;
const INDEX_RESERVED_OFFSET = 56;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const SOURCE_RECORD = /^([0-9A-Fa-f]{40}):([1-9][0-9]{0,9})$/u;
const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const UINT32_MAX = 0xffff_ffff;
const DEFAULT_MAX_SOURCE_BYTES = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_RECORDS = 1_000_000_000;
const DEFAULT_MAX_LINE_BYTES = 64;
const DEFAULT_READ_CHUNK_BYTES = 1024 * 1024;
const RECORD_BATCH_RECORDS = 4_096;
const DEFAULT_CANDIDATE_YIELD_INTERVAL = 25;

export type OfflineBreachProgressPhase = 'source-validate' | 'index-validate' | 'password-scan';

export interface OfflineBreachProgress {
  readonly phase: OfflineBreachProgressPhase;
  readonly completed: number;
  readonly total: number;
}

export interface OfflineBreachOperationContext {
  readonly signal?: AbortSignal;
  readonly assertAuthorized?: () => Promise<void> | void;
  readonly onProgress?: (progress: OfflineBreachProgress) => Promise<void> | void;
  readonly yieldControl?: () => Promise<void> | void;
}

export interface OfflineBreachServiceOptions {
  /** Test seam. Production accepts at most a documented 64-GiB source file. */
  readonly maxSourceBytes?: number;
  /** Test seam. Production accepts at most one billion unique records. */
  readonly maxRecords?: number;
  /** Test seam bounded by the format's mandatory 64-byte maximum. */
  readonly maxLineBytes?: number;
  readonly readChunkBytes?: number;
  readonly candidateYieldInterval?: number;
}

export interface OfflineBreachIndexBuildInput {
  /** Absolute Main-process-selected source path. It must never originate in Renderer IPC. */
  readonly sourcePath: string;
  /**
   * Fresh absolute Main-owned staging path below an existing regular directory.
   *
   * The service removes a partial file on every failed build. After a successful build the caller
   * owns the staged file and must remove it in a `finally` block after its atomic commit attempt.
   */
  readonly stagingPath: string;
  readonly context?: OfflineBreachOperationContext;
}

export interface OfflineBreachIndexInspectInput {
  readonly indexPath: string;
  readonly expectedIndexSha256?: string;
  readonly context?: OfflineBreachOperationContext;
}

export interface OfflineBreachIndexMetadata {
  readonly format: typeof OFFLINE_BREACH_SOURCE_FORMAT;
  readonly version: typeof OFFLINE_BREACH_INDEX_VERSION;
  readonly recordCount: number;
  readonly sourceSha256: string;
  readonly indexSha256: string;
  readonly indexBytes: number;
}

export interface OfflineBreachIndexBuildResult extends OfflineBreachIndexMetadata {
  readonly sourceBytes: number;
  readonly stagingPath: string;
}

export interface OfflineBreachTechnicalReference {
  readonly vaultId: string;
  readonly entryId: string;
  readonly updatedAt: string;
}

export interface OfflineBreachPasswordCandidate {
  readonly reference: OfflineBreachTechnicalReference;
  readonly password: string;
  readonly deletedAt?: string | null;
}

export interface OfflineBreachScanInput {
  readonly indexPath: string;
  readonly expectedIndexSha256?: string;
  readonly candidates: readonly OfflineBreachPasswordCandidate[];
  readonly context?: OfflineBreachOperationContext;
}

export interface OfflineBreachScanResult {
  readonly checkedCandidates: number;
  readonly matches: OfflineBreachTechnicalReference[];
  readonly networkUsed: false;
}

interface OpenedRegularFile {
  readonly handle: FileHandle;
  readonly initialPathState: Stats;
  readonly initialHandleState: Stats;
}

interface ValidatedOpenIndex {
  readonly metadata: OfflineBreachIndexMetadata;
  readonly prefixTable: Buffer;
}

interface MutableBuildState {
  recordCount: number;
  nextPrefix: number;
  firstLine: boolean;
  previousDigest: Buffer | null;
  recordBatchLength: number;
  recordWritePosition: number;
}

/**
 * Builds and queries a bounded offline breach index without retaining the corpus in memory.
 *
 * The only password-derived values created by this service are short-lived Buffers inside
 * `scan()`. They are never returned or persisted and are erased in `finally` paths.
 */
export class OfflineBreachService {
  private readonly maxSourceBytes: number;
  private readonly maxRecords: number;
  private readonly maxLineBytes: number;
  private readonly readChunkBytes: number;
  private readonly candidateYieldInterval: number;

  public constructor(options: OfflineBreachServiceOptions = {}) {
    this.maxSourceBytes = requireSafeInteger(
      options.maxSourceBytes ?? DEFAULT_MAX_SOURCE_BYTES,
      1,
      Number.MAX_SAFE_INTEGER,
      'Das Groessenlimit der Offline-Hashliste ist ungueltig.',
    );
    this.maxRecords = requireSafeInteger(
      options.maxRecords ?? DEFAULT_MAX_RECORDS,
      1,
      DEFAULT_MAX_RECORDS,
      'Das Datensatzlimit der Offline-Hashliste ist ungueltig.',
    );
    this.maxLineBytes = requireSafeInteger(
      options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES,
      1,
      DEFAULT_MAX_LINE_BYTES,
      'Das Zeilenlimit der Offline-Hashliste ist ungueltig.',
    );
    this.readChunkBytes = requireSafeInteger(
      options.readChunkBytes ?? DEFAULT_READ_CHUNK_BYTES,
      1,
      16 * 1024 * 1024,
      'Die Chunkgroesse der Offline-Hashliste ist ungueltig.',
    );
    this.candidateYieldInterval = requireSafeInteger(
      options.candidateYieldInterval ?? DEFAULT_CANDIDATE_YIELD_INTERVAL,
      1,
      1_000_000,
      'Das Freigabeintervall des Offline-Abgleichs ist ungueltig.',
    );
  }

  public async buildIndex(
    input: OfflineBreachIndexBuildInput,
  ): Promise<OfflineBreachIndexBuildResult> {
    let source: OpenedRegularFile | null = null;
    let stagingHandle: FileHandle | null = null;
    let buildSucceeded = false;
    let prefixTable: Buffer | null = null;
    let recordBatch: Buffer | null = null;
    let pendingLine: Buffer | null = null;
    let sourceChunk: Buffer | null = null;
    let sourceDigest: Buffer | null = null;
    let header: Buffer | null = null;
    let buildState: MutableBuildState | null = null;
    let stagingCreated = false;
    const context = input.context ?? {};

    try {
      requireAbsolutePath(input.sourcePath);
      requireAbsolutePath(input.stagingPath);
      if (samePlatformPath(input.sourcePath, input.stagingPath)) {
        throw invalid('Quell- und Stagingdatei muessen verschieden sein.');
      }
      await assertActive(context);
      source = await openRegularFile(input.sourcePath, 'source');
      if (
        !Number.isSafeInteger(source.initialHandleState.size) ||
        source.initialHandleState.size < 1
      ) {
        throw invalid('Die Offline-Hashliste ist leer oder ungueltig.');
      }
      if (source.initialHandleState.size > this.maxSourceBytes) {
        throw new VaultaError(
          'FILE_TOO_LARGE',
          'Die Offline-Hashliste ueberschreitet das dokumentierte Groessenlimit.',
        );
      }

      const stagingParent = await safeLstat(path.dirname(input.stagingPath));
      if (
        stagingParent === null ||
        stagingParent.isSymbolicLink() ||
        !stagingParent.isDirectory()
      ) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das interne Stagingverzeichnis ist nicht sicher verfuegbar.',
        );
      }
      const existingStage = await safeLstat(input.stagingPath);
      if (existingStage !== null) {
        throw new VaultaError('CONFLICT', 'Die interne Stagingdatei existiert bereits.');
      }
      try {
        stagingHandle = await open(
          input.stagingPath,
          constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
          0o600,
        );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new VaultaError('CONFLICT', 'Die interne Stagingdatei existiert bereits.');
        }
        throw internal('Die interne Indexdatei konnte nicht angelegt werden.', error);
      }
      stagingCreated = true;
      const stagingState = await stagingHandle.stat();
      if (!stagingState.isFile()) {
        throw new VaultaError('UNSAFE_PATH', 'Die interne Stagingdatei ist keine regulaere Datei.');
      }

      prefixTable = Buffer.alloc(INDEX_PREFIX_BYTES);
      recordBatch = Buffer.alloc(INDEX_RECORD_BYTES * RECORD_BATCH_RECORDS);
      header = Buffer.alloc(INDEX_HEADER_BYTES);
      await writeAll(stagingHandle, header, 0);
      await writeAll(stagingHandle, prefixTable, INDEX_HEADER_BYTES);

      const state: MutableBuildState = {
        recordCount: 0,
        nextPrefix: 0,
        firstLine: true,
        previousDigest: null,
        recordBatchLength: 0,
        recordWritePosition: INDEX_RECORDS_OFFSET,
      };
      buildState = state;
      const sourceHash = createHash('sha256');
      sourceChunk = Buffer.alloc(this.readChunkBytes);
      pendingLine = Buffer.alloc(0);
      let sourcePosition = 0;
      await reportProgress(context, {
        phase: 'source-validate',
        completed: 0,
        total: source.initialHandleState.size,
      });

      while (sourcePosition < source.initialHandleState.size) {
        await assertActive(context);
        const requested = Math.min(
          sourceChunk.length,
          source.initialHandleState.size - sourcePosition,
        );
        const { bytesRead } = await source.handle.read(sourceChunk, 0, requested, sourcePosition);
        if (bytesRead === 0) {
          throw new VaultaError(
            'CONFLICT',
            'Die Offline-Hashliste wurde waehrend des Imports veraendert.',
          );
        }
        const chunk = sourceChunk.subarray(0, bytesRead);
        sourceHash.update(chunk);
        let chunkOffset = 0;

        for (;;) {
          const newlineOffset = chunk.indexOf(0x0a, chunkOffset);
          if (newlineOffset < 0) {
            pendingLine = appendLineFragment(
              pendingLine,
              chunk.subarray(chunkOffset),
              this.maximumRawLineBytes(state.firstLine),
            );
            break;
          }

          const fragment = chunk.subarray(chunkOffset, newlineOffset);
          const line =
            pendingLine.length === 0
              ? fragment
              : Buffer.concat([pendingLine, fragment], pendingLine.length + fragment.length);
          if (line.length > this.maximumRawLineBytes(state.firstLine)) {
            if (line !== fragment) line.fill(0);
            throw invalid('Die Offline-Hashliste enthaelt eine zu lange Zeile.');
          }
          const batchFull = this.consumeSourceLine(line, state, prefixTable, recordBatch);
          if (line !== fragment) line.fill(0);
          pendingLine.fill(0);
          pendingLine = Buffer.alloc(0);
          if (batchFull) {
            await this.flushRecordBatch(stagingHandle, state, recordBatch);
          }
          chunkOffset = newlineOffset + 1;
        }

        sourcePosition += bytesRead;
        await reportProgress(context, {
          phase: 'source-validate',
          completed: sourcePosition,
          total: source.initialHandleState.size,
        });
        await yieldAndAssert(context);
      }

      if (pendingLine.length > 0) {
        const batchFull = this.consumeSourceLine(pendingLine, state, prefixTable, recordBatch);
        pendingLine.fill(0);
        pendingLine = Buffer.alloc(0);
        if (batchFull) await this.flushRecordBatch(stagingHandle, state, recordBatch);
      }
      if (state.recordCount === 0) {
        throw invalid('Die Offline-Hashliste enthaelt keinen Datensatz.');
      }
      await this.flushRecordBatch(stagingHandle, state, recordBatch);
      while (state.nextPrefix < INDEX_PREFIX_COUNT) {
        writePrefixOffset(prefixTable, state.nextPrefix, state.recordCount);
        state.nextPrefix += 1;
      }

      await assertFileUnchanged(input.sourcePath, source);
      sourceDigest = sourceHash.digest();
      this.writeHeader(header, state.recordCount, sourceDigest);
      await writeAll(stagingHandle, header, 0);
      await writeAll(stagingHandle, prefixTable, INDEX_HEADER_BYTES);
      await stagingHandle.truncate(INDEX_RECORDS_OFFSET + state.recordCount * INDEX_RECORD_BYTES);
      await stagingHandle.sync();
      await stagingHandle.close();
      stagingHandle = null;
      await source.handle.close();
      source = null;

      const sourceSha256 = sourceDigest.toString('hex');
      sourceDigest.fill(0);
      sourceDigest = null;
      const inspected = await this.inspectIndex({
        indexPath: input.stagingPath,
        context,
      });
      if (inspected.sourceSha256 !== sourceSha256 || inspected.recordCount !== state.recordCount) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Der vorbereitete Offline-Index konnte nicht verifiziert werden.',
        );
      }
      buildSucceeded = true;
      return {
        ...inspected,
        sourceBytes: sourcePosition,
        stagingPath: input.stagingPath,
      };
    } catch (error) {
      throw safeOperationError(error, 'Der Offline-Index konnte nicht sicher vorbereitet werden.');
    } finally {
      sourceDigest?.fill(0);
      sourceChunk?.fill(0);
      pendingLine?.fill(0);
      recordBatch?.fill(0);
      prefixTable?.fill(0);
      header?.fill(0);
      buildState?.previousDigest?.fill(0);
      await source?.handle.close().catch(() => undefined);
      await stagingHandle?.close().catch(() => undefined);
      if (!buildSucceeded && stagingCreated) {
        await rm(input.stagingPath, { force: true }).catch(() => undefined);
      }
    }
  }

  public async inspectIndex(
    input: OfflineBreachIndexInspectInput,
  ): Promise<OfflineBreachIndexMetadata> {
    const context = input.context ?? {};
    let opened: OpenedRegularFile | null = null;
    let prefixTable: Buffer | null = null;
    try {
      requireAbsolutePath(input.indexPath);
      await assertActive(context);
      opened = await openRegularFile(input.indexPath, 'index');
      const validated = await this.validateOpenIndex(
        opened,
        input.indexPath,
        input.expectedIndexSha256,
        context,
      );
      prefixTable = validated.prefixTable;
      return validated.metadata;
    } catch (error) {
      throw safeOperationError(error, 'Der Offline-Index konnte nicht sicher geprueft werden.');
    } finally {
      prefixTable?.fill(0);
      await opened?.handle.close().catch(() => undefined);
    }
  }

  public async scan(input: OfflineBreachScanInput): Promise<OfflineBreachScanResult> {
    const context = input.context ?? {};
    let opened: OpenedRegularFile | null = null;
    let prefixTable: Buffer | null = null;
    const recordBuffer = Buffer.alloc(INDEX_RECORD_BYTES);
    try {
      requireAbsolutePath(input.indexPath);
      await assertActive(context);
      opened = await openRegularFile(input.indexPath, 'index');
      const validated = await this.validateOpenIndex(
        opened,
        input.indexPath,
        input.expectedIndexSha256,
        context,
      );
      prefixTable = validated.prefixTable;

      const matches: OfflineBreachTechnicalReference[] = [];
      const matchedReferences = new Set<string>();
      let checkedCandidates = 0;
      await reportProgress(context, {
        phase: 'password-scan',
        completed: 0,
        total: input.candidates.length,
      });

      for (let index = 0; index < input.candidates.length; index += 1) {
        await assertActive(context);
        const candidate = input.candidates[index]!;
        this.validateCandidate(candidate);
        if (
          (candidate.deletedAt === null || candidate.deletedAt === undefined) &&
          candidate.password.length > 0
        ) {
          checkedCandidates += 1;
          let passwordBuffer: Buffer | null = Buffer.from(candidate.password, 'utf8');
          let digest: Buffer | null = null;
          try {
            digest = createHash('sha1').update(passwordBuffer).digest();
            passwordBuffer.fill(0);
            passwordBuffer = null;
            const present = await this.containsDigest(
              opened.handle,
              prefixTable,
              digest,
              recordBuffer,
              context,
            );
            if (present) {
              const key = technicalReferenceKey(candidate.reference);
              if (!matchedReferences.has(key)) {
                matchedReferences.add(key);
                matches.push({ ...candidate.reference });
              }
            }
          } finally {
            passwordBuffer?.fill(0);
            digest?.fill(0);
          }
        }

        await reportProgress(context, {
          phase: 'password-scan',
          completed: index + 1,
          total: input.candidates.length,
        });
        if ((index + 1) % this.candidateYieldInterval === 0) {
          await yieldAndAssert(context);
        }
      }

      await assertActive(context);
      await assertFileUnchanged(input.indexPath, opened);
      return { checkedCandidates, matches, networkUsed: false };
    } catch (error) {
      throw safeOperationError(
        error,
        'Der lokale Datenleckabgleich konnte nicht sicher abgeschlossen werden.',
      );
    } finally {
      recordBuffer.fill(0);
      prefixTable?.fill(0);
      await opened?.handle.close().catch(() => undefined);
    }
  }

  private consumeSourceLine(
    rawLine: Buffer,
    state: MutableBuildState,
    prefixTable: Buffer,
    recordBatch: Buffer,
  ): boolean {
    let line = rawLine;
    if (state.firstLine && line.subarray(0, UTF8_BOM.length).equals(UTF8_BOM)) {
      line = line.subarray(UTF8_BOM.length);
    }
    state.firstLine = false;
    if (line.at(-1) === 0x0d) line = line.subarray(0, -1);
    if (line.length === 0 || line.length > this.maxLineBytes) {
      throw invalid('Die Offline-Hashliste enthaelt eine ungueltige Zeile.');
    }
    const match = SOURCE_RECORD.exec(line.toString('latin1'));
    if (match === null) {
      throw invalid('Die Offline-Hashliste entspricht nicht dem dokumentierten Format.');
    }
    const count = Number(match[2]);
    if (!Number.isSafeInteger(count) || count < 1 || count > UINT32_MAX) {
      throw invalid('Die Offline-Hashliste enthaelt einen ungueltigen Vorkommenswert.');
    }
    if (state.recordCount >= this.maxRecords) {
      throw new VaultaError(
        'FILE_TOO_LARGE',
        'Die Offline-Hashliste enthaelt zu viele Datensaetze.',
      );
    }

    const digest = Buffer.from(match[1]!, 'hex');
    if (state.previousDigest !== null && Buffer.compare(state.previousDigest, digest) >= 0) {
      digest.fill(0);
      throw invalid('Die Offline-Hashliste ist nicht streng sortiert und eindeutig.');
    }
    const prefix = digest.readUInt16BE(0);
    while (state.nextPrefix <= prefix) {
      writePrefixOffset(prefixTable, state.nextPrefix, state.recordCount);
      state.nextPrefix += 1;
    }

    const batchOffset = state.recordBatchLength * INDEX_RECORD_BYTES;
    digest.copy(recordBatch, batchOffset);
    recordBatch.writeUInt32LE(count, batchOffset + 20);
    state.recordBatchLength += 1;
    state.recordCount += 1;
    state.previousDigest?.fill(0);
    state.previousDigest = digest;
    return state.recordBatchLength === RECORD_BATCH_RECORDS;
  }

  private async flushRecordBatch(
    stagingHandle: FileHandle,
    state: MutableBuildState,
    recordBatch: Buffer,
  ): Promise<void> {
    if (state.recordBatchLength === 0) return;
    const byteLength = state.recordBatchLength * INDEX_RECORD_BYTES;
    await writeAll(stagingHandle, recordBatch.subarray(0, byteLength), state.recordWritePosition);
    recordBatch.fill(0, 0, byteLength);
    state.recordWritePosition += byteLength;
    state.recordBatchLength = 0;
  }

  private writeHeader(header: Buffer, recordCount: number, sourceSha256: Buffer): void {
    header.fill(0);
    INDEX_MAGIC.copy(header, 0);
    header.writeUInt16LE(OFFLINE_BREACH_INDEX_VERSION, 8);
    header.writeUInt8(INDEX_ALGORITHM_SHA1, 10);
    header.writeUInt8(INDEX_RECORD_BYTES, 11);
    header.writeBigUInt64LE(BigInt(recordCount), 12);
    header.writeUInt32LE(INDEX_PREFIX_COUNT, 20);
    sourceSha256.copy(header, INDEX_SOURCE_SHA256_OFFSET);
  }

  private async validateOpenIndex(
    opened: OpenedRegularFile,
    indexPath: string,
    expectedIndexSha256: string | undefined,
    context: OfflineBreachOperationContext,
  ): Promise<ValidatedOpenIndex> {
    if (expectedIndexSha256 !== undefined && !SHA256_HEX.test(expectedIndexSha256.toLowerCase())) {
      throw invalid('Die erwartete Indexpruefsumme ist ungueltig.');
    }
    const indexSize = opened.initialHandleState.size;
    if (!Number.isSafeInteger(indexSize) || indexSize < INDEX_RECORDS_OFFSET) {
      throw corrupt('Der Offline-Index ist abgeschnitten.');
    }

    const header = Buffer.alloc(INDEX_HEADER_BYTES);
    const prefixTable = Buffer.alloc(INDEX_PREFIX_BYTES);
    const recordChunk = Buffer.alloc(
      Math.max(
        INDEX_RECORD_BYTES,
        Math.floor(this.readChunkBytes / INDEX_RECORD_BYTES) * INDEX_RECORD_BYTES,
      ),
    );
    let previousDigest: Buffer | null = null;
    try {
      await reportProgress(context, {
        phase: 'index-validate',
        completed: 0,
        total: indexSize,
      });
      await assertActive(context);
      await readExact(opened.handle, header, 0);
      if (!header.subarray(0, INDEX_MAGIC.length).equals(INDEX_MAGIC)) {
        throw new VaultaError(
          'UNSUPPORTED_FORMAT',
          'Die Datei ist kein unterstuetzter Offline-Index.',
        );
      }
      const version = header.readUInt16LE(8);
      if (version > OFFLINE_BREACH_INDEX_VERSION) {
        throw new VaultaError(
          'UNSUPPORTED_FORMAT',
          'Der Offline-Index verwendet eine neuere, nicht unterstuetzte Formatversion.',
        );
      }
      if (version !== OFFLINE_BREACH_INDEX_VERSION) {
        throw corrupt('Die Formatversion des Offline-Indexes ist ungueltig.');
      }
      if (
        header.readUInt8(10) !== INDEX_ALGORITHM_SHA1 ||
        header.readUInt8(11) !== INDEX_RECORD_BYTES ||
        header.readUInt32LE(20) !== INDEX_PREFIX_COUNT ||
        header.subarray(INDEX_RESERVED_OFFSET).some((value) => value !== 0)
      ) {
        throw corrupt('Der technische Header des Offline-Indexes ist ungueltig.');
      }

      const recordCountBig = header.readBigUInt64LE(12);
      if (
        recordCountBig < 1n ||
        recordCountBig > BigInt(this.maxRecords) ||
        recordCountBig > BigInt(Number.MAX_SAFE_INTEGER)
      ) {
        throw corrupt('Die Datensatzanzahl des Offline-Indexes ist ungueltig.');
      }
      const recordCount = Number(recordCountBig);
      const expectedSize = INDEX_RECORDS_OFFSET + recordCount * INDEX_RECORD_BYTES;
      if (expectedSize !== indexSize) {
        throw corrupt('Der Offline-Index besitzt eine ungueltige Dateilaenge.');
      }

      await readExact(opened.handle, prefixTable, INDEX_HEADER_BYTES);
      let previousPrefixOffset = -1;
      for (let prefix = 0; prefix < INDEX_PREFIX_COUNT; prefix += 1) {
        const offset = readPrefixOffset(prefixTable, prefix);
        if (
          offset < 0 ||
          offset > recordCount ||
          offset < previousPrefixOffset ||
          (prefix === 0 && offset !== 0) ||
          (prefix === INDEX_PREFIX_COUNT - 1 && offset !== recordCount)
        ) {
          throw corrupt('Die Praefixtabelle des Offline-Indexes ist ungueltig.');
        }
        previousPrefixOffset = offset;
      }

      const indexHash = createHash('sha256');
      indexHash.update(header);
      indexHash.update(prefixTable);
      let recordIndex = 0;
      let nextExpectedPrefix = 0;
      let bytePosition = INDEX_RECORDS_OFFSET;
      await reportProgress(context, {
        phase: 'index-validate',
        completed: INDEX_RECORDS_OFFSET,
        total: indexSize,
      });

      while (recordIndex < recordCount) {
        await assertActive(context);
        const recordsThisChunk = Math.min(
          Math.floor(recordChunk.length / INDEX_RECORD_BYTES),
          recordCount - recordIndex,
        );
        const bytesThisChunk = recordsThisChunk * INDEX_RECORD_BYTES;
        const target = recordChunk.subarray(0, bytesThisChunk);
        await readExact(opened.handle, target, bytePosition);
        indexHash.update(target);

        for (let localIndex = 0; localIndex < recordsThisChunk; localIndex += 1) {
          const offset = localIndex * INDEX_RECORD_BYTES;
          const digest = target.subarray(offset, offset + 20);
          const count = target.readUInt32LE(offset + 20);
          if (count < 1) {
            throw corrupt('Der Offline-Index enthaelt einen ungueltigen Datensatz.');
          }
          if (previousDigest !== null && Buffer.compare(previousDigest, digest) >= 0) {
            throw corrupt('Der Offline-Index ist nicht streng sortiert und eindeutig.');
          }
          const prefix = digest.readUInt16BE(0);
          while (nextExpectedPrefix <= prefix) {
            if (readPrefixOffset(prefixTable, nextExpectedPrefix) !== recordIndex + localIndex) {
              throw corrupt('Die Praefixtabelle des Offline-Indexes passt nicht zu den Daten.');
            }
            nextExpectedPrefix += 1;
          }
          previousDigest?.fill(0);
          previousDigest = Buffer.from(digest);
        }

        recordIndex += recordsThisChunk;
        bytePosition += bytesThisChunk;
        await reportProgress(context, {
          phase: 'index-validate',
          completed: bytePosition,
          total: indexSize,
        });
        await yieldAndAssert(context);
      }
      while (nextExpectedPrefix < INDEX_PREFIX_COUNT) {
        if (readPrefixOffset(prefixTable, nextExpectedPrefix) !== recordCount) {
          throw corrupt('Die Praefixtabelle des Offline-Indexes passt nicht zu den Daten.');
        }
        nextExpectedPrefix += 1;
      }

      const indexSha256 = indexHash.digest('hex');
      if (expectedIndexSha256 !== undefined && indexSha256 !== expectedIndexSha256.toLowerCase()) {
        throw corrupt('Die Pruefsumme des Offline-Indexes stimmt nicht.');
      }
      await assertActive(context);
      await assertFileUnchanged(indexPath, opened);
      return {
        metadata: {
          format: OFFLINE_BREACH_SOURCE_FORMAT,
          version: OFFLINE_BREACH_INDEX_VERSION,
          recordCount,
          sourceSha256: header
            .subarray(INDEX_SOURCE_SHA256_OFFSET, INDEX_SOURCE_SHA256_OFFSET + 32)
            .toString('hex'),
          indexSha256,
          indexBytes: indexSize,
        },
        prefixTable,
      };
    } catch (error) {
      prefixTable.fill(0);
      throw error;
    } finally {
      header.fill(0);
      recordChunk.fill(0);
      previousDigest?.fill(0);
    }
  }

  private async containsDigest(
    indexHandle: FileHandle,
    prefixTable: Buffer,
    digest: Buffer,
    recordBuffer: Buffer,
    context: OfflineBreachOperationContext,
  ): Promise<boolean> {
    const prefix = digest.readUInt16BE(0);
    let low = readPrefixOffset(prefixTable, prefix);
    let high = readPrefixOffset(prefixTable, prefix + 1);
    while (low < high) {
      await assertActive(context);
      const middle = low + Math.floor((high - low) / 2);
      await readExact(
        indexHandle,
        recordBuffer,
        INDEX_RECORDS_OFFSET + middle * INDEX_RECORD_BYTES,
      );
      const comparison = Buffer.compare(recordBuffer.subarray(0, 20), digest);
      if (comparison < 0) low = middle + 1;
      else if (comparison > 0) high = middle;
      else return true;
    }
    return false;
  }

  private validateCandidate(candidate: OfflineBreachPasswordCandidate): void {
    const reference = candidate.reference;
    if (
      typeof candidate.password !== 'string' ||
      typeof reference.vaultId !== 'string' ||
      reference.vaultId.length < 1 ||
      reference.vaultId.length > 200 ||
      typeof reference.entryId !== 'string' ||
      reference.entryId.length < 1 ||
      reference.entryId.length > 200 ||
      typeof reference.updatedAt !== 'string' ||
      reference.updatedAt.length < 1 ||
      reference.updatedAt.length > 100 ||
      (candidate.deletedAt !== undefined &&
        candidate.deletedAt !== null &&
        typeof candidate.deletedAt !== 'string')
    ) {
      throw invalid('Ein technischer Passwortverweis ist ungueltig.');
    }
  }

  private maximumRawLineBytes(firstLine: boolean): number {
    return this.maxLineBytes + 1 + (firstLine ? UTF8_BOM.length : 0);
  }
}

function appendLineFragment(pending: Buffer, fragment: Buffer, maximumBytes: number): Buffer {
  if (fragment.length === 0) return pending;
  if (pending.length + fragment.length > maximumBytes) {
    throw invalid('Die Offline-Hashliste enthaelt eine zu lange Zeile.');
  }
  const combined = Buffer.concat([pending, fragment], pending.length + fragment.length);
  pending.fill(0);
  return combined;
}

function writePrefixOffset(table: Buffer, prefix: number, recordOffset: number): void {
  table.writeBigUInt64LE(BigInt(recordOffset), prefix * 8);
}

function readPrefixOffset(table: Buffer, prefix: number): number {
  const value = table.readBigUInt64LE(prefix * 8);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) return -1;
  return Number(value);
}

function technicalReferenceKey(reference: OfflineBreachTechnicalReference): string {
  return JSON.stringify([reference.vaultId, reference.entryId, reference.updatedAt]);
}

async function openRegularFile(
  filePath: string,
  purpose: 'source' | 'index',
): Promise<OpenedRegularFile> {
  const initialPathState = await safeLstat(filePath);
  if (initialPathState === null) {
    throw new VaultaError(
      'NOT_FOUND',
      purpose === 'source'
        ? 'Die ausgewaehlte Offline-Hashliste wurde nicht gefunden.'
        : 'Der lokale Offline-Index wurde nicht gefunden.',
    );
  }
  if (initialPathState.isSymbolicLink() || !initialPathState.isFile()) {
    throw new VaultaError(
      'UNSAFE_PATH',
      purpose === 'source'
        ? 'Die ausgewaehlte Offline-Hashliste ist keine regulaere Datei.'
        : 'Der lokale Offline-Index ist keine regulaere Datei.',
    );
  }
  let handle: FileHandle;
  try {
    handle = await open(filePath, constants.O_RDONLY);
  } catch (error) {
    throw internal('Die lokale Datei konnte nicht sicher geoeffnet werden.', error);
  }
  try {
    const initialHandleState = await handle.stat();
    if (!initialHandleState.isFile() || !sameFileIdentity(initialPathState, initialHandleState)) {
      throw new VaultaError('CONFLICT', 'Die lokale Datei wurde vor dem Einlesen ausgetauscht.');
    }
    return { handle, initialPathState, initialHandleState };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function assertFileUnchanged(filePath: string, opened: OpenedRegularFile): Promise<void> {
  const finalHandleState = await opened.handle.stat();
  const finalPathState = await safeLstat(filePath);
  if (
    finalPathState === null ||
    finalPathState.isSymbolicLink() ||
    !finalPathState.isFile() ||
    !sameFileIdentity(opened.initialHandleState, finalHandleState) ||
    !sameFileIdentity(opened.initialPathState, finalPathState) ||
    !sameFileIdentity(finalHandleState, finalPathState)
  ) {
    throw new VaultaError('CONFLICT', 'Die lokale Datei wurde waehrend des Einlesens veraendert.');
  }
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function safeLstat(filePath: string): Promise<Stats | null> {
  try {
    return await lstat(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw internal('Der lokale Dateistatus konnte nicht sicher gelesen werden.', error);
  }
}

async function readExact(handle: FileHandle, target: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < target.length) {
    const { bytesRead } = await handle.read(
      target,
      offset,
      target.length - offset,
      position + offset,
    );
    if (bytesRead === 0) throw corrupt('Der Offline-Index ist abgeschnitten.');
    offset += bytesRead;
  }
}

async function writeAll(handle: FileHandle, contents: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < contents.length) {
    const { bytesWritten } = await handle.write(
      contents,
      offset,
      contents.length - offset,
      position + offset,
    );
    if (bytesWritten === 0) {
      throw new VaultaError(
        'INTERNAL',
        'Die interne Indexdatei konnte nicht vollstaendig geschrieben werden.',
      );
    }
    offset += bytesWritten;
  }
}

async function assertActive(context: OfflineBreachOperationContext): Promise<void> {
  throwIfAborted(context);
  await context.assertAuthorized?.();
  throwIfAborted(context);
}

function throwIfAborted(context: OfflineBreachOperationContext): void {
  if (context.signal?.aborted === true) throw cancelled();
}

async function yieldAndAssert(context: OfflineBreachOperationContext): Promise<void> {
  if (context.yieldControl === undefined) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  } else {
    await context.yieldControl();
  }
  await assertActive(context);
}

async function reportProgress(
  context: OfflineBreachOperationContext,
  progress: OfflineBreachProgress,
): Promise<void> {
  await context.onProgress?.(progress);
  await assertActive(context);
}

function requireAbsolutePath(value: string): void {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 32_767 ||
    value.includes('\0') ||
    !path.isAbsolute(value)
  ) {
    throw new VaultaError(
      'UNSAFE_PATH',
      'Die lokale Datei benoetigt einen absoluten Main-Prozess-Pfad.',
    );
  }
  if (process.platform === 'win32' && !/^[A-Za-z]:[\\/]$/u.test(path.win32.parse(value).root)) {
    throw new VaultaError(
      'UNSAFE_PATH',
      'Die lokale Datei muss auf einem lokalen Windows-Laufwerk liegen.',
    );
  }
}

function samePlatformPath(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLocaleLowerCase('en-US') === normalizedRight.toLocaleLowerCase('en-US')
    : normalizedLeft === normalizedRight;
}

function requireSafeInteger(
  value: number,
  minimum: number,
  maximum: number,
  message: string,
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid(message);
  }
  return value;
}

function safeOperationError(error: unknown, message: string): VaultaError {
  return error instanceof VaultaError ? error : internal(message, error);
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}

function corrupt(message: string): VaultaError {
  return new VaultaError('CORRUPT_DATA', message);
}

function cancelled(): VaultaError {
  return new VaultaError('CANCELLED', 'Die lokale Offline-Pruefung wurde abgebrochen.');
}

function internal(message: string, cause: unknown): VaultaError {
  return new VaultaError('INTERNAL', message, null, { cause });
}
