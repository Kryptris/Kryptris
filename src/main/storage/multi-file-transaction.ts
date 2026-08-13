import { constants } from 'node:fs';
import {
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  rmdir,
  type FileHandle,
} from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import { AtomicFileWriter } from './atomic-file';
import { resolveInside } from './path-safety';
import { SerialExecutor } from './serial-executor';

export const MULTI_FILE_TRANSACTION_DIRECTORY = '.vaulta-multi-file-transaction';

const JOURNAL_FILE = 'journal.json';
const TERMINAL_FILE = 'terminal.json';
const JOURNAL_FORMAT = 'vaulta-multi-file-transaction';
const TERMINAL_FORMAT = 'vaulta-multi-file-terminal';
const FORMAT_VERSION = 1;
const MAX_TRANSACTION_ENTRIES = 10_000;
const MAX_RECORD_BYTES = 4 * 1024 * 1024;
const HASH_CHUNK_BYTES = 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const ROLLBACK_FILE = /^rollback-[0-9]{6}\.bin$/u;
const TECHNICAL_TEMP_FILE = /^\.(?:journal|terminal)\.json\.tmp-[0-9a-f-]{36}$/iu;

interface FileState {
  readonly exists: boolean;
  readonly size: number;
  readonly sha256: string | null;
}

interface FileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
}

interface PreparedFileSnapshot {
  readonly absolutePath: string;
  readonly identity: FileIdentity;
  readonly size: number;
  readonly sha256: string;
}

interface TransactionEntry {
  readonly relativePath: string;
  readonly action: 'write' | 'delete';
  readonly rollbackFile: string | null;
  readonly sourceExists: boolean;
  readonly sourceSize: number;
  readonly sourceSha256: string | null;
  readonly targetExists: boolean;
  readonly targetSize: number;
  readonly targetSha256: string | null;
}

interface TransactionJournal {
  readonly format: typeof JOURNAL_FORMAT;
  readonly version: typeof FORMAT_VERSION;
  readonly transactionId: string;
  readonly createdDirectories: readonly string[];
  readonly entries: readonly TransactionEntry[];
}

interface TerminalMarker {
  readonly format: typeof TERMINAL_FORMAT;
  readonly version: typeof FORMAT_VERSION;
  readonly transactionId: string;
  readonly journalSha256: string;
  readonly outcome: 'committed' | 'rolled-back';
}

interface ActiveTransaction {
  readonly rootPath: string;
  readonly journal: TransactionJournal;
  readonly journalBytes: Buffer;
}

interface PreparedWriteChange {
  readonly type: 'write';
  readonly relativePath: string;
  readonly contents: Buffer;
  readonly expectedSha256: string | null | undefined;
  readonly source: FileState;
  readonly target: FileState;
}

interface PreparedWriteFileChange {
  readonly type: 'write-file';
  readonly relativePath: string;
  readonly preparedFile: PreparedFileSnapshot;
  readonly expectedSha256: string | null | undefined;
  readonly source: FileState;
  readonly target: FileState;
}

interface PreparedDeleteChange {
  readonly type: 'delete';
  readonly relativePath: string;
  readonly expectedSha256: string | null | undefined;
  readonly source: FileState;
  readonly target: FileState;
}

type PreparedChange = PreparedWriteChange | PreparedWriteFileChange | PreparedDeleteChange;

export interface MultiFileWriteChange {
  readonly type: 'write';
  readonly relativePath: string;
  /** Final byte representation to persist. Callers must encrypt sensitive payloads first. */
  readonly contents: Buffer;
  /** `null` requires an absent file; a hash requires that exact current generation. */
  readonly expectedSha256?: string | null;
}

export interface MultiFileWriteFileChange {
  readonly type: 'write-file';
  readonly relativePath: string;
  /**
   * Absolute, internal Main-process path to an already prepared encrypted file.
   * The path is never serialized into the transaction journal and remains owned
   * by the caller after execute returns.
   */
  readonly sourcePath: string;
  /** `null` requires an absent target; a hash requires its exact current generation. */
  readonly expectedSha256?: string | null;
}

export interface MultiFileDeleteChange {
  readonly type: 'delete';
  readonly relativePath: string;
  /** `null` requires an absent file; a hash requires that exact current generation. */
  readonly expectedSha256?: string | null;
}

export type MultiFileChange =
  MultiFileWriteChange | MultiFileWriteFileChange | MultiFileDeleteChange;

export interface MultiFileTransactionHooks {
  /** Diagnostic/test seam invoked only after the durable journal is installed. */
  afterJournalInstalled?(journalPath: string): Promise<void> | void;
}

export interface MultiFileTransactionServiceOptions {
  readonly rootDir: string;
  readonly atomicWriter?: AtomicFileWriter;
  readonly hooks?: MultiFileTransactionHooks;
}

export interface MultiFileExecuteOptions {
  /** Rechecked throughout the operation so session cancellation aborts before commit. */
  readonly assertAuthorized?: () => Promise<void> | void;
}

export interface MultiFileTransactionResult {
  readonly transactionId: string;
  readonly changedPaths: readonly string[];
}

export interface MultiFileRecoveryResult {
  readonly status: 'none' | 'discarded' | 'committed' | 'rolled-back';
  readonly transactionId: string | null;
}

/**
 * Crash-recoverable transaction boundary for a bounded set of files below one data root.
 *
 * The journal contains paths, actions, sizes and hashes only. Existing files are copied
 * byte-for-byte into rollback sidecars, so encrypted at-rest data remains encrypted and
 * no semantic vault values are introduced into transaction metadata.
 */
export class MultiFileTransactionService {
  private readonly rootDir: string;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly hooks: MultiFileTransactionHooks;
  private readonly executor = new SerialExecutor();

  public constructor(options: MultiFileTransactionServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.hooks = options.hooks ?? {};
  }

  public async execute(
    changes: readonly MultiFileChange[],
    options: MultiFileExecuteOptions = {},
  ): Promise<MultiFileTransactionResult> {
    return this.executor.run(async () => this.executeLocked(changes, options.assertAuthorized));
  }

  public async recoverInterruptedTransaction(): Promise<MultiFileRecoveryResult> {
    return this.executor.run(async () => this.recoverLocked());
  }

  private async executeLocked(
    changes: readonly MultiFileChange[],
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<MultiFileTransactionResult> {
    await this.assertRootSafe();
    await this.recoverLocked();
    await assertAuthorized?.();

    const prepared = await this.prepareChanges(changes, assertAuthorized);
    const transaction = await this.beginTransaction(prepared, assertAuthorized);
    let committed = false;

    try {
      await this.hooks.afterJournalInstalled?.(resolveInside(transaction.rootPath, JOURNAL_FILE));
      for (const change of prepared) {
        await assertAuthorized?.();
        await this.assertSourceState(change);
        await this.assertPathHierarchySafe(change.relativePath, true);
        await this.applyChange(change, assertAuthorized);
      }
      await assertAuthorized?.();
      await this.assertTransactionState(transaction, 'committed');
      await this.writeTerminalMarker(transaction, 'committed');
      committed = true;
    } catch (error) {
      if (!committed) {
        try {
          await this.rollbackTransaction(transaction);
        } catch (rollbackError) {
          throw new VaultaError(
            'CORRUPT_DATA',
            'Die Dateitransaktion ist fehlgeschlagen und konnte nicht vollstaendig zurueckgesetzt werden.',
            'Kryptris neu starten, damit die technische Recovery erneut ausgefuehrt wird.',
            { cause: new AggregateError([error, rollbackError]) },
          );
        }
      }
      throw error;
    }

    await this.cleanupTransactionDirectory(transaction.rootPath).catch(() => undefined);
    return {
      transactionId: transaction.journal.transactionId,
      changedPaths: prepared.map((change) => change.relativePath),
    };
  }

  private async prepareChanges(
    changes: readonly MultiFileChange[],
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<PreparedChange[]> {
    if (changes.length === 0 || changes.length > MAX_TRANSACTION_ENTRIES) {
      throw new VaultaError(
        'INVALID_INPUT',
        `Eine Dateitransaktion benoetigt 1 bis ${MAX_TRANSACTION_ENTRIES} Aenderungen.`,
      );
    }

    const relativePaths = new Set<string>();
    const prepared: PreparedChange[] = [];
    for (const change of changes) {
      await assertAuthorized?.();
      const relativePath = this.normalizeRelativePath(change.relativePath, 'INVALID_INPUT');
      if (relativePaths.has(relativePath)) {
        throw new VaultaError(
          'INVALID_INPUT',
          `Die Dateitransaktion enthaelt den Pfad ${relativePath} mehrfach.`,
        );
      }
      relativePaths.add(relativePath);
      await this.assertPathHierarchySafe(relativePath, true);
      await this.assertNoAtomicArtifacts(relativePath);
      const source = await this.readFileState(this.resolveTransactionTarget(relativePath));
      const expectedSha256 = this.normalizeExpectedHash(change.expectedSha256);
      this.assertPrecondition(relativePath, source, expectedSha256);

      if (change.type === 'write') {
        if (!Buffer.isBuffer(change.contents)) {
          throw new VaultaError(
            'INVALID_INPUT',
            'Der Schreibinhalt muss als Bytepuffer vorliegen.',
          );
        }
        const contents = Buffer.from(change.contents);
        prepared.push({
          type: 'write',
          relativePath,
          contents,
          expectedSha256,
          source,
          target: {
            exists: true,
            size: contents.length,
            sha256: createHash('sha256').update(contents).digest('hex'),
          },
        });
      } else if (change.type === 'write-file') {
        const sourcePath = this.normalizePreparedSourcePath(change.sourcePath);
        const preparedFile = await this.readPreparedFileSnapshot(sourcePath, assertAuthorized);
        prepared.push({
          type: 'write-file',
          relativePath,
          preparedFile,
          expectedSha256,
          source,
          target: {
            exists: true,
            size: preparedFile.size,
            sha256: preparedFile.sha256,
          },
        });
      } else if (change.type === 'delete') {
        prepared.push({
          type: 'delete',
          relativePath,
          expectedSha256,
          source,
          target: { exists: false, size: 0, sha256: null },
        });
      } else {
        throw new VaultaError(
          'INVALID_INPUT',
          'Die Dateitransaktion enthaelt eine unbekannte Aktion.',
        );
      }
    }
    return prepared;
  }

  private async beginTransaction(
    prepared: readonly PreparedChange[],
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<ActiveTransaction> {
    const rootPath = resolveInside(this.rootDir, MULTI_FILE_TRANSACTION_DIRECTORY);
    await mkdir(rootPath, { mode: 0o700 }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new VaultaError(
          'CONFLICT',
          'Es existiert bereits eine unvollstaendige Dateitransaktion.',
        );
      }
      throw error;
    });
    await this.syncDirectory(this.rootDir);

    let journalInstalled = false;
    try {
      const entries: TransactionEntry[] = [];
      for (const [index, change] of prepared.entries()) {
        await assertAuthorized?.();
        await this.assertSourceState(change);
        const rollbackFile = change.source.exists
          ? `rollback-${String(index).padStart(6, '0')}.bin`
          : null;
        if (rollbackFile !== null) {
          const targetPath = this.resolveTransactionTarget(change.relativePath);
          const rollbackPath = resolveInside(rootPath, rollbackFile);
          await copyFile(targetPath, rollbackPath, constants.COPYFILE_EXCL);
          await this.syncFile(rollbackPath);
          const rollbackState = await this.readFileState(rollbackPath);
          this.assertStateEquals(
            rollbackState,
            change.source,
            `Die Rollbackdatei fuer ${change.relativePath} wurde nicht bytegenau erstellt.`,
          );
        }
        entries.push({
          relativePath: change.relativePath,
          action: change.type === 'delete' ? 'delete' : 'write',
          rollbackFile,
          sourceExists: change.source.exists,
          sourceSize: change.source.size,
          sourceSha256: change.source.sha256,
          targetExists: change.target.exists,
          targetSize: change.target.size,
          targetSha256: change.target.sha256,
        });
      }

      for (const change of prepared) {
        await assertAuthorized?.();
        await this.assertSourceState(change);
        if (change.type === 'write-file') {
          await this.assertPreparedFileUnchanged(change, assertAuthorized);
        }
      }

      const journal: TransactionJournal = {
        format: JOURNAL_FORMAT,
        version: FORMAT_VERSION,
        transactionId: randomUUID(),
        createdDirectories: await this.collectMissingDirectories(prepared),
        entries,
      };
      const journalBytes = Buffer.from(JSON.stringify(journal), 'utf8');
      await this.writeTechnicalRecord(rootPath, JOURNAL_FILE, journalBytes);
      journalInstalled = true;
      await this.syncDirectory(this.rootDir);
      await assertAuthorized?.();
      return { rootPath, journal, journalBytes };
    } catch (error) {
      if (!journalInstalled) {
        await this.cleanupTransactionDirectory(rootPath).catch(() => undefined);
      }
      throw error;
    }
  }

  private async applyChange(
    change: PreparedChange,
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<void> {
    const targetPath = this.resolveTransactionTarget(change.relativePath);
    if (change.type === 'write') {
      await this.atomicWriter.writeFile(
        targetPath,
        change.contents,
        async (temporaryPath) => {
          const temporaryState = await this.readFileState(temporaryPath);
          this.assertStateEquals(
            temporaryState,
            change.target,
            `Der neue Dateistand fuer ${change.relativePath} ist unvollstaendig.`,
          );
        },
        async () => this.assertSourceState(change),
      );
      return;
    }
    if (change.type === 'write-file') {
      await this.atomicWriter.writeGenerated(
        targetPath,
        async (handle) => this.copyPreparedFileToHandle(change, handle, assertAuthorized),
        async (temporaryPath) => {
          const temporaryState = await this.readFileState(temporaryPath);
          this.assertStateEquals(
            temporaryState,
            change.target,
            `Der neue Dateistand fuer ${change.relativePath} ist unvollstaendig.`,
          );
        },
        async () => this.assertSourceState(change),
      );
      return;
    }

    await this.assertSourceState(change);
    await rm(targetPath, { force: true });
    await this.syncExistingDirectory(path.dirname(targetPath));
  }

  private async recoverLocked(): Promise<MultiFileRecoveryResult> {
    await this.assertRootSafe();
    const rootPath = resolveInside(this.rootDir, MULTI_FILE_TRANSACTION_DIRECTORY);
    const transactionInfo = await lstat(rootPath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (transactionInfo === null) return { status: 'none', transactionId: null };
    if (transactionInfo.isSymbolicLink() || !transactionInfo.isDirectory()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das technische Transaktionsverzeichnis ist kein regulaeres Verzeichnis.',
      );
    }

    const journalBytes = await this.readOptionalTechnicalRecord(
      resolveInside(rootPath, JOURNAL_FILE),
    );
    const terminalBytes = await this.readOptionalTechnicalRecord(
      resolveInside(rootPath, TERMINAL_FILE),
    );

    if (journalBytes === null) {
      const terminal = terminalBytes === null ? null : this.parseTerminalMarker(terminalBytes);
      await this.cleanupTransactionDirectory(rootPath);
      return { status: 'discarded', transactionId: terminal?.transactionId ?? null };
    }

    const journal = this.parseJournal(journalBytes);
    const transaction = { rootPath, journal, journalBytes };
    await this.assertJournalPathsSafe(journal);
    if (terminalBytes !== null) {
      const terminal = this.parseTerminalMarker(terminalBytes);
      this.assertTerminalMatchesJournal(terminal, transaction);
      await this.assertTransactionState(transaction, terminal.outcome);
      await this.cleanupTransactionDirectory(rootPath);
      return { status: terminal.outcome, transactionId: journal.transactionId };
    }

    await this.rollbackTransaction(transaction);
    return { status: 'rolled-back', transactionId: journal.transactionId };
  }

  private async rollbackTransaction(transaction: ActiveTransaction): Promise<void> {
    for (const entry of transaction.journal.entries) {
      await this.assertPathHierarchySafe(entry.relativePath, true);
      if (!entry.sourceExists) continue;
      const rollbackPath = resolveInside(transaction.rootPath, entry.rollbackFile as string);
      const rollbackState = await this.readFileState(rollbackPath);
      this.assertStateEquals(
        rollbackState,
        this.sourceState(entry),
        `Die Rollbackdatei fuer ${entry.relativePath} ist unvollstaendig oder veraendert.`,
      );
    }

    for (const entry of transaction.journal.entries) {
      const targetPath = this.resolveTransactionTarget(entry.relativePath);
      await this.cleanupAtomicTemporaryFiles(targetPath);
      if (!entry.sourceExists) {
        await this.assertPathHierarchySafe(entry.relativePath, true);
        await rm(targetPath, { force: true });
        await rm(`${targetPath}.previous`, { force: true });
        await this.syncExistingDirectory(path.dirname(targetPath));
        continue;
      }

      const rollbackPath = resolveInside(transaction.rootPath, entry.rollbackFile as string);
      const expected = this.sourceState(entry);
      await rm(`${targetPath}.previous`, { force: true });
      await this.atomicWriter.writeGenerated(
        targetPath,
        async (handle) => this.copyRegularFileToHandle(rollbackPath, handle),
        async (temporaryPath) => {
          const temporaryState = await this.readFileState(temporaryPath);
          this.assertStateEquals(
            temporaryState,
            expected,
            `Die Recovery fuer ${entry.relativePath} ist nicht bytegenau.`,
          );
        },
      );
      await this.cleanupAtomicTemporaryFiles(targetPath);
    }

    await this.assertTransactionState(transaction, 'rolled-back');
    await this.removeCreatedDirectories(transaction.journal.createdDirectories);
    await this.writeTerminalMarker(transaction, 'rolled-back');
    await this.cleanupTransactionDirectory(transaction.rootPath).catch(() => undefined);
  }

  private async assertTransactionState(
    transaction: ActiveTransaction,
    outcome: TerminalMarker['outcome'],
  ): Promise<void> {
    for (const entry of transaction.journal.entries) {
      await this.assertPathHierarchySafe(entry.relativePath, true);
      const actual = await this.readFileState(this.resolveTransactionTarget(entry.relativePath));
      const expected = outcome === 'committed' ? this.targetState(entry) : this.sourceState(entry);
      this.assertStateEquals(
        actual,
        expected,
        `Der ${outcome === 'committed' ? 'Commit' : 'Rollback'} fuer ${entry.relativePath} ist unvollstaendig.`,
      );
    }
  }

  private async writeTerminalMarker(
    transaction: ActiveTransaction,
    outcome: TerminalMarker['outcome'],
  ): Promise<void> {
    const marker: TerminalMarker = {
      format: TERMINAL_FORMAT,
      version: FORMAT_VERSION,
      transactionId: transaction.journal.transactionId,
      journalSha256: createHash('sha256').update(transaction.journalBytes).digest('hex'),
      outcome,
    };
    await this.writeTechnicalRecord(
      transaction.rootPath,
      TERMINAL_FILE,
      Buffer.from(JSON.stringify(marker), 'utf8'),
    );
    await this.syncDirectory(this.rootDir);
  }

  private parseJournal(bytes: Buffer): TransactionJournal {
    const value = this.parseRecord(bytes, 'Das technische Transaktionsjournal ist beschaedigt.');
    if (
      value.format !== JOURNAL_FORMAT ||
      value.version !== FORMAT_VERSION ||
      typeof value.transactionId !== 'string' ||
      !UUID.test(value.transactionId) ||
      !Array.isArray(value.createdDirectories) ||
      value.createdDirectories.length > MAX_TRANSACTION_ENTRIES ||
      !Array.isArray(value.entries) ||
      value.entries.length === 0 ||
      value.entries.length > MAX_TRANSACTION_ENTRIES
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Das technische Transaktionsjournal ist ungueltig.');
    }

    const paths = new Set<string>();
    const rollbackFiles = new Set<string>();
    const entries = value.entries.map((candidate, index) => {
      if (
        !isRecord(candidate) ||
        typeof candidate.relativePath !== 'string' ||
        (candidate.action !== 'write' && candidate.action !== 'delete') ||
        (candidate.rollbackFile !== null &&
          (typeof candidate.rollbackFile !== 'string' ||
            !ROLLBACK_FILE.test(candidate.rollbackFile))) ||
        typeof candidate.sourceExists !== 'boolean' ||
        !isSafeSize(candidate.sourceSize) ||
        (candidate.sourceSha256 !== null &&
          (typeof candidate.sourceSha256 !== 'string' || !SHA256.test(candidate.sourceSha256))) ||
        typeof candidate.targetExists !== 'boolean' ||
        !isSafeSize(candidate.targetSize) ||
        (candidate.targetSha256 !== null &&
          (typeof candidate.targetSha256 !== 'string' || !SHA256.test(candidate.targetSha256)))
      ) {
        throw new VaultaError('CORRUPT_DATA', 'Ein technischer Journaleintrag ist ungueltig.');
      }
      const relativePath = this.normalizeRelativePath(candidate.relativePath, 'CORRUPT_DATA');
      const action: TransactionEntry['action'] = candidate.action;
      const expectedRollback = candidate.sourceExists
        ? `rollback-${String(index).padStart(6, '0')}.bin`
        : null;
      if (
        paths.has(relativePath) ||
        candidate.rollbackFile !== expectedRollback ||
        (candidate.rollbackFile !== null && rollbackFiles.has(candidate.rollbackFile)) ||
        (candidate.sourceExists
          ? candidate.sourceSha256 === null
          : candidate.sourceSize !== 0 || candidate.sourceSha256 !== null) ||
        (candidate.targetExists
          ? candidate.targetSha256 === null
          : candidate.targetSize !== 0 || candidate.targetSha256 !== null) ||
        (action === 'write' && !candidate.targetExists) ||
        (action === 'delete' && candidate.targetExists)
      ) {
        throw new VaultaError('CORRUPT_DATA', 'Ein technischer Journaleintrag widerspricht sich.');
      }
      paths.add(relativePath);
      if (candidate.rollbackFile !== null) rollbackFiles.add(candidate.rollbackFile);
      return {
        relativePath,
        action,
        rollbackFile: candidate.rollbackFile,
        sourceExists: candidate.sourceExists,
        sourceSize: candidate.sourceSize,
        sourceSha256: candidate.sourceSha256,
        targetExists: candidate.targetExists,
        targetSize: candidate.targetSize,
        targetSha256: candidate.targetSha256,
      };
    });

    const directories = new Set<string>();
    const writePaths = entries
      .filter((entry) => entry.action === 'write')
      .map((entry) => entry.relativePath);
    const createdDirectories = value.createdDirectories.map((candidate) => {
      if (typeof candidate !== 'string') {
        throw new VaultaError('CORRUPT_DATA', 'Das Journal enthaelt ein ungueltiges Verzeichnis.');
      }
      const directory = this.normalizeRelativePath(candidate, 'CORRUPT_DATA');
      if (
        directories.has(directory) ||
        !writePaths.some((relativePath) => relativePath.startsWith(`${directory}/`))
      ) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Das Journal enthaelt ein unerwartetes Recovery-Verzeichnis.',
        );
      }
      directories.add(directory);
      return directory;
    });

    return {
      format: JOURNAL_FORMAT,
      version: FORMAT_VERSION,
      transactionId: value.transactionId,
      createdDirectories,
      entries,
    };
  }

  private parseTerminalMarker(bytes: Buffer): TerminalMarker {
    const value = this.parseRecord(bytes, 'Der technische Commit-Marker ist beschaedigt.');
    if (
      value.format !== TERMINAL_FORMAT ||
      value.version !== FORMAT_VERSION ||
      typeof value.transactionId !== 'string' ||
      !UUID.test(value.transactionId) ||
      typeof value.journalSha256 !== 'string' ||
      !SHA256.test(value.journalSha256) ||
      (value.outcome !== 'committed' && value.outcome !== 'rolled-back')
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Der technische Commit-Marker ist ungueltig.');
    }
    return {
      format: TERMINAL_FORMAT,
      version: FORMAT_VERSION,
      transactionId: value.transactionId,
      journalSha256: value.journalSha256,
      outcome: value.outcome,
    };
  }

  private parseRecord(bytes: Buffer, message: string): Record<string, unknown> {
    if (bytes.length > MAX_RECORD_BYTES) throw new VaultaError('CORRUPT_DATA', message);
    try {
      const value = JSON.parse(bytes.toString('utf8')) as unknown;
      if (!isRecord(value)) throw new Error('record expected');
      return value;
    } catch (error) {
      throw new VaultaError('CORRUPT_DATA', message, null, { cause: error });
    }
  }

  private assertTerminalMatchesJournal(
    marker: TerminalMarker,
    transaction: ActiveTransaction,
  ): void {
    const journalSha256 = createHash('sha256').update(transaction.journalBytes).digest('hex');
    if (
      marker.transactionId !== transaction.journal.transactionId ||
      marker.journalSha256 !== journalSha256
    ) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Der technische Commit-Marker gehoert nicht zum vorhandenen Journal.',
      );
    }
  }

  private async assertJournalPathsSafe(journal: TransactionJournal): Promise<void> {
    for (const entry of journal.entries) {
      await this.assertPathHierarchySafe(entry.relativePath, true);
    }
    for (const relativePath of journal.createdDirectories) {
      this.resolveTransactionTarget(relativePath);
    }
  }

  private normalizeRelativePath(
    value: unknown,
    errorCode: 'INVALID_INPUT' | 'CORRUPT_DATA',
  ): string {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > 4096 ||
      value.includes('\\') ||
      value.includes('\0') ||
      value.startsWith('/') ||
      value.endsWith('/') ||
      path.posix.isAbsolute(value) ||
      path.win32.isAbsolute(value) ||
      path.posix.normalize(value) !== value ||
      value === '.' ||
      value === '..' ||
      value.startsWith('../') ||
      value === MULTI_FILE_TRANSACTION_DIRECTORY ||
      value.startsWith(`${MULTI_FILE_TRANSACTION_DIRECTORY}/`)
    ) {
      throw new VaultaError(errorCode, 'Die Dateitransaktion enthaelt einen unsicheren Pfad.');
    }
    this.resolveTransactionTarget(value);
    return value;
  }

  private normalizePreparedSourcePath(value: unknown): string {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > 32_767 ||
      value.includes('\0') ||
      !path.isAbsolute(value)
    ) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Die vorbereitete Transaktionsquelle muss einen absoluten Dateipfad besitzen.',
      );
    }
    return path.resolve(value);
  }

  private resolveTransactionTarget(relativePath: string): string {
    return resolveInside(this.rootDir, ...relativePath.split('/'));
  }

  private normalizeExpectedHash(value: string | null | undefined): string | null | undefined {
    if (value === undefined || value === null) return value;
    const normalized = value.toLowerCase();
    if (!SHA256.test(normalized)) {
      throw new VaultaError('INVALID_INPUT', 'Die erwartete Dateiversion ist ungueltig.');
    }
    return normalized;
  }

  private assertPrecondition(
    relativePath: string,
    actual: FileState,
    expectedSha256: string | null | undefined,
  ): void {
    if (expectedSha256 === undefined) return;
    if (expectedSha256 === null && !actual.exists) return;
    if (expectedSha256 !== null && actual.exists && actual.sha256 === expectedSha256) return;
    throw new VaultaError(
      'CONFLICT',
      `Die Datei ${relativePath} entspricht nicht mehr der erwarteten Generation.`,
    );
  }

  private async assertSourceState(change: PreparedChange): Promise<void> {
    const actual = await this.readFileState(this.resolveTransactionTarget(change.relativePath));
    this.assertStateEquals(
      actual,
      change.source,
      `Die Datei ${change.relativePath} wurde waehrend der Transaktion veraendert.`,
      'CONFLICT',
    );
  }

  private assertStateEquals(
    actual: FileState,
    expected: FileState,
    message: string,
    code: 'CONFLICT' | 'CORRUPT_DATA' = 'CORRUPT_DATA',
  ): void {
    if (
      actual.exists !== expected.exists ||
      actual.size !== expected.size ||
      actual.sha256 !== expected.sha256
    ) {
      throw new VaultaError(code, message);
    }
  }

  private sourceState(entry: TransactionEntry): FileState {
    return {
      exists: entry.sourceExists,
      size: entry.sourceSize,
      sha256: entry.sourceSha256,
    };
  }

  private targetState(entry: TransactionEntry): FileState {
    return {
      exists: entry.targetExists,
      size: entry.targetSize,
      sha256: entry.targetSha256,
    };
  }

  private async assertRootSafe(): Promise<void> {
    const info = await lstat(this.rootDir).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Der Datenordner fuer die Dateitransaktion fehlt.');
      }
      throw error;
    });
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Der Datenordner ist kein regulaeres Verzeichnis.');
    }
  }

  private async assertPathHierarchySafe(
    relativePath: string,
    allowMissingTarget: boolean,
  ): Promise<void> {
    const segments = relativePath.split('/');
    let current = this.rootDir;
    for (const [index, segment] of segments.entries()) {
      current = resolveInside(current, segment);
      const info = await lstat(current).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
        throw error;
      });
      if (info === null) {
        if (index === segments.length - 1 && !allowMissingTarget) {
          throw new VaultaError('NOT_FOUND', `Die Datei ${relativePath} fehlt.`);
        }
        continue;
      }
      if (info.isSymbolicLink()) {
        throw new VaultaError('UNSAFE_PATH', `Der Pfad ${relativePath} enthaelt einen Link.`);
      }
      const isTarget = index === segments.length - 1;
      if ((isTarget && !info.isFile()) || (!isTarget && !info.isDirectory())) {
        throw new VaultaError(
          'UNSAFE_PATH',
          `Der Pfad ${relativePath} enthaelt keinen regulaeren Datei-Pfad.`,
        );
      }
    }
  }

  private async assertNoAtomicArtifacts(relativePath: string): Promise<void> {
    const targetPath = this.resolveTransactionTarget(relativePath);
    const previousInfo = await lstat(`${targetPath}.previous`).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (previousInfo !== null) {
      throw new VaultaError(
        'CONFLICT',
        `Fuer ${relativePath} existiert bereits ein unvollstaendiger atomarer Schreibvorgang.`,
      );
    }
    const directory = path.dirname(targetPath);
    const baseName = path.basename(targetPath);
    const prefix = `.${baseName}.vaulta-tmp-`;
    const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    if (entries.some((entry) => entry.name.startsWith(prefix))) {
      throw new VaultaError(
        'CONFLICT',
        `Fuer ${relativePath} existiert bereits eine atomare Temporaerdatei.`,
      );
    }
  }

  private async collectMissingDirectories(prepared: readonly PreparedChange[]): Promise<string[]> {
    const directories = new Set<string>();
    for (const change of prepared) {
      if (change.type === 'delete') continue;
      const segments = change.relativePath.split('/').slice(0, -1);
      let current = '';
      for (const segment of segments) {
        current = current.length === 0 ? segment : `${current}/${segment}`;
        const info = await lstat(this.resolveTransactionTarget(current)).catch((error) => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
          throw error;
        });
        if (info === null) directories.add(current);
      }
    }
    return [...directories].sort((left, right) => {
      const depth = left.split('/').length - right.split('/').length;
      return depth === 0 ? left.localeCompare(right) : depth;
    });
  }

  private async removeCreatedDirectories(relativePaths: readonly string[]): Promise<void> {
    const deepestFirst = [...relativePaths].sort((left, right) => {
      const depth = right.split('/').length - left.split('/').length;
      return depth === 0 ? right.localeCompare(left) : depth;
    });
    for (const relativePath of deepestFirst) {
      const directory = this.resolveTransactionTarget(relativePath);
      const info = await lstat(directory).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
        throw error;
      });
      if (info === null) continue;
      if (info.isSymbolicLink() || !info.isDirectory()) {
        throw new VaultaError('UNSAFE_PATH', 'Ein Recovery-Verzeichnis wurde unerwartet ersetzt.');
      }
      await rmdir(directory).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOTEMPTY') return;
        throw error;
      });
      await this.syncDirectory(path.dirname(directory));
    }
  }

  private async cleanupAtomicTemporaryFiles(targetPath: string): Promise<void> {
    const directory = path.dirname(targetPath);
    const prefix = `.${path.basename(targetPath)}.vaulta-tmp-`;
    const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.startsWith(prefix)) continue;
      await rm(resolveInside(directory, entry.name), { force: true });
    }
    await this.syncDirectory(directory).catch(() => undefined);
  }

  private async cleanupTransactionDirectory(rootPath: string): Promise<void> {
    const entries = await readdir(rootPath, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    for (const entry of entries) {
      const isKnown =
        entry.name === JOURNAL_FILE ||
        entry.name === TERMINAL_FILE ||
        ROLLBACK_FILE.test(entry.name) ||
        TECHNICAL_TEMP_FILE.test(entry.name);
      if (!isKnown || entry.isSymbolicLink() || !entry.isFile()) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das technische Transaktionsverzeichnis enthaelt unerwartete Dateien.',
        );
      }
    }

    for (const entry of entries) {
      if (entry.name === TERMINAL_FILE) continue;
      await rm(resolveInside(rootPath, entry.name), { force: true });
    }
    await this.syncDirectory(rootPath);
    await rm(resolveInside(rootPath, TERMINAL_FILE), { force: true });
    await this.syncDirectory(rootPath);
    await rmdir(rootPath);
    await this.syncDirectory(this.rootDir);
  }

  private async writeTechnicalRecord(
    rootPath: string,
    fileName: typeof JOURNAL_FILE | typeof TERMINAL_FILE,
    bytes: Buffer,
  ): Promise<void> {
    const targetPath = resolveInside(rootPath, fileName);
    const temporaryPath = resolveInside(rootPath, `.${fileName}.tmp-${randomUUID()}`);
    await this.writeDurableExclusive(temporaryPath, bytes);
    try {
      await rename(temporaryPath, targetPath);
      await this.syncDirectory(rootPath);
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  private async writeDurableExclusive(filePath: string, bytes: Buffer): Promise<void> {
    let handle: FileHandle | null = null;
    let complete = false;
    try {
      handle = await open(
        filePath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = null;
      complete = true;
    } finally {
      await handle?.close().catch(() => undefined);
      if (!complete) await rm(filePath, { force: true }).catch(() => undefined);
    }
  }

  private async readOptionalTechnicalRecord(filePath: string): Promise<Buffer | null> {
    const info = await lstat(filePath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) return null;
    if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_RECORD_BYTES) {
      throw new VaultaError('UNSAFE_PATH', 'Ein technischer Transaktionsdatensatz ist ungueltig.');
    }
    return readFile(filePath);
  }

  private async readFileState(filePath: string): Promise<FileState> {
    const pathInfo = await lstat(filePath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (pathInfo === null) return { exists: false, size: 0, sha256: null };
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Die Transaktionsquelle ist keine regulaere Datei.');
    }
    let handle: FileHandle | null = null;
    try {
      handle = await open(filePath, constants.O_RDONLY);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { exists: false, size: 0, sha256: null };
      }
      throw error;
    }
    try {
      const info = await handle.stat();
      if (!info.isFile()) {
        throw new VaultaError('UNSAFE_PATH', 'Die Transaktionsquelle ist keine regulaere Datei.');
      }
      const hash = createHash('sha256');
      const chunk = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
      let size = 0;
      for (;;) {
        const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        hash.update(chunk.subarray(0, bytesRead));
        size += bytesRead;
      }
      const after = await handle.stat();
      if (after.size !== info.size || size !== info.size) {
        throw new VaultaError(
          'CONFLICT',
          'Eine Transaktionsdatei wurde waehrend des Lesens veraendert.',
        );
      }
      return { exists: true, size, sha256: hash.digest('hex') };
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  private async readPreparedFileSnapshot(
    sourcePath: string,
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<PreparedFileSnapshot> {
    await this.assertPreparedSourceHierarchySafe(sourcePath);
    await assertAuthorized?.();
    const pathInfo = await lstat(sourcePath);
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Die vorbereitete Transaktionsquelle ist keine regulaere Datei.',
      );
    }

    const source = await open(sourcePath, constants.O_RDONLY);
    const chunk = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    try {
      const before = await source.stat();
      if (!before.isFile() || !sameFileIdentity(pathInfo, before)) {
        throw new VaultaError(
          'CONFLICT',
          'Die vorbereitete Transaktionsquelle wurde vor dem Einlesen ausgetauscht.',
        );
      }
      const hash = createHash('sha256');
      let size = 0;
      for (;;) {
        await assertAuthorized?.();
        const { bytesRead } = await source.read(chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        hash.update(chunk.subarray(0, bytesRead));
        size += bytesRead;
      }
      const after = await source.stat();
      const afterPath = await lstat(sourcePath);
      if (
        afterPath.isSymbolicLink() ||
        !afterPath.isFile() ||
        !sameFileIdentity(before, after) ||
        !sameFileIdentity(after, afterPath) ||
        size !== after.size
      ) {
        throw new VaultaError(
          'CONFLICT',
          'Die vorbereitete Transaktionsquelle wurde waehrend des Einlesens veraendert.',
        );
      }
      await assertAuthorized?.();
      return {
        absolutePath: sourcePath,
        identity: fileIdentity(after),
        size,
        sha256: hash.digest('hex'),
      };
    } finally {
      chunk.fill(0);
      await source.close().catch(() => undefined);
    }
  }

  private async assertPreparedFileUnchanged(
    change: PreparedWriteFileChange,
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<void> {
    const current = await this.readPreparedFileSnapshot(
      change.preparedFile.absolutePath,
      assertAuthorized,
    );
    if (
      current.size !== change.preparedFile.size ||
      current.sha256 !== change.preparedFile.sha256 ||
      !sameFileIdentity(current.identity, change.preparedFile.identity)
    ) {
      throw new VaultaError(
        'CONFLICT',
        'Die vorbereitete Transaktionsquelle entspricht nicht mehr der geprueften Generation.',
      );
    }
  }

  private async copyPreparedFileToHandle(
    change: PreparedWriteFileChange,
    target: FileHandle,
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<void> {
    const sourcePath = change.preparedFile.absolutePath;
    await this.assertPreparedSourceHierarchySafe(sourcePath);
    await assertAuthorized?.();
    const pathInfo = await lstat(sourcePath);
    if (pathInfo.isSymbolicLink() || !pathInfo.isFile()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Die vorbereitete Transaktionsquelle ist keine regulaere Datei.',
      );
    }
    if (!sameFileIdentity(pathInfo, change.preparedFile.identity)) {
      throw new VaultaError(
        'CONFLICT',
        'Die vorbereitete Transaktionsquelle wurde vor dem Kopieren ausgetauscht.',
      );
    }

    const source = await open(sourcePath, constants.O_RDONLY);
    const chunk = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    try {
      const before = await source.stat();
      if (!before.isFile() || !sameFileIdentity(pathInfo, before)) {
        throw new VaultaError(
          'CONFLICT',
          'Die vorbereitete Transaktionsquelle wurde vor dem Kopieren ausgetauscht.',
        );
      }
      const hash = createHash('sha256');
      let size = 0;
      for (;;) {
        await assertAuthorized?.();
        const { bytesRead } = await source.read(chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        const data = chunk.subarray(0, bytesRead);
        hash.update(data);
        await this.writeAll(target, data);
        size += bytesRead;
        await assertAuthorized?.();
      }
      const after = await source.stat();
      const afterPath = await lstat(sourcePath);
      const sha256 = hash.digest('hex');
      if (
        afterPath.isSymbolicLink() ||
        !afterPath.isFile() ||
        !sameFileIdentity(before, after) ||
        !sameFileIdentity(after, afterPath) ||
        !sameFileIdentity(after, change.preparedFile.identity) ||
        size !== change.preparedFile.size ||
        sha256 !== change.preparedFile.sha256
      ) {
        throw new VaultaError(
          'CONFLICT',
          'Die vorbereitete Transaktionsquelle wurde waehrend des Kopierens veraendert.',
        );
      }
      await assertAuthorized?.();
    } finally {
      chunk.fill(0);
      await source.close().catch(() => undefined);
    }
  }

  private async assertPreparedSourceHierarchySafe(sourcePath: string): Promise<void> {
    const parsed = path.parse(sourcePath);
    const relative = path.relative(parsed.root, sourcePath);
    if (relative.length === 0 || relative === '..' || relative.startsWith(`..${path.sep}`)) {
      throw new VaultaError('UNSAFE_PATH', 'Der vorbereitete Transaktionspfad ist ungueltig.');
    }
    const segments = relative.split(path.sep).filter((segment) => segment.length > 0);
    let current = parsed.root;
    for (const [index, segment] of segments.entries()) {
      current = path.join(current, segment);
      const info = await lstat(current).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new VaultaError(
            'NOT_FOUND',
            'Die vorbereitete Transaktionsquelle wurde nicht gefunden.',
          );
        }
        throw error;
      });
      if (info.isSymbolicLink()) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Der vorbereitete Transaktionspfad enthaelt einen symbolischen Link.',
        );
      }
      const isSource = index === segments.length - 1;
      if ((isSource && !info.isFile()) || (!isSource && !info.isDirectory())) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Der vorbereitete Transaktionspfad ist kein regulaerer Dateipfad.',
        );
      }
    }
  }

  private async writeAll(target: FileHandle, data: Buffer): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
      const { bytesWritten } = await target.write(data, offset, data.length - offset, null);
      if (bytesWritten === 0) {
        throw new VaultaError(
          'INTERNAL',
          'Die vorbereitete Transaktionsdatei konnte nicht vollstaendig geschrieben werden.',
        );
      }
      offset += bytesWritten;
    }
  }

  private async copyRegularFileToHandle(sourcePath: string, target: FileHandle): Promise<void> {
    const source = await open(sourcePath, constants.O_RDONLY);
    try {
      const info = await source.stat();
      if (!info.isFile()) {
        throw new VaultaError('UNSAFE_PATH', 'Die Rollbackdatei ist keine regulaere Datei.');
      }
      const chunk = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
      for (;;) {
        const { bytesRead } = await source.read(chunk, 0, chunk.length, null);
        if (bytesRead === 0) break;
        await target.write(chunk.subarray(0, bytesRead));
      }
    } finally {
      await source.close().catch(() => undefined);
    }
  }

  private async syncFile(filePath: string): Promise<void> {
    const handle = await open(filePath, constants.O_RDWR);
    try {
      await handle.sync();
    } finally {
      await handle.close().catch(() => undefined);
    }
  }

  private async syncDirectory(directory: string): Promise<void> {
    let handle: FileHandle | null = null;
    try {
      handle = await open(directory, constants.O_RDONLY);
      await handle.sync();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const expected =
        process.platform === 'win32' ? ['EINVAL', 'EPERM', 'EACCES'] : ['EINVAL', 'EPERM'];
      if (code === undefined || !expected.includes(code)) throw error;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  private async syncExistingDirectory(directory: string): Promise<void> {
    const info = await lstat(directory).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) return;
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Ein Transaktionsverzeichnis wurde unerwartet ersetzt.');
    }
    await this.syncDirectory(directory);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSafeSize(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function fileIdentity(value: FileIdentity): FileIdentity {
  return {
    dev: value.dev,
    ino: value.ino,
    size: value.size,
    mtimeMs: value.mtimeMs,
    ctimeMs: value.ctimeMs,
  };
}

function sameFileIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
