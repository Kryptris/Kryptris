import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readdir, realpath, rm, stat, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type { AttachmentMetadata } from '../../shared/models';
import { requireCurrentFormatVersion } from '../migrations/format-version';
import { type AesGcmEnvelope, CryptoService } from '../security/crypto-service';
import { AtomicFileWriter } from '../storage/atomic-file';
import {
  writeExclusiveCleartextFile,
  type CleartextFileWriteOptions,
} from '../storage/cleartext-file';
import { assertSafeIdentifier, resolveInside } from '../storage/path-safety';
import type { VaultService } from './vault-service';

const ATTACHMENT_MAGIC = Buffer.from('VLTATT01', 'ascii');
export const ATTACHMENT_FORMAT_VERSION = 1 as const;
const ATTACHMENT_VERSION = ATTACHMENT_FORMAT_VERSION;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const DEFAULT_MAX_BYTES = 100 * 1024 * 1024;
const HEADER_LIMIT = 64 * 1024;
const RECORD_HEADER_BYTES = 9;
const TAG_BYTES = 16;
const DATA_RECORD = 0;
const FOOTER_RECORD = 1;

const SAFE_PREVIEW_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'text/plain',
  'text/markdown',
  'application/pdf',
]);

/** The allow-list is shared by every path that creates attachment metadata. */
export function isSafeAttachmentPreviewMediaType(mediaType: string): boolean {
  return SAFE_PREVIEW_TYPES.has(mediaType);
}

interface AttachmentHeader {
  format: 'vaulta-attachment';
  version: typeof ATTACHMENT_VERSION;
  cipher: 'AES-256-GCM-CHUNKED';
  chunkSize: number;
  noncePrefix: string;
  wrappedFileKey: AesGcmEnvelope;
}

interface AttachmentFooter {
  formatVersion: typeof ATTACHMENT_VERSION;
  chunkCount: number;
  totalBytes: number;
  sha256: string;
}

export interface AttachmentServiceOptions {
  rootDir: string;
  vaultService: VaultService;
  crypto?: CryptoService;
  atomicWriter?: AtomicFileWriter;
  chunkSize?: number;
  defaultMaxBytes?: number;
  now?: () => Date;
}

export interface EncryptAttachmentInput {
  vaultId: string;
  sourcePath: string;
  attachmentId?: string;
  name?: string;
  mediaType?: string;
  maxBytes?: number;
}

/**
 * Main-process-only input for preparing a cross-vault attachment copy.
 * `stagingPath` must come from the internal transaction coordinator and must
 * never be accepted from a renderer IPC request.
 */
export interface ReencryptAttachmentToStagingInput {
  sourceVaultId: string;
  sourceAttachmentId: string;
  targetVaultId: string;
  targetAttachmentId: string;
  stagingPath: string;
  name: string;
  mediaType: string;
  assertAuthorized: () => void;
}

/**
 * Main-process-only package-import bridge. `contents` is the short-lived,
 * already authenticated plaintext emitted by the package reader; it is never
 * written as a cleartext file. The caller owns the encrypted staging file and
 * the input buffer and must remove/erase both after its wider transaction.
 */
export interface EncryptAttachmentBufferToStagingInput {
  targetVaultId: string;
  targetAttachmentId: string;
  stagingPath: string;
  /** The controller-owned direct parent directory for `stagingPath`. */
  stagingDirectory: string;
  /** Revalidates the controller's canonical-directory capability before writes. */
  assertStagingDirectory: () => Promise<void> | void;
  name: string;
  mediaType: string;
  contents: Buffer;
  targetVaultKey: Buffer;
  createdAt?: string;
  assertAuthorized: () => void;
}

export interface AuthenticatedAttachmentMetadata {
  readonly size: number;
  readonly sha256: string;
}

export interface StoredAttachmentReference {
  readonly vaultId: string;
  readonly attachmentId: string;
}

export interface StoredAttachmentInventory {
  readonly references: StoredAttachmentReference[];
  readonly invalidEntryCount: number;
}

export interface AttachmentIntegrityOptions {
  readonly assertAuthorized?: () => void;
  readonly yieldControl?: () => Promise<void>;
  readonly yieldEveryChunks?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseJson(value: Buffer, message: string): unknown {
  try {
    return JSON.parse(value.toString('utf8')) as unknown;
  } catch (error) {
    throw new VaultaError('CORRUPT_DATA', message, null, { cause: error });
  }
}

function parseEnvelope(value: unknown): AesGcmEnvelope {
  if (
    !isRecord(value) ||
    value.algorithm !== 'AES-256-GCM' ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string' ||
    typeof value.tag !== 'string'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangsschlüssel ist beschädigt.');
  }
  return {
    algorithm: value.algorithm,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    tag: value.tag,
  };
}

function parseHeader(value: unknown): AttachmentHeader {
  if (!isRecord(value)) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
  }
  requireCurrentFormatVersion(value.version, ATTACHMENT_VERSION, 'Vaulta-Anhangsheader');
  if (
    value.format !== 'vaulta-attachment' ||
    value.cipher !== 'AES-256-GCM-CHUNKED' ||
    typeof value.chunkSize !== 'number' ||
    !Number.isSafeInteger(value.chunkSize) ||
    value.chunkSize < 4096 ||
    value.chunkSize > 16 * 1024 * 1024 ||
    typeof value.noncePrefix !== 'string'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
  }
  if (Buffer.from(value.noncePrefix, 'base64').length !== 8) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangs-Nonce ist ungültig.');
  }
  return {
    format: 'vaulta-attachment',
    version: ATTACHMENT_VERSION,
    cipher: 'AES-256-GCM-CHUNKED',
    chunkSize: value.chunkSize,
    noncePrefix: value.noncePrefix,
    wrappedFileKey: parseEnvelope(value.wrappedFileKey),
  };
}

async function writeAll(handle: FileHandle, data: Buffer, position: number): Promise<number> {
  let written = 0;
  while (written < data.length) {
    const result = await handle.write(data, written, data.length - written, position + written);
    if (result.bytesWritten === 0) throw new Error('Could not make progress writing file');
    written += result.bytesWritten;
  }
  return position + written;
}

async function readExact(handle: FileHandle, length: number, position: number): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(length);
  let read = 0;
  while (read < length) {
    const result = await handle.read(buffer, read, length - read, position + read);
    if (result.bytesRead === 0) {
      throw new VaultaError('CORRUPT_DATA', 'Der verschlüsselte Anhang ist unvollständig.');
    }
    read += result.bytesRead;
  }
  return buffer;
}

export class AttachmentService {
  private readonly attachmentsDir: string;
  private readonly vaultService: VaultService;
  private readonly crypto: CryptoService;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly chunkSize: number;
  private readonly defaultMaxBytes: number;
  private readonly now: () => Date;

  public constructor(options: AttachmentServiceOptions) {
    this.attachmentsDir = path.resolve(options.rootDir, 'attachments');
    this.vaultService = options.vaultService;
    this.crypto = options.crypto ?? new CryptoService();
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
    this.defaultMaxBytes = options.defaultMaxBytes ?? DEFAULT_MAX_BYTES;
    this.now = options.now ?? (() => new Date());
    if (
      !Number.isSafeInteger(this.chunkSize) ||
      this.chunkSize < 4096 ||
      this.chunkSize > 16 * 1024 * 1024
    ) {
      throw new VaultaError('INVALID_INPUT', 'Die Anhangs-Chunkgröße ist ungültig.');
    }
  }

  public async encryptFile(input: EncryptAttachmentInput): Promise<AttachmentMetadata> {
    assertSafeIdentifier(input.vaultId, 'Tresor-ID');
    const attachmentId = input.attachmentId ?? randomUUID();
    assertSafeIdentifier(attachmentId, 'Anhangs-ID');
    const sourceInfo = await stat(input.sourcePath);
    if (!sourceInfo.isFile()) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Als Anhang können nur reguläre Dateien gewählt werden.',
      );
    }
    const maxBytes = input.maxBytes ?? this.defaultMaxBytes;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || sourceInfo.size > maxBytes) {
      throw new VaultaError('FILE_TOO_LARGE', 'Die Datei überschreitet das erlaubte Größenlimit.');
    }

    const name = (input.name ?? path.basename(input.sourcePath)).trim();
    const mediaType = input.mediaType ?? 'application/octet-stream';
    if (
      name.length === 0 ||
      name.length > 255 ||
      [...name].some((character) => character.charCodeAt(0) < 32)
    ) {
      throw new VaultaError('INVALID_INPUT', 'Der Anhangsname ist ungültig.');
    }
    if (mediaType.length === 0 || mediaType.length > 127) {
      throw new VaultaError('INVALID_INPUT', 'Der Medientyp des Anhangs ist ungültig.');
    }

    const targetPath = this.attachmentPath(input.vaultId, attachmentId);
    return this.vaultService.withVaultKey(input.vaultId, async (vaultKey) => {
      const fileKey = this.crypto.randomBytes(32);
      const noncePrefix = this.crypto.randomBytes(8);
      const header: AttachmentHeader = {
        format: 'vaulta-attachment',
        version: ATTACHMENT_VERSION,
        cipher: 'AES-256-GCM-CHUNKED',
        chunkSize: this.chunkSize,
        noncePrefix: noncePrefix.toString('base64'),
        wrappedFileKey: this.crypto.wrapKey(
          fileKey,
          vaultKey,
          `attachment:${input.vaultId}:${attachmentId}:file-key`,
        ),
      };
      const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
      const hash = createHash('sha256');
      let totalBytes = 0;
      let chunkCount = 0;

      try {
        await this.atomicWriter.writeGenerated(
          targetPath,
          async (output) => {
            let outputPosition = 0;
            outputPosition = await writeAll(output, ATTACHMENT_MAGIC, outputPosition);
            const headerLength = Buffer.allocUnsafe(4);
            headerLength.writeUInt32BE(headerBytes.length);
            outputPosition = await writeAll(output, headerLength, outputPosition);
            outputPosition = await writeAll(output, headerBytes, outputPosition);

            const source = await open(input.sourcePath, constants.O_RDONLY);
            try {
              let sourcePosition = 0;
              while (true) {
                const chunkBuffer = Buffer.allocUnsafe(this.chunkSize);
                const { bytesRead } = await source.read(
                  chunkBuffer,
                  0,
                  this.chunkSize,
                  sourcePosition,
                );
                if (bytesRead === 0) break;
                sourcePosition += bytesRead;
                totalBytes += bytesRead;
                if (totalBytes > maxBytes) {
                  throw new VaultaError(
                    'FILE_TOO_LARGE',
                    'Die Datei ist während des Einlesens über das Größenlimit gewachsen.',
                  );
                }
                const chunk = chunkBuffer.subarray(0, bytesRead);
                hash.update(chunk);
                outputPosition = await this.writeRecord(
                  output,
                  outputPosition,
                  DATA_RECORD,
                  chunkCount,
                  chunk,
                  fileKey,
                  noncePrefix,
                  headerBytes,
                );
                chunkBuffer.fill(0);
                chunkCount += 1;
              }
            } finally {
              await source.close();
            }

            const footer: AttachmentFooter = {
              formatVersion: ATTACHMENT_VERSION,
              chunkCount,
              totalBytes,
              sha256: hash.digest('hex'),
            };
            const footerBytes = Buffer.from(JSON.stringify(footer), 'utf8');
            await this.writeRecord(
              output,
              outputPosition,
              FOOTER_RECORD,
              chunkCount,
              footerBytes,
              fileKey,
              noncePrefix,
              headerBytes,
            );
            footerBytes.fill(0);
          },
          async (temporaryPath) => {
            await this.decryptAndVerify(
              temporaryPath,
              input.vaultId,
              attachmentId,
              vaultKey,
              () => undefined,
            );
          },
        );
      } finally {
        this.crypto.erase(fileKey);
        this.crypto.erase(noncePrefix);
        this.crypto.erase(headerBytes);
      }

      return {
        id: attachmentId,
        name,
        mediaType,
        size: totalBytes,
        sha256: await this.getVerifiedHash(targetPath, input.vaultId, attachmentId, vaultKey),
        createdAt: this.now().toISOString(),
        previewable: isSafeAttachmentPreviewMediaType(mediaType),
      };
    });
  }

  /**
   * Authenticates an existing attachment chunk by chunk and immediately
   * encrypts each plaintext chunk for another vault. The caller owns the
   * resulting, fully verified staging file and is responsible for committing
   * it as part of a wider transaction.
   */
  public async reencryptToStaging(
    input: ReencryptAttachmentToStagingInput,
  ): Promise<AttachmentMetadata> {
    assertSafeIdentifier(input.sourceVaultId, 'Quell-Tresor-ID');
    assertSafeIdentifier(input.sourceAttachmentId, 'Quell-Anhangs-ID');
    assertSafeIdentifier(input.targetVaultId, 'Ziel-Tresor-ID');
    assertSafeIdentifier(input.targetAttachmentId, 'Ziel-Anhangs-ID');
    if (input.sourceAttachmentId === input.targetAttachmentId) {
      throw new VaultaError('INVALID_INPUT', 'Die Ziel-Anhangs-ID muss neu sein.');
    }
    if (!path.isAbsolute(input.stagingPath)) {
      throw new VaultaError('UNSAFE_PATH', 'Der Staging-Pfad muss absolut sein.');
    }

    const stagingPath = path.resolve(input.stagingPath);
    const sourcePath = this.attachmentPath(input.sourceVaultId, input.sourceAttachmentId);
    if (this.samePath(stagingPath, sourcePath)) {
      throw new VaultaError('UNSAFE_PATH', 'Der Quell-Anhang darf nicht als Staging-Ziel dienen.');
    }
    const name = input.name.trim();
    if (
      name.length === 0 ||
      name.length > 255 ||
      [...name].some((character) => character.charCodeAt(0) < 32)
    ) {
      throw new VaultaError('INVALID_INPUT', 'Der Anhangsname ist ungültig.');
    }
    if (input.mediaType.length === 0 || input.mediaType.length > 127) {
      throw new VaultaError('INVALID_INPUT', 'Der Medientyp des Anhangs ist ungültig.');
    }

    input.assertAuthorized();
    let output: FileHandle | null = null;
    let stagingCreated = false;
    let completed = false;
    try {
      output = await open(
        stagingPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
        0o600,
      );
      stagingCreated = true;
      const metadata = await this.vaultService.withVaultKey(
        input.sourceVaultId,
        async (sourceVaultKey) =>
          this.vaultService.withVaultKey(input.targetVaultId, async (targetVaultKey) => {
            input.assertAuthorized();
            let targetFileKey: Buffer | null = null;
            let targetNoncePrefix: Buffer | null = null;
            let targetHeaderBytes: Buffer | null = null;

            try {
              targetFileKey = this.crypto.randomBytes(32);
              targetNoncePrefix = this.crypto.randomBytes(8);
              const activeTargetFileKey = targetFileKey;
              const activeTargetNoncePrefix = targetNoncePrefix;
              const targetHeader: AttachmentHeader = {
                format: 'vaulta-attachment',
                version: ATTACHMENT_VERSION,
                cipher: 'AES-256-GCM-CHUNKED',
                chunkSize: this.chunkSize,
                noncePrefix: activeTargetNoncePrefix.toString('base64'),
                wrappedFileKey: this.crypto.wrapKey(
                  activeTargetFileKey,
                  targetVaultKey,
                  `attachment:${input.targetVaultId}:${input.targetAttachmentId}:file-key`,
                ),
              };
              targetHeaderBytes = Buffer.from(JSON.stringify(targetHeader), 'utf8');
              const activeTargetHeaderBytes = targetHeaderBytes;
              let outputPosition = 0;
              let targetChunkCount = 0;

              outputPosition = await writeAll(output!, ATTACHMENT_MAGIC, outputPosition);
              const headerLength = Buffer.allocUnsafe(4);
              try {
                headerLength.writeUInt32BE(targetHeaderBytes.length);
                outputPosition = await writeAll(output!, headerLength, outputPosition);
              } finally {
                this.crypto.erase(headerLength);
              }
              outputPosition = await writeAll(output!, activeTargetHeaderBytes, outputPosition);
              input.assertAuthorized();

              const sourceFooter = await this.decryptAndVerify(
                sourcePath,
                input.sourceVaultId,
                input.sourceAttachmentId,
                sourceVaultKey,
                async (chunk) => {
                  for (let offset = 0; offset < chunk.length; offset += this.chunkSize) {
                    input.assertAuthorized();
                    outputPosition = await this.writeRecord(
                      output!,
                      outputPosition,
                      DATA_RECORD,
                      targetChunkCount,
                      chunk.subarray(offset, offset + this.chunkSize),
                      activeTargetFileKey,
                      activeTargetNoncePrefix,
                      activeTargetHeaderBytes,
                    );
                    targetChunkCount += 1;
                    input.assertAuthorized();
                  }
                },
                input.assertAuthorized,
              );
              input.assertAuthorized();

              const targetFooter: AttachmentFooter = {
                formatVersion: ATTACHMENT_VERSION,
                chunkCount: targetChunkCount,
                totalBytes: sourceFooter.totalBytes,
                sha256: sourceFooter.sha256,
              };
              const targetFooterBytes = Buffer.from(JSON.stringify(targetFooter), 'utf8');
              try {
                outputPosition = await this.writeRecord(
                  output!,
                  outputPosition,
                  FOOTER_RECORD,
                  targetChunkCount,
                  targetFooterBytes,
                  activeTargetFileKey,
                  activeTargetNoncePrefix,
                  activeTargetHeaderBytes,
                );
              } finally {
                this.crypto.erase(targetFooterBytes);
              }
              input.assertAuthorized();
              await output!.truncate(outputPosition);
              await output!.sync();
              await output!.close();
              output = null;
              input.assertAuthorized();

              const verifiedFooter = await this.decryptAndVerify(
                stagingPath,
                input.targetVaultId,
                input.targetAttachmentId,
                targetVaultKey,
                () => input.assertAuthorized(),
                input.assertAuthorized,
              );
              input.assertAuthorized();
              if (
                verifiedFooter.totalBytes !== sourceFooter.totalBytes ||
                verifiedFooter.sha256 !== sourceFooter.sha256
              ) {
                throw new VaultaError(
                  'CORRUPT_DATA',
                  'Der neu verschlüsselte Anhang stimmt nicht mit der Quelle überein.',
                );
              }

              return {
                id: input.targetAttachmentId,
                name,
                mediaType: input.mediaType,
                size: verifiedFooter.totalBytes,
                sha256: verifiedFooter.sha256,
                createdAt: this.now().toISOString(),
                previewable: isSafeAttachmentPreviewMediaType(input.mediaType),
              };
            } finally {
              this.crypto.erase(targetFileKey);
              this.crypto.erase(targetNoncePrefix);
              this.crypto.erase(targetHeaderBytes);
            }
          }),
      );
      input.assertAuthorized();
      completed = true;
      return metadata;
    } finally {
      await output?.close().catch(() => undefined);
      if (!completed && stagingCreated) await rm(stagingPath, { force: true });
    }
  }

  /**
   * Writes a new encrypted attachment directly from a verified Main-process
   * buffer into an exclusive staging path. Unlike `encryptFile`, this path
   * never creates a cleartext filesystem artifact and does not publish the
   * attachment before the caller's multi-file transaction has committed.
   */
  public async encryptBufferToStaging(
    input: EncryptAttachmentBufferToStagingInput,
  ): Promise<AttachmentMetadata> {
    assertSafeIdentifier(input.targetVaultId, 'Ziel-Tresor-ID');
    assertSafeIdentifier(input.targetAttachmentId, 'Ziel-Anhangs-ID');
    if (!path.isAbsolute(input.stagingPath)) {
      throw new VaultaError('UNSAFE_PATH', 'Der Staging-Pfad muss absolut sein.');
    }
    if (input.targetVaultKey.length !== 32) {
      throw new VaultaError('INVALID_INPUT', 'Der Ziel-Tresorschluessel ist ungueltig.');
    }
    const stagingPath = path.resolve(input.stagingPath);
    const stagingDirectory = path.resolve(input.stagingDirectory);
    if (
      path.dirname(stagingPath) !== stagingDirectory ||
      path.basename(stagingPath) !== `${input.targetAttachmentId}.vatt`
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Staging-Pfad ist nicht controller-eigen.');
    }
    if (
      this.samePath(stagingPath, this.attachmentPath(input.targetVaultId, input.targetAttachmentId))
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der Staging-Pfad darf kein Live-Anhang sein.');
    }
    const name = input.name.trim();
    if (
      name.length === 0 ||
      name.length > 255 ||
      [...name].some((character) => character.charCodeAt(0) < 32)
    ) {
      throw new VaultaError('INVALID_INPUT', 'Der Anhangsname ist ungueltig.');
    }
    if (input.mediaType.length === 0 || input.mediaType.length > 127) {
      throw new VaultaError('INVALID_INPUT', 'Der Medientyp des Anhangs ist ungueltig.');
    }
    if (input.contents.length > this.defaultMaxBytes) {
      throw new VaultaError('FILE_TOO_LARGE', 'Der Paket-Anhang ueberschreitet das Groessenlimit.');
    }
    const createdAt = input.createdAt ?? this.now().toISOString();
    if (!Number.isFinite(Date.parse(createdAt))) {
      throw new VaultaError('INVALID_INPUT', 'Der Anhangszeitpunkt ist ungueltig.');
    }

    input.assertAuthorized();
    let output: FileHandle | null = null;
    let fileKey: Buffer | null = null;
    let noncePrefix: Buffer | null = null;
    let headerBytes: Buffer | null = null;
    try {
      await this.assertOwnedPackageStagingDirectory(stagingDirectory, input.assertStagingDirectory);
      input.assertAuthorized();
      output = await open(
        stagingPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
        0o600,
      );
      await this.assertOpenedPackageStagingFile(
        output,
        stagingPath,
        stagingDirectory,
        input.assertStagingDirectory,
      );
      input.assertAuthorized();
      fileKey = this.crypto.randomBytes(32);
      noncePrefix = this.crypto.randomBytes(8);
      const header: AttachmentHeader = {
        format: 'vaulta-attachment',
        version: ATTACHMENT_VERSION,
        cipher: 'AES-256-GCM-CHUNKED',
        chunkSize: this.chunkSize,
        noncePrefix: noncePrefix.toString('base64'),
        wrappedFileKey: this.crypto.wrapKey(
          fileKey,
          input.targetVaultKey,
          `attachment:${input.targetVaultId}:${input.targetAttachmentId}:file-key`,
        ),
      };
      headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
      let outputPosition = 0;
      outputPosition = await writeAll(output, ATTACHMENT_MAGIC, outputPosition);
      const headerLength = Buffer.allocUnsafe(4);
      try {
        headerLength.writeUInt32BE(headerBytes.length);
        outputPosition = await writeAll(output, headerLength, outputPosition);
      } finally {
        this.crypto.erase(headerLength);
      }
      outputPosition = await writeAll(output, headerBytes, outputPosition);

      const hash = createHash('sha256');
      let chunkCount = 0;
      for (let offset = 0; offset < input.contents.length; offset += this.chunkSize) {
        input.assertAuthorized();
        const chunk = input.contents.subarray(
          offset,
          Math.min(offset + this.chunkSize, input.contents.length),
        );
        hash.update(chunk);
        outputPosition = await this.writeRecord(
          output,
          outputPosition,
          DATA_RECORD,
          chunkCount,
          chunk,
          fileKey,
          noncePrefix,
          headerBytes,
        );
        chunkCount += 1;
      }
      const footer: AttachmentFooter = {
        formatVersion: ATTACHMENT_VERSION,
        chunkCount,
        totalBytes: input.contents.length,
        sha256: hash.digest('hex'),
      };
      const footerBytes = Buffer.from(JSON.stringify(footer), 'utf8');
      try {
        outputPosition = await this.writeRecord(
          output,
          outputPosition,
          FOOTER_RECORD,
          chunkCount,
          footerBytes,
          fileKey,
          noncePrefix,
          headerBytes,
        );
      } finally {
        this.crypto.erase(footerBytes);
      }
      input.assertAuthorized();
      await output.truncate(outputPosition);
      await output.sync();
      input.assertAuthorized();

      // Verify through the already validated descriptor. A later pathname swap
      // cannot redirect either the ciphertext verification or future writes.
      const verified = await this.decryptAndVerifyHandle(
        output,
        input.targetVaultId,
        input.targetAttachmentId,
        input.targetVaultKey,
        () => input.assertAuthorized(),
        input.assertAuthorized,
      );
      if (verified.totalBytes !== input.contents.length || verified.sha256 !== footer.sha256) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Der verschluesselte Paket-Anhang stimmt nicht mit dem geprueften Inhalt ueberein.',
        );
      }
      await output.close();
      output = null;
      return {
        id: input.targetAttachmentId,
        name,
        mediaType: input.mediaType,
        size: verified.totalBytes,
        sha256: verified.sha256,
        createdAt,
        previewable: isSafeAttachmentPreviewMediaType(input.mediaType),
      };
    } finally {
      await output?.close().catch(() => undefined);
      this.crypto.erase(fileKey);
      this.crypto.erase(noncePrefix);
      this.crypto.erase(headerBytes);
      // Do not unlink by a later pathname here. The controller owns staging
      // cleanup and revalidates its directory/file identities before removal;
      // doing it here could delete a path swapped after this handle closed.
    }
  }

  public async decryptToFile(
    vaultId: string,
    attachmentId: string,
    destinationPath: string,
    assertAuthorized: () => void = () => undefined,
    options: CleartextFileWriteOptions = {},
  ): Promise<void> {
    assertAuthorized();
    const sourcePath = this.attachmentPath(vaultId, attachmentId);
    await writeExclusiveCleartextFile(
      destinationPath,
      async (output) => {
        assertAuthorized();
        await this.vaultService.withVaultKey(vaultId, async (vaultKey) => {
          let position = 0;
          await this.decryptAndVerify(
            sourcePath,
            vaultId,
            attachmentId,
            vaultKey,
            async (chunk) => {
              assertAuthorized();
              position = await writeAll(output, chunk, position);
              assertAuthorized();
            },
          );
        });
        assertAuthorized();
      },
      options,
    );
  }

  public async readBuffer(
    vaultId: string,
    attachmentId: string,
    maximumBytes = 10 * 1024 * 1024,
  ): Promise<Buffer> {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
      throw new VaultaError('INVALID_INPUT', 'Das Vorschaulimit ist ungültig.');
    }
    const chunks: Buffer[] = [];
    let total = 0;
    await this.vaultService.withVaultKey(vaultId, async (vaultKey) => {
      await this.decryptAndVerify(
        this.attachmentPath(vaultId, attachmentId),
        vaultId,
        attachmentId,
        vaultKey,
        (chunk) => {
          total += chunk.length;
          if (total > maximumBytes) {
            throw new VaultaError('FILE_TOO_LARGE', 'Der Anhang ist für eine Vorschau zu groß.');
          }
          chunks.push(Buffer.from(chunk));
        },
      );
    });
    return Buffer.concat(chunks);
  }

  public async verify(vaultId: string, attachmentId: string): Promise<void> {
    await this.inspectStoredFormatVersion(vaultId, attachmentId);
  }

  /**
   * Authenticates an encrypted attachment and binds the verified footer to the
   * metadata stored in the vault document. Coordinators use this before a
   * merge so a stale or forged size/hash pair cannot be committed.
   */
  public async verifyMetadata(
    vaultId: string,
    metadata: AttachmentMetadata,
    assertAuthorized: () => void = () => undefined,
  ): Promise<void> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertSafeIdentifier(metadata.id, 'Anhangs-ID');
    if (
      !Number.isSafeInteger(metadata.size) ||
      metadata.size < 0 ||
      !/^[a-f0-9]{64}$/u.test(metadata.sha256)
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Die Anhangsmetadaten sind ungültig.');
    }

    const footer = await this.readAuthenticatedMetadata(vaultId, metadata.id, assertAuthorized);
    assertAuthorized();
    if (footer.size !== metadata.size || footer.sha256 !== metadata.sha256) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Anhangsmetadaten und authentifizierter Dateiinhalt stimmen nicht überein.',
      );
    }
  }

  /** Returns only authenticated technical footer values for Main-process consistency checks. */
  public async readAuthenticatedMetadata(
    vaultId: string,
    attachmentId: string,
    assertAuthorized: () => void = () => undefined,
  ): Promise<AuthenticatedAttachmentMetadata> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertSafeIdentifier(attachmentId, 'Anhangs-ID');
    assertAuthorized();
    const footer = await this.vaultService.withVaultKey(vaultId, async (vaultKey) => {
      assertAuthorized();
      return await this.decryptAndVerify(
        this.attachmentPath(vaultId, attachmentId),
        vaultId,
        attachmentId,
        vaultKey,
        () => assertAuthorized(),
        assertAuthorized,
      );
    });
    assertAuthorized();
    return { size: footer.totalBytes, sha256: footer.sha256 };
  }

  /**
   * Authenticates every encrypted chunk and yields regularly so an immediate
   * lock can invalidate the caller's authorization epoch.
   */
  public async inspectIntegrity(
    vaultId: string,
    attachmentId: string,
    options: AttachmentIntegrityOptions = {},
  ): Promise<AuthenticatedAttachmentMetadata> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertSafeIdentifier(attachmentId, 'Anhangs-ID');
    const assertAuthorized = options.assertAuthorized ?? (() => undefined);
    const yieldControl =
      options.yieldControl ?? (() => new Promise<void>((resolve) => setImmediate(resolve)));
    const yieldEveryChunks = options.yieldEveryChunks ?? 1;
    if (
      !Number.isSafeInteger(yieldEveryChunks) ||
      yieldEveryChunks < 1 ||
      yieldEveryChunks > 1_024
    ) {
      throw new VaultaError('INVALID_INPUT', 'Das Intervall der Integritätsprüfung ist ungültig.');
    }

    assertAuthorized();
    let processedChunks = 0;
    const footer = await this.vaultService.withVaultKey(vaultId, async (vaultKey) => {
      assertAuthorized();
      return await this.decryptAndVerify(
        this.attachmentPath(vaultId, attachmentId),
        vaultId,
        attachmentId,
        vaultKey,
        async () => {
          assertAuthorized();
          processedChunks += 1;
          if (processedChunks % yieldEveryChunks === 0) {
            await yieldControl();
            assertAuthorized();
          }
        },
        assertAuthorized,
      );
    });
    assertAuthorized();
    return { size: footer.totalBytes, sha256: footer.sha256 };
  }

  /**
   * Enumerates identifier-only storage references. Invalid entries are counted
   * without exposing their directory or file names to callers.
   */
  public async inspectStoredAttachmentInventory(
    assertAuthorized: () => void = () => undefined,
  ): Promise<StoredAttachmentInventory> {
    const references: StoredAttachmentReference[] = [];
    const seen = new Set<string>();
    let invalidEntryCount = 0;
    assertAuthorized();
    const directories = await readdir(this.attachmentsDir, { withFileTypes: true }).catch(
      (error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
        throw error;
      },
    );
    for (const directory of directories) {
      assertAuthorized();
      if (!directory.isDirectory() || !/^[A-Za-z0-9_-]+$/u.test(directory.name)) {
        invalidEntryCount += 1;
        continue;
      }
      const files = await readdir(resolveInside(this.attachmentsDir, directory.name), {
        withFileTypes: true,
      });
      for (const file of files) {
        assertAuthorized();
        if (!file.isFile() || !/^[A-Za-z0-9_-]+\.vatt$/u.test(file.name)) {
          invalidEntryCount += 1;
          continue;
        }
        const reference = {
          vaultId: directory.name,
          attachmentId: file.name.slice(0, -'.vatt'.length),
        };
        const key = `${reference.vaultId}/${reference.attachmentId}`;
        if (seen.has(key)) {
          invalidEntryCount += 1;
          continue;
        }
        seen.add(key);
        references.push(reference);
      }
    }
    assertAuthorized();
    references.sort(
      (left, right) =>
        left.vaultId.localeCompare(right.vaultId, 'en') ||
        left.attachmentId.localeCompare(right.attachmentId, 'en'),
    );
    return { references, invalidEntryCount };
  }

  /** Enumerates identifier-only storage references; paths never leave the Main process. */
  public async listStoredAttachmentReferences(
    assertAuthorized: () => void = () => undefined,
  ): Promise<StoredAttachmentReference[]> {
    const inventory = await this.inspectStoredAttachmentInventory(assertAuthorized);
    if (inventory.invalidEntryCount > 0) {
      throw new VaultaError('CONFLICT', 'Der Anhangsspeicher enthält einen ungültigen Stand.');
    }
    return inventory.references;
  }

  public async validateStorageConsistency(
    expected: readonly { vaultId: string; attachmentId: string }[],
    assertAuthorized: () => void = () => undefined,
  ): Promise<void> {
    const expectedIds = new Set(
      expected.map(({ vaultId, attachmentId }) => {
        assertSafeIdentifier(vaultId, 'Tresor-ID');
        assertSafeIdentifier(attachmentId, 'Anhangs-ID');
        return `${vaultId}/${attachmentId}`;
      }),
    );
    if (expectedIds.size !== expected.length) {
      throw new VaultaError('CORRUPT_DATA', 'Ein Anhang wird mehrfach referenziert.');
    }

    const actualIds = new Set<string>();
    const directories = await readdir(this.attachmentsDir, { withFileTypes: true }).catch(
      (error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
        throw error;
      },
    );
    for (const directory of directories) {
      assertAuthorized();
      if (!directory.isDirectory() || !/^[A-Za-z0-9_-]+$/u.test(directory.name)) {
        throw new VaultaError(
          'CONFLICT',
          'Der Anhangsspeicher enthaelt einen nicht bestaetigten Dateistand.',
        );
      }
      const files = await readdir(resolveInside(this.attachmentsDir, directory.name), {
        withFileTypes: true,
      });
      for (const file of files) {
        if (!file.isFile() || !/^[A-Za-z0-9_-]+\.vatt$/u.test(file.name)) {
          throw new VaultaError(
            'CONFLICT',
            'Der Anhangsspeicher enthaelt einen nicht bestaetigten Dateistand.',
          );
        }
        actualIds.add(`${directory.name}/${file.name.slice(0, -'.vatt'.length)}`);
      }
    }
    if (JSON.stringify([...actualIds].sort()) !== JSON.stringify([...expectedIds].sort())) {
      throw new VaultaError(
        'CONFLICT',
        'Anhangsdateien und Tresorreferenzen bilden keinen bestaetigten gemeinsamen Stand.',
      );
    }

    for (const id of [...expectedIds].sort()) {
      assertAuthorized();
      const [vaultId, attachmentId] = id.split('/');
      if (vaultId === undefined || attachmentId === undefined) {
        throw new VaultaError('CORRUPT_DATA', 'Eine Anhangsreferenz ist ungueltig.');
      }
      await this.inspectStoredFormatVersion(vaultId, attachmentId, assertAuthorized);
    }
    assertAuthorized();
  }

  public async inspectStoredFormatVersion(
    vaultId: string,
    attachmentId: string,
    assertAuthorized: () => void = () => undefined,
  ): Promise<number> {
    assertAuthorized();
    await this.vaultService.withVaultKey(vaultId, async (vaultKey) => {
      assertAuthorized();
      await this.decryptAndVerify(
        this.attachmentPath(vaultId, attachmentId),
        vaultId,
        attachmentId,
        vaultKey,
        () => assertAuthorized(),
      );
    });
    assertAuthorized();
    return ATTACHMENT_FORMAT_VERSION;
  }

  public async remove(vaultId: string, attachmentId: string): Promise<void> {
    await rm(this.attachmentPath(vaultId, attachmentId), { force: true });
  }

  public getEncryptedPath(vaultId: string, attachmentId: string): string {
    return this.attachmentPath(vaultId, attachmentId);
  }

  /**
   * A package import receives its path only from the controller, but an
   * untrusted same-user process can still attempt to exchange a directory for
   * a junction between checks. Require both the controller capability and a
   * direct canonical directory before a new descriptor is opened.
   */
  private async assertOwnedPackageStagingDirectory(
    stagingDirectory: string,
    assertStagingDirectory: () => Promise<void> | void,
  ): Promise<void> {
    await assertStagingDirectory();
    const initial = await lstat(stagingDirectory).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingverzeichnis ist nicht sicher.', null, {
        cause: error,
      });
    });
    if (initial.isSymbolicLink() || !initial.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingverzeichnis ist nicht sicher.');
    }
    const canonical = await realpath(stagingDirectory).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingverzeichnis ist nicht sicher.', null, {
        cause: error,
      });
    });
    const current = await lstat(stagingDirectory).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingverzeichnis ist nicht sicher.', null, {
        cause: error,
      });
    });
    if (
      current.isSymbolicLink() ||
      !current.isDirectory() ||
      !this.sameFilesystemIdentity(initial, current) ||
      !this.samePath(canonical, stagingDirectory)
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingverzeichnis wurde ausgetauscht.');
    }
    await assertStagingDirectory();
  }

  /**
   * O_EXCL prevents replacement of an existing file; O_NOFOLLOW plus this
   * descriptor/path identity comparison ensures no bytes are written until the
   * just-opened handle is proven to still name a file below the owned stage.
   */
  private async assertOpenedPackageStagingFile(
    output: FileHandle,
    stagingPath: string,
    stagingDirectory: string,
    assertStagingDirectory: () => Promise<void> | void,
  ): Promise<void> {
    const opened = await output.stat();
    if (!opened.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Staging-Anhang ist keine regulaere Datei.');
    }
    await this.assertOwnedPackageStagingDirectory(stagingDirectory, assertStagingDirectory);
    const current = await lstat(stagingPath).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Staging-Anhang ist nicht sicher.', null, {
        cause: error,
      });
    });
    const canonical = await realpath(stagingPath).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Staging-Anhang ist nicht sicher.', null, {
        cause: error,
      });
    });
    if (
      current.isSymbolicLink() ||
      !current.isFile() ||
      !this.sameFilesystemIdentity(opened, current) ||
      !this.samePath(canonical, stagingPath)
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Staging-Anhang wurde ausgetauscht.');
    }
    await this.assertOwnedPackageStagingDirectory(stagingDirectory, assertStagingDirectory);
  }

  private async writeRecord(
    output: FileHandle,
    position: number,
    type: number,
    index: number,
    plaintext: Buffer,
    fileKey: Buffer,
    noncePrefix: Buffer,
    headerBytes: Buffer,
  ): Promise<number> {
    if (index >= 0xffffffff) {
      throw new VaultaError('FILE_TOO_LARGE', 'Der Anhang enthält zu viele Chunks.');
    }
    let nonce: Buffer | null = null;
    let aad: Buffer | null = null;
    let ciphertext: Buffer | null = null;
    let tag: Buffer | null = null;
    let recordHeader: Buffer | null = null;
    try {
      nonce = this.recordNonce(noncePrefix, index);
      aad = this.recordAad(headerBytes, type, index);
      const envelope = this.crypto.encryptWithNonce(plaintext, fileKey, aad, nonce);
      ciphertext = Buffer.from(envelope.ciphertext, 'base64');
      tag = Buffer.from(envelope.tag, 'base64');
      recordHeader = Buffer.allocUnsafe(RECORD_HEADER_BYTES);
      recordHeader.writeUInt8(type, 0);
      recordHeader.writeUInt32BE(index, 1);
      recordHeader.writeUInt32BE(ciphertext.length, 5);
      let next = await writeAll(output, recordHeader, position);
      next = await writeAll(output, tag, next);
      return await writeAll(output, ciphertext, next);
    } finally {
      this.crypto.erase(recordHeader);
      this.crypto.erase(ciphertext);
      this.crypto.erase(tag);
      this.crypto.erase(aad);
      this.crypto.erase(nonce);
    }
  }

  private sameFilesystemIdentity(
    left: { readonly dev: number; readonly ino: number },
    right: { readonly dev: number; readonly ino: number },
  ): boolean {
    return left.dev === right.dev && left.ino === right.ino;
  }

  private async decryptAndVerify(
    filePath: string,
    vaultId: string,
    attachmentId: string,
    vaultKey: Buffer,
    consume: (chunk: Buffer) => Promise<void> | void,
    assertAuthorized: () => void = () => undefined,
  ): Promise<AttachmentFooter> {
    assertAuthorized();
    const input = await open(filePath, constants.O_RDONLY).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Der verschlüsselte Anhang wurde nicht gefunden.');
      }
      throw error;
    });
    try {
      return await this.decryptAndVerifyHandle(
        input,
        vaultId,
        attachmentId,
        vaultKey,
        consume,
        assertAuthorized,
      );
    } finally {
      await input.close().catch(() => undefined);
    }
  }

  /** Verifies an attachment through an already opened, caller-owned descriptor. */
  private async decryptAndVerifyHandle(
    input: FileHandle,
    vaultId: string,
    attachmentId: string,
    vaultKey: Buffer,
    consume: (chunk: Buffer) => Promise<void> | void,
    assertAuthorized: () => void = () => undefined,
  ): Promise<AttachmentFooter> {
    let fileKey: Buffer | null = null;
    let headerBytes: Buffer | null = null;
    let noncePrefix: Buffer | null = null;
    try {
      assertAuthorized();
      const fileInfo = await input.stat();
      const magic = await readExact(input, ATTACHMENT_MAGIC.length, 0);
      if (!this.crypto.equals(magic, ATTACHMENT_MAGIC)) {
        throw new VaultaError('CORRUPT_DATA', 'Das Anhangsformat ist ungültig.');
      }
      const lengthBytes = await readExact(input, 4, ATTACHMENT_MAGIC.length);
      const headerLength = lengthBytes.readUInt32BE(0);
      if (headerLength === 0 || headerLength > HEADER_LIMIT) {
        throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
      }
      const headerPosition = ATTACHMENT_MAGIC.length + 4;
      headerBytes = await readExact(input, headerLength, headerPosition);
      let parsed: unknown;
      try {
        parsed = JSON.parse(headerBytes.toString('utf8')) as unknown;
      } catch (error) {
        throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist beschädigt.', null, {
          cause: error,
        });
      }
      const header = parseHeader(parsed);
      fileKey = this.crypto.unwrapKey(
        header.wrappedFileKey,
        vaultKey,
        `attachment:${vaultId}:${attachmentId}:file-key`,
      );
      noncePrefix = Buffer.from(header.noncePrefix, 'base64');
      const hash = createHash('sha256');
      let position = headerPosition + headerLength;
      let expectedIndex = 0;
      let totalBytes = 0;
      let footer: AttachmentFooter | null = null;

      while (position < fileInfo.size) {
        assertAuthorized();
        const recordHeader = await readExact(input, RECORD_HEADER_BYTES, position);
        position += RECORD_HEADER_BYTES;
        const type = recordHeader.readUInt8(0);
        const index = recordHeader.readUInt32BE(1);
        const ciphertextLength = recordHeader.readUInt32BE(5);
        if (index !== expectedIndex || (type !== DATA_RECORD && type !== FOOTER_RECORD)) {
          throw new VaultaError('CORRUPT_DATA', 'Die Anhangschunks sind vertauscht oder ungültig.');
        }
        const maximumLength = type === DATA_RECORD ? header.chunkSize : 4096;
        if (ciphertextLength > maximumLength) {
          throw new VaultaError('CORRUPT_DATA', 'Ein Anhangschunk hat eine ungültige Länge.');
        }
        const tag = await readExact(input, TAG_BYTES, position);
        position += TAG_BYTES;
        const ciphertext = await readExact(input, ciphertextLength, position);
        position += ciphertextLength;
        const nonce = this.recordNonce(noncePrefix, index);
        const aad = this.recordAad(headerBytes, type, index);
        let plaintext: Buffer | null = null;

        try {
          plaintext = this.crypto.decrypt(
            {
              algorithm: 'AES-256-GCM',
              nonce: nonce.toString('base64'),
              ciphertext: ciphertext.toString('base64'),
              tag: tag.toString('base64'),
            },
            fileKey,
            aad,
          );
          assertAuthorized();
          if (type === DATA_RECORD) {
            hash.update(plaintext);
            totalBytes += plaintext.length;
            await consume(plaintext);
            expectedIndex += 1;
          } else {
            const parsedFooter = parseJson(plaintext, 'Der Anhangsabschluss ist beschädigt.');
            if (!isRecord(parsedFooter)) {
              throw new VaultaError('CORRUPT_DATA', 'Der Anhangsabschluss ist ungültig.');
            }
            requireCurrentFormatVersion(
              parsedFooter.formatVersion,
              ATTACHMENT_VERSION,
              'Vaulta-Anhangsabschluss',
            );
            if (
              parsedFooter.chunkCount !== expectedIndex ||
              parsedFooter.totalBytes !== totalBytes ||
              typeof parsedFooter.sha256 !== 'string'
            ) {
              throw new VaultaError('CORRUPT_DATA', 'Der Anhangsabschluss ist ungültig.');
            }
            footer = {
              formatVersion: ATTACHMENT_VERSION,
              chunkCount: expectedIndex,
              totalBytes,
              sha256: parsedFooter.sha256,
            };
            if (position !== fileInfo.size || footer.sha256 !== hash.digest('hex')) {
              throw new VaultaError('CORRUPT_DATA', 'Der Anhang wurde gekürzt oder verändert.');
            }
            break;
          }
        } finally {
          this.crypto.erase(plaintext);
          this.crypto.erase(ciphertext);
          this.crypto.erase(tag);
          this.crypto.erase(nonce);
          this.crypto.erase(aad);
          this.crypto.erase(recordHeader);
        }
      }

      if (footer === null) {
        throw new VaultaError('CORRUPT_DATA', 'Der authentifizierte Anhangsabschluss fehlt.');
      }
      assertAuthorized();
      return footer;
    } finally {
      this.crypto.erase(noncePrefix);
      this.crypto.erase(headerBytes);
      this.crypto.erase(fileKey);
    }
  }

  private async getVerifiedHash(
    filePath: string,
    vaultId: string,
    attachmentId: string,
    vaultKey: Buffer,
  ): Promise<string> {
    const footer = await this.decryptAndVerify(
      filePath,
      vaultId,
      attachmentId,
      vaultKey,
      () => undefined,
    );
    return footer.sha256;
  }

  private recordNonce(prefix: Buffer, index: number): Buffer {
    const nonce = Buffer.allocUnsafe(12);
    prefix.copy(nonce, 0);
    nonce.writeUInt32BE(index, 8);
    return nonce;
  }

  private recordAad(headerBytes: Buffer, type: number, index: number): Buffer {
    const record = Buffer.allocUnsafe(5);
    record.writeUInt8(type, 0);
    record.writeUInt32BE(index, 1);
    return Buffer.concat([
      Buffer.from('vaulta:attachment-record:v1', 'utf8'),
      this.crypto.sha256(headerBytes),
      record,
    ]);
  }

  private attachmentPath(vaultId: string, attachmentId: string): string {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertSafeIdentifier(attachmentId, 'Anhangs-ID');
    return resolveInside(this.attachmentsDir, vaultId, `${attachmentId}.vatt`);
  }

  private samePath(left: string, right: string): boolean {
    const normalize = (value: string): string =>
      process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
    return normalize(left) === normalize(right);
  }
}
