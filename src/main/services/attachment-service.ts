import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readdir, rm, stat, type FileHandle } from 'node:fs/promises';
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
        previewable: SAFE_PREVIEW_TYPES.has(mediaType),
      };
    });
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
    const nonce = this.recordNonce(noncePrefix, index);
    const envelope = this.crypto.encryptWithNonce(
      plaintext,
      fileKey,
      this.recordAad(headerBytes, type, index),
      nonce,
    );
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const recordHeader = Buffer.allocUnsafe(RECORD_HEADER_BYTES);
    recordHeader.writeUInt8(type, 0);
    recordHeader.writeUInt32BE(index, 1);
    recordHeader.writeUInt32BE(ciphertext.length, 5);
    let next = await writeAll(output, recordHeader, position);
    next = await writeAll(output, tag, next);
    next = await writeAll(output, ciphertext, next);
    this.crypto.erase(ciphertext);
    this.crypto.erase(tag);
    this.crypto.erase(nonce);
    return next;
  }

  private async decryptAndVerify(
    filePath: string,
    vaultId: string,
    attachmentId: string,
    vaultKey: Buffer,
    consume: (chunk: Buffer) => Promise<void> | void,
  ): Promise<AttachmentFooter> {
    const input = await open(filePath, constants.O_RDONLY).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Der verschlüsselte Anhang wurde nicht gefunden.');
      }
      throw error;
    });
    let fileKey: Buffer | null = null;
    try {
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
      const headerBytes = await readExact(input, headerLength, headerPosition);
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
      const noncePrefix = Buffer.from(header.noncePrefix, 'base64');
      const hash = createHash('sha256');
      let position = headerPosition + headerLength;
      let expectedIndex = 0;
      let totalBytes = 0;
      let footer: AttachmentFooter | null = null;

      while (position < fileInfo.size) {
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
        const plaintext = this.crypto.decrypt(
          {
            algorithm: 'AES-256-GCM',
            nonce: nonce.toString('base64'),
            ciphertext: ciphertext.toString('base64'),
            tag: tag.toString('base64'),
          },
          fileKey,
          this.recordAad(headerBytes, type, index),
        );
        this.crypto.erase(ciphertext);
        this.crypto.erase(tag);
        this.crypto.erase(nonce);

        try {
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
        }
      }

      if (footer === null) {
        throw new VaultaError('CORRUPT_DATA', 'Der authentifizierte Anhangsabschluss fehlt.');
      }
      return footer;
    } finally {
      this.crypto.erase(fileKey);
      await input.close();
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
}
