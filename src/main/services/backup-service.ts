import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import {
  access,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  type FileHandle,
} from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type { BackupInfo, BackupRotation } from '../../shared/models';
import { type AesGcmEnvelope, CryptoService } from '../security/crypto-service';
import { AtomicFileWriter } from '../storage/atomic-file';
import { assertSafeIdentifier, normalizeBackupPath, resolveInside } from '../storage/path-safety';
import { parseStoredProfileHeader } from './profile-service';
import type {
  BackupCredential,
  ProfileBackupAccessHeader,
  ProfileService,
  StoredProfileHeader,
} from './profile-service';

const BACKUP_MAGIC = Buffer.from('VLTBKP01', 'ascii');
const BACKUP_VERSION = 1 as const;
const BACKUP_EXTENSION = '.vaulta-backup';
const CHUNK_SIZE = 1024 * 1024;
const HEADER_LIMIT = 2 * 1024 * 1024;
const RECORD_HEADER_BYTES = 9;
const TAG_BYTES = 16;
const FILE_START_RECORD = 0;
const FILE_DATA_RECORD = 1;
const FILE_END_RECORD = 2;
const MANIFEST_RECORD = 3;
const MAX_METADATA_RECORD_BYTES = 8 * 1024 * 1024;
const RESTORE_COMMIT_MARKER = '.vaulta-restore-committed';

interface BackupProfileHeader extends ProfileBackupAccessHeader {
  format: 'vaulta-backup-profile-access';
  version: 1;
  updatedAt: string;
}

interface BackupHeader {
  format: 'vaulta-backup';
  version: typeof BACKUP_VERSION;
  backupId: string;
  createdAt: string;
  automatic: boolean;
  purpose: 'user' | 'migration';
  cipher: 'AES-256-GCM-CHUNKED';
  chunkSize: typeof CHUNK_SIZE;
  noncePrefix: string;
  profileHeader: BackupProfileHeader;
  keyWraps: {
    master: AesGcmEnvelope;
    recovery: AesGcmEnvelope | null;
  };
}

interface BackupManifestEntry {
  path: string;
  size: number;
  sha256: string;
}

interface BackupManifest {
  formatVersion: typeof BACKUP_VERSION;
  backupId: string;
  createdAt: string;
  files: BackupManifestEntry[];
  rootSha256: string;
  vaultCount: number;
  attachmentCount: number;
}

export interface BackupServiceOptions {
  rootDir: string;
  profileService: ProfileService;
  crypto?: CryptoService;
  atomicWriter?: AtomicFileWriter;
  now?: () => Date;
}

export interface CreateBackupInput {
  destination?: string;
  automatic?: boolean;
  rotation?: BackupRotation;
  replaceExisting?: boolean;
  assertAuthorized?: () => void;
  /**
   * Validates relationships which cannot be proven by the outer backup
   * manifest alone (vault keys, attachment references and the audit log).
   * It runs while the fully written temporary backup is still uncommitted.
   */
  validateLiveState?: () => Promise<void>;
}

export interface RestoreBackupInput {
  backupPath: string;
  credential: BackupCredential;
  targetRoot?: string;
  replaceExisting?: boolean;
}

export interface BackupRestoreResult {
  targetRoot: string;
  profileId: string;
  createdAt: string;
  fileCount: number;
  vaultCount: number;
  attachmentCount: number;
  requiresApplicationReload: true;
}

export interface BackupInspection {
  profileId: string;
  createdAt: string;
  fileCount: number;
  vaultCount: number;
  attachmentCount: number;
  automatic: boolean;
}

interface SourceFile {
  absolutePath: string;
  backupPath: string;
  size: number;
  snapshot: Buffer | null;
  dev: number;
  ino: number;
  mtimeMs: number;
  ctimeMs: number;
}

interface FileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
}

export interface MigrationSnapshotSourceExpectation {
  readonly size: number;
  readonly sha256: string;
}

export interface CreateMigrationSnapshotInput {
  readonly destination: string;
  readonly sourcePaths: readonly string[];
  readonly expectedSources: Readonly<Record<string, MigrationSnapshotSourceExpectation>>;
  readonly assertAuthorized?: () => void;
}

interface ProcessingFile {
  entry: BackupManifestEntry;
  hash: ReturnType<typeof createHash>;
  bytesWritten: number;
  output: FileHandle | null;
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

function isEnvelope(value: unknown): value is AesGcmEnvelope {
  return (
    isRecord(value) &&
    value.algorithm === 'AES-256-GCM' &&
    typeof value.nonce === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.tag === 'string'
  );
}

function parseEnvelope(value: unknown): AesGcmEnvelope {
  if (
    !isRecord(value) ||
    value.algorithm !== 'AES-256-GCM' ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string' ||
    typeof value.tag !== 'string'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Ein Backup-Schlüssel-Wrap ist beschädigt.');
  }
  return {
    algorithm: value.algorithm,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    tag: value.tag,
  };
}

function backupProfileHeader(header: StoredProfileHeader): BackupProfileHeader {
  return {
    format: 'vaulta-backup-profile-access',
    version: 1,
    profileId: header.profileId,
    updatedAt: header.updatedAt,
    access: {
      kdf: header.access.kdf,
      passwordVerifier: header.access.passwordVerifier,
      wrappedMasterGateKey: header.access.wrappedMasterGateKey,
    },
    recovery: header.recovery,
  };
}

function parseBackupProfileHeader(value: unknown): BackupProfileHeader {
  // Backups created by early v1 development builds remain readable, but new
  // files never duplicate protected or factor metadata in the clear header.
  if (isRecord(value) && value.format === 'vaulta-profile') {
    return backupProfileHeader(parseStoredProfileHeader(value));
  }
  if (
    !isRecord(value) ||
    value.format !== 'vaulta-backup-profile-access' ||
    value.version !== 1 ||
    typeof value.profileId !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    !isRecord(value.access) ||
    !isRecord(value.access.kdf) ||
    typeof value.access.kdf.salt !== 'string' ||
    !isRecord(value.access.kdf.parameters) ||
    !isEnvelope(value.access.passwordVerifier) ||
    !isEnvelope(value.access.wrappedMasterGateKey) ||
    (value.recovery !== null && !isRecord(value.recovery))
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der technische Backup-Zugangsheader ist ungueltig.');
  }
  const parameters = value.access.kdf.parameters;
  if (
    parameters.algorithm !== 'argon2id' ||
    typeof parameters.memorySizeKiB !== 'number' ||
    !Number.isSafeInteger(parameters.memorySizeKiB) ||
    typeof parameters.iterations !== 'number' ||
    !Number.isSafeInteger(parameters.iterations) ||
    typeof parameters.parallelism !== 'number' ||
    !Number.isSafeInteger(parameters.parallelism) ||
    parameters.hashLength !== 32
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Die Argon2id-Parameter im Backup sind ungueltig.');
  }
  let recovery: StoredProfileHeader['recovery'] = null;
  if (value.recovery !== null) {
    if (typeof value.recovery.salt !== 'string' || !isEnvelope(value.recovery.wrappedProfileKey)) {
      throw new VaultaError('CORRUPT_DATA', 'Der Recovery-Zugang im Backup ist ungueltig.');
    }
    recovery = {
      salt: value.recovery.salt,
      wrappedProfileKey: value.recovery.wrappedProfileKey,
    };
  }
  assertSafeIdentifier(value.profileId, 'Profil-ID');
  return {
    format: 'vaulta-backup-profile-access',
    version: 1,
    profileId: value.profileId,
    updatedAt: value.updatedAt,
    access: {
      kdf: {
        salt: value.access.kdf.salt,
        parameters: {
          algorithm: 'argon2id',
          memorySizeKiB: parameters.memorySizeKiB,
          iterations: parameters.iterations,
          parallelism: parameters.parallelism,
          hashLength: 32,
        },
      },
      passwordVerifier: parseEnvelope(value.access.passwordVerifier),
      wrappedMasterGateKey: parseEnvelope(value.access.wrappedMasterGateKey),
    },
    recovery,
  };
}

function parseBackupHeader(value: unknown): BackupHeader {
  if (
    !isRecord(value) ||
    value.format !== 'vaulta-backup' ||
    value.version !== BACKUP_VERSION ||
    typeof value.backupId !== 'string' ||
    typeof value.createdAt !== 'string' ||
    (value.automatic !== undefined && typeof value.automatic !== 'boolean') ||
    (value.purpose !== undefined && value.purpose !== 'user' && value.purpose !== 'migration') ||
    value.cipher !== 'AES-256-GCM-CHUNKED' ||
    value.chunkSize !== CHUNK_SIZE ||
    typeof value.noncePrefix !== 'string' ||
    Buffer.from(value.noncePrefix, 'base64').length !== 8 ||
    !isRecord(value.keyWraps) ||
    !isEnvelope(value.keyWraps.master) ||
    (value.keyWraps.recovery !== null && !isEnvelope(value.keyWraps.recovery))
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Backup-Header ist ungültig.');
  }
  return {
    format: 'vaulta-backup',
    version: BACKUP_VERSION,
    backupId: value.backupId,
    createdAt: value.createdAt,
    automatic: value.automatic === true,
    purpose: value.purpose === 'migration' ? 'migration' : 'user',
    cipher: 'AES-256-GCM-CHUNKED',
    chunkSize: CHUNK_SIZE,
    noncePrefix: value.noncePrefix,
    profileHeader: parseBackupProfileHeader(value.profileHeader),
    keyWraps: {
      master: parseEnvelope(value.keyWraps.master),
      recovery: value.keyWraps.recovery === null ? null : parseEnvelope(value.keyWraps.recovery),
    },
  };
}

function parseManifest(value: unknown): BackupManifest {
  if (
    !isRecord(value) ||
    value.formatVersion !== BACKUP_VERSION ||
    typeof value.backupId !== 'string' ||
    typeof value.createdAt !== 'string' ||
    !Array.isArray(value.files) ||
    typeof value.rootSha256 !== 'string' ||
    typeof value.vaultCount !== 'number' ||
    typeof value.attachmentCount !== 'number'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Das Backup-Manifest ist ungültig.');
  }
  const files = value.files.map((entry) => {
    if (
      !isRecord(entry) ||
      typeof entry.path !== 'string' ||
      typeof entry.size !== 'number' ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0 ||
      typeof entry.sha256 !== 'string'
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Ein Backup-Manifesteintrag ist ungültig.');
    }
    return { path: entry.path, size: entry.size, sha256: entry.sha256 };
  });
  return {
    formatVersion: BACKUP_VERSION,
    backupId: value.backupId,
    createdAt: value.createdAt,
    files,
    rootSha256: value.rootSha256,
    vaultCount: value.vaultCount,
    attachmentCount: value.attachmentCount,
  };
}

async function writeAll(handle: FileHandle, data: Buffer, position: number): Promise<number> {
  let written = 0;
  while (written < data.length) {
    const result = await handle.write(data, written, data.length - written, position + written);
    if (result.bytesWritten === 0) throw new Error('Could not make progress writing backup');
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
      throw new VaultaError('CORRUPT_DATA', 'Die Sicherungsdatei ist unvollständig.');
    }
    read += result.bytesRead;
  }
  return buffer;
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

function sameSourceIdentity(source: SourceFile, current: FileIdentity): boolean {
  return sameFileIdentity(source, current);
}

export class BackupService {
  private readonly rootDir: string;
  private readonly profileService: ProfileService;
  private readonly crypto: CryptoService;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly now: () => Date;

  public constructor(options: BackupServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.profileService = options.profileService;
    this.crypto = options.crypto ?? new CryptoService();
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.now = options.now ?? (() => new Date());
  }

  public async createBackup(input: CreateBackupInput = {}): Promise<BackupInfo> {
    return this.createBackupInternal(input);
  }

  public async createMigrationSnapshot(input: CreateMigrationSnapshotInput): Promise<BackupInfo> {
    if (input.sourcePaths.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Ein Migrations-Snapshot darf nicht leer sein.');
    }
    const normalizedSources = input.sourcePaths.map((sourcePath) =>
      normalizeBackupPath(sourcePath),
    );
    for (const expectedPath of Object.keys(input.expectedSources)) {
      const normalizedExpected = normalizeBackupPath(expectedPath);
      if (normalizedExpected !== expectedPath || !normalizedSources.includes(expectedPath)) {
        throw new VaultaError(
          'INVALID_INPUT',
          'Die Migrations-Hashbindung enthält einen fremden Pfad.',
        );
      }
    }
    return this.createBackupInternal(
      {
        destination: input.destination,
        automatic: false,
        ...(input.assertAuthorized === undefined
          ? {}
          : { assertAuthorized: input.assertAuthorized }),
      },
      { sourcePaths: normalizedSources, expectedSources: input.expectedSources },
    );
  }

  private async createBackupInternal(
    input: CreateBackupInput,
    migration?: {
      readonly sourcePaths: readonly string[];
      readonly expectedSources: Readonly<Record<string, MigrationSnapshotSourceExpectation>>;
    },
  ): Promise<BackupInfo> {
    input.assertAuthorized?.();
    const createdAt = this.now().toISOString();
    const backupId = randomUUID();
    const destination = await this.resolveDestination(input.destination, createdAt);
    await access(destination).then(
      () => {
        if (input.replaceExisting !== true) {
          throw new VaultaError('CONFLICT', 'Am Ziel existiert bereits eine Sicherungsdatei.');
        }
      },
      (error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error;
      },
    );

    const sourceFiles = await this.collectSourceFiles(migration?.sourcePaths);
    input.assertAuthorized?.();
    const profileSnapshot = sourceFiles.find(
      (file) => file.backupPath === 'profile.json',
    )?.snapshot;
    if (profileSnapshot === undefined || profileSnapshot === null) {
      throw new VaultaError('CORRUPT_DATA', 'Der Profilheader fehlt in der Sicherung.');
    }
    const profileHeader = parseStoredProfileHeader(
      JSON.parse(profileSnapshot.toString('utf8')) as unknown,
    );
    const vaultCount = sourceFiles.filter((file) => file.backupPath.startsWith('vaults/')).length;
    const attachmentCount = sourceFiles.filter((file) =>
      file.backupPath.startsWith('attachments/'),
    ).length;
    const fileKey = this.crypto.randomBytes(32);
    const noncePrefix = this.crypto.randomBytes(8);
    let verifiedManifest: BackupManifest | null = null;

    try {
      await this.profileService.withBackupAccessKeys(async (accessKeys) => {
        const header: BackupHeader = {
          format: 'vaulta-backup',
          version: BACKUP_VERSION,
          backupId,
          createdAt,
          automatic: input.automatic === true,
          purpose: migration === undefined ? 'user' : 'migration',
          cipher: 'AES-256-GCM-CHUNKED',
          chunkSize: CHUNK_SIZE,
          noncePrefix: noncePrefix.toString('base64'),
          profileHeader: backupProfileHeader(profileHeader),
          keyWraps: {
            master: this.crypto.wrapKey(fileKey, accessKeys.master, `backup:${backupId}:master`),
            recovery:
              profileHeader.recovery === null
                ? null
                : this.crypto.wrapKey(fileKey, accessKeys.recovery, `backup:${backupId}:recovery`),
          },
        };
        const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');

        await this.atomicWriter.writeGenerated(
          destination,
          async (output) => {
            let position = 0;
            let recordIndex = 0;
            position = await writeAll(output, BACKUP_MAGIC, position);
            const length = Buffer.allocUnsafe(4);
            length.writeUInt32BE(headerBytes.length);
            position = await writeAll(output, length, position);
            position = await writeAll(output, headerBytes, position);
            const manifestEntries: BackupManifestEntry[] = [];

            for (const source of sourceFiles) {
              input.assertAuthorized?.();
              const start = Buffer.from(
                JSON.stringify({ path: source.backupPath, size: source.size }),
                'utf8',
              );
              position = await this.writeRecord(
                output,
                position,
                FILE_START_RECORD,
                recordIndex++,
                start,
                fileKey,
                noncePrefix,
                headerBytes,
              );
              this.crypto.erase(start);

              const hash = createHash('sha256');
              let sourcePosition = 0;
              if (source.snapshot !== null) {
                while (sourcePosition < source.snapshot.length) {
                  input.assertAuthorized?.();
                  const chunk = source.snapshot.subarray(
                    sourcePosition,
                    Math.min(sourcePosition + CHUNK_SIZE, source.snapshot.length),
                  );
                  sourcePosition += chunk.length;
                  hash.update(chunk);
                  position = await this.writeRecord(
                    output,
                    position,
                    FILE_DATA_RECORD,
                    recordIndex++,
                    chunk,
                    fileKey,
                    noncePrefix,
                    headerBytes,
                  );
                }
              } else {
                const sourceHandle = await open(source.absolutePath, constants.O_RDONLY);
                try {
                  const opened = await sourceHandle.stat();
                  if (!opened.isFile() || !sameSourceIdentity(source, opened)) {
                    throw new VaultaError(
                      'CONFLICT',
                      'Eine Vaulta-Datei wurde vor dem Backup-Lesen ausgetauscht.',
                    );
                  }
                  while (true) {
                    input.assertAuthorized?.();
                    const chunkBuffer = Buffer.allocUnsafe(CHUNK_SIZE);
                    const { bytesRead } = await sourceHandle.read(
                      chunkBuffer,
                      0,
                      CHUNK_SIZE,
                      sourcePosition,
                    );
                    if (bytesRead === 0) break;
                    sourcePosition += bytesRead;
                    const chunk = chunkBuffer.subarray(0, bytesRead);
                    hash.update(chunk);
                    position = await this.writeRecord(
                      output,
                      position,
                      FILE_DATA_RECORD,
                      recordIndex++,
                      chunk,
                      fileKey,
                      noncePrefix,
                      headerBytes,
                    );
                    chunkBuffer.fill(0);
                  }
                } finally {
                  await sourceHandle.close();
                }
              }
              if (sourcePosition !== source.size) {
                throw new VaultaError(
                  'CONFLICT',
                  'Eine Vaulta-Datei wurde während der Sicherung verändert. Bitte wiederhole die Sicherung.',
                );
              }
              if (source.snapshot === null) {
                const after = await lstat(source.absolutePath);
                if (after.isSymbolicLink() || !after.isFile() || !sameFileIdentity(source, after)) {
                  throw new VaultaError(
                    'CONFLICT',
                    'Eine Vaulta-Datei wurde während der Sicherung verändert. Bitte wiederhole die Sicherung.',
                  );
                }
              }
              const sha256 = hash.digest('hex');
              const entry: BackupManifestEntry = {
                path: source.backupPath,
                size: sourcePosition,
                sha256,
              };
              const expected = migration?.expectedSources[source.backupPath];
              if (
                expected !== undefined &&
                (expected.size !== entry.size || expected.sha256 !== entry.sha256)
              ) {
                throw new VaultaError(
                  'CONFLICT',
                  `Die Migrationsquelle ${source.backupPath} wurde vor dem Snapshot verändert.`,
                );
              }
              manifestEntries.push(entry);
              const end = Buffer.from(JSON.stringify(entry), 'utf8');
              position = await this.writeRecord(
                output,
                position,
                FILE_END_RECORD,
                recordIndex++,
                end,
                fileKey,
                noncePrefix,
                headerBytes,
              );
              this.crypto.erase(end);
            }

            const manifest: BackupManifest = {
              formatVersion: BACKUP_VERSION,
              backupId,
              createdAt,
              files: manifestEntries,
              rootSha256: this.manifestRootHash(manifestEntries),
              vaultCount,
              attachmentCount,
            };
            const manifestBytes = Buffer.from(JSON.stringify(manifest), 'utf8');
            await this.writeRecord(
              output,
              position,
              MANIFEST_RECORD,
              recordIndex,
              manifestBytes,
              fileKey,
              noncePrefix,
              headerBytes,
            );
            this.crypto.erase(manifestBytes);
          },
          async (temporaryPath) => {
            input.assertAuthorized?.();
            const verified = await this.processBackup(
              temporaryPath,
              { type: 'master', value: '' },
              null,
              {
                accessKeyOverride: accessKeys.master,
              },
            );
            await this.assertLiveSourcesMatchManifest(
              verified.manifest,
              migration?.sourcePaths,
              input.assertAuthorized,
            );
            await input.validateLiveState?.();
            input.assertAuthorized?.();
            verifiedManifest = verified.manifest;
          },
          async () => {
            input.assertAuthorized?.();
            if (verifiedManifest === null) {
              throw new VaultaError(
                'INTERNAL',
                'Das Backup wurde vor dem Commit nicht vollstaendig verifiziert.',
              );
            }
            await this.assertLiveSourcesMatchManifest(
              verifiedManifest,
              migration?.sourcePaths,
              input.assertAuthorized,
            );
            input.assertAuthorized?.();
          },
        );
        input.assertAuthorized?.();
        this.crypto.erase(headerBytes);

        if (input.automatic === true) {
          await this.rotateBackups(
            path.dirname(destination),
            input.rotation ?? { daily: 7, weekly: 4, monthly: 6 },
            profileHeader.profileId,
            accessKeys.master,
          );
        }
      });
    } finally {
      this.crypto.erase(fileKey);
      this.crypto.erase(noncePrefix);
      sourceFiles.forEach((source) => this.crypto.erase(source.snapshot));
    }

    const resultInfo = await stat(destination);
    return {
      path: destination,
      createdAt,
      size: resultInfo.size,
      vaultCount,
      attachmentCount,
      automatic: input.automatic === true,
    };
  }

  public async inspectBackup(
    backupPath: string,
    credential: BackupCredential,
  ): Promise<BackupInspection> {
    const result = await this.processBackup(path.resolve(backupPath), credential, null);
    return {
      profileId: result.header.profileHeader.profileId,
      createdAt: result.manifest.createdAt,
      fileCount: result.manifest.files.length,
      vaultCount: result.manifest.vaultCount,
      attachmentCount: result.manifest.attachmentCount,
      automatic: result.header.automatic,
    };
  }

  public async inspectBackupWithActiveProfile(backupPath: string): Promise<BackupInspection> {
    return this.profileService.withBackupAccessKeys(async (accessKeys) => {
      const result = await this.processBackup(
        path.resolve(backupPath),
        { type: 'master', value: '' },
        null,
        { accessKeyOverride: accessKeys.master },
      );
      return {
        profileId: result.header.profileHeader.profileId,
        createdAt: result.manifest.createdAt,
        fileCount: result.manifest.files.length,
        vaultCount: result.manifest.vaultCount,
        attachmentCount: result.manifest.attachmentCount,
        automatic: result.header.automatic,
      };
    });
  }

  public async restoreBackup(input: RestoreBackupInput): Promise<BackupRestoreResult> {
    const targetRoot = path.resolve(input.targetRoot ?? this.rootDir);
    const { stageRoot, rollbackRoot } = this.restorePaths(targetRoot);
    await this.recoverInterruptedRestore(targetRoot);
    await mkdir(stageRoot, { recursive: false });
    let completed = false;

    try {
      const result = await this.processBackup(
        path.resolve(input.backupPath),
        input.credential,
        stageRoot,
      );
      const stagedHeaderBytes = await readFile(resolveInside(stageRoot, 'profile.json'), 'utf8');
      const stagedHeader = parseStoredProfileHeader(JSON.parse(stagedHeaderBytes) as unknown);
      if (
        stagedHeader.profileId !== result.header.profileHeader.profileId ||
        stagedHeader.updatedAt !== result.header.profileHeader.updatedAt
      ) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Profilheader und Backup-Manifest passen nicht zusammen.',
        );
      }
      await this.syncDirectoryTree(stageRoot);
      await this.atomicWriter.writeFile(
        resolveInside(stageRoot, RESTORE_COMMIT_MARKER),
        Buffer.from(
          JSON.stringify({
            format: 'vaulta-restore-commit',
            backupId: result.header.backupId,
            targetRoot,
          }),
          'utf8',
        ),
      );

      const targetExists = await this.pathExists(targetRoot);
      if (targetExists) {
        const existing = await readdir(targetRoot);
        if (existing.length > 0 && input.replaceExisting !== true) {
          throw new VaultaError(
            'CONFLICT',
            'Das Ziel enthält bereits Daten. Eine geprüfte Sicherung wird nur nach ausdrücklicher Bestätigung ersetzt.',
          );
        }
        await rename(targetRoot, rollbackRoot);
        await this.syncDirectory(path.dirname(targetRoot));
      }

      await rename(stageRoot, targetRoot);
      await this.syncDirectory(path.dirname(targetRoot));
      // Keep a byte-exact rollback until the installed profile was
      // authenticated and every protected artifact was semantically read.
      if (!targetExists) {
        await rm(resolveInside(targetRoot, RESTORE_COMMIT_MARKER), { force: true });
        await this.syncDirectory(targetRoot);
      }
      completed = true;

      return {
        targetRoot,
        profileId: result.header.profileHeader.profileId,
        createdAt: result.manifest.createdAt,
        fileCount: result.manifest.files.length,
        vaultCount: result.manifest.vaultCount,
        attachmentCount: result.manifest.attachmentCount,
        requiresApplicationReload: true,
      };
    } finally {
      if (!completed) await this.recoverInterruptedRestore(targetRoot);
    }
  }

  /**
   * Bringt einen durch einen Prozessabbruch oder Stromausfall unterbrochenen
   * Restore deterministisch in den letzten eindeutig sicheren Zustand zurück.
   */
  public async recoverInterruptedRestore(targetRoot: string = this.rootDir): Promise<boolean> {
    const resolvedTarget = path.resolve(targetRoot);
    const { stageRoot, rollbackRoot, discardRoot } = this.restorePaths(resolvedTarget);
    const [targetExists, stageExists, rollbackExists, discardExists] = await Promise.all([
      this.pathExists(resolvedTarget),
      this.pathExists(stageRoot),
      this.pathExists(rollbackRoot),
      this.pathExists(discardRoot),
    ]);
    const targetIsCommitted =
      targetExists && (await this.hasValidRestoreCommitMarker(resolvedTarget));
    let recovered = false;

    if (discardExists && rollbackExists) {
      throw new VaultaError(
        'CONFLICT',
        'Restore-Recovery hat gleichzeitig Rollback- und Cleanup-Daten gefunden. Beide bleiben unangetastet.',
      );
    }

    if (discardExists) {
      if (!targetExists) {
        await rename(discardRoot, resolvedTarget);
        recovered = true;
      }
    }

    if (rollbackExists && targetIsCommitted) {
      // A plain JSON marker cannot authorize deletion of the last confirmed
      // state, so startup conservatively restores the byte-exact rollback.
      await rm(resolvedTarget, { recursive: true, force: true });
      await rename(rollbackRoot, resolvedTarget);
      recovered = true;
    } else if (rollbackExists) {
      if (targetExists) {
        const unexpectedTargetEntries = await readdir(resolvedTarget);
        if (unexpectedTargetEntries.length > 0) {
          throw new VaultaError(
            'CONFLICT',
            'Restore-Recovery hat sowohl einen unverifizierten Zielstand als auch einen Rollback gefunden. Beide Stände bleiben unangetastet.',
          );
        }
        await rm(resolvedTarget, { recursive: true });
      }
      await rename(rollbackRoot, resolvedTarget);
      recovered = true;
    }

    if (stageExists) {
      // Ein Stage ohne installierten Zielpfad ist nicht als vollständig
      // verifiziert markiert und wird deshalb niemals automatisch promoted.
      await rm(stageRoot, { recursive: true, force: true });
      recovered = true;
    }

    if (targetIsCommitted && !rollbackExists && !discardExists) {
      await rm(resolveInside(resolvedTarget, RESTORE_COMMIT_MARKER), { force: true });
      recovered = true;
    }

    if (recovered) await this.syncDirectory(path.dirname(resolvedTarget));

    return recovered;
  }

  /**
   * Removes the rollback only after the caller has authenticated the installed
   * profile and semantically validated every protected live artifact.
   */
  public async finalizeInterruptedRestore(
    validateInstalledState: () => Promise<void>,
    targetRoot: string = this.rootDir,
  ): Promise<boolean> {
    const resolvedTarget = path.resolve(targetRoot);
    const { rollbackRoot, discardRoot } = this.restorePaths(resolvedTarget);
    const [rollbackExists, discardExists] = await Promise.all([
      this.pathExists(rollbackRoot),
      this.pathExists(discardRoot),
    ]);
    const markerIsValid = await this.hasValidRestoreCommitMarker(resolvedTarget);
    if (
      !(await this.pathExists(resolvedTarget)) ||
      (!rollbackExists && !discardExists) ||
      (rollbackExists && !markerIsValid)
    ) {
      return false;
    }

    await validateInstalledState();
    const [rollbackStillExists, discardStillExists] = await Promise.all([
      this.pathExists(rollbackRoot),
      this.pathExists(discardRoot),
    ]);
    const markerStillValid = await this.hasValidRestoreCommitMarker(resolvedTarget);
    if (
      !(await this.pathExists(resolvedTarget)) ||
      (!rollbackStillExists && !discardStillExists) ||
      (rollbackStillExists && !markerStillValid)
    ) {
      throw new VaultaError(
        'CONFLICT',
        'Der Restore-Zustand wurde waehrend der Pruefung veraendert.',
      );
    }
    if (rollbackStillExists && discardStillExists) {
      throw new VaultaError('CONFLICT', 'Ein Restore-Cleanup ist noch nicht abgeschlossen.');
    }

    // Renaming the rollback out of its recovery role is the durable commit.
    // A crash during the following deletion can no longer replace the target
    // with a partially deleted directory.
    if (rollbackStillExists) {
      await rename(rollbackRoot, discardRoot);
      await this.syncDirectory(path.dirname(resolvedTarget));
    }
    await rm(resolveInside(resolvedTarget, RESTORE_COMMIT_MARKER), { force: true });
    await this.syncDirectory(resolvedTarget);
    await rm(discardRoot, { recursive: true, force: true });
    await this.syncDirectory(path.dirname(resolvedTarget));
    return true;
  }

  private async rotateBackups(
    folder: string,
    rotation: BackupRotation,
    profileId: string,
    masterAccessKey: Buffer,
  ): Promise<string[]> {
    for (const value of [rotation.daily, rotation.weekly, rotation.monthly]) {
      if (!Number.isSafeInteger(value) || value < 0 || value > 10_000) {
        throw new VaultaError('INVALID_INPUT', 'Die Backup-Rotation ist ungültig.');
      }
    }
    const resolvedFolder = path.resolve(folder);
    const entries = await readdir(resolvedFolder, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    const candidates: Array<{ path: string; createdAt: Date }> = [];
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(BACKUP_EXTENSION)) continue;
      const backupPath = resolveInside(resolvedFolder, entry.name);
      try {
        const { header } = await this.readBackupHeader(backupPath);
        if (header.automatic !== true || header.profileHeader.profileId !== profileId) continue;
        const authenticated = await this.processBackup(
          backupPath,
          { type: 'master', value: '' },
          null,
          { accessKeyOverride: masterAccessKey },
        );
        if (
          authenticated.header.automatic !== true ||
          authenticated.header.profileHeader.profileId !== profileId
        ) {
          continue;
        }
        const createdAt = new Date(authenticated.header.createdAt);
        if (!Number.isNaN(createdAt.getTime())) candidates.push({ path: backupPath, createdAt });
      } catch {
        // Unknown or corrupt files are never removed automatically.
      }
    }
    candidates.sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());

    const keep = new Set<string>();
    this.keepDistinctPeriods(
      candidates,
      rotation.daily,
      (date) => date.toISOString().slice(0, 10),
      keep,
    );
    this.keepDistinctPeriods(candidates, rotation.weekly, (date) => this.isoWeek(date), keep);
    this.keepDistinctPeriods(
      candidates,
      rotation.monthly,
      (date) => date.toISOString().slice(0, 7),
      keep,
    );
    const removed = candidates.filter((candidate) => !keep.has(candidate.path));
    await Promise.all(removed.map((candidate) => rm(candidate.path, { force: true })));
    return removed.map((candidate) => candidate.path);
  }

  private restorePaths(targetRoot: string): {
    stageRoot: string;
    rollbackRoot: string;
    discardRoot: string;
  } {
    const parent = path.dirname(targetRoot);
    if (parent === targetRoot) {
      throw new VaultaError('UNSAFE_PATH', 'Das Wurzelverzeichnis darf nicht ersetzt werden.');
    }
    const baseName = path.basename(targetRoot);
    return {
      stageRoot: path.join(parent, `.${baseName}.vaulta-restore-stage`),
      rollbackRoot: path.join(parent, `.${baseName}.vaulta-restore-rollback`),
      discardRoot: path.join(parent, `.${baseName}.vaulta-restore-discard`),
    };
  }

  private async pathExists(candidate: string): Promise<boolean> {
    return lstat(candidate).then(
      (info) => {
        if (info.isSymbolicLink() || !info.isDirectory()) {
          throw new VaultaError(
            'UNSAFE_PATH',
            'Restore-Pfade müssen lokale Verzeichnisse ohne symbolische Verknüpfungen sein.',
          );
        }
        return true;
      },
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return false;
        throw error;
      },
    );
  }

  private async hasValidRestoreCommitMarker(targetRoot: string): Promise<boolean> {
    const markerPath = resolveInside(targetRoot, RESTORE_COMMIT_MARKER);
    try {
      const marker = JSON.parse(await readFile(markerPath, 'utf8')) as unknown;
      return (
        isRecord(marker) &&
        marker.format === 'vaulta-restore-commit' &&
        typeof marker.backupId === 'string' &&
        marker.targetRoot === targetRoot
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      if (error instanceof SyntaxError) return false;
      throw error;
    }
  }

  private async syncDirectoryTree(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) await this.syncDirectoryTree(path.join(directory, entry.name));
    }
    await this.syncDirectory(directory);
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

  private async processBackup(
    backupPath: string,
    credential: BackupCredential,
    stageRoot: string | null,
    options: { accessKeyOverride?: Buffer } = {},
  ): Promise<{ header: BackupHeader; manifest: BackupManifest }> {
    const input = await open(backupPath, constants.O_RDONLY).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Die Sicherungsdatei wurde nicht gefunden.');
      }
      throw error;
    });
    let fileKey: Buffer | null = null;
    let accessKey: Buffer | null = null;
    let current: ProcessingFile | null = null;

    try {
      const fileInfo = await input.stat();
      const parsedHeader = await this.readBackupHeaderFromHandle(input);
      const { header, headerBytes, dataOffset } = parsedHeader;
      accessKey =
        options.accessKeyOverride === undefined
          ? await this.profileService.deriveBackupAccessKeyFromHeader(
              header.profileHeader,
              credential,
            )
          : Buffer.from(options.accessKeyOverride);
      const wrappedKey =
        credential.type === 'recovery' ? header.keyWraps.recovery : header.keyWraps.master;
      if (wrappedKey === null) {
        throw new VaultaError(
          'AUTH_FAILED',
          'Diese Sicherung besitzt keinen Wiederherstellungszugang.',
        );
      }
      try {
        fileKey = this.crypto.unwrapKey(
          wrappedKey,
          accessKey,
          `backup:${header.backupId}:${credential.type}`,
        );
      } catch (error) {
        throw new VaultaError('AUTH_FAILED', 'Die Sicherung konnte nicht entsperrt werden.', null, {
          cause: error,
        });
      }

      const noncePrefix = Buffer.from(header.noncePrefix, 'base64');
      const observed: BackupManifestEntry[] = [];
      const seenPaths = new Set<string>();
      let position = dataOffset;
      let expectedIndex = 0;
      let manifest: BackupManifest | null = null;

      while (position < fileInfo.size) {
        const recordHeader = await readExact(input, RECORD_HEADER_BYTES, position);
        position += RECORD_HEADER_BYTES;
        const type = recordHeader.readUInt8(0);
        const index = recordHeader.readUInt32BE(1);
        const ciphertextLength = recordHeader.readUInt32BE(5);
        if (index !== expectedIndex || type > MANIFEST_RECORD) {
          throw new VaultaError('CORRUPT_DATA', 'Die Backup-Datensätze sind vertauscht.');
        }
        const maximum = type === FILE_DATA_RECORD ? CHUNK_SIZE : MAX_METADATA_RECORD_BYTES;
        if (ciphertextLength > maximum) {
          throw new VaultaError('CORRUPT_DATA', 'Ein Backup-Datensatz ist zu groß.');
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
          if (type === FILE_START_RECORD) {
            if (current !== null) {
              throw new VaultaError(
                'CORRUPT_DATA',
                'Ein Backup-Dateidatensatz wurde nicht abgeschlossen.',
              );
            }
            const start = parseJson(plaintext, 'Ein Backup-Dateianfang ist beschädigt.');
            if (
              !isRecord(start) ||
              typeof start.path !== 'string' ||
              typeof start.size !== 'number' ||
              !Number.isSafeInteger(start.size) ||
              start.size < 0
            ) {
              throw new VaultaError('CORRUPT_DATA', 'Ein Backup-Dateianfang ist ungültig.');
            }
            const safePath = this.validateRestorablePath(
              normalizeBackupPath(start.path),
              header.purpose,
            );
            if (seenPaths.has(safePath)) {
              throw new VaultaError('CORRUPT_DATA', 'Die Sicherung enthält doppelte Dateipfade.');
            }
            seenPaths.add(safePath);
            let output: FileHandle | null = null;
            if (stageRoot !== null) {
              const outputPath = resolveInside(stageRoot, ...safePath.split('/'));
              await mkdir(path.dirname(outputPath), { recursive: true });
              output = await open(
                outputPath,
                constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
                0o600,
              );
            }
            current = {
              entry: { path: safePath, size: start.size, sha256: '' },
              hash: createHash('sha256'),
              bytesWritten: 0,
              output,
            };
          } else if (type === FILE_DATA_RECORD) {
            if (current === null) {
              throw new VaultaError('CORRUPT_DATA', 'Ein Backup-Datenchunk besitzt keine Datei.');
            }
            if (current.bytesWritten + plaintext.length > current.entry.size) {
              throw new VaultaError(
                'CORRUPT_DATA',
                'Eine Backup-Datei ist größer als angekündigt.',
              );
            }
            current.hash.update(plaintext);
            if (current.output !== null) {
              await writeAll(current.output, plaintext, current.bytesWritten);
            }
            current.bytesWritten += plaintext.length;
          } else if (type === FILE_END_RECORD) {
            if (current === null) {
              throw new VaultaError(
                'CORRUPT_DATA',
                'Ein Backup-Dateiabschluss besitzt keine Datei.',
              );
            }
            const end = parseJson(plaintext, 'Ein Backup-Dateiabschluss ist beschädigt.');
            const actualHash = current.hash.digest('hex');
            if (
              !isRecord(end) ||
              end.path !== current.entry.path ||
              end.size !== current.entry.size ||
              end.sha256 !== actualHash ||
              current.bytesWritten !== current.entry.size
            ) {
              throw new VaultaError(
                'CORRUPT_DATA',
                'Eine Backup-Datei ist unvollständig oder verändert.',
              );
            }
            current.entry.sha256 = actualHash;
            if (current.output !== null) {
              await current.output.sync();
              await current.output.close();
            }
            observed.push(current.entry);
            current = null;
          } else {
            if (current !== null || manifest !== null || position !== fileInfo.size) {
              throw new VaultaError(
                'CORRUPT_DATA',
                'Das Backup-Manifest steht nicht am Dateiende.',
              );
            }
            manifest = parseManifest(parseJson(plaintext, 'Das Backup-Manifest ist beschädigt.'));
            this.verifyManifest(header, manifest, observed);
          }
        } finally {
          this.crypto.erase(plaintext);
        }
        expectedIndex += 1;
      }

      if (manifest === null || current !== null) {
        throw new VaultaError('CORRUPT_DATA', 'Der authentifizierte Backup-Abschluss fehlt.');
      }
      return { header, manifest };
    } finally {
      await current?.output?.close().catch(() => undefined);
      this.crypto.erase(fileKey);
      this.crypto.erase(accessKey);
      await input.close();
    }
  }

  private async assertLiveSourcesMatchManifest(
    manifest: BackupManifest,
    sourcePaths?: readonly string[],
    assertAuthorized: () => void = () => undefined,
  ): Promise<void> {
    assertAuthorized();
    const sources = await this.collectSourceFiles(sourcePaths);
    try {
      const observed: BackupManifestEntry[] = [];
      for (const source of sources) {
        assertAuthorized();
        const digest = await this.hashLiveSource(source, assertAuthorized);
        observed.push({ path: source.backupPath, size: digest.size, sha256: digest.sha256 });
      }
      assertAuthorized();
      if (JSON.stringify(observed) !== JSON.stringify(manifest.files)) {
        throw new VaultaError(
          'CONFLICT',
          'Die Vaulta-Daten wurden waehrend der Sicherung veraendert. Das Backup wurde nicht ersetzt.',
        );
      }
    } finally {
      sources.forEach((source) => this.crypto.erase(source.snapshot));
    }
  }

  private async hashLiveSource(
    source: SourceFile,
    assertAuthorized: () => void,
  ): Promise<{ size: number; sha256: string }> {
    if (source.snapshot !== null) {
      return {
        size: source.snapshot.length,
        sha256: createHash('sha256').update(source.snapshot).digest('hex'),
      };
    }

    const handle = await open(source.absolutePath, constants.O_RDONLY);
    const hash = createHash('sha256');
    let position = 0;
    try {
      const before = await handle.stat();
      if (!before.isFile() || !sameSourceIdentity(source, before)) {
        throw new VaultaError(
          'CONFLICT',
          'Eine Vaulta-Datei wurde vor der Sicherungspruefung ausgetauscht.',
        );
      }
      while (true) {
        assertAuthorized();
        const buffer = Buffer.allocUnsafe(CHUNK_SIZE);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) {
          buffer.fill(0);
          break;
        }
        hash.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
        buffer.fill(0);
      }
      const after = await handle.stat();
      const pathInfo = await lstat(source.absolutePath);
      if (
        !pathInfo.isFile() ||
        pathInfo.isSymbolicLink() ||
        !sameFileIdentity(before, after) ||
        !sameFileIdentity(after, pathInfo) ||
        position !== after.size
      ) {
        throw new VaultaError(
          'CONFLICT',
          'Eine Vaulta-Datei wurde waehrend der Sicherungspruefung veraendert.',
        );
      }
      return { size: position, sha256: hash.digest('hex') };
    } finally {
      await handle.close();
    }
  }

  private async collectSourceFiles(sourcePaths?: readonly string[]): Promise<SourceFile[]> {
    if (sourcePaths !== undefined) {
      const files: SourceFile[] = [];
      const normalizedPaths = sourcePaths.map((sourcePath) => normalizeBackupPath(sourcePath));
      if (new Set(normalizedPaths).size !== normalizedPaths.length) {
        throw new VaultaError('INVALID_INPUT', 'Der Migrations-Snapshot enthält doppelte Pfade.');
      }
      for (const sourcePath of normalizedPaths) {
        await this.addSourceFile(files, sourcePath, true, sourcePath === 'profile.json');
      }
      return files.sort((left, right) => left.backupPath.localeCompare(right.backupPath));
    }
    const files: SourceFile[] = [];
    await this.addSourceFile(files, 'profile.json', true, true);
    await this.addSourceFile(files, 'audit.vaulta', false);
    await this.collectFlatDirectory(files, 'vaults', '.vaulta');

    const attachmentsRoot = resolveInside(this.rootDir, 'attachments');
    const vaultDirectories = await readdir(attachmentsRoot, { withFileTypes: true }).catch(
      (error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
        throw error;
      },
    );
    for (const directory of vaultDirectories) {
      if (!directory.isDirectory() || !/^[A-Za-z0-9_-]+$/u.test(directory.name)) {
        throw new VaultaError(
          'CONFLICT',
          'Der Anhangsspeicher enthaelt einen nicht bestaetigten Dateistand.',
        );
      }
      await this.collectFlatDirectory(files, `attachments/${directory.name}`, '.vatt');
    }
    return files.sort((left, right) => left.backupPath.localeCompare(right.backupPath));
  }

  private async collectFlatDirectory(
    files: SourceFile[],
    relativeDirectory: string,
    extension: string,
  ): Promise<void> {
    const directory = resolveInside(this.rootDir, ...relativeDirectory.split('/'));
    const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    for (const entry of entries) {
      if (
        !entry.isFile() ||
        !entry.name.endsWith(extension) ||
        !/^[A-Za-z0-9_-]+$/u.test(entry.name.slice(0, -extension.length))
      ) {
        throw new VaultaError(
          'CONFLICT',
          'Ein verwalteter Vaulta-Datenordner enthaelt einen nicht bestaetigten Dateistand.',
        );
      }
      await this.addSourceFile(files, `${relativeDirectory}/${entry.name}`, true);
    }
  }

  private async addSourceFile(
    files: SourceFile[],
    backupPath: string,
    required: boolean,
    snapshot = false,
  ): Promise<void> {
    const normalized = normalizeBackupPath(backupPath);
    const absolutePath = resolveInside(this.rootDir, ...normalized.split('/'));
    const info = await lstat(absolutePath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT' && !required) return null;
      throw error;
    });
    if (info === null) return;
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Eine zu sichernde Vaulta-Datei ist kein regulärer Dateityp.',
      );
    }
    const snapshotBytes = snapshot ? await readFile(absolutePath) : null;
    if (snapshotBytes !== null) {
      const after = await lstat(absolutePath);
      if (
        after.isSymbolicLink() ||
        !after.isFile() ||
        !sameFileIdentity(info, after) ||
        snapshotBytes.length !== after.size
      ) {
        this.crypto.erase(snapshotBytes);
        throw new VaultaError(
          'CONFLICT',
          'Eine Vaulta-Datei wurde waehrend der Sicherung veraendert. Bitte wiederhole die Sicherung.',
        );
      }
    }
    files.push({
      absolutePath,
      backupPath: normalized,
      size: snapshotBytes?.length ?? info.size,
      snapshot: snapshotBytes,
      dev: info.dev,
      ino: info.ino,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs,
    });
  }

  private async resolveDestination(
    destination: string | undefined,
    createdAt: string,
  ): Promise<string> {
    const fallback = resolveInside(this.rootDir, 'backups');
    const selected = path.resolve(destination ?? fallback);
    const isBackupFile = selected.endsWith(BACKUP_EXTENSION);
    const folder = isBackupFile ? path.dirname(selected) : selected;
    await mkdir(folder, { recursive: true });
    if (isBackupFile) return selected;
    const timestamp = createdAt.replace(/[:.]/g, '-');
    return resolveInside(
      folder,
      `Vaulta-${timestamp}-${randomUUID().slice(0, 8)}${BACKUP_EXTENSION}`,
    );
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
      throw new VaultaError('FILE_TOO_LARGE', 'Die Sicherung enthält zu viele Datensätze.');
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
    this.crypto.erase(nonce);
    this.crypto.erase(tag);
    this.crypto.erase(ciphertext);
    return next;
  }

  private async readBackupHeader(backupPath: string): Promise<{
    header: BackupHeader;
    headerBytes: Buffer;
    dataOffset: number;
  }> {
    const handle = await open(backupPath, constants.O_RDONLY);
    try {
      return await this.readBackupHeaderFromHandle(handle);
    } finally {
      await handle.close();
    }
  }

  private async readBackupHeaderFromHandle(handle: FileHandle): Promise<{
    header: BackupHeader;
    headerBytes: Buffer;
    dataOffset: number;
  }> {
    const magic = await readExact(handle, BACKUP_MAGIC.length, 0);
    if (!this.crypto.equals(magic, BACKUP_MAGIC)) {
      throw new VaultaError('CORRUPT_DATA', 'Das Sicherungsformat ist ungültig.');
    }
    const lengthBytes = await readExact(handle, 4, BACKUP_MAGIC.length);
    const headerLength = lengthBytes.readUInt32BE(0);
    if (headerLength === 0 || headerLength > HEADER_LIMIT) {
      throw new VaultaError('CORRUPT_DATA', 'Der Sicherungsheader ist ungültig.');
    }
    const headerBytes = await readExact(handle, headerLength, BACKUP_MAGIC.length + 4);
    try {
      return {
        header: parseBackupHeader(JSON.parse(headerBytes.toString('utf8')) as unknown),
        headerBytes,
        dataOffset: BACKUP_MAGIC.length + 4 + headerLength,
      };
    } catch (error) {
      if (error instanceof VaultaError) throw error;
      throw new VaultaError('CORRUPT_DATA', 'Der Sicherungsheader ist beschädigt.', null, {
        cause: error,
      });
    }
  }

  private verifyManifest(
    header: BackupHeader,
    manifest: BackupManifest,
    observed: BackupManifestEntry[],
  ): void {
    if (
      manifest.backupId !== header.backupId ||
      manifest.createdAt !== header.createdAt ||
      JSON.stringify(manifest.files) !== JSON.stringify(observed) ||
      manifest.rootSha256 !== this.manifestRootHash(observed) ||
      manifest.vaultCount !== observed.filter((file) => file.path.startsWith('vaults/')).length ||
      manifest.attachmentCount !==
        observed.filter((file) => file.path.startsWith('attachments/')).length
    ) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Das Backup-Manifest stimmt nicht mit den Dateien überein.',
      );
    }
  }

  private manifestRootHash(entries: BackupManifestEntry[]): string {
    return this.crypto.sha256(Buffer.from(JSON.stringify(entries), 'utf8')).toString('hex');
  }

  private validateRestorablePath(relativePath: string, purpose: BackupHeader['purpose']): string {
    if (relativePath === 'profile.json' || relativePath === 'audit.vaulta') return relativePath;
    if (/^vaults\/[A-Za-z0-9_-]+\.vaulta$/.test(relativePath)) return relativePath;
    if (/^attachments\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\.vatt$/.test(relativePath)) {
      return relativePath;
    }
    if (purpose === 'migration' && /^vaults\/[A-Za-z0-9_.-]+$/.test(relativePath)) {
      return relativePath;
    }
    throw new VaultaError('CORRUPT_DATA', 'Die Sicherung enthält einen unerlaubten Dateipfad.');
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
      Buffer.from('vaulta:backup-record:v1', 'utf8'),
      this.crypto.sha256(headerBytes),
      record,
    ]);
  }

  private keepDistinctPeriods(
    candidates: Array<{ path: string; createdAt: Date }>,
    count: number,
    period: (date: Date) => string,
    keep: Set<string>,
  ): void {
    const seen = new Set<string>();
    for (const candidate of candidates) {
      const key = period(candidate.createdAt);
      if (seen.has(key)) continue;
      if (seen.size >= count) break;
      seen.add(key);
      keep.add(candidate.path);
    }
  }

  private isoWeek(date: Date): string {
    const value = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
    const day = value.getUTCDay() || 7;
    value.setUTCDate(value.getUTCDate() + 4 - day);
    const yearStart = new Date(Date.UTC(value.getUTCFullYear(), 0, 1));
    const week = Math.ceil(((value.getTime() - yearStart.getTime()) / 86_400_000 + 1) / 7);
    return `${value.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
  }
}
