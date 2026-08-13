import { lstat, realpath, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import { toVaultaError, VaultaError, type VaultaErrorCode } from '../../shared/errors';
import { resolveInside } from '../storage/path-safety';
import { SerialExecutor } from '../storage/serial-executor';
import type { BackupInspection } from './backup-service';

const BACKUP_EXTENSION = '.vaulta-backup';
const BACKUP_HEALTH_NAMESPACE = 'backup-health-v1';
const BACKUP_HEALTH_VERSION = 1 as const;

export interface BackupHealthProfile {
  getProtectedMetadata<T>(namespace: string): Promise<T | null>;
  setProtectedMetadata(namespace: string, value: unknown): Promise<void>;
}

export interface BackupHealthInspector {
  inspectBackupWithActiveProfile(backupPath: string): Promise<BackupInspection>;
}

export interface BackupGenerationCounts {
  readonly daily: number;
  readonly weekly: number;
  readonly monthly: number;
}

export interface BackupHealthFailure {
  readonly occurredAt: string;
  readonly code: VaultaErrorCode;
}

export interface BackupHealthLatestBackup {
  readonly createdAt: string;
  readonly size: number;
  readonly vaultCount: number;
  readonly attachmentCount: number;
  readonly automatic: boolean;
}

export interface BackupHealthSnapshot {
  /** Does not expose the configured folder or a file name. */
  readonly targetReachable: boolean;
  readonly sameDriveWarning: boolean;
  readonly backupCount: number;
  readonly unreadableBackupCount: number;
  readonly totalSize: number;
  readonly generations: BackupGenerationCounts;
  readonly latestBackup: BackupHealthLatestBackup | null;
  readonly lastSuccessfulBackupAt: string | null;
  readonly lastFailure: BackupHealthFailure | null;
  readonly lastSemanticVerificationAt: string | null;
}

export interface BackupHealthServiceOptions {
  readonly rootDir: string;
  readonly profile: BackupHealthProfile;
  readonly inspector: BackupHealthInspector;
  readonly now?: () => Date;
}

interface StoredBackupHealth {
  readonly version: typeof BACKUP_HEALTH_VERSION;
  readonly lastSuccessfulBackupAt: string | null;
  readonly lastFailure: BackupHealthFailure | null;
  readonly lastSemanticVerificationAt: string | null;
}

interface VerifiedBackup extends BackupHealthLatestBackup {
  readonly path: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseDate(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) {
    throw new VaultaError('CORRUPT_DATA', `${label} ist ungueltig.`);
  }
  return value;
}

function parseFailure(value: unknown): BackupHealthFailure | null {
  if (value === null) return null;
  if (!isRecord(value) || typeof value.occurredAt !== 'string' || typeof value.code !== 'string') {
    throw new VaultaError('CORRUPT_DATA', 'Der letzte Sicherungsfehler ist ungueltig.');
  }
  if (!Number.isFinite(Date.parse(value.occurredAt)) || !isVaultaErrorCode(value.code)) {
    throw new VaultaError('CORRUPT_DATA', 'Der letzte Sicherungsfehler ist ungueltig.');
  }
  return { occurredAt: value.occurredAt, code: value.code };
}

function isVaultaErrorCode(value: string): value is VaultaErrorCode {
  return [
    'AUTH_FAILED',
    'AUTH_FACTOR_REQUIRED',
    'AUTH_RATE_LIMITED',
    'CORRUPT_DATA',
    'INVALID_INPUT',
    'LOCKED',
    'NOT_FOUND',
    'CANCELLED',
    'CONFLICT',
    'FILE_TOO_LARGE',
    'UNSUPPORTED_FORMAT',
    'UNSAFE_PATH',
    'INTERNAL',
  ].includes(value);
}

function emptyStoredHealth(): StoredBackupHealth {
  return {
    version: BACKUP_HEALTH_VERSION,
    lastSuccessfulBackupAt: null,
    lastFailure: null,
    lastSemanticVerificationAt: null,
  };
}

function parseStoredHealth(value: unknown): StoredBackupHealth {
  if (value === null) return emptyStoredHealth();
  if (!isRecord(value) || value.version !== BACKUP_HEALTH_VERSION) {
    throw new VaultaError('CORRUPT_DATA', 'Die Sicherungsstatusdaten sind ungueltig.');
  }
  return {
    version: BACKUP_HEALTH_VERSION,
    lastSuccessfulBackupAt: parseDate(
      value.lastSuccessfulBackupAt,
      'Der letzte Sicherungszeitpunkt',
    ),
    lastFailure: parseFailure(value.lastFailure),
    lastSemanticVerificationAt: parseDate(
      value.lastSemanticVerificationAt,
      'Der letzte Pruefzeitpunkt',
    ),
  };
}

function compareIsoDates(left: string | null, right: string | null): string | null {
  if (left === null) return right;
  if (right === null) return left;
  return Date.parse(left) >= Date.parse(right) ? left : right;
}

function isoWeek(value: Date): string {
  const date = new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
  const weekday = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - weekday);
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((date.getTime() - yearStart.getTime()) / 86_400_000 + 1) / 7);
  return `${String(date.getUTCFullYear())}-W${String(week).padStart(2, '0')}`;
}

function isUnavailable(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === 'ENOENT' || code === 'EACCES' || code === 'EPERM';
}

function isSameVolume(
  sourcePath: string,
  targetPath: string,
  sourceDevice: number,
  targetDevice: number,
): boolean {
  if (process.platform !== 'win32') return sourceDevice === targetDevice;
  return (
    path.win32.parse(sourcePath).root.toLocaleLowerCase('en-US') ===
    path.win32.parse(targetPath).root.toLocaleLowerCase('en-US')
  );
}

/**
 * Builds a path-free backup health summary. Every on-disk backup is authenticated
 * before it affects success, generation, count, or size values. The small status
 * record is protected profile metadata and deliberately stores only timestamps
 * and an error code -- never a path, backup name, or original error message.
 */
export class BackupHealthService {
  private readonly rootDir: string;
  private readonly profile: BackupHealthProfile;
  private readonly inspector: BackupHealthInspector;
  private readonly now: () => Date;
  private readonly writes = new SerialExecutor();

  public constructor(options: BackupHealthServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.profile = options.profile;
    this.inspector = options.inspector;
    this.now = options.now ?? (() => new Date());
  }

  public async inspect(
    destination: string | null,
    assertAuthorized: () => void = () => undefined,
  ): Promise<BackupHealthSnapshot> {
    assertAuthorized();
    const stored = await this.readStored();
    assertAuthorized();
    if (destination === null) return this.emptySnapshot(stored);

    const requestedFolder = path.resolve(destination);
    const requestedInfo = await lstat(requestedFolder).catch((error: NodeJS.ErrnoException) => {
      if (isUnavailable(error)) return null;
      throw error;
    });
    if (requestedInfo === null) {
      return this.emptySnapshot(stored);
    }
    const folder = await realpath(requestedFolder).catch((error: NodeJS.ErrnoException) => {
      if (isUnavailable(error)) return null;
      throw error;
    });
    if (folder === null) return this.emptySnapshot(stored);
    const folderInfo = await lstat(folder).catch((error: NodeJS.ErrnoException) => {
      if (isUnavailable(error)) return null;
      throw error;
    });
    if (folderInfo === null || folderInfo.isSymbolicLink() || !folderInfo.isDirectory()) {
      return this.emptySnapshot(stored);
    }

    let entries;
    try {
      entries = await readdir(folder, { withFileTypes: true });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EACCES' || code === 'EPERM' || code === 'ENOENT')
        return this.emptySnapshot(stored);
      throw error;
    }
    const verified: VerifiedBackup[] = [];
    let unreadableBackupCount = 0;
    for (const entry of entries) {
      assertAuthorized();
      if (!entry.name.endsWith(BACKUP_EXTENSION)) continue;
      if (!entry.isFile()) {
        unreadableBackupCount += 1;
        continue;
      }
      const backupPath = resolveInside(folder, entry.name);
      try {
        const entryInfo = await lstat(backupPath);
        if (entryInfo.isSymbolicLink() || !entryInfo.isFile()) {
          unreadableBackupCount += 1;
          continue;
        }
        const [inspection, fileInfo] = await Promise.all([
          this.inspector.inspectBackupWithActiveProfile(backupPath),
          stat(backupPath),
        ]);
        assertAuthorized();
        if (!fileInfo.isFile() || fileInfo.size < 0 || !Number.isSafeInteger(fileInfo.size)) {
          unreadableBackupCount += 1;
          continue;
        }
        if (!Number.isFinite(Date.parse(inspection.createdAt))) {
          unreadableBackupCount += 1;
          continue;
        }
        verified.push({
          path: backupPath,
          createdAt: inspection.createdAt,
          size: fileInfo.size,
          vaultCount: inspection.vaultCount,
          attachmentCount: inspection.attachmentCount,
          automatic: inspection.automatic,
        });
      } catch {
        // An untrusted or foreign backup remains untouched and is counted only.
        unreadableBackupCount += 1;
      }
    }
    assertAuthorized();
    verified.sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
    const latest = verified[0] ?? null;
    const automatic = verified.filter((backup) => backup.automatic);
    const generations = this.generationCounts(automatic);
    const canonicalRoot = await realpath(this.rootDir).catch(() => null);
    const sourceInfo = canonicalRoot === null ? null : await stat(canonicalRoot).catch(() => null);
    const sameDriveWarning =
      sourceInfo !== null &&
      canonicalRoot !== null &&
      isSameVolume(canonicalRoot, folder, sourceInfo.dev, folderInfo.dev);

    return {
      targetReachable: true,
      sameDriveWarning,
      backupCount: verified.length,
      unreadableBackupCount,
      totalSize: verified.reduce((total, backup) => total + backup.size, 0),
      generations,
      latestBackup:
        latest === null
          ? null
          : {
              createdAt: latest.createdAt,
              size: latest.size,
              vaultCount: latest.vaultCount,
              attachmentCount: latest.attachmentCount,
              automatic: latest.automatic,
            },
      lastSuccessfulBackupAt: compareIsoDates(
        stored.lastSuccessfulBackupAt,
        latest?.createdAt ?? null,
      ),
      lastFailure: stored.lastFailure,
      lastSemanticVerificationAt: stored.lastSemanticVerificationAt,
    };
  }

  public async recordSuccessfulBackup(createdAt: string = this.now().toISOString()): Promise<void> {
    this.assertTimestamp(createdAt, 'Der Sicherungszeitpunkt');
    await this.writes.run(async () => {
      const current = await this.readStored();
      await this.writeStored({
        ...current,
        lastSuccessfulBackupAt: compareIsoDates(current.lastSuccessfulBackupAt, createdAt),
        lastFailure: null,
      });
    });
  }

  public async recordBackupFailure(
    error: unknown,
    occurredAt: string = this.now().toISOString(),
  ): Promise<void> {
    this.assertTimestamp(occurredAt, 'Der Fehlerzeitpunkt');
    const code = toVaultaError(error).code;
    await this.writes.run(async () => {
      const current = await this.readStored();
      await this.writeStored({
        ...current,
        lastFailure: { occurredAt, code },
      });
    });
  }

  public async recordSemanticVerification(
    verifiedAt: string = this.now().toISOString(),
  ): Promise<void> {
    this.assertTimestamp(verifiedAt, 'Der Pruefzeitpunkt');
    await this.writes.run(async () => {
      const current = await this.readStored();
      await this.writeStored({
        ...current,
        lastSemanticVerificationAt: compareIsoDates(current.lastSemanticVerificationAt, verifiedAt),
      });
    });
  }

  private async readStored(): Promise<StoredBackupHealth> {
    return parseStoredHealth(
      await this.profile.getProtectedMetadata<unknown>(BACKUP_HEALTH_NAMESPACE),
    );
  }

  private async writeStored(value: StoredBackupHealth): Promise<void> {
    await this.profile.setProtectedMetadata(BACKUP_HEALTH_NAMESPACE, value);
  }

  private emptySnapshot(stored: StoredBackupHealth): BackupHealthSnapshot {
    return {
      targetReachable: false,
      sameDriveWarning: false,
      backupCount: 0,
      unreadableBackupCount: 0,
      totalSize: 0,
      generations: { daily: 0, weekly: 0, monthly: 0 },
      latestBackup: null,
      lastSuccessfulBackupAt: stored.lastSuccessfulBackupAt,
      lastFailure: stored.lastFailure,
      lastSemanticVerificationAt: stored.lastSemanticVerificationAt,
    };
  }

  private generationCounts(backups: readonly VerifiedBackup[]): BackupGenerationCounts {
    const daily = new Set<string>();
    const weekly = new Set<string>();
    const monthly = new Set<string>();
    for (const backup of backups) {
      const createdAt = new Date(backup.createdAt);
      daily.add(createdAt.toISOString().slice(0, 10));
      weekly.add(isoWeek(createdAt));
      monthly.add(createdAt.toISOString().slice(0, 7));
    }
    return { daily: daily.size, weekly: weekly.size, monthly: monthly.size };
  }

  private assertTimestamp(value: string, label: string): void {
    if (!Number.isFinite(Date.parse(value))) {
      throw new VaultaError('INVALID_INPUT', `${label} ist ungueltig.`);
    }
  }
}
