import { copyFile, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import {
  PERSISTENT_FORMAT_BASELINE,
  PersistentMigrationService,
  type PersistentFormatAdapter,
} from '../../src/main/services/persistent-migration-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import { VaultaError } from '../../src/shared/errors';

const fixtures = path.resolve('tests', 'fixtures', 'migrations');
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Persistente Vaulta-Migrationen', () => {
  it('erkennt alle aktuellen v1-Formatfixtures idempotent und ohne Schreibvorgang', async () => {
    const root = await createRoot();
    await installBaselineFixtures(root);
    const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
    const migrations = new PersistentMigrationService({ rootDir: root, profileService: profile });

    expect(PERSISTENT_FORMAT_BASELINE).toEqual({
      profileHeader: 1,
      encryptedContainer: 1,
      vaultDocument: 1,
      auditDocument: 1,
      attachment: 1,
    });
    await expect(migrations.inspect()).resolves.toEqual({ inspectedFiles: 4, pendingFiles: 0 });
    await expect(migrations.migrate()).resolves.toEqual({
      inspectedFiles: 4,
      pendingFiles: 0,
      migratedFiles: 0,
      backupPath: null,
    });
    await expect(readdir(path.join(root, 'migration-backups'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it.each([
    ['Profil', 'profile'],
    ['Container', 'container'],
    ['Anhang', 'attachment'],
  ] as const)('lehnt eine unbekannte %s-Zukunftsversion fail-closed ab', async (_label, kind) => {
    const root = await createRoot();
    await installBaselineFixtures(root);
    await installFutureVersion(root, kind);
    const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
    const migrations = new PersistentMigrationService({ rootDir: root, profileService: profile });

    const error = await captureVaultaError(migrations.inspect());

    expect(error.code).toBe('UNSUPPORTED_FORMAT');
    expect(error.action).toContain('nicht verändert');
    await expect(readdir(path.join(root, 'migration-backups'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('erstellt und verifiziert vor dem ersten Write ein verschluesseltes bytegenaues Snapshot', async () => {
    const root = await createRoot();
    const profile = await createUnlockedProfile(root);
    const sourcePath = path.join(root, 'vaults', 'state.migration-test');
    await mkdir(path.dirname(sourcePath), { recursive: true });
    const source = Buffer.from(
      JSON.stringify({ format: 'migration-test', version: 1, payload: 'SNAPSHOT-CANARY' }),
      'utf8',
    );
    await writeFile(sourcePath, source);
    const profileBefore = await readFile(path.join(root, 'profile.json'));
    let snapshotWasCompleteBeforeWrite = false;
    const migrationReference: { current: PersistentMigrationService | null } = { current: null };
    const atomicWriter = new AtomicFileWriter({
      beforeReplace: async (_temporaryPath, targetPath) => {
        if (targetPath !== sourcePath) return;
        const snapshotRoot = path.join(root, 'migration-backups');
        const snapshots = await readdir(snapshotRoot);
        expect(snapshots).toHaveLength(1);
        const snapshotPath = path.join(snapshotRoot, snapshots[0] as string);
        const current = migrationReference.current;
        if (current === null) throw new Error('Migrationsdienst fehlt im Commit-Hook');
        await expect(current.verifySnapshot(snapshotPath)).resolves.toBeUndefined();
        snapshotWasCompleteBeforeWrite = true;
      },
    });
    const migrations = new PersistentMigrationService({
      rootDir: root,
      profileService: profile,
      atomicWriter,
      additionalAdapters: [testAdapter()],
      now: () => new Date('2026-07-14T12:00:00.000Z'),
    });
    migrationReference.current = migrations;

    const result = await migrations.migrate();

    expect(snapshotWasCompleteBeforeWrite).toBe(true);
    expect(result).toMatchObject({ pendingFiles: 1, migratedFiles: 1 });
    expect(result.backupPath).not.toBeNull();
    const backupPath = result.backupPath as string;
    const snapshotBytes = await readFile(backupPath);
    expect(snapshotBytes.toString('utf8')).not.toContain('SNAPSHOT-CANARY');
    expect(snapshotBytes.toString('utf8')).not.toContain('state.migration-test');
    await expect(migrations.verifySnapshot(backupPath)).resolves.toBeUndefined();
    expect(JSON.parse(await readFile(sourcePath, 'utf8'))).toEqual({
      format: 'migration-test',
      version: 2,
      payload: 'SNAPSHOT-CANARY',
      migratedWithoutLoss: true,
    });

    const tamperedPath = backupPath.replace(/\.vaulta-backup$/u, '-tampered.vaulta-backup');
    await copyFile(backupPath, tamperedPath);
    const tampered = await readFile(tamperedPath);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 1;
    await writeFile(tamperedPath, tampered);
    await expect(migrations.verifySnapshot(tamperedPath)).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });
    await rm(tamperedPath, { force: true });

    await expect(migrations.migrate()).resolves.toMatchObject({
      pendingFiles: 0,
      migratedFiles: 0,
      backupPath: null,
    });
    expect(await readdir(path.join(root, 'migration-backups'))).toHaveLength(1);

    await migrations.restoreSnapshot(backupPath, {
      type: 'master',
      value: 'Migration Master-Passwort!123',
    });
    expect(await readFile(sourcePath)).toEqual(source);
    expect(await readFile(path.join(root, 'profile.json'))).toEqual(profileBefore);
  });

  it('rollt nach einem Crash zwischen zwei Writes beim Neustart beide Dateien bytegenau zurueck', async () => {
    const root = await createRoot();
    const profile = await createUnlockedProfile(root);
    const firstPath = path.join(root, 'vaults', 'state-a.migration-test');
    const secondPath = path.join(root, 'vaults', 'state-b.migration-test');
    await mkdir(path.dirname(firstPath), { recursive: true });
    const firstSource = Buffer.from(
      JSON.stringify({ format: 'migration-test', version: 1, payload: 'FIRST-ORIGINAL' }),
      'utf8',
    );
    const secondSource = Buffer.from(
      JSON.stringify({ format: 'migration-test', version: 1, payload: 'SECOND-ORIGINAL' }),
      'utf8',
    );
    await writeFile(firstPath, firstSource);
    await writeFile(secondPath, secondSource);

    const migrationTargets = new Set([firstPath, secondPath]);
    let installedMigrationFiles = 0;
    const crashWriter = new AtomicFileWriter({
      afterReplace: (targetPath) => {
        if (!migrationTargets.has(targetPath)) return;
        installedMigrationFiles += 1;
        if (installedMigrationFiles === 1) throw new Error('Simulierter Prozessabbruch');
      },
    });
    const interrupted = new PersistentMigrationService({
      rootDir: root,
      profileService: profile,
      atomicWriter: crashWriter,
      additionalAdapters: [multiFileTestAdapter()],
    });

    await expect(interrupted.migrate()).rejects.toThrow('Simulierter Prozessabbruch');

    expect(installedMigrationFiles).toBe(1);
    expect(await readFile(firstPath)).not.toEqual(firstSource);
    expect(await readFile(secondPath)).toEqual(secondSource);
    const transactionEntries = await readdir(path.join(root, '.vaulta-migration-transaction'));
    expect(transactionEntries).toContain('journal.json');
    expect(
      transactionEntries.filter((entry) => /^rollback-[0-9]{6}\.bin$/u.test(entry)),
    ).toHaveLength(2);
    const snapshotsBeforeRestart = await readdir(path.join(root, 'migration-backups'));
    expect(snapshotsBeforeRestart).toHaveLength(1);

    const restarted = new PersistentMigrationService({
      rootDir: root,
      profileService: profile,
      additionalAdapters: [multiFileTestAdapter()],
    });
    await expect(restarted.recoverInterruptedWrites()).resolves.toBeUndefined();

    expect(await readFile(firstPath)).toEqual(firstSource);
    expect(await readFile(secondPath)).toEqual(secondSource);
    await expect(readdir(path.join(root, '.vaulta-migration-transaction'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    const snapshotsAfterRestart = await readdir(path.join(root, 'migration-backups'));
    expect(snapshotsAfterRestart).toEqual(snapshotsBeforeRestart);
    await expect(
      restarted.verifySnapshot(
        path.join(root, 'migration-backups', snapshotsAfterRestart[0] as string),
      ),
    ).resolves.toBeUndefined();
    await expect(restarted.inspect()).resolves.toMatchObject({ pendingFiles: 2 });
  });

  it('verwirft eine ungesicherte v0-Datei ohne erfundene Migration und ohne Write', async () => {
    const root = await createRoot();
    const profile = await createUnlockedProfile(root);
    const sourcePath = path.join(root, 'vaults', 'state.migration-test');
    await mkdir(path.dirname(sourcePath), { recursive: true });
    const source = Buffer.from(
      JSON.stringify({ format: 'migration-test', version: 0, payload: 'LEGACY' }),
      'utf8',
    );
    await writeFile(sourcePath, source);
    const migrations = new PersistentMigrationService({
      rootDir: root,
      profileService: profile,
      additionalAdapters: [testAdapter()],
    });

    const error = await captureVaultaError(migrations.migrate());

    expect(error.code).toBe('UNSUPPORTED_FORMAT');
    expect(error.message).toContain('kein verlustfreier Migrationspfad');
    expect(await readFile(sourcePath)).toEqual(source);
    await expect(readdir(path.join(root, 'migration-backups'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('bricht bei verlorener Auth-Epoche vor dem Write ab und entfernt den Teilsnapshot', async () => {
    const root = await createRoot();
    const profile = await createUnlockedProfile(root);
    const sourcePath = path.join(root, 'vaults', 'state.migration-test');
    await mkdir(path.dirname(sourcePath), { recursive: true });
    const source = Buffer.from(
      JSON.stringify({ format: 'migration-test', version: 1, payload: 'EPOCH' }),
      'utf8',
    );
    await writeFile(sourcePath, source);
    const migrations = new PersistentMigrationService({
      rootDir: root,
      profileService: profile,
      additionalAdapters: [testAdapter()],
    });
    let checks = 0;

    await expect(
      migrations.migrate(() => {
        checks += 1;
        if (checks >= 6) throw new Error('Auth-Epoche wurde invalidiert');
      }),
    ).rejects.toThrow('Auth-Epoche wurde invalidiert');

    expect(await readFile(sourcePath)).toEqual(source);
    const snapshots = await readdir(path.join(root, 'migration-backups')).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return [];
        throw error;
      },
    );
    expect(snapshots).toEqual([]);
  });
});

async function captureVaultaError(promise: Promise<unknown>): Promise<VaultaError> {
  try {
    await promise;
  } catch (error: unknown) {
    if (error instanceof VaultaError) {
      return error;
    }
    throw error;
  }
  throw new Error('Erwarteter VaultaError wurde nicht ausgeloest.');
}

function testAdapter(): PersistentFormatAdapter {
  const readVersionFromBytes = (bytes: Buffer): number => {
    const value = JSON.parse(bytes.toString('utf8')) as { format?: unknown; version?: unknown };
    if (value.format !== 'migration-test' || typeof value.version !== 'number') {
      throw new Error('Ungueltiges Testformat');
    }
    return value.version;
  };
  return {
    id: 'migration-test-fixture',
    formatName: 'Migrations-Testfixture',
    currentVersion: 2,
    matches: (relativePath: string) => relativePath === 'vaults/state.migration-test',
    readVersion: async (filePath: string) => readVersionFromBytes(await readFile(filePath)),
    readVersionFromBytes,
    validateAtRest: async (filePath: string) => {
      const value = JSON.parse(await readFile(filePath, 'utf8')) as Record<string, unknown>;
      if (value.version !== 2 || value.migratedWithoutLoss !== true) {
        throw new Error('Migration ist unvollstaendig');
      }
    },
    validateCurrent: (bytes: Buffer) => {
      const value = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
      if (value.version !== 2 || value.migratedWithoutLoss !== true) {
        throw new Error('Migration ist unvollstaendig');
      }
    },
    migrations: [
      {
        fromVersion: 1,
        toVersion: 2,
        migrate: (payload) => {
          const value = JSON.parse(payload.bytes.toString('utf8')) as Record<string, unknown>;
          return {
            ...payload,
            version: 2,
            bytes: Buffer.from(
              JSON.stringify({ ...value, version: 2, migratedWithoutLoss: true }),
              'utf8',
            ),
          };
        },
      },
    ],
  };
}

function multiFileTestAdapter(): PersistentFormatAdapter {
  return {
    ...testAdapter(),
    id: 'multi-file-migration-test-fixture',
    matches: (relativePath: string) => /^vaults\/state-[ab]\.migration-test$/u.test(relativePath),
  };
}

async function createRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-migration-'));
  roots.push(root);
  return root;
}

async function installBaselineFixtures(root: string): Promise<void> {
  await mkdir(path.join(root, 'vaults'), { recursive: true });
  await mkdir(path.join(root, 'attachments', 'vault-1'), { recursive: true });
  await writeFile(path.join(root, 'profile.json'), await fixture('profile-v1.json'));
  const container = await fixture('container-v1.vaulta');
  await writeFile(path.join(root, 'audit.vaulta'), container);
  await writeFile(path.join(root, 'vaults', 'vault-1.vaulta'), container);
  await writeFile(
    path.join(root, 'attachments', 'vault-1', 'attachment-1.vatt'),
    await attachmentFixture(1),
  );
}

async function installFutureVersion(
  root: string,
  kind: 'profile' | 'container' | 'attachment',
): Promise<void> {
  if (kind === 'attachment') {
    await writeFile(
      path.join(root, 'attachments', 'vault-1', 'attachment-1.vatt'),
      await attachmentFixture(2),
    );
    return;
  }
  const target =
    kind === 'profile'
      ? path.join(root, 'profile.json')
      : path.join(root, 'vaults', 'vault-1.vaulta');
  const value = JSON.parse(await readFile(target, 'utf8')) as Record<string, unknown>;
  if (kind === 'profile') value.version = 2;
  else (value.header as Record<string, unknown>).version = 2;
  await writeFile(target, JSON.stringify(value));
}

async function attachmentFixture(version: number): Promise<Buffer> {
  const header = JSON.parse(
    await readFile(path.join(fixtures, 'attachment-header-v1.json'), 'utf8'),
  ) as Record<string, unknown>;
  header.version = version;
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(headerBytes.length);
  return Buffer.concat([Buffer.from('VLTATT01', 'ascii'), length, headerBytes]);
}

async function fixture(name: string): Promise<Buffer> {
  return readFile(path.join(fixtures, name));
}

async function createUnlockedProfile(root: string): Promise<ProfileService> {
  const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
  const pending = await profile.beginSetup('Migration Master-Passwort!123', false);
  await profile.completeSetup(pending.pendingId, {});
  return profile;
}

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: {
      algorithm: 'argon2id',
      memorySizeKiB: 64,
      iterations: 1,
      parallelism: 1,
      hashLength: 32,
    },
    allowUnsafeParametersForTests: true,
  });
}
