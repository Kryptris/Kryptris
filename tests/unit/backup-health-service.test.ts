import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { BackupInspection } from '../../src/main/services/backup-service';
import { BackupHealthService } from '../../src/main/services/backup-health-service';

const roots: string[] = [];

class MemoryProfile {
  public value: unknown = null;

  public getProtectedMetadata<T>(): Promise<T | null> {
    return Promise.resolve((this.value as T | null) ?? null);
  }

  public setProtectedMetadata(_namespace: string, value: unknown): Promise<void> {
    this.value = structuredClone(value);
    return Promise.resolve();
  }
}

class FixtureInspector {
  public readonly calls: string[] = [];

  public constructor(private readonly inspections: Readonly<Record<string, BackupInspection>>) {}

  public inspectBackupWithActiveProfile(backupPath: string): Promise<BackupInspection> {
    this.calls.push(backupPath);
    const inspection = this.inspections[path.basename(backupPath)];
    if (inspection === undefined) throw new Error('Nicht authentifizierbar');
    return Promise.resolve(structuredClone(inspection));
  }
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Backup-Gesundheitsservice', () => {
  it('liefert nur authentifizierte, pfadfreie Gesundheitsdaten und Generationen', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-health-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    const destination = path.join(workspace, 'backups');
    await Promise.all([mkdir(profileRoot), mkdir(destination)]);
    await Promise.all([
      writeFile(path.join(destination, 'one.vaulta-backup'), Buffer.alloc(10)),
      writeFile(path.join(destination, 'two.vaulta-backup'), Buffer.alloc(20)),
      writeFile(path.join(destination, 'three.vaulta-backup'), Buffer.alloc(30)),
      writeFile(path.join(destination, 'foreign.vaulta-backup'), Buffer.alloc(40)),
    ]);
    const profile = new MemoryProfile();
    const inspector = new FixtureInspector({
      'one.vaulta-backup': {
        profileId: 'profile-a',
        createdAt: '2026-01-05T10:00:00.000Z',
        fileCount: 2,
        vaultCount: 1,
        attachmentCount: 0,
        automatic: true,
      },
      'two.vaulta-backup': {
        profileId: 'profile-a',
        createdAt: '2026-01-06T10:00:00.000Z',
        fileCount: 3,
        vaultCount: 2,
        attachmentCount: 1,
        automatic: true,
      },
      'three.vaulta-backup': {
        profileId: 'profile-a',
        createdAt: '2026-02-03T10:00:00.000Z',
        fileCount: 4,
        vaultCount: 3,
        attachmentCount: 2,
        automatic: true,
      },
    });
    const service = new BackupHealthService({
      rootDir: profileRoot,
      profile,
      inspector,
      now: () => new Date('2026-02-04T10:00:00.000Z'),
    });
    await service.recordSuccessfulBackup('2026-01-01T10:00:00.000Z');
    await service.recordSemanticVerification('2026-02-04T10:00:00.000Z');

    const result = await service.inspect(destination);

    expect(result).toMatchObject({
      targetReachable: true,
      sameDriveWarning: true,
      backupCount: 3,
      unreadableBackupCount: 1,
      totalSize: 60,
      generations: { daily: 3, weekly: 2, monthly: 2 },
      latestBackup: {
        createdAt: '2026-02-03T10:00:00.000Z',
        size: 30,
        vaultCount: 3,
        attachmentCount: 2,
        automatic: true,
      },
      lastSuccessfulBackupAt: '2026-02-03T10:00:00.000Z',
      lastSemanticVerificationAt: '2026-02-04T10:00:00.000Z',
    });
    expect(JSON.stringify(result)).not.toContain(destination);
    expect(JSON.stringify(result)).not.toContain('three.vaulta-backup');
    expect(inspector.calls).toHaveLength(4);
  });

  it('speichert bei Fehlern nur einen redigierten Code und behält Status bei unerreichbarem Ziel', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-health-redacted-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    await mkdir(profileRoot);
    const profile = new MemoryProfile();
    const service = new BackupHealthService({
      rootDir: profileRoot,
      profile,
      inspector: new FixtureInspector({}),
      now: () => new Date('2026-02-04T10:00:00.000Z'),
    });
    const sensitivePath = 'C:\\synthetischer-geheimer-ordner\\backup.vaulta-backup';
    await service.recordSuccessfulBackup('2026-02-01T10:00:00.000Z');
    await service.recordBackupFailure(new Error(`Fehler bei ${sensitivePath}`));

    const result = await service.inspect(path.join(workspace, 'nicht-vorhanden'));

    expect(result).toMatchObject({
      targetReachable: false,
      lastSuccessfulBackupAt: '2026-02-01T10:00:00.000Z',
      lastFailure: { occurredAt: '2026-02-04T10:00:00.000Z', code: 'INTERNAL' },
    });
    expect(JSON.stringify(profile.value)).not.toContain(sensitivePath);
    expect(JSON.stringify(result)).not.toContain(sensitivePath);
  });

  it('verwirft manipulierte Statusmetadaten statt sie als Gesundheitsstatus auszugeben', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-health-corrupt-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    await mkdir(profileRoot);
    const profile = new MemoryProfile();
    profile.value = { version: 1, lastSuccessfulBackupAt: 'keine-zeit', lastFailure: null };
    const service = new BackupHealthService({
      rootDir: profileRoot,
      profile,
      inspector: new FixtureInspector({}),
    });

    await expect(service.inspect(null)).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
  });
});
