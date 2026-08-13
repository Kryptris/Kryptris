import { readdirSync, rmSync, symlinkSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { AuditService } from '../../src/main/services/audit-service';
import { BackupService } from '../../src/main/services/backup-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const roots: string[] = [];
const masterPassword = 'Nur-synthetisches-Backup-Testpasswort!123';

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

async function fixture(
  root: string,
  enableRecovery = false,
): Promise<{
  profile: ProfileService;
  vaults: VaultService;
  recoveryKey: string | null;
}> {
  const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
  const pending = await profile.beginSetup(masterPassword, enableRecovery);
  await profile.completeSetup(
    pending.pendingId,
    pending.recovery === null
      ? {}
      : (Object.fromEntries(
          pending.recovery.confirmationIndexes.map((index) => [
            String(index),
            pending.recovery?.groups[index],
          ]),
        ) as Record<string, string>),
  );
  return {
    profile,
    vaults: new VaultService({ rootDir: root, profileService: profile }),
    recoveryKey: pending.recovery?.displayKey ?? null,
  };
}

function backupService(root: string, profile: ProfileService, dryRunRoot: string): BackupService {
  return new BackupService({
    rootDir: root,
    profileService: profile,
    dryRunTemporaryRoot: dryRunRoot,
    stagedProfileFactory: (stageRoot) =>
      new ProfileService({ rootDir: stageRoot, keyDerivation: testDerivation() }),
  });
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Isolierter Restore-Probelauf', () => {
  it('prueft Backup, Profil, Tresore und Audit ohne das aktive Profil zu veraendern', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const { profile, vaults } = await fixture(root);
    const vault = await vaults.createVault('Synthetischer Testtresor', '#2DD4BF');
    await new AuditService({ rootDir: root, profileService: profile }).record({
      type: 'backup-created',
      vaultId: vault.id,
    });
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup();
    const beforeProfile = await readFile(path.join(root, 'profile.json'));
    const beforeVault = await readFile(path.join(root, 'vaults', `${vault.id}.vaulta`));

    const result = await service.dryRunBackup({
      backupPath: backup.path,
      credential: { type: 'master', value: masterPassword },
    });
    expect(result.profileId).toEqual(expect.any(String));
    expect(result).toMatchObject({
      vaultCount: 1,
      attachmentCount: 0,
      semanticallyVerified: true,
    });

    expect(await readdir(dryRunRoot)).toEqual([]);
    await expect(readFile(path.join(root, 'profile.json'))).resolves.toEqual(beforeProfile);
    await expect(readFile(path.join(root, 'vaults', `${vault.id}.vaulta`))).resolves.toEqual(
      beforeVault,
    );
    await expect(vaults.readVault(vault.id)).resolves.toMatchObject({
      name: 'Synthetischer Testtresor',
    });
  });

  it('prueft einen Recovery-Zugang nur im weggeraeumten Stagingbereich', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-recovery-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const { profile, vaults, recoveryKey } = await fixture(root, true);
    await vaults.createVault('Recovery-Tests', '#8B5CF6');
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup();
    const beforeProfile = await readFile(path.join(root, 'profile.json'));
    if (recoveryKey === null) throw new Error('Recovery-Key fehlt im Testfixture');

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'recovery', value: recoveryKey },
      }),
    ).resolves.toMatchObject({ semanticallyVerified: true, vaultCount: 1 });
    expect(await readdir(dryRunRoot)).toEqual([]);
    await expect(readFile(path.join(root, 'profile.json'))).resolves.toEqual(beforeProfile);
  });

  it('validiert Recovery ohne den persistenten Recovery-Header-Pfad im Staging', async () => {
    const workspace = await mkdtemp(
      path.join(os.tmpdir(), 'kryptris-backup-dry-run-recovery-readonly-'),
    );
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const { profile, vaults, recoveryKey } = await fixture(root, true);
    await vaults.createVault('Recovery-ReadOnly-Tests', '#7C3AED');
    const recoverCalls: unknown[][] = [];
    const service = new BackupService({
      rootDir: root,
      profileService: profile,
      dryRunTemporaryRoot: dryRunRoot,
      stagedProfileFactory: (stageRoot) => {
        const staged = new ProfileService({ rootDir: stageRoot, keyDerivation: testDerivation() });
        vi.spyOn(staged, 'recover').mockImplementation((...args) => {
          recoverCalls.push(args);
          return Promise.reject(
            new Error('Der persistierende Recovery-Pfad darf nicht ausgeführt werden.'),
          );
        });
        return staged;
      },
    });
    const backup = await service.createBackup();
    if (recoveryKey === null) throw new Error('Recovery-Key fehlt im Testfixture');

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'recovery', value: recoveryKey },
      }),
    ).resolves.toMatchObject({ semanticallyVerified: true, vaultCount: 1 });
    expect(recoverCalls).toEqual([]);
    expect(await readdir(dryRunRoot)).toEqual([]);
  });

  it('verwirft einen kryptografisch gueltigen, aber semantisch inkonsistenten Stand', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-semantic-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const sourcePath = path.join(workspace, 'attachment-source.bin');
    const { profile, vaults } = await fixture(root);
    const vault = await vaults.createVault('Semantik-Tests', '#EC4899');
    await writeFile(sourcePath, Buffer.from('synthetischer-attachment-inhalt'));
    await new AttachmentService({ rootDir: root, vaultService: vaults }).encryptFile({
      vaultId: vault.id,
      sourcePath,
      attachmentId: 'orphaned-test-attachment',
    });
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup();

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'master', value: masterPassword },
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    expect(await readdir(dryRunRoot)).toEqual([]);
  });

  it('raeumt einen beschaedigten oder abgebrochenen Probelauf ohne Rest auf', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-cleanup-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const { profile, vaults } = await fixture(root);
    await vaults.createVault('Cleanup-Tests', '#F59E0B');
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup();
    const tampered = await readFile(backup.path);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    await writeFile(backup.path, tampered);

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'master', value: masterPassword },
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    expect(await readdir(dryRunRoot)).toEqual([]);

    const healthy = await service.createBackup({
      destination: path.join(workspace, 'healthy.vaulta-backup'),
    });
    const controller = new AbortController();
    await expect(
      service.dryRunBackup({
        backupPath: healthy.path,
        credential: { type: 'master', value: masterPassword },
        signal: controller.signal,
        onProgress: (progress) => {
          if (progress.phase === 'semantisch-pruefen') controller.abort();
        },
      }),
    ).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(await readdir(dryRunRoot)).toEqual([]);
  });

  it('verweigert einen temporären Probelauf im aktiven Profilordner', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-path-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const { profile, vaults } = await fixture(root);
    await vaults.createVault('Pfadtests', '#14B8A6');
    const service = backupService(root, profile, root);
    const backup = await service.createBackup({
      destination: path.join(workspace, 'test.vaulta-backup'),
    });

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'master', value: masterPassword },
      }),
    ).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
  });

  it('verweigert auch einen Junction- oder Symlink-Alias zum aktiven Profil vor dem Anlegen', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-alias-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const alias = path.join(workspace, 'profile-alias');
    const { profile, vaults } = await fixture(root);
    await vaults.createVault('Alias-Tests', '#14B8A6');
    try {
      await symlink(root, alias, process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EPERM') return;
      throw error;
    }
    const service = backupService(root, profile, path.join(alias, 'staging'));
    const backup = await service.createBackup({
      destination: path.join(workspace, 'test.vaulta-backup'),
    });

    await expect(
      service.dryRunBackup({
        backupPath: backup.path,
        credential: { type: 'master', value: masterPassword },
      }),
    ).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
    await expect(readdir(path.join(root, 'staging'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('verwirft eine vor der Extraktion eingehängte Junction ohne ausserhalb zu schreiben', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'kryptris-backup-dry-run-stage-link-'));
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const outside = path.join(workspace, 'outside');
    await mkdir(outside);
    const outsideSentinel = path.join(outside, 'sentinel.txt');
    await writeFile(outsideSentinel, 'unveraendert');
    const { profile, vaults } = await fixture(root);
    await vaults.createVault('Staging-Link-Tests', '#0EA5E9');
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup({
      destination: path.join(workspace, 'stage-link.vaulta-backup'),
    });

    let injected = false;
    let linkUnavailable = false;
    const run = service.dryRunBackup({
      backupPath: backup.path,
      credential: { type: 'master', value: masterPassword },
      onProgress: (progress) => {
        if (progress.phase !== 'entschluesseln' || injected || linkUnavailable) return;
        const stageNames = readdirSync(dryRunRoot).filter((name) =>
          name.startsWith('kryptris-restore-dry-run-'),
        );
        if (stageNames.length !== 1)
          throw new Error('Dry-run-Staging wurde nicht eindeutig angelegt.');
        try {
          symlinkSync(
            outside,
            path.join(dryRunRoot, stageNames[0]!, 'vaults'),
            process.platform === 'win32' ? 'junction' : 'dir',
          );
          injected = true;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === 'EPERM') {
            linkUnavailable = true;
            return;
          }
          throw error;
        }
      },
    });

    let failure: unknown = null;
    try {
      await run;
    } catch (error) {
      failure = error;
    }
    if (linkUnavailable) {
      expect(failure).toBeNull();
      return;
    }
    expect(failure).toMatchObject({ code: 'UNSAFE_PATH' });
    expect(injected).toBe(true);
    await expect(readFile(outsideSentinel, 'utf8')).resolves.toBe('unveraendert');
    expect(await readdir(outside)).toEqual(['sentinel.txt']);
    expect(await readdir(dryRunRoot)).toEqual([]);
  });

  it('verwirft eine nach der Extraktion eingehängte Junction vor der Recovery-Semantik', async () => {
    const workspace = await mkdtemp(
      path.join(os.tmpdir(), 'kryptris-backup-dry-run-late-stage-link-'),
    );
    roots.push(workspace);
    const root = path.join(workspace, 'profile');
    const dryRunRoot = path.join(workspace, 'temporary-probes');
    const outside = path.join(workspace, 'outside');
    await mkdir(outside);
    const outsideSentinel = path.join(outside, 'sentinel.txt');
    await writeFile(outsideSentinel, 'unveraendert');
    const { profile, vaults, recoveryKey } = await fixture(root, true);
    await vaults.createVault('Spaete-Staging-Link-Tests', '#EA580C');
    const service = backupService(root, profile, dryRunRoot);
    const backup = await service.createBackup({
      destination: path.join(workspace, 'late-stage-link.vaulta-backup'),
    });
    if (recoveryKey === null) throw new Error('Recovery-Key fehlt im Testfixture');

    let injected = false;
    let linkUnavailable = false;
    const run = service.dryRunBackup({
      backupPath: backup.path,
      credential: { type: 'recovery', value: recoveryKey },
      onProgress: (progress) => {
        if (progress.phase !== 'semantisch-pruefen' || injected || linkUnavailable) return;
        const stageNames = readdirSync(dryRunRoot).filter((name) =>
          name.startsWith('kryptris-restore-dry-run-'),
        );
        if (stageNames.length !== 1)
          throw new Error('Dry-run-Staging wurde nicht eindeutig angelegt.');
        const vaultsDirectory = path.join(dryRunRoot, stageNames[0]!, 'vaults');
        rmSync(vaultsDirectory, { recursive: true, force: true });
        try {
          symlinkSync(outside, vaultsDirectory, process.platform === 'win32' ? 'junction' : 'dir');
          injected = true;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === 'EPERM') {
            linkUnavailable = true;
            return;
          }
          throw error;
        }
      },
    });

    let failure: unknown = null;
    try {
      await run;
    } catch (error) {
      failure = error;
    }
    if (linkUnavailable) {
      expect(failure).toBeNull();
      return;
    }
    expect(failure).toMatchObject({ code: 'UNSAFE_PATH' });
    expect(injected).toBe(true);
    await expect(readFile(outsideSentinel, 'utf8')).resolves.toBe('unveraendert');
    expect(await readdir(outside)).toEqual(['sentinel.txt']);
    expect(await readdir(dryRunRoot)).toEqual([]);
  });
});
