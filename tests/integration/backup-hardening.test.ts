import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { BackupService } from '../../src/main/services/backup-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const roots: string[] = [];

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

async function createProfile(root: string): Promise<ProfileService> {
  await mkdir(root, { recursive: true });
  const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
  const pending = await profile.beginSetup('Backup Master-Passwort!123', false);
  await profile.completeSetup(pending.pendingId, {});
  return profile;
}

async function exists(candidate: string): Promise<boolean> {
  return access(candidate).then(
    () => true,
    () => false,
  );
}

async function writeRestoreCommitMarker(root: string, targetRoot: string): Promise<void> {
  await writeFile(
    path.join(root, '.vaulta-restore-committed'),
    JSON.stringify({
      format: 'vaulta-restore-commit',
      backupId: 'test-backup',
      targetRoot,
    }),
  );
}

async function rewriteAutomaticMarker(
  source: string,
  destination: string,
  automatic?: boolean,
): Promise<void> {
  const bytes = await readFile(source);
  const magicLength = 8;
  const headerLengthOffset = magicLength;
  const headerOffset = headerLengthOffset + 4;
  const oldHeaderLength = bytes.readUInt32BE(headerLengthOffset);
  const header = JSON.parse(
    bytes.subarray(headerOffset, headerOffset + oldHeaderLength).toString('utf8'),
  ) as Record<string, unknown>;
  if (automatic === undefined) delete header.automatic;
  else header.automatic = automatic;
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const lengthBytes = Buffer.allocUnsafe(4);
  lengthBytes.writeUInt32BE(headerBytes.length);
  await writeFile(
    destination,
    Buffer.concat([
      bytes.subarray(0, magicLength),
      lengthBytes,
      headerBytes,
      bytes.subarray(headerOffset + oldHeaderLength),
    ]),
  );
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Backup-Rotation und Restore-Recovery', () => {
  it('behält ein bestätigtes Ziel bei einem Verifikationsfehler vollständig bei', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-replace-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    const profile = await createProfile(profileRoot);
    const destination = path.join(workspace, 'bestehend.vaulta-backup');
    const confirmed = Buffer.from('BESTÄTIGTES-BESTEHENDES-BACKUP', 'utf8');
    await writeFile(destination, confirmed);
    const service = new BackupService({
      rootDir: profileRoot,
      profileService: profile,
      atomicWriter: new AtomicFileWriter({
        afterTempSynced: async (temporaryPath, targetPath) => {
          if (targetPath === destination) await writeFile(temporaryPath, 'beschädigt');
        },
      }),
    });

    await expect(
      service.createBackup({ destination, replaceExisting: true }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    await expect(readFile(destination)).resolves.toEqual(confirmed);
  });

  it('committet kein Backup bei einer Live-Aenderung waehrend der semantischen Pruefung', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-consistency-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    const profile = await createProfile(profileRoot);
    const destination = path.join(workspace, 'bestehend.vaulta-backup');
    const confirmed = Buffer.from('LETZTES-BESTAETIGTES-BACKUP', 'utf8');
    await writeFile(destination, confirmed);
    const service = new BackupService({ rootDir: profileRoot, profileService: profile });
    let semanticValidationRan = false;

    await expect(
      service.createBackup({
        destination,
        replaceExisting: true,
        validateLiveState: async () => {
          semanticValidationRan = true;
          await profile.setProtectedMetadata('backup-consistency-test', { changed: true });
        },
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });

    expect(semanticValidationRan).toBe(true);
    await expect(readFile(destination)).resolves.toEqual(confirmed);
  });

  it('rotiert nur authentifizierte automatische Backups desselben Profils', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-rotation-'));
    roots.push(workspace);
    const backupFolder = path.join(workspace, 'backups');
    const ownProfile = await createProfile(path.join(workspace, 'own-profile'));
    const foreignProfile = await createProfile(path.join(workspace, 'foreign-profile'));
    const manualPath = path.join(backupFolder, 'manual.vaulta-backup');
    const legacyPath = path.join(backupFolder, 'legacy.vaulta-backup');
    const forgedPath = path.join(backupFolder, 'forged-automatic.vaulta-backup');
    const foreignPath = path.join(backupFolder, 'foreign.vaulta-backup');
    const firstAutomaticPath = path.join(backupFolder, 'automatic-old.vaulta-backup');
    const secondAutomaticPath = path.join(backupFolder, 'automatic-new.vaulta-backup');
    const rotation = { daily: 1, weekly: 0, monthly: 0 };

    const manualService = new BackupService({
      rootDir: path.join(workspace, 'own-profile'),
      profileService: ownProfile,
      now: () => new Date('2026-07-14T08:00:00.000Z'),
    });
    const manual = await manualService.createBackup({ destination: manualPath });
    expect(manual.automatic).toBe(false);
    await rewriteAutomaticMarker(manualPath, legacyPath);
    await rewriteAutomaticMarker(manualPath, forgedPath, true);

    const foreignService = new BackupService({
      rootDir: path.join(workspace, 'foreign-profile'),
      profileService: foreignProfile,
      now: () => new Date('2026-07-14T08:30:00.000Z'),
    });
    await foreignService.createBackup({
      destination: foreignPath,
      automatic: true,
      rotation,
    });

    const firstService = new BackupService({
      rootDir: path.join(workspace, 'own-profile'),
      profileService: ownProfile,
      now: () => new Date('2026-07-14T09:00:00.000Z'),
    });
    await firstService.createBackup({
      destination: firstAutomaticPath,
      automatic: true,
      rotation,
    });
    const secondService = new BackupService({
      rootDir: path.join(workspace, 'own-profile'),
      profileService: ownProfile,
      now: () => new Date('2026-07-14T10:00:00.000Z'),
    });
    const newest = await secondService.createBackup({
      destination: secondAutomaticPath,
      automatic: true,
      rotation,
    });

    expect(newest.automatic).toBe(true);
    expect(
      await secondService.inspectBackup(secondAutomaticPath, {
        type: 'master',
        value: 'Backup Master-Passwort!123',
      }),
    ).toMatchObject({ automatic: true });
    expect(await exists(firstAutomaticPath)).toBe(false);
    expect(await exists(secondAutomaticPath)).toBe(true);
    expect(await exists(manualPath)).toBe(true);
    expect(await exists(legacyPath)).toBe(true);
    expect(await exists(forgedPath)).toBe(true);
    expect(await exists(foreignPath)).toBe(true);
  });

  it('rollt jedes Restore-Absturzfenster idempotent in einen sicheren Zustand', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'vaulta-restore-recovery-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    const profile = await createProfile(profileRoot);
    const service = new BackupService({ rootDir: profileRoot, profileService: profile });

    const beforeSwap = path.join(workspace, 'before-swap');
    const beforeSwapStage = path.join(workspace, '.before-swap.vaulta-restore-stage');
    await mkdir(beforeSwap);
    await mkdir(beforeSwapStage);
    await writeFile(path.join(beforeSwap, 'state.txt'), 'alt');
    await writeFile(path.join(beforeSwapStage, 'state.txt'), 'neu');
    await writeRestoreCommitMarker(beforeSwapStage, beforeSwap);
    expect(await service.recoverInterruptedRestore(beforeSwap)).toBe(true);
    expect(await readFile(path.join(beforeSwap, 'state.txt'), 'utf8')).toBe('alt');
    expect(await exists(beforeSwapStage)).toBe(false);
    expect(await service.recoverInterruptedRestore(beforeSwap)).toBe(false);

    const duringSwap = path.join(workspace, 'during-swap');
    const duringSwapStage = path.join(workspace, '.during-swap.vaulta-restore-stage');
    const duringSwapRollback = path.join(workspace, '.during-swap.vaulta-restore-rollback');
    await mkdir(duringSwapStage);
    await mkdir(duringSwapRollback);
    await writeFile(path.join(duringSwapStage, 'state.txt'), 'neu');
    await writeFile(path.join(duringSwapRollback, 'state.txt'), 'alt');
    await writeRestoreCommitMarker(duringSwapStage, duringSwap);
    expect(await service.recoverInterruptedRestore(duringSwap)).toBe(true);
    expect(await readFile(path.join(duringSwap, 'state.txt'), 'utf8')).toBe('alt');
    expect(await exists(duringSwapStage)).toBe(false);
    expect(await exists(duringSwapRollback)).toBe(false);
    expect(await service.recoverInterruptedRestore(duringSwap)).toBe(false);

    const afterInstall = path.join(workspace, 'after-install');
    const afterInstallRollback = path.join(workspace, '.after-install.vaulta-restore-rollback');
    await mkdir(afterInstall);
    await mkdir(afterInstallRollback);
    await writeFile(path.join(afterInstall, 'state.txt'), 'neu');
    await writeFile(path.join(afterInstallRollback, 'state.txt'), 'alt');
    await writeRestoreCommitMarker(afterInstall, afterInstall);
    expect(await service.recoverInterruptedRestore(afterInstall)).toBe(true);
    expect(await readFile(path.join(afterInstall, 'state.txt'), 'utf8')).toBe('alt');
    expect(await exists(afterInstallRollback)).toBe(false);
    expect(await exists(path.join(afterInstall, '.vaulta-restore-committed'))).toBe(false);
    expect(await service.recoverInterruptedRestore(afterInstall)).toBe(false);

    const validated = path.join(workspace, 'validated');
    const validatedRollback = path.join(workspace, '.validated.vaulta-restore-rollback');
    await mkdir(validated);
    await mkdir(validatedRollback);
    await writeFile(path.join(validated, 'state.txt'), 'authentifiziert-neu');
    await writeFile(path.join(validatedRollback, 'state.txt'), 'alt');
    await writeRestoreCommitMarker(validated, validated);
    let validatedSemantically = false;
    expect(
      await service.finalizeInterruptedRestore(async () => {
        validatedSemantically = true;
        expect(await readFile(path.join(validated, 'state.txt'), 'utf8')).toBe(
          'authentifiziert-neu',
        );
      }, validated),
    ).toBe(true);
    expect(validatedSemantically).toBe(true);
    expect(await readFile(path.join(validated, 'state.txt'), 'utf8')).toBe('authentifiziert-neu');
    expect(await exists(validatedRollback)).toBe(false);
    expect(await exists(path.join(validated, '.vaulta-restore-committed'))).toBe(false);

    const cleanupInterrupted = path.join(workspace, 'cleanup-interrupted');
    const cleanupDiscard = path.join(workspace, '.cleanup-interrupted.vaulta-restore-discard');
    await mkdir(cleanupInterrupted);
    await mkdir(cleanupDiscard);
    await writeFile(path.join(cleanupInterrupted, 'state.txt'), 'authentifiziert-neu');
    await writeFile(path.join(cleanupDiscard, 'state.txt'), 'bestaetigt-alt');
    await writeRestoreCommitMarker(cleanupInterrupted, cleanupInterrupted);
    expect(await service.recoverInterruptedRestore(cleanupInterrupted)).toBe(false);
    expect(await readFile(path.join(cleanupDiscard, 'state.txt'), 'utf8')).toBe('bestaetigt-alt');
    expect(
      await service.finalizeInterruptedRestore(() => Promise.resolve(), cleanupInterrupted),
    ).toBe(true);
    expect(await exists(cleanupDiscard)).toBe(false);

    const rejected = path.join(workspace, 'rejected');
    const rejectedRollback = path.join(workspace, '.rejected.vaulta-restore-rollback');
    await mkdir(rejected);
    await mkdir(rejectedRollback);
    await writeFile(path.join(rejected, 'state.txt'), 'beschaedigt-neu');
    await writeFile(path.join(rejectedRollback, 'state.txt'), 'bestaetigt-alt');
    await writeRestoreCommitMarker(rejected, rejected);
    await expect(
      service.finalizeInterruptedRestore(
        () => Promise.reject(new Error('semantische Validierung fehlgeschlagen')),
        rejected,
      ),
    ).rejects.toThrow('semantische Validierung fehlgeschlagen');
    expect(await readFile(path.join(rejected, 'state.txt'), 'utf8')).toBe('beschaedigt-neu');
    expect(await readFile(path.join(rejectedRollback, 'state.txt'), 'utf8')).toBe('bestaetigt-alt');
    expect(await service.recoverInterruptedRestore(rejected)).toBe(true);
    expect(await readFile(path.join(rejected, 'state.txt'), 'utf8')).toBe('bestaetigt-alt');

    const newTarget = path.join(workspace, 'new-target');
    const newTargetStage = path.join(workspace, '.new-target.vaulta-restore-stage');
    await mkdir(newTargetStage);
    await writeFile(path.join(newTargetStage, 'state.txt'), 'nicht verifiziert');
    await writeRestoreCommitMarker(newTargetStage, newTarget);
    expect(await service.recoverInterruptedRestore(newTarget)).toBe(true);
    expect(await exists(newTarget)).toBe(false);
    expect(await exists(newTargetStage)).toBe(false);
    expect(await service.recoverInterruptedRestore(newTarget)).toBe(false);

    const ambiguousTarget = path.join(workspace, 'ambiguous');
    const ambiguousRollback = path.join(workspace, '.ambiguous.vaulta-restore-rollback');
    await mkdir(ambiguousTarget);
    await mkdir(ambiguousRollback);
    await writeFile(path.join(ambiguousTarget, 'unknown.txt'), 'unverifiziert');
    await writeFile(path.join(ambiguousRollback, 'state.txt'), 'alt');
    await expect(service.recoverInterruptedRestore(ambiguousTarget)).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    expect(await readFile(path.join(ambiguousTarget, 'unknown.txt'), 'utf8')).toBe('unverifiziert');
    expect(await readFile(path.join(ambiguousRollback, 'state.txt'), 'utf8')).toBe('alt');
  });

  it('verweigert manipulierte Restore-Pfade über Symlinks oder Junctions', async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), 'vaulta-restore-link-'));
    roots.push(workspace);
    const profileRoot = path.join(workspace, 'profile');
    const profile = await createProfile(profileRoot);
    const service = new BackupService({ rootDir: profileRoot, profileService: profile });
    const target = path.join(workspace, 'target');
    const outside = path.join(workspace, 'outside');
    const rollback = path.join(workspace, '.target.vaulta-restore-rollback');
    await mkdir(target);
    await mkdir(outside);
    await writeFile(path.join(target, 'state.txt'), 'lokal');
    await writeFile(path.join(outside, 'state.txt'), 'extern');
    try {
      await symlink(outside, rollback, process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EPERM') return;
      throw error;
    }

    await expect(service.recoverInterruptedRestore(target)).rejects.toMatchObject({
      code: 'UNSAFE_PATH',
    });
    expect(await readFile(path.join(target, 'state.txt'), 'utf8')).toBe('lokal');
    expect(await readFile(path.join(outside, 'state.txt'), 'utf8')).toBe('extern');
  });
});
