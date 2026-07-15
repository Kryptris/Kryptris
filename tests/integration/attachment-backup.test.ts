import { mkdtemp, open, readFile, readdir, rm, truncate, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

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

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

async function fixture(root: string): Promise<{
  profile: ProfileService;
  vaults: VaultService;
  attachments: AttachmentService;
  recoveryKey: string;
}> {
  const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
  const pending = await profile.beginSetup('Backup Master-Passwort!123', true);
  if (pending.recovery === null) throw new Error('Recovery setup missing');
  await profile.completeSetup(
    pending.pendingId,
    Object.fromEntries(
      pending.recovery.confirmationIndexes.map((index) => [
        String(index),
        pending.recovery?.groups[index],
      ]),
    ) as Record<string, string>,
  );
  const vaults = new VaultService({ rootDir: root, profileService: profile });
  const attachments = new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4096,
  });
  return {
    profile,
    vaults,
    attachments,
    recoveryKey: pending.recovery.displayKey,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Gestreamte Anhänge und native Sicherungen', () => {
  it('erzwingt das 100-MiB-Standardlimit und ein konfiguriertes Limit vor dem Schreiben', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-attachment-limit-'));
    roots.push(root);
    const { vaults, attachments } = await fixture(root);
    const vault = await vaults.createVault('Dateilimits', '#2DD4BF');
    const sparseSource = path.join(root, 'sparse-over-default.bin');
    await writeFile(sparseSource, '');
    await truncate(sparseSource, 100 * 1024 * 1024 + 1);

    await expect(
      attachments.encryptFile({
        vaultId: vault.id,
        attachmentId: 'default-limit-overflow',
        sourcePath: sparseSource,
      }),
    ).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
    await expect(
      readFile(attachments.getEncryptedPath(vault.id, 'default-limit-overflow')),
    ).rejects.toMatchObject({ code: 'ENOENT' });

    const exactSource = path.join(root, 'configured-exact.bin');
    await writeFile(exactSource, Buffer.alloc(4_096, 0x5a));
    await expect(
      attachments.encryptFile({
        vaultId: vault.id,
        attachmentId: 'configured-limit-exact',
        sourcePath: exactSource,
        maxBytes: 4_096,
      }),
    ).resolves.toMatchObject({ size: 4_096 });

    const configuredOverflow = path.join(root, 'configured-over.bin');
    await writeFile(configuredOverflow, '');
    await truncate(configuredOverflow, 4_097);
    await expect(
      attachments.encryptFile({
        vaultId: vault.id,
        attachmentId: 'configured-limit-overflow',
        sourcePath: configuredOverflow,
        maxBytes: 4_096,
      }),
    ).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
  });

  it('erkennt Änderung und Kürzung gechunkter Anhänge', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-attachment-'));
    roots.push(root);
    const { vaults, attachments } = await fixture(root);
    const vault = await vaults.createVault('Dateien', '#2DD4BF');
    const source = path.join(root, 'source.bin');
    const plaintext = Buffer.from('chunk-test-'.repeat(2_000));
    await writeFile(source, plaintext);
    const metadata = await attachments.encryptFile({ vaultId: vault.id, sourcePath: source });
    expect(
      (await attachments.readBuffer(vault.id, metadata.id, plaintext.length)).equals(plaintext),
    ).toBe(true);

    const encryptedPath = attachments.getEncryptedPath(vault.id, metadata.id);
    const encrypted = await readFile(encryptedPath);
    const handle = await open(encryptedPath, 'r+');
    try {
      const changed = Buffer.from([encrypted[Math.floor(encrypted.length / 2)]! ^ 1]);
      await handle.write(changed, 0, 1, Math.floor(encrypted.length / 2));
    } finally {
      await handle.close();
    }
    await expect(attachments.verify(vault.id, metadata.id)).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });
    const failedExport = path.join(root, 'entschluesselter-canary.bin');
    await expect(
      attachments.decryptToFile(vault.id, metadata.id, failedExport),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    await expect(readFile(failedExport)).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await readdir(root)).some((name) => name.endsWith('.tmp'))).toBe(false);

    const second = await attachments.encryptFile({
      vaultId: vault.id,
      sourcePath: source,
      attachmentId: 'truncated-file',
    });
    const secondPath = attachments.getEncryptedPath(vault.id, second.id);
    const secondSize = (await readFile(secondPath)).length;
    await truncate(secondPath, secondSize - 20);
    await expect(attachments.verify(vault.id, second.id)).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });
  });

  it('verwirft verwaiste oder fehlende Anhangsdateien als unbestaetigten Stand', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-attachment-consistency-'));
    roots.push(root);
    const { vaults, attachments } = await fixture(root);
    const vault = await vaults.createVault('Konsistenz', '#8B5CF6');
    const source = path.join(root, 'orphan.txt');
    await writeFile(source, 'verschluesselter Anhang ohne Referenz');
    const orphan = await attachments.encryptFile({
      vaultId: vault.id,
      sourcePath: source,
      mediaType: 'text/plain',
    });

    await expect(attachments.validateStorageConsistency([])).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    await attachments.remove(vault.id, orphan.id);
    await expect(
      attachments.validateStorageConsistency([{ vaultId: vault.id, attachmentId: orphan.id }]),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('erstellt ein verschlüsseltes Streaming-Backup und stellt es erst nach Vollprüfung wieder her', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-source-'));
    const target = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-target-parent-'));
    const restoredRoot = path.join(target, 'restored');
    roots.push(root, target);
    const { profile, vaults, attachments, recoveryKey } = await fixture(root);
    const vault = await vaults.createVault('Wiederhergestellt', '#8B5CF6');
    const source = path.join(root, 'document.txt');
    await writeFile(source, 'hoch vertraulicher Anhang');
    const attachment = await attachments.encryptFile({
      vaultId: vault.id,
      sourcePath: source,
      mediaType: 'text/plain',
    });
    const audit = new AuditService({ rootDir: root, profileService: profile });
    await audit.record({ type: 'backup-created', vaultId: vault.id });
    const backups = new BackupService({ rootDir: root, profileService: profile });
    const backup = await backups.createBackup();
    const backupBytes = await readFile(backup.path, 'utf8');
    expect(backupBytes).not.toContain('Wiederhergestellt');
    expect(backupBytes).not.toContain('hoch vertraulicher Anhang');
    expect(backupBytes).toContain('vaulta-backup-profile-access');
    expect(backupBytes).not.toContain('protectedMetadata');
    expect(backupBytes).not.toContain('publicFactorData');
    expect(backupBytes).not.toContain('additionalKeyWraps');
    expect(
      await backups.inspectBackup(backup.path, { type: 'recovery', value: recoveryKey }),
    ).toMatchObject({ vaultCount: 1, attachmentCount: 1 });

    const restored = await backups.restoreBackup({
      backupPath: backup.path,
      credential: { type: 'master', value: 'Backup Master-Passwort!123' },
      targetRoot: restoredRoot,
    });
    expect(restored.requiresApplicationReload).toBe(true);
    const restoredProfile = new ProfileService({
      rootDir: restoredRoot,
      keyDerivation: testDerivation(),
    });
    await restoredProfile.unlock('Backup Master-Passwort!123');
    const restoredVaults = new VaultService({
      rootDir: restoredRoot,
      profileService: restoredProfile,
    });
    expect((await restoredVaults.readVault(vault.id)).name).toBe('Wiederhergestellt');
    const restoredAttachments = new AttachmentService({
      rootDir: restoredRoot,
      vaultService: restoredVaults,
      chunkSize: 4096,
    });
    expect((await restoredAttachments.readBuffer(vault.id, attachment.id)).toString('utf8')).toBe(
      'hoch vertraulicher Anhang',
    );
  });

  it('verwirft ein manipuliertes Backup vor jeder Zieländerung', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-tamper-'));
    const target = await mkdtemp(path.join(os.tmpdir(), 'vaulta-backup-untouched-'));
    roots.push(root, target);
    const { profile, vaults } = await fixture(root);
    await vaults.createVault('Privat', '#2DD4BF');
    const backups = new BackupService({ rootDir: root, profileService: profile });
    const backup = await backups.createBackup();
    const bytes = await readFile(backup.path);
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    await writeFile(backup.path, bytes);
    await writeFile(path.join(target, 'bleibt.txt'), 'unverändert');
    await expect(
      backups.restoreBackup({
        backupPath: backup.path,
        credential: { type: 'master', value: 'Backup Master-Passwort!123' },
        targetRoot: target,
        replaceExisting: true,
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    expect(await readFile(path.join(target, 'bleibt.txt'), 'utf8')).toBe('unverändert');
  });
});
