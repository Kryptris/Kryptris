import {
  access,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { VaultaError } from '../../src/shared/errors';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const NOW = new Date('2026-07-21T12:00:00.000Z');
const roots: string[] = [];

interface Fixture {
  attachments: AttachmentService;
  sourceVaultId: string;
  targetVaultId: string;
}

async function fixture(root: string): Promise<Fixture> {
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const setup = await profile.beginSetup('Attachment-Testpasswort!123', false);
  await profile.completeSetup(setup.pendingId, {});
  const vaults = new VaultService({ rootDir: root, profileService: profile });
  const source = await vaults.createVault('Quelle', '#2DD4BF');
  const target = await vaults.createVault('Ziel', '#8B5CF6');
  return {
    attachments: new AttachmentService({
      rootDir: root,
      vaultService: vaults,
      chunkSize: 4096,
      now: () => NOW,
    }),
    sourceVaultId: source.id,
    targetVaultId: target.id,
  };
}

async function createSource(
  root: string,
  fixtureValue: Fixture,
  plaintext: Buffer,
  attachmentId = 'source-attachment',
): Promise<string> {
  const sourcePath = path.join(root, 'source.bin');
  await writeFile(sourcePath, plaintext);
  await fixtureValue.attachments.encryptFile({
    vaultId: fixtureValue.sourceVaultId,
    attachmentId,
    sourcePath,
    name: 'Dokument.bin',
    mediaType: 'application/octet-stream',
  });
  return attachmentId;
}

async function expectMissing(filePath: string): Promise<void> {
  await expect(access(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Attachment-Neuverschlüsselung für Cross-Vault-Transaktionen', () => {
  it('bindet Größe und Hash der Vault-Metadaten an den authentifizierten Footer', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-metadata-'));
    roots.push(root);
    const current = await fixture(root);
    const sourcePath = path.join(root, 'metadata-source.bin');
    await writeFile(sourcePath, Buffer.from('authentifizierter Inhalt'));
    const metadata = await current.attachments.encryptFile({
      vaultId: current.sourceVaultId,
      attachmentId: 'metadata-attachment',
      sourcePath,
      name: 'Inhalt.bin',
      mediaType: 'application/octet-stream',
    });

    await expect(
      current.attachments.verifyMetadata(current.sourceVaultId, metadata),
    ).resolves.toBeUndefined();
    await expect(
      current.attachments.readAuthenticatedMetadata(current.sourceVaultId, metadata.id),
    ).resolves.toEqual({ size: metadata.size, sha256: metadata.sha256 });
    await expect(current.attachments.listStoredAttachmentReferences()).resolves.toEqual([
      { vaultId: current.sourceVaultId, attachmentId: metadata.id },
    ]);
    await expect(
      current.attachments.verifyMetadata(current.sourceVaultId, {
        ...metadata,
        size: metadata.size + 1,
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    await expect(
      current.attachments.verifyMetadata(current.sourceVaultId, {
        ...metadata,
        sha256: '0'.repeat(64),
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
  });

  it('streamt einen authentifizierten Anhang unter einem neuen Tresorschlüssel in eine verifizierte Staging-Datei', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-reencrypt-'));
    roots.push(root);
    const current = await fixture(root);
    const plaintext = Buffer.from('cross-vault-secret-'.repeat(1_500));
    const sourceAttachmentId = await createSource(root, current, plaintext);
    const targetAttachmentId = 'target-attachment';
    const stagingDir = path.join(root, 'transaction-stage');
    const stagingPath = path.join(stagingDir, `${targetAttachmentId}.vatt`);
    await mkdir(stagingDir);

    const metadata = await current.attachments.reencryptToStaging({
      sourceVaultId: current.sourceVaultId,
      sourceAttachmentId,
      targetVaultId: current.targetVaultId,
      targetAttachmentId,
      stagingPath,
      name: 'Dokument.bin',
      mediaType: 'application/octet-stream',
      assertAuthorized: () => undefined,
    });

    expect(metadata).toMatchObject({
      id: targetAttachmentId,
      name: 'Dokument.bin',
      mediaType: 'application/octet-stream',
      size: plaintext.length,
      createdAt: NOW.toISOString(),
      previewable: false,
    });
    const sourceEncrypted = await readFile(
      current.attachments.getEncryptedPath(current.sourceVaultId, sourceAttachmentId),
    );
    const stagedEncrypted = await readFile(stagingPath);
    expect(stagedEncrypted.equals(sourceEncrypted)).toBe(false);
    expect(stagedEncrypted.includes(plaintext.subarray(0, 64))).toBe(false);

    const committedPath = current.attachments.getEncryptedPath(
      current.targetVaultId,
      targetAttachmentId,
    );
    await mkdir(path.dirname(committedPath), { recursive: true });
    await rename(stagingPath, committedPath);
    expect(
      (
        await current.attachments.readBuffer(
          current.targetVaultId,
          targetAttachmentId,
          plaintext.length,
        )
      ).equals(plaintext),
    ).toBe(true);
  });

  it('verwirft eine spät manipulierte Quelle und entfernt den unvollständigen Staging-Output', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-tamper-'));
    roots.push(root);
    const current = await fixture(root);
    const plaintext = Buffer.from('tamper-after-streaming-'.repeat(1_500));
    const sourceAttachmentId = await createSource(root, current, plaintext);
    const sourcePath = current.attachments.getEncryptedPath(
      current.sourceVaultId,
      sourceAttachmentId,
    );
    const sourceBytes = await readFile(sourcePath);
    const sourceHandle = await open(sourcePath, 'r+');
    try {
      const changed = Buffer.from([sourceBytes[sourceBytes.length - 1]! ^ 1]);
      await sourceHandle.write(changed, 0, changed.length, sourceBytes.length - 1);
    } finally {
      await sourceHandle.close();
    }
    const stagingDir = path.join(root, 'transaction-stage');
    const stagingPath = path.join(stagingDir, 'tampered-target.vatt');
    await mkdir(stagingDir);

    await expect(
      current.attachments.reencryptToStaging({
        sourceVaultId: current.sourceVaultId,
        sourceAttachmentId,
        targetVaultId: current.targetVaultId,
        targetAttachmentId: 'tampered-target',
        stagingPath,
        name: 'Dokument.bin',
        mediaType: 'application/octet-stream',
        assertAuthorized: () => undefined,
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    await expectMissing(stagingPath);
    await expect(readdir(stagingDir)).resolves.toEqual([]);
  });

  it('bricht während des Chunk-Streams ab und hinterlässt keine Staging-Datei', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-cancel-'));
    roots.push(root);
    const current = await fixture(root);
    const plaintext = Buffer.from('cancel-stream-'.repeat(2_000));
    const sourceAttachmentId = await createSource(root, current, plaintext);
    const stagingDir = path.join(root, 'transaction-stage');
    const stagingPath = path.join(stagingDir, 'cancelled-target.vatt');
    await mkdir(stagingDir);
    let authorizationChecks = 0;

    await expect(
      current.attachments.reencryptToStaging({
        sourceVaultId: current.sourceVaultId,
        sourceAttachmentId,
        targetVaultId: current.targetVaultId,
        targetAttachmentId: 'cancelled-target',
        stagingPath,
        name: 'Dokument.bin',
        mediaType: 'application/octet-stream',
        assertAuthorized: () => {
          authorizationChecks += 1;
          if (authorizationChecks === 10) {
            throw new VaultaError('CANCELLED', 'Die Neuverschlüsselung wurde abgebrochen.');
          }
        },
      }),
    ).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(authorizationChecks).toBe(10);
    await expectMissing(stagingPath);
    await expect(readdir(stagingDir)).resolves.toEqual([]);
    expect(
      (
        await current.attachments.readBuffer(
          current.sourceVaultId,
          sourceAttachmentId,
          plaintext.length,
        )
      ).equals(plaintext),
    ).toBe(true);
  });

  it('überschreibt keinen bereits vorhandenen Staging-Pfad', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-exclusive-'));
    roots.push(root);
    const current = await fixture(root);
    const sourceAttachmentId = await createSource(root, current, Buffer.from('secret'));
    const stagingDir = path.join(root, 'transaction-stage');
    const stagingPath = path.join(stagingDir, 'existing-target.vatt');
    await mkdir(stagingDir);
    await writeFile(stagingPath, 'bleibt unverändert');

    await expect(
      current.attachments.reencryptToStaging({
        sourceVaultId: current.sourceVaultId,
        sourceAttachmentId,
        targetVaultId: current.targetVaultId,
        targetAttachmentId: 'existing-target',
        stagingPath,
        name: 'Dokument.bin',
        mediaType: 'application/octet-stream',
        assertAuthorized: () => undefined,
      }),
    ).rejects.toMatchObject({ code: 'EEXIST' });
    await expect(readFile(stagingPath, 'utf8')).resolves.toBe('bleibt unverändert');
  });
});
