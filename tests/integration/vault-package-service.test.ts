import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { ProfileService } from '../../src/main/services/profile-service';
import {
  VAULT_PACKAGE_EXTENSION,
  VaultPackageService,
} from '../../src/main/services/vault-package-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const NOW = new Date('2026-08-09T10:00:00.000Z');
const roots: string[] = [];

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

async function fixture(root: string): Promise<{
  vaults: VaultService;
  attachments: AttachmentService;
  packages: VaultPackageService;
}> {
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: testDerivation(),
    now: () => NOW,
  });
  const pending = await profile.beginSetup('Paket-Masterpasswort!123', false);
  await profile.completeSetup(pending.pendingId, {});
  const vaults = new VaultService({ rootDir: root, profileService: profile, now: () => NOW });
  const attachments = new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4096,
    now: () => NOW,
  });
  return {
    vaults,
    attachments,
    packages: new VaultPackageService({
      vaultService: vaults,
      attachmentService: attachments,
      keyDerivation: testDerivation(),
      now: () => NOW,
    }),
  };
}

async function createVaultWithAttachment(
  root: string,
  value: Awaited<ReturnType<typeof fixture>>,
): Promise<{ vaultId: string; attachmentContents: Buffer }> {
  const vault = await value.vaults.createVault('Reiseunterlagen', '#2DD4BF');
  const entry = await value.vaults.createEntry(vault.id, {
    title: 'Buchung',
    folderId: null,
    tags: ['reise'],
    favorite: false,
    note: 'Private Reiseinformation',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: 'reise@example.invalid',
        password: 'Paket-Geheimnis-123!',
        websites: ['https://reisen.example.invalid'],
        appNames: [],
      },
    },
  });
  const attachmentContents = Buffer.from('vertraulicher Anhang fuer den Pakettest');
  const attachmentPath = path.join(root, 'attachment-source.txt');
  await writeFile(attachmentPath, attachmentContents);
  const attachment = await value.attachments.encryptFile({
    vaultId: vault.id,
    attachmentId: 'reise-anhang',
    sourcePath: attachmentPath,
    name: 'reiseplan.txt',
    mediaType: 'text/plain',
  });
  const document = await value.vaults.readVault(vault.id);
  const indexed = document.entries.find((candidate) => candidate.id === entry.id);
  if (indexed === undefined) throw new Error('Eintrag fehlt');
  indexed.attachments = [attachment];
  await value.vaults.replaceVault(document);
  return { vaultId: vault.id, attachmentContents };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Portables verschluesseltes Tresor-Paket', () => {
  it('exportiert unabhaengig verschluesselt, prueft vollstaendig und remappt jede technische ID', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-vault-package-'));
    roots.push(root);
    const current = await fixture(root);
    const source = await createVaultWithAttachment(root, current);
    const packagePath = path.join(root, `reise${VAULT_PACKAGE_EXTENSION}`);

    const exported = await current.packages.exportPackage({
      vaultId: source.vaultId,
      exportPassword: 'Eigenes Exportpasswort!123',
      destination: packagePath,
      includeAttachments: true,
    });
    expect(exported).toMatchObject({
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
    });
    const packageBytes = await readFile(packagePath);
    expect(packageBytes.toString('utf8')).not.toContain('Paket-Geheimnis-123!');
    expect(packageBytes.toString('utf8')).not.toContain('reiseplan.txt');

    await expect(
      current.packages.inspectPackage({
        packagePath,
        exportPassword: 'falsches Exportpasswort',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    await expect(
      current.packages.inspectPackage({
        packagePath,
        exportPassword: 'Eigenes Exportpasswort!123',
        existingVaultNames: ['Reiseunterlagen'],
      }),
    ).resolves.toEqual({
      createdAt: NOW.toISOString(),
      vaultName: 'Reiseunterlagen',
      color: '#2DD4BF',
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
      nameConflict: true,
    });

    const targetVaultId = randomUUID();
    const plan = await current.packages.prepareImport({
      packagePath,
      exportPassword: 'Eigenes Exportpasswort!123',
      targetVaultId,
      targetVaultName: 'Reiseunterlagen Kopie',
      existingVaultNames: ['Reiseunterlagen'],
    });
    try {
      expect(plan.document.id).toBe(targetVaultId);
      expect(plan.document.entries).toHaveLength(1);
      expect(plan.document.entries[0]).toMatchObject({ vaultId: targetVaultId });
      expect(plan.document.entries[0]?.id).not.toBe(
        (await current.vaults.readVault(source.vaultId)).entries[0]?.id,
      );
      expect(plan.attachments).toHaveLength(1);
      expect(plan.attachments[0]).toMatchObject({
        name: 'reiseplan.txt',
        mediaType: 'text/plain',
        size: source.attachmentContents.length,
      });
      expect(plan.attachments[0]?.attachmentId).not.toBe('reise-anhang');
      expect(plan.attachments[0]?.contents.equals(source.attachmentContents)).toBe(true);
      expect(plan.document.entries[0]?.attachments[0]?.id).toBe(plan.attachments[0]?.attachmentId);
    } finally {
      plan.dispose();
    }
    expect(
      plan.attachments[0]?.contents.equals(Buffer.alloc(source.attachmentContents.length)),
    ).toBe(true);
    expect(() => plan.assertUsable()).toThrowError(/verworfen/u);
  });

  it('entfernt Anhangsreferenzen beim Export ohne Anhaenge und behaelt keine Klartextdatei zurueck', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-vault-package-no-attachments-'));
    roots.push(root);
    const current = await fixture(root);
    const source = await createVaultWithAttachment(root, current);
    const packagePath = path.join(root, `ohne-anhaenge${VAULT_PACKAGE_EXTENSION}`);

    await current.packages.exportPackage({
      vaultId: source.vaultId,
      exportPassword: 'Eigenes Exportpasswort!123',
      destination: packagePath,
      includeAttachments: false,
    });
    const plan = await current.packages.prepareImport({
      packagePath,
      exportPassword: 'Eigenes Exportpasswort!123',
      targetVaultId: randomUUID(),
      targetVaultName: 'Ohne Anhaenge',
    });
    try {
      expect(plan.attachments).toEqual([]);
      expect(plan.document.entries[0]?.attachments).toEqual([]);
      expect((await readFile(packagePath)).toString('utf8')).not.toContain(
        'vertraulicher Anhang fuer den Pakettest',
      );
    } finally {
      plan.dispose();
    }
  });

  it('verwirft manipulierte oder zukuenftige Pakete vor einer Importplanung', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-vault-package-corrupt-'));
    roots.push(root);
    const current = await fixture(root);
    const source = await createVaultWithAttachment(root, current);
    const packagePath = path.join(root, `manipuliert${VAULT_PACKAGE_EXTENSION}`);
    await current.packages.exportPackage({
      vaultId: source.vaultId,
      exportPassword: 'Eigenes Exportpasswort!123',
      destination: packagePath,
      includeAttachments: true,
    });

    const tampered = await readFile(packagePath);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    await writeFile(packagePath, tampered);
    await expect(
      current.packages.prepareImport({
        packagePath,
        exportPassword: 'Eigenes Exportpasswort!123',
        targetVaultId: randomUUID(),
        targetVaultName: 'Unveraendert',
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });

    const futurePath = path.join(root, `zukunft${VAULT_PACKAGE_EXTENSION}`);
    await current.packages.exportPackage({
      vaultId: source.vaultId,
      exportPassword: 'Eigenes Exportpasswort!123',
      destination: futurePath,
      includeAttachments: false,
    });
    const future = await readFile(futurePath);
    const headerLength = future.readUInt32BE(8);
    const headerStart = 12;
    const header = JSON.parse(
      future.subarray(headerStart, headerStart + headerLength).toString('utf8'),
    ) as {
      version: number;
    };
    header.version = 2;
    const replacement = Buffer.from(JSON.stringify(header), 'utf8');
    expect(replacement).toHaveLength(headerLength);
    replacement.copy(future, headerStart);
    await writeFile(futurePath, future);
    await expect(
      current.packages.inspectPackage({
        packagePath: futurePath,
        exportPassword: 'Eigenes Exportpasswort!123',
      }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_FORMAT' });
  });

  it('schuetzt den Zielnamen vor unbeabsichtigten Konflikten', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-vault-package-conflict-'));
    roots.push(root);
    const current = await fixture(root);
    const source = await createVaultWithAttachment(root, current);
    const packagePath = path.join(root, `konflikt${VAULT_PACKAGE_EXTENSION}`);
    await current.packages.exportPackage({
      vaultId: source.vaultId,
      exportPassword: 'Eigenes Exportpasswort!123',
      destination: packagePath,
      includeAttachments: false,
    });

    await expect(
      current.packages.prepareImport({
        packagePath,
        exportPassword: 'Eigenes Exportpasswort!123',
        targetVaultId: randomUUID(),
        targetVaultName: 'Reiseunterlagen',
        existingVaultNames: [' reiseunterlagen '],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('laesst ein bestaetigtes vorhandenes Paket bei einer fehlgeschlagenen Vollpruefung unveraendert', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-vault-package-atomic-'));
    roots.push(root);
    const current = await fixture(root);
    const source = await createVaultWithAttachment(root, current);
    const packagePath = path.join(root, `bestaetigt${VAULT_PACKAGE_EXTENSION}`);
    const confirmed = Buffer.from('BISHERIGES-VERIFIZIERTES-PAKET', 'utf8');
    await writeFile(packagePath, confirmed);
    const failing = new VaultPackageService({
      vaultService: current.vaults,
      attachmentService: current.attachments,
      keyDerivation: testDerivation(),
      atomicWriter: new AtomicFileWriter({
        afterTempSynced: async (temporaryPath) => {
          await writeFile(temporaryPath, 'manipuliertes-temporaeres-paket');
        },
      }),
      now: () => NOW,
    });

    await expect(
      failing.exportPackage({
        vaultId: source.vaultId,
        exportPassword: 'Eigenes Exportpasswort!123',
        destination: packagePath,
        includeAttachments: true,
        replaceExisting: true,
      }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_FORMAT' });
    await expect(readFile(packagePath)).resolves.toEqual(confirmed);
  });
});
