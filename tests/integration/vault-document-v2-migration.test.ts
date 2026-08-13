import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { EntryInput, VaultDocument, VaultDocumentV1 } from '../../src/shared/models';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import {
  PersistentMigrationService,
  createVaultDocumentEmbeddedMigrationAdapter,
} from '../../src/main/services/persistent-migration-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import { EncryptedContainerCodec } from '../../src/main/storage/encrypted-container';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const MASTER_PASSWORD = 'Migration Master-Passwort!123';
const roots: string[] = [];

describe('eingebettete VaultDocument-V2-Migration', () => {
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });

  it('migriert mehrere Vaults gemeinsam und lässt Anhänge, Faktoren und Fachwerte unverändert', async () => {
    const fixture = await createFixture();
    const first = await fixture.vaults.createVault('Privat', '#14b8a6');
    const second = await fixture.vaults.createVault('Arbeit', '#334155');
    await fixture.vaults.createEntry(first.id, credentialInput('Erster Zugang', 'Secret-A!123'));
    await fixture.vaults.createEntry(second.id, credentialInput('Zweiter Zugang', 'Secret-B!123'));

    const sourcePath = path.join(fixture.root, 'attachment-source.txt');
    await writeFile(sourcePath, Buffer.from('verschlüsselter Anhang ohne Migration', 'utf8'));
    const attachment = await new AttachmentService({
      rootDir: fixture.root,
      vaultService: fixture.vaults,
      chunkSize: 4096,
    }).encryptFile({ vaultId: first.id, sourcePath });
    await fixture.vaults.mutateVault(first.id, (document) => {
      const entry = document.entries[0];
      if (entry === undefined) throw new Error('Fixture-Eintrag fehlt');
      entry.attachments.push(attachment);
    });

    const expectedPublicFactors = await fixture.profile.getPublicFactorData();
    await fixture.profile.commitFactorState({
      namespace: 'factors',
      expectedPublicFactorData: expectedPublicFactors,
      publicFactorData: {
        totpEnabled: true,
        securityKeys: [{ id: 'fixture-key', name: 'Fixture-Key', mode: 'presence' }],
      },
      protectedMetadata: {
        totpSecret: 'JBSWY3DPEHPK3PXP',
        securityKeyCredentialIds: ['fixture-credential'],
      },
    });

    const firstLegacy = await installLegacyDocument(fixture, first.id);
    const secondLegacy = await installLegacyDocument(fixture, second.id);
    const profileBefore = await readFile(path.join(fixture.root, 'profile.json'));
    const attachmentPath = path.join(
      fixture.root,
      'attachments',
      first.id,
      `${attachment.id}.vatt`,
    );
    const attachmentBefore = await readFile(attachmentPath);

    const migrations = migrationService(fixture);
    const result = await migrations.migrate();

    expect(result).toMatchObject({ pendingFiles: 2, migratedFiles: 2 });
    expect(result.backupPath).not.toBeNull();
    expect(await readFile(path.join(fixture.root, 'profile.json'))).toEqual(profileBefore);
    expect(await readFile(attachmentPath)).toEqual(attachmentBefore);
    await expectMigratedDocument(fixture.vaults, firstLegacy.document);
    await expectMigratedDocument(fixture.vaults, secondLegacy.document);

    const backupsBefore = await migrationBackups(fixture.root);
    expect(backupsBefore).toHaveLength(1);
    await expect(migrations.migrate()).resolves.toMatchObject({
      pendingFiles: 0,
      migratedFiles: 0,
      backupPath: null,
    });
    expect(await migrationBackups(fixture.root)).toEqual(backupsBefore);
  });

  it('schreibt ein historisches V2-Zwischenformat mit fehlenden Lebenszyklen atomar neu', async () => {
    const fixture = await createFixture();
    const vault = await fixture.vaults.createVault('Historisch', '#14b8a6');
    const missingLifecycle = await fixture.vaults.createEntry(
      vault.id,
      credentialInput('Historischer Zugang', 'Historisch-A!123'),
    );
    const retainedLifecycle = await fixture.vaults.createEntry(
      vault.id,
      credentialInput('Bereits erweitert', 'Historisch-B!123'),
    );
    const expectedRetainedLifecycle = {
      rotationIntervalDays: 90,
      nextRotationDate: '2030-01-15',
      rotationExcluded: false,
      twoFactorStatus: 'active' as const,
      expiryReminderDate: null,
    };
    await fixture.vaults.mutateVault(vault.id, (document) => {
      const entry = document.entries.find((candidate) => candidate.id === retainedLifecycle.id);
      if (entry === undefined) throw new Error('Erweiterter Fixture-Eintrag fehlt.');
      entry.lifecycle = expectedRetainedLifecycle;
    });
    const historical = await installHistoricalV2Document(fixture, vault.id);

    await expect(
      fixture.vaults.inspectDocumentBytes(vault.id, historical.bytes),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
    await expect(
      fixture.vaults.inspectDocumentMigrationVersion(vault.id, historical.bytes),
    ).resolves.toBe(1);

    const result = await migrationService(fixture).migrate();

    expect(result).toMatchObject({ pendingFiles: 1, migratedFiles: 1 });
    expect(result.backupPath).not.toBeNull();
    fixture.vaults.clearCachedDocuments();
    await expect(
      fixture.vaults.inspectDocumentBytes(vault.id, await readFile(historical.filePath)),
    ).resolves.toBe(2);
    const migrated = await fixture.vaults.readVault(vault.id);
    expect(migrated).toMatchObject(historical.document);
    const migratedMissingLifecycle = migrated.entries.find(
      (entry) => entry.id === missingLifecycle.id,
    );
    const migratedRetainedLifecycle = migrated.entries.find(
      (entry) => entry.id === retainedLifecycle.id,
    );
    expect(migratedMissingLifecycle?.lifecycle).toEqual({
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    });
    expect(migratedRetainedLifecycle?.lifecycle).toEqual(expectedRetainedLifecycle);
    expect(await migrationBackups(fixture.root)).toHaveLength(1);
  });

  it('lehnt partielle Lebenszyklen im historischen V2-Zwischenformat vor Snapshot und Write ab', async () => {
    const fixture = await createFixture();
    const vault = await fixture.vaults.createVault('Teilweise', '#14b8a6');
    await fixture.vaults.createEntry(vault.id, credentialInput('Ohne Lebenszyklus', 'Ohne-A!123'));
    await fixture.vaults.createEntry(
      vault.id,
      credentialInput('Teilweise Lebenszyklus', 'Teilweise-B!123'),
    );
    const current = await fixture.vaults.readVault(vault.id);
    const [missingLifecycle, partialLifecycle] = current.entries;
    if (missingLifecycle === undefined || partialLifecycle === undefined) {
      throw new Error('Historische V2-Fixture hat zu wenige Einträge.');
    }
    const { lifecycle: _missingLifecycle, ...legacyEntry } = missingLifecycle;
    void _missingLifecycle;
    const malformed = {
      ...current,
      entries: [legacyEntry, { ...partialLifecycle, lifecycle: { rotationIntervalDays: null } }],
    };
    const filePath = vaultPath(fixture.root, vault.id);
    await fixture.vaults.withVaultKey(vault.id, async (key) => {
      await writeFile(
        filePath,
        new EncryptedContainerCodec().encodeJson(malformed, key, 'vault', vault.id),
      );
    });
    fixture.vaults.clearCachedDocuments();
    const bytesBefore = await readFile(filePath);

    await expect(migrationService(fixture).migrate()).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });

    expect(await readFile(filePath)).toEqual(bytesBefore);
    expect(await migrationBackups(fixture.root)).toEqual([]);
  });

  it('rollt einen unterbrochenen Commit über mehrere Vaults bytegenau zurück', async () => {
    const fixture = await createFixture();
    const first = await fixture.vaults.createVault('A', '#14b8a6');
    const second = await fixture.vaults.createVault('B', '#334155');
    await fixture.vaults.createEntry(first.id, credentialInput('Rollback A', 'Rollback-A!123'));
    await fixture.vaults.createEntry(second.id, credentialInput('Rollback B', 'Rollback-B!123'));
    const firstLegacy = await installLegacyDocument(fixture, first.id);
    const secondLegacy = await installLegacyDocument(fixture, second.id);
    const targets = new Set([firstLegacy.filePath, secondLegacy.filePath]);
    let replaced = 0;
    const crashWriter = new AtomicFileWriter({
      afterReplace: (targetPath) => {
        if (!targets.has(targetPath)) return;
        replaced += 1;
        if (replaced === 1) throw new Error('Simulierter Vault-V2-Abbruch');
      },
    });

    await expect(migrationService(fixture, crashWriter).migrate()).rejects.toThrow(
      'Simulierter Vault-V2-Abbruch',
    );
    expect(replaced).toBe(1);
    const transactionDir = path.join(fixture.root, '.vaulta-migration-transaction');
    const transactionFiles = await readdir(transactionDir);
    expect(transactionFiles).toContain('journal.json');
    expect(transactionFiles.filter((name) => name.startsWith('rollback-'))).toHaveLength(2);
    for (const fileName of transactionFiles) {
      const contents = await readFile(path.join(transactionDir, fileName), 'utf8');
      expect(contents).not.toContain('Rollback-A!123');
      expect(contents).not.toContain('Rollback-B!123');
      expect(contents).not.toContain('Rollback A');
      expect(contents).not.toContain('Rollback B');
    }

    await migrationService(fixture).recoverInterruptedWrites();

    expect(await readFile(firstLegacy.filePath)).toEqual(firstLegacy.bytes);
    expect(await readFile(secondLegacy.filePath)).toEqual(secondLegacy.bytes);
    await expect(readdir(transactionDir)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(
      await fixture.vaults.inspectDocumentBytes(first.id, await readFile(firstLegacy.filePath)),
    ).toBe(1);
    expect(
      await fixture.vaults.inspectDocumentBytes(second.id, await readFile(secondLegacy.filePath)),
    ).toBe(1);
  });

  it('lehnt ein verschlüsseltes Future-Dokument vor Snapshot und Write ab', async () => {
    const fixture = await createFixture();
    const vault = await fixture.vaults.createVault('Future', '#14b8a6');
    await fixture.vaults.createEntry(vault.id, credentialInput('Future', 'Future-Secret!123'));
    const current = await fixture.vaults.readVault(vault.id);
    const filePath = vaultPath(fixture.root, vault.id);
    await fixture.vaults.withVaultKey(vault.id, async (key) => {
      await writeFile(
        filePath,
        new EncryptedContainerCodec().encodeJson(
          { ...current, formatVersion: 3 },
          key,
          'vault',
          vault.id,
        ),
      );
    });
    fixture.vaults.clearCachedDocuments();
    const bytesBefore = await readFile(filePath);

    await expect(migrationService(fixture).migrate()).rejects.toMatchObject({
      code: 'UNSUPPORTED_FORMAT',
    });

    expect(await readFile(filePath)).toEqual(bytesBefore);
    expect(await migrationBackups(fixture.root)).toEqual([]);
  });
});

interface Fixture {
  root: string;
  profile: ProfileService;
  vaults: VaultService;
}

type HistoricalV2Document = Omit<VaultDocument, 'entries'> & {
  readonly entries: Array<VaultDocumentV1['entries'][number] | VaultDocument['entries'][number]>;
};

async function createFixture(): Promise<Fixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-v2-migration-'));
  roots.push(root);
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const pending = await profile.beginSetup(MASTER_PASSWORD, true);
  if (pending.recovery === null) throw new Error('Recovery-Fixture fehlt');
  const confirmation = Object.fromEntries(
    pending.recovery.confirmationIndexes.map((index) => [
      String(index),
      pending.recovery?.groups[index],
    ]),
  ) as Record<string, string>;
  await profile.completeSetup(pending.pendingId, confirmation);
  return { root, profile, vaults: new VaultService({ rootDir: root, profileService: profile }) };
}

function migrationService(fixture: Fixture, atomicWriter?: AtomicFileWriter) {
  return new PersistentMigrationService({
    rootDir: fixture.root,
    profileService: fixture.profile,
    ...(atomicWriter === undefined ? {} : { atomicWriter }),
    embeddedInspectors: [createVaultDocumentEmbeddedMigrationAdapter(fixture.vaults)],
  });
}

async function installLegacyDocument(
  fixture: Fixture,
  vaultId: string,
): Promise<{ document: VaultDocumentV1; filePath: string; bytes: Buffer }> {
  const current = await fixture.vaults.readVault(vaultId);
  const document = toLegacyDocument(current);
  const filePath = vaultPath(fixture.root, vaultId);
  let bytes: Buffer = Buffer.alloc(0);
  await fixture.vaults.withVaultKey(vaultId, async (key) => {
    bytes = new EncryptedContainerCodec().encodeJson(document, key, 'vault', vaultId);
    await writeFile(filePath, bytes);
  });
  fixture.vaults.clearCachedDocuments();
  return { document, filePath, bytes };
}

async function installHistoricalV2Document(
  fixture: Fixture,
  vaultId: string,
): Promise<{ document: HistoricalV2Document; filePath: string; bytes: Buffer }> {
  const current = await fixture.vaults.readVault(vaultId);
  const [missingLifecycle, ...retainedEntries] = current.entries;
  if (missingLifecycle === undefined) throw new Error('Historische V2-Fixture hat keine Einträge.');
  const { lifecycle: _ignoredLifecycle, ...legacyEntry } = missingLifecycle;
  void _ignoredLifecycle;
  const document: HistoricalV2Document = {
    ...current,
    entries: [legacyEntry, ...retainedEntries.map((entry) => structuredClone(entry))],
  };
  const filePath = vaultPath(fixture.root, vaultId);
  let bytes: Buffer = Buffer.alloc(0);
  await fixture.vaults.withVaultKey(vaultId, async (key) => {
    bytes = new EncryptedContainerCodec().encodeJson(document, key, 'vault', vaultId);
    await writeFile(filePath, bytes);
  });
  fixture.vaults.clearCachedDocuments();
  return { document, filePath, bytes };
}

function toLegacyDocument(document: VaultDocument): VaultDocumentV1 {
  return {
    formatVersion: 1,
    id: document.id,
    name: document.name,
    color: document.color,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
    folders: structuredClone(document.folders),
    entries: document.entries.map(({ lifecycle: ignoredLifecycle, ...entry }) => {
      void ignoredLifecycle;
      return structuredClone(entry);
    }),
  };
}

async function expectMigratedDocument(
  vaults: VaultService,
  expected: VaultDocumentV1,
): Promise<void> {
  const actual = await vaults.readVault(expected.id);
  expect(actual.formatVersion).toBe(2);
  expect({ ...actual, formatVersion: 1, entries: undefined }).toMatchObject({
    ...expected,
    entries: undefined,
  });
  expect(actual.entries).toHaveLength(expected.entries.length);
  actual.entries.forEach((entry, index) => {
    const { lifecycle, ...withoutLifecycle } = entry;
    expect(withoutLifecycle).toEqual(expected.entries[index]);
    expect(lifecycle).toEqual({
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    });
  });
}

function credentialInput(title: string, password: string): EntryInput {
  return {
    title,
    folderId: null,
    tags: ['Migration'],
    favorite: false,
    note: 'Fachwert bleibt unverändert',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: `${title.toLowerCase().replaceAll(' ', '.')}@example.invalid`,
        password,
        websites: ['https://example.invalid'],
        appNames: [],
      },
    },
  };
}

function vaultPath(root: string, vaultId: string): string {
  return path.join(root, 'vaults', `${vaultId}.vaulta`);
}

async function migrationBackups(root: string): Promise<string[]> {
  return readdir(path.join(root, 'migration-backups')).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
}
