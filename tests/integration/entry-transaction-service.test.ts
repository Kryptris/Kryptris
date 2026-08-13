import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { AuditService } from '../../src/main/services/audit-service';
import { EntryTransactionService } from '../../src/main/services/entry-transaction-service';
import { ProductivityService } from '../../src/main/services/productivity-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import { MultiFileTransactionService } from '../../src/main/storage/multi-file-transaction';
import type { EntryInput } from '../../src/shared/models';
import { VaultaError } from '../../src/shared/errors';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const roots: string[] = [];

interface Fixture {
  root: string;
  vaults: VaultService;
  attachments: AttachmentService;
  audit: AuditService;
  transactions: EntryTransactionService;
  sourceVaultId: string;
  targetVaultId: string;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Atomare Eintrags-Transaktionen', () => {
  it('kopiert Eintrag und Anhang neu verschlüsselt in einen anderen Tresor', async () => {
    const current = await fixture();
    const plaintext = Buffer.from('cross-vault-canary-'.repeat(2_000));
    const entryId = await createEntryWithAttachment(current, plaintext);

    const result = await current.transactions.transfer({
      vaultId: current.sourceVaultId,
      entryIds: [entryId],
      action: { type: 'copy-to-vault', targetVaultId: current.targetVaultId },
    });

    expect(result.affected).toBe(1);
    const source = await current.vaults.readVault(current.sourceVaultId);
    const target = await current.vaults.readVault(current.targetVaultId);
    expect(source.entries).toHaveLength(1);
    expect(target.entries).toHaveLength(1);
    const copied = target.entries[0]!;
    expect(copied.id).not.toBe(entryId);
    expect(copied.vaultId).toBe(current.targetVaultId);
    expect(copied.attachments[0]?.id).not.toBe(source.entries[0]?.attachments[0]?.id);
    const targetAttachment = copied.attachments[0]!;
    await expect(
      current.attachments.readBuffer(current.targetVaultId, targetAttachment.id, plaintext.length),
    ).resolves.toEqual(plaintext);
    const encryptedTarget = await readFile(
      current.attachments.getEncryptedPath(current.targetVaultId, targetAttachment.id),
    );
    expect(encryptedTarget.includes(plaintext.subarray(0, 64))).toBe(false);
    await expect(current.audit.list()).resolves.toEqual([
      expect.objectContaining({
        type: 'entry-copied-to-vault',
        vaultId: current.targetVaultId,
        entryId: copied.id,
      }),
    ]);
    await expectMissing(path.join(current.root, '.vaulta-entry-transaction-staging'));
  });

  it('verschiebt erst nach verifiziertem Zielcommit und entfernt danach die Quellgeneration', async () => {
    const current = await fixture();
    const plaintext = Buffer.from('move-secret-'.repeat(1_500));
    const entryId = await createEntryWithAttachment(current, plaintext);
    const sourceBefore = await current.vaults.readVault(current.sourceVaultId);
    const sourceAttachmentId = sourceBefore.entries[0]!.attachments[0]!.id;

    const result = await current.transactions.transfer({
      vaultId: current.sourceVaultId,
      entryIds: [entryId],
      action: { type: 'move-to-vault', targetVaultId: current.targetVaultId },
    });

    expect(result.sourceEntryIds).toEqual([entryId]);
    expect((await current.vaults.readVault(current.sourceVaultId)).entries).toHaveLength(0);
    const moved = (await current.vaults.readVault(current.targetVaultId)).entries[0]!;
    await expectMissing(
      current.attachments.getEncryptedPath(current.sourceVaultId, sourceAttachmentId),
    );
    await expect(
      current.attachments.readBuffer(
        current.targetVaultId,
        moved.attachments[0]!.id,
        plaintext.length,
      ),
    ).resolves.toEqual(plaintext);
  });

  it('lässt Quelle und Ziel bei Abbruch während der Neuverschlüsselung unverändert', async () => {
    const current = await fixture();
    const plaintext = Buffer.from('cancel-transfer-'.repeat(4_000));
    const entryId = await createEntryWithAttachment(current, plaintext);
    const sourceBefore = await current.vaults.readVault(current.sourceVaultId);
    const auditBefore = await current.audit.list();
    let checks = 0;

    await expect(
      current.transactions.transfer(
        {
          vaultId: current.sourceVaultId,
          entryIds: [entryId],
          action: { type: 'move-to-vault', targetVaultId: current.targetVaultId },
        },
        () => {
          checks += 1;
          if (checks === 12) throw new VaultaError('CANCELLED', 'Testabbruch');
        },
      ),
    ).rejects.toMatchObject({ code: 'CANCELLED' });

    current.vaults.clearCachedDocuments();
    expect(await current.vaults.readVault(current.sourceVaultId)).toEqual(sourceBefore);
    expect((await current.vaults.readVault(current.targetVaultId)).entries).toHaveLength(0);
    expect(await current.audit.list()).toEqual(auditBefore);
    await expectMissing(path.join(current.root, '.vaulta-entry-transaction-staging'));
  });

  it('rollt Cross-Vault-Dokumente und Attachment-Ziel nach einem Teilcommit zurück', async () => {
    let failAfterFirstReplace = true;
    const writer = new AtomicFileWriter({
      afterReplace: () => {
        if (!failAfterFirstReplace) return;
        failAfterFirstReplace = false;
        throw new Error('simulierter Cross-Vault-Teilcommit');
      },
    });
    const root = await createRoot();
    const current = await fixture(
      root,
      new MultiFileTransactionService({ rootDir: root, atomicWriter: writer }),
    );
    const plaintext = Buffer.from('rollback-transfer-'.repeat(2_000));
    const entryId = await createEntryWithAttachment(current, plaintext);
    const sourceBefore = await current.vaults.readVault(current.sourceVaultId);
    const auditBefore = await current.audit.list();
    const sourceAttachmentId = sourceBefore.entries[0]!.attachments[0]!.id;

    await expect(
      current.transactions.transfer({
        vaultId: current.sourceVaultId,
        entryIds: [entryId],
        action: { type: 'move-to-vault', targetVaultId: current.targetVaultId },
      }),
    ).rejects.toThrow('simulierter Cross-Vault-Teilcommit');

    current.vaults.clearCachedDocuments();
    expect(await current.vaults.readVault(current.sourceVaultId)).toEqual(sourceBefore);
    expect((await current.vaults.readVault(current.targetVaultId)).entries).toHaveLength(0);
    expect(await current.audit.list()).toEqual(auditBefore);
    await expect(
      current.attachments.readBuffer(current.sourceVaultId, sourceAttachmentId, plaintext.length),
    ).resolves.toEqual(plaintext);
    await expectMissing(path.join(current.root, 'attachments', current.targetVaultId));
    await expectMissing(path.join(current.root, '.vaulta-entry-transaction-staging'));
  });

  it('rollt einen Attachment-Purge nach einem Teilwrite auf Vault und Datei zurück', async () => {
    let failAfterFirstReplace = true;
    const writer = new AtomicFileWriter({
      afterReplace: () => {
        if (!failAfterFirstReplace) return;
        failAfterFirstReplace = false;
        throw new Error('simulierter Fehler nach erstem Replace');
      },
    });
    const root = await createRoot();
    const current = await fixture(
      root,
      new MultiFileTransactionService({ rootDir: root, atomicWriter: writer }),
    );
    const plaintext = Buffer.from('purge-secret');
    const entryId = await createEntryWithAttachment(current, plaintext, true);
    const before = await current.vaults.readVault(current.sourceVaultId);
    const attachmentId = before.entries[0]!.attachments[0]!.id;
    const productivity = new ProductivityService();

    await expect(
      current.transactions.purge(current.sourceVaultId, (document) =>
        productivity.applyBatch(document, {
          vaultId: current.sourceVaultId,
          entryIds: [entryId],
          action: { type: 'purge', masterPassword: 'bereits-geprüft', confirmationCount: 1 },
        }),
      ),
    ).rejects.toThrow('simulierter Fehler');

    current.vaults.clearCachedDocuments();
    expect(await current.vaults.readVault(current.sourceVaultId)).toEqual(before);
    await expect(
      access(current.attachments.getEncryptedPath(current.sourceVaultId, attachmentId)),
    ).resolves.toBeUndefined();
    await expect(
      current.attachments.readBuffer(current.sourceVaultId, attachmentId, plaintext.length),
    ).resolves.toEqual(plaintext);
  });

  it('löscht Papierkorbeintrag und Anhang in einem erfolgreichen Commit', async () => {
    const current = await fixture();
    const entryId = await createEntryWithAttachment(current, Buffer.from('delete-me'), true);
    const before = await current.vaults.readVault(current.sourceVaultId);
    const attachmentId = before.entries[0]!.attachments[0]!.id;
    const productivity = new ProductivityService();

    const result = await current.transactions.purge(current.sourceVaultId, (document) =>
      productivity.applyBatch(document, {
        vaultId: current.sourceVaultId,
        entryIds: [entryId],
        action: { type: 'purge', masterPassword: 'bereits-geprüft', confirmationCount: 1 },
      }),
    );

    expect(result.affected).toBe(1);
    expect((await current.vaults.readVault(current.sourceVaultId)).entries).toHaveLength(0);
    await expectMissing(current.attachments.getEncryptedPath(current.sourceVaultId, attachmentId));
  });
});

async function fixture(
  existingRoot?: string,
  multiFileTransactions?: MultiFileTransactionService,
): Promise<Fixture> {
  const root = existingRoot ?? (await createRoot());
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const setup = await profile.beginSetup('Ein sehr langes Testpasswort!123', false);
  await profile.completeSetup(setup.pendingId, {});
  const vaults = new VaultService({ rootDir: root, profileService: profile });
  const source = await vaults.createVault('Quelle', '#2DD4BF');
  const target = await vaults.createVault('Ziel', '#8B5CF6');
  const attachments = new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4096,
  });
  const audit = new AuditService({ rootDir: root, profileService: profile });
  return {
    root,
    vaults,
    attachments,
    audit,
    transactions: new EntryTransactionService({
      rootDir: root,
      vaultService: vaults,
      attachmentService: attachments,
      ...(multiFileTransactions === undefined ? {} : { transactions: multiFileTransactions }),
      getAuditService: () => audit,
    }),
    sourceVaultId: source.id,
    targetVaultId: target.id,
  };
}

async function createRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-entry-transaction-'));
  roots.push(root);
  return root;
}

async function createEntryWithAttachment(
  current: Fixture,
  plaintext: Buffer,
  deleted = false,
): Promise<string> {
  const input: EntryInput = {
    title: 'Transaktionstest',
    folderId: null,
    tags: ['Test'],
    favorite: false,
    note: '',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: 'test@example.invalid',
        password: 'Nur-für-den-lokalen-Test!123',
        websites: ['https://example.invalid'],
        appNames: [],
      },
    },
  };
  const entry = await current.vaults.createEntry(current.sourceVaultId, input);
  const sourcePath = path.join(current.root, `${entry.id}.bin`);
  await writeFile(sourcePath, plaintext);
  const metadata = await current.attachments.encryptFile({
    vaultId: current.sourceVaultId,
    sourcePath,
    name: 'Anhang.bin',
    mediaType: 'application/octet-stream',
  });
  await current.vaults.mutateVault(current.sourceVaultId, (document) => {
    const stored = document.entries.find((candidate) => candidate.id === entry.id)!;
    stored.attachments.push(metadata);
    if (deleted) stored.deletedAt = '2026-07-20T12:00:00.000Z';
  });
  return entry.id;
}

async function expectMissing(filePath: string): Promise<void> {
  await expect(access(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
}
