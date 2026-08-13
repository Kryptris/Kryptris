import { randomUUID } from 'node:crypto';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { AuditService } from '../../src/main/services/audit-service';
import {
  DuplicateMergeCoordinator,
  type DuplicateMergeRequest,
} from '../../src/main/services/duplicate-merge-coordinator';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import {
  MULTI_FILE_TRANSACTION_DIRECTORY,
  MultiFileTransactionService,
} from '../../src/main/storage/multi-file-transaction';
import { VaultaError } from '../../src/shared/errors';
import type {
  AttachmentMetadata,
  AuditEvent,
  EntryInput,
  VaultDocument,
  VaultEntry,
} from '../../src/shared/models';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const CREATED_AT = new Date('2026-07-22T09:00:00.000Z');
const MERGED_AT = new Date('2026-07-22T10:00:00.000Z');
const STAGING_DIRECTORY = '.vaulta-duplicate-merge-staging';
const roots: string[] = [];

interface Fixture {
  root: string;
  vaults: VaultService;
  attachments: AttachmentService;
  audit: AuditService;
  coordinator: DuplicateMergeCoordinator;
  sourceVaultId: string;
  targetVaultId: string;
}

interface PersistentSnapshot {
  documents: Map<string, VaultDocument>;
  vaultBytes: Map<string, Buffer>;
  attachmentReferences: Awaited<ReturnType<AttachmentService['listStoredAttachmentReferences']>>;
  attachmentBytes: Map<string, Buffer>;
  auditEvents: AuditEvent[];
  auditBytes: Buffer | null;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('DuplicateMergeCoordinator', () => {
  it('führt Dubletten im selben Tresor zusammen und dedupliziert authentifizierten Inhalt', async () => {
    const current = await fixture();
    const sharedPlaintext = Buffer.from('synthetischer-gleicher-anhang-ohne-personenbezug');
    const survivor = await createCredential(current, current.sourceVaultId, {
      title: 'Anonymisierter Zugang A',
      username: 'konto-a@example.invalid',
      password: 'synthetisches-geheimnis-a',
      tags: ['Lokal'],
    });
    const duplicate = await createCredential(current, current.sourceVaultId, {
      title: 'Anonymisierter Zugang B',
      username: 'konto-b@example.invalid',
      password: 'synthetisches-geheimnis-b',
      tags: ['Prüfung'],
    });
    const survivorAttachment = await attachToEntry(
      current,
      survivor,
      sharedPlaintext,
      'survivor-anlage.bin',
    );
    const duplicateAttachment = await attachToEntry(
      current,
      duplicate,
      sharedPlaintext,
      'duplicate-anlage.bin',
    );
    const request = await mergeRequest(current, survivor, duplicate, [
      { field: 'title', source: 'duplicate' },
      { field: 'credential.username', source: 'duplicate' },
    ]);

    const result = await current.coordinator.merge(request);

    expect(result).toMatchObject({
      survivor: {
        vaultId: current.sourceVaultId,
        entryId: survivor.id,
        updatedAt: MERGED_AT.toISOString(),
      },
      duplicate: {
        vaultId: current.sourceVaultId,
        entryId: duplicate.id,
        updatedAt: MERGED_AT.toISOString(),
      },
      copiedAttachments: 0,
      deduplicatedAttachments: 1,
    });
    const document = await current.vaults.readVault(current.sourceVaultId);
    const merged = requireEntry(document, survivor.id);
    const trashed = requireEntry(document, duplicate.id);
    expect(merged).toMatchObject({
      title: 'Anonymisierter Zugang B',
      tags: ['Lokal', 'Prüfung'],
      deletedAt: null,
    });
    expect(merged.data.type).toBe('credential');
    if (merged.data.type !== 'credential') throw new Error('Unerwarteter Testtyp.');
    expect(merged.data.value.username).toBe('konto-b@example.invalid');
    expect(merged.attachments).toEqual([survivorAttachment]);
    expect(trashed.deletedAt).toBe(MERGED_AT.toISOString());
    expect(trashed.attachments).toEqual([duplicateAttachment]);
    await expect(
      current.attachments.verifyMetadata(current.sourceVaultId, survivorAttachment),
    ).resolves.toBeUndefined();
    await expect(
      current.attachments.readBuffer(
        current.sourceVaultId,
        survivorAttachment.id,
        sharedPlaintext.length,
      ),
    ).resolves.toEqual(sharedPlaintext);

    const auditEvents = await current.audit.list();
    expectRedactedMergeAudit(auditEvents, current.sourceVaultId, survivor.id, [
      'synthetisches-geheimnis-a',
      'synthetisches-geheimnis-b',
      'Anonymisierter Zugang B',
      duplicate.id,
      duplicateAttachment.name,
    ]);
    await expectMissing(path.join(current.root, STAGING_DIRECTORY));
  });

  it('übernimmt Cross-Vault-Anhänge neu verschlüsselt und dedupliziert verifizierten Inhalt', async () => {
    const current = await fixture();
    const commonPlaintext = Buffer.from('anonymisierter-gemeinsamer-dateiinhalt');
    const copiedPlaintext = Buffer.from('anonymisierter-cross-vault-inhalt-'.repeat(400));
    const survivor = await createCredential(current, current.sourceVaultId, {
      title: 'Lokales Ziel',
      username: 'ziel@example.invalid',
      password: 'synthetisches-zielgeheimnis',
      tags: ['Ziel'],
    });
    const duplicate = await createCredential(current, current.targetVaultId, {
      title: 'Lokale Quelle',
      username: 'quelle@example.invalid',
      password: 'synthetisches-quellgeheimnis',
      tags: ['Quelle'],
    });
    const survivorCommon = await attachToEntry(
      current,
      survivor,
      commonPlaintext,
      'gemeinsam-ziel.bin',
    );
    const duplicateCommon = await attachToEntry(
      current,
      duplicate,
      commonPlaintext,
      'gemeinsam-quelle.bin',
    );
    const duplicateUnique = await attachToEntry(
      current,
      duplicate,
      copiedPlaintext,
      'nur-quelle.bin',
    );
    const sourceCiphertext = await readFile(
      current.attachments.getEncryptedPath(current.targetVaultId, duplicateUnique.id),
    );
    const request = await mergeRequest(current, survivor, duplicate);
    let authorizationChecks = 0;

    const result = await current.coordinator.merge(request, () => {
      authorizationChecks += 1;
    });

    expect(result.copiedAttachments).toBe(1);
    expect(result.deduplicatedAttachments).toBe(1);
    expect(authorizationChecks).toBeGreaterThan(20);
    const sourceDocument = await current.vaults.readVault(current.sourceVaultId);
    const targetDocument = await current.vaults.readVault(current.targetVaultId);
    const merged = requireEntry(sourceDocument, survivor.id);
    const trashed = requireEntry(targetDocument, duplicate.id);
    expect(merged.attachments).toHaveLength(2);
    expect(merged.attachments).toContainEqual(survivorCommon);
    expect(merged.attachments).not.toContainEqual(
      expect.objectContaining({ id: duplicateCommon.id }),
    );
    const copied = merged.attachments.find(
      (attachment) => attachment.sha256 === duplicateUnique.sha256,
    );
    expect(copied).toBeDefined();
    expect(copied?.id).not.toBe(duplicateUnique.id);
    expect(trashed.deletedAt).toBe(MERGED_AT.toISOString());
    expect(trashed.attachments).toEqual([duplicateCommon, duplicateUnique]);
    await expect(
      current.attachments.verifyMetadata(current.sourceVaultId, copied!),
    ).resolves.toBeUndefined();
    await expect(
      current.attachments.readAuthenticatedMetadata(current.sourceVaultId, copied!.id),
    ).resolves.toEqual({
      size: duplicateUnique.size,
      sha256: duplicateUnique.sha256,
    });
    await expect(
      current.attachments.readBuffer(current.sourceVaultId, copied!.id, copiedPlaintext.length),
    ).resolves.toEqual(copiedPlaintext);
    const targetCiphertext = await readFile(
      current.attachments.getEncryptedPath(current.sourceVaultId, copied!.id),
    );
    expect(targetCiphertext.equals(sourceCiphertext)).toBe(false);
    expect(targetCiphertext.includes(copiedPlaintext.subarray(0, 64))).toBe(false);

    const auditEvents = await current.audit.list();
    expectRedactedMergeAudit(auditEvents, current.sourceVaultId, survivor.id, [
      'synthetisches-zielgeheimnis',
      'synthetisches-quellgeheimnis',
      'Lokale Quelle',
      duplicate.id,
      duplicateUnique.name,
    ]);
    const auditBytes = await readFile(path.join(current.root, 'audit.vaulta'));
    expect(auditBytes.includes(Buffer.from('synthetisches-quellgeheimnis'))).toBe(false);
    await expectMissing(path.join(current.root, STAGING_DIRECTORY));
  });

  it('rollt Vaults, neu erzeugten Anhang und Audit nach einem Teilcommit bytegenau zurück', async () => {
    let failAfterFirstReplace = true;
    const replacedPaths: string[] = [];
    const atomicWriter = new AtomicFileWriter({
      afterReplace: (targetPath) => {
        replacedPaths.push(targetPath);
        if (!failAfterFirstReplace) return;
        failAfterFirstReplace = false;
        throw new Error('simulierter Merge-Teilcommit');
      },
    });
    const root = await createRoot();
    const current = await fixture(
      root,
      new MultiFileTransactionService({ rootDir: root, atomicWriter }),
    );
    const survivor = await createCredential(current, current.sourceVaultId, {
      title: 'Rollback-Ziel',
      username: 'rollback-ziel@example.invalid',
      password: 'synthetisches-rollback-ziel',
      tags: ['Vorher'],
    });
    const duplicate = await createCredential(current, current.targetVaultId, {
      title: 'Rollback-Quelle',
      username: 'rollback-quelle@example.invalid',
      password: 'synthetisches-rollback-quelle',
      tags: ['Quelle'],
    });
    await attachToEntry(
      current,
      duplicate,
      Buffer.from('anonymisierter-rollback-anhang-'.repeat(300)),
      'rollback-anlage.bin',
    );
    await current.audit.record({ type: 'unlocked' });
    const request = await mergeRequest(current, survivor, duplicate);
    const before = await persistentSnapshot(current);

    await expect(current.coordinator.merge(request)).rejects.toThrow(
      'simulierter Merge-Teilcommit',
    );

    expect(replacedPaths.length).toBeGreaterThanOrEqual(1);
    expect(replacedPaths[0]).toMatch(/[\\/]vaults[\\/].+\.vaulta$/u);
    expect(failAfterFirstReplace).toBe(false);
    await expectPersistentState(current, before);
    await expectMissing(path.join(current.root, STAGING_DIRECTORY));
    await expectMissing(path.join(current.root, MULTI_FILE_TRANSACTION_DIRECTORY));
  });

  it('bricht während der authentifizierten Anhangsverarbeitung ohne Teilzustand ab', async () => {
    const current = await fixture();
    const survivor = await createCredential(current, current.sourceVaultId, {
      title: 'Abbruch-Ziel',
      username: 'abbruch-ziel@example.invalid',
      password: 'synthetisches-abbruch-ziel',
      tags: [],
    });
    const duplicate = await createCredential(current, current.targetVaultId, {
      title: 'Abbruch-Quelle',
      username: 'abbruch-quelle@example.invalid',
      password: 'synthetisches-abbruch-quelle',
      tags: [],
    });
    await attachToEntry(
      current,
      duplicate,
      Buffer.from('anonymisierter-abbruchinhalt-'.repeat(3_000)),
      'abbruch-anlage.bin',
    );
    await current.audit.record({ type: 'unlocked' });
    const request = await mergeRequest(current, survivor, duplicate);
    const before = await persistentSnapshot(current);
    let authorizationChecks = 0;

    await expect(
      current.coordinator.merge(request, () => {
        authorizationChecks += 1;
        if (authorizationChecks === 12) {
          throw new VaultaError('CANCELLED', 'Simulierter lokaler Abbruch.');
        }
      }),
    ).rejects.toMatchObject({ code: 'CANCELLED' });

    expect(authorizationChecks).toBe(12);
    await expectPersistentState(current, before);
    await expectMissing(path.join(current.root, STAGING_DIRECTORY));
    await expectMissing(path.join(current.root, MULTI_FILE_TRANSACTION_DIRECTORY));
  });

  it('prüft die Autorisierung vor dem Lesen oder Vorbereiten eines Merge-Zustands', async () => {
    const current = await fixture();
    const survivor = await createCredential(current, current.sourceVaultId, {
      title: 'Sperr-Ziel',
      username: 'sperr-ziel@example.invalid',
      password: 'synthetisches-sperr-ziel',
      tags: [],
    });
    const duplicate = await createCredential(current, current.targetVaultId, {
      title: 'Sperr-Quelle',
      username: 'sperr-quelle@example.invalid',
      password: 'synthetisches-sperr-quelle',
      tags: [],
    });
    const request = await mergeRequest(current, survivor, duplicate);
    const before = await persistentSnapshot(current);
    let authorizationChecks = 0;

    await expect(
      current.coordinator.merge(request, () => {
        authorizationChecks += 1;
        throw new VaultaError('LOCKED', 'Der lokale Testtresor ist gesperrt.');
      }),
    ).rejects.toMatchObject({ code: 'LOCKED' });

    expect(authorizationChecks).toBe(1);
    await expectPersistentState(current, before);
    await expectMissing(path.join(current.root, STAGING_DIRECTORY));
    await expectMissing(path.join(current.root, MULTI_FILE_TRANSACTION_DIRECTORY));
  });
});

async function fixture(
  existingRoot?: string,
  transactions?: MultiFileTransactionService,
): Promise<Fixture> {
  const root = existingRoot ?? (await createRoot());
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const setup = await profile.beginSetup('Ausschließlich synthetisches Testpasswort!123', false);
  await profile.completeSetup(setup.pendingId, {});
  const vaults = new VaultService({
    rootDir: root,
    profileService: profile,
    now: () => CREATED_AT,
  });
  const source = await vaults.createVault('Anonymisiertes Ziel', '#2DD4BF');
  const target = await vaults.createVault('Anonymisierte Quelle', '#8B5CF6');
  const attachments = new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4096,
    now: () => CREATED_AT,
  });
  const audit = new AuditService({
    rootDir: root,
    profileService: profile,
    now: () => MERGED_AT,
  });
  const multiFileTransactions = transactions ?? new MultiFileTransactionService({ rootDir: root });
  return {
    root,
    vaults,
    attachments,
    audit,
    coordinator: new DuplicateMergeCoordinator({
      rootDir: root,
      vaultService: vaults,
      attachmentService: attachments,
      getAuditService: () => audit,
      transactions: multiFileTransactions,
      now: () => MERGED_AT,
    }),
    sourceVaultId: source.id,
    targetVaultId: target.id,
  };
}

async function createRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-duplicate-merge-'));
  roots.push(root);
  return root;
}

async function createCredential(
  current: Fixture,
  vaultId: string,
  values: {
    title: string;
    username: string;
    password: string;
    tags: string[];
  },
): Promise<VaultEntry> {
  const input: EntryInput = {
    title: values.title,
    folderId: null,
    tags: values.tags,
    favorite: false,
    note: '',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: values.username,
        password: values.password,
        websites: ['https://example.invalid'],
        appNames: [],
      },
    },
  };
  return current.vaults.createEntry(vaultId, input);
}

async function attachToEntry(
  current: Fixture,
  entry: VaultEntry,
  plaintext: Buffer,
  name: string,
): Promise<AttachmentMetadata> {
  const sourcePath = path.join(current.root, `fixture-${randomUUID()}.bin`);
  await writeFile(sourcePath, plaintext);
  let metadata: AttachmentMetadata;
  try {
    metadata = await current.attachments.encryptFile({
      vaultId: entry.vaultId,
      sourcePath,
      name,
      mediaType: 'application/octet-stream',
    });
  } finally {
    await rm(sourcePath, { force: true });
  }
  await current.vaults.mutateVault(entry.vaultId, (document) => {
    requireEntry(document, entry.id).attachments.push(metadata);
  });
  return metadata;
}

async function mergeRequest(
  current: Fixture,
  survivor: VaultEntry,
  duplicate: VaultEntry,
  fieldChoices: DuplicateMergeRequest['fieldChoices'] = [],
): Promise<DuplicateMergeRequest> {
  const currentSurvivor = requireEntry(
    await current.vaults.readVault(survivor.vaultId),
    survivor.id,
  );
  const currentDuplicate = requireEntry(
    await current.vaults.readVault(duplicate.vaultId),
    duplicate.id,
  );
  return {
    survivor: referenceOf(currentSurvivor),
    duplicate: referenceOf(currentDuplicate),
    fieldChoices,
    collectionChoices: [
      { field: 'tags', strategy: 'union' },
      { field: 'attachments', strategy: 'union' },
    ],
  };
}

function referenceOf(entry: VaultEntry): DuplicateMergeRequest['survivor'] {
  return {
    vaultId: entry.vaultId,
    entryId: entry.id,
    updatedAt: entry.updatedAt,
  };
}

function requireEntry(document: VaultDocument, entryId: string): VaultEntry {
  const entry = document.entries.find((candidate) => candidate.id === entryId);
  if (entry === undefined) throw new Error(`Testeintrag ${entryId} fehlt.`);
  return entry;
}

function expectRedactedMergeAudit(
  events: AuditEvent[],
  vaultId: string,
  survivorEntryId: string,
  forbiddenValues: readonly string[],
): void {
  expect(events).toHaveLength(1);
  expect(typeof events[0]?.id).toBe('string');
  expect(events[0]).toMatchObject({
    occurredAt: MERGED_AT.toISOString(),
    type: 'entries-merged',
    vaultId,
    entryId: survivorEntryId,
    summary: 'Dubletten zusammengeführt',
  });
  expect(Object.keys(events[0]!).sort()).toEqual([
    'entryId',
    'id',
    'occurredAt',
    'summary',
    'type',
    'vaultId',
  ]);
  const serialized = JSON.stringify(events);
  for (const value of forbiddenValues) expect(serialized).not.toContain(value);
}

async function persistentSnapshot(current: Fixture): Promise<PersistentSnapshot> {
  const vaultIds = [current.sourceVaultId, current.targetVaultId];
  const documents = new Map<string, VaultDocument>();
  const vaultBytes = new Map<string, Buffer>();
  for (const vaultId of vaultIds) {
    documents.set(vaultId, await current.vaults.readVault(vaultId));
    vaultBytes.set(vaultId, await readFile(vaultPath(current.root, vaultId)));
  }
  const attachmentReferences = await current.attachments.listStoredAttachmentReferences();
  const attachmentBytes = new Map<string, Buffer>();
  for (const reference of attachmentReferences) {
    attachmentBytes.set(
      `${reference.vaultId}/${reference.attachmentId}`,
      await readFile(
        current.attachments.getEncryptedPath(reference.vaultId, reference.attachmentId),
      ),
    );
  }
  const auditEvents = await current.audit.list({ limit: 1_000 });
  const auditBytes = await readOptional(path.join(current.root, 'audit.vaulta'));
  return {
    documents,
    vaultBytes,
    attachmentReferences,
    attachmentBytes,
    auditEvents,
    auditBytes,
  };
}

async function expectPersistentState(
  current: Fixture,
  expected: PersistentSnapshot,
): Promise<void> {
  current.vaults.clearCachedDocuments();
  for (const [vaultId, document] of expected.documents) {
    expect(await current.vaults.readVault(vaultId)).toEqual(document);
    expect(await readFile(vaultPath(current.root, vaultId))).toEqual(
      expected.vaultBytes.get(vaultId),
    );
  }
  expect(await current.attachments.listStoredAttachmentReferences()).toEqual(
    expected.attachmentReferences,
  );
  for (const [reference, bytes] of expected.attachmentBytes) {
    const [vaultId, attachmentId] = reference.split('/');
    if (vaultId === undefined || attachmentId === undefined) {
      throw new Error('Ungültige Attachment-Referenz im Test.');
    }
    expect(await readFile(current.attachments.getEncryptedPath(vaultId, attachmentId))).toEqual(
      bytes,
    );
  }
  expect(await current.audit.list({ limit: 1_000 })).toEqual(expected.auditEvents);
  expect(await readOptional(path.join(current.root, 'audit.vaulta'))).toEqual(expected.auditBytes);
}

function vaultPath(root: string, vaultId: string): string {
  return path.join(root, 'vaults', `${vaultId}.vaulta`);
}

async function readOptional(filePath: string): Promise<Buffer | null> {
  return readFile(filePath).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  });
}

async function expectMissing(filePath: string): Promise<void> {
  await expect(access(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
}
