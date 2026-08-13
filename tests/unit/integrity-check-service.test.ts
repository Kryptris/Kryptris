import { describe, expect, it, vi } from 'vitest';

import {
  IntegrityCheckService,
  type IntegrityAttachmentReader,
  type IntegrityAuditReader,
  type IntegrityProfileReader,
  type IntegrityProgress,
  type IntegrityVaultReader,
} from '../../src/main/services/integrity-check-service';
import { VaultaError } from '../../src/shared/errors';
import type {
  AttachmentMetadata,
  SavedViewRecord,
  VaultDocument,
  VaultEntry,
} from '../../src/shared/models';
import { credentialEntry } from './service-fixtures';

const NOW = new Date('2026-07-26T12:00:00.000Z');
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

interface Harness {
  readonly profile: IntegrityProfileReader;
  readonly vaults: IntegrityVaultReader;
  readonly attachments: IntegrityAttachmentReader;
  readonly audit: IntegrityAuditReader;
  readonly readVaultFresh: ReturnType<typeof vi.fn>;
  readonly inspectAttachment: IntegrityAttachmentReader['inspectIntegrity'];
  readonly inspectAudit: ReturnType<typeof vi.fn>;
}

describe('IntegrityCheckService', () => {
  it('prüft den vollständigen gültigen Kern deterministisch mit monotonem Fortschritt', async () => {
    const attachment = metadata('attachment-a', HASH_A);
    const document = vaultDocument([
      credential({
        id: 'entry-a',
        vaultId: 'vault-a',
        folderId: 'folder-a',
        attachments: [attachment],
      }),
    ]);
    const harness = createHarness(document, [attachmentReference('vault-a', attachment.id)]);
    const progress: IntegrityProgress[] = [];
    const yieldControl = vi.fn(() => Promise.resolve());
    const service = createService(harness);

    const first = await service.scan({
      savedViews: [savedView('view-a', 'vault-a', 'folder-a')],
      onProgress: (value) => progress.push(value),
      yieldControl,
    });
    const second = await service.scan({
      savedViews: [savedView('view-a', 'vault-a', 'folder-a')],
      yieldControl,
    });

    expect(first).toEqual(second);
    expect(first).toEqual({
      generatedAt: NOW.toISOString(),
      success: true,
      scannedVaults: 1,
      scannedEntries: 1,
      scannedAttachments: 1,
      findings: [],
      networkUsed: false,
    });
    expect(harness.readVaultFresh).toHaveBeenCalledTimes(2);
    expect(harness.inspectAttachment).toHaveBeenCalledWith(
      'vault-a',
      'attachment-a',
      expect.objectContaining({ yieldEveryChunks: 1 }),
    );
    expect(progress[0]).toEqual({ phase: 'profile', completed: 0, total: 5 });
    expect(progress.at(-1)).toEqual({ phase: 'audit', completed: 5, total: 5 });
    expect(progress.map((value) => value.completed)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(yieldControl).toHaveBeenCalled();
  });

  it('sammelt unabhängige Befunde und entfernt Werte, Pfade, Namen, Hashes und Rohfehler', async () => {
    const secret = 'CANARY-SECRET-do-not-report';
    const pathCanary = 'C:\\private\\CANARY-PATH\\secret.bin';
    const duplicate = metadata('attachment-duplicate', HASH_A);
    const missing = metadata('attachment-missing', HASH_B);
    const first = credential({
      id: 'entry-duplicate',
      vaultId: 'wrong-vault',
      folderId: 'missing-folder',
      title: secret,
      attachments: [duplicate, missing],
    });
    const second = credential({
      id: 'entry-duplicate',
      vaultId: 'vault-a',
      attachments: [duplicate],
    });
    const document = vaultDocument(
      [first, second],
      [
        { id: 'folder-duplicate', name: secret, color: '#112233', createdAt: NOW.toISOString() },
        {
          id: 'folder-duplicate',
          name: pathCanary,
          color: '#112233',
          createdAt: NOW.toISOString(),
        },
      ],
    );
    const harness = createHarness(
      document,
      [
        attachmentReference('vault-a', duplicate.id),
        attachmentReference('vault-a', 'attachment-orphan'),
      ],
      (_vaultId: string, attachmentId: string) => {
        if (attachmentId === 'attachment-orphan') {
          return Promise.reject(new Error(`${secret}:${pathCanary}:${HASH_A}`));
        }
        return Promise.resolve({ size: duplicate.size + 1, sha256: HASH_B });
      },
    );
    harness.inspectAudit.mockRejectedValue(new Error(`${secret}:${pathCanary}`));
    const service = createService(harness);

    const report = await service.scan({
      savedViews: [
        savedView('duplicate-view', 'missing-vault', null, secret),
        savedView('duplicate-view', 'vault-a', 'missing-folder', pathCanary),
      ],
      yieldControl: () => Promise.resolve(),
    });
    const serialized = JSON.stringify(report);

    expect(report.success).toBe(false);
    expect(report.findings.map((finding) => finding.code)).toEqual(
      expect.arrayContaining([
        'duplicate-folder-id',
        'duplicate-entry-id',
        'entry-vault-mismatch',
        'folder-reference-invalid',
        'attachment-reference-duplicate',
        'saved-view-reference-invalid',
        'attachment-missing',
        'attachment-orphan',
        'attachment-container-invalid',
        'attachment-metadata-mismatch',
        'audit-invalid',
      ]),
    );
    expect(report.findings.map((finding) => finding.id)).toEqual(
      report.findings.map((_, index) => `integrity-finding-${String(index + 1).padStart(4, '0')}`),
    );
    for (const forbidden of [
      secret,
      pathCanary,
      HASH_A,
      HASH_B,
      'vault-a',
      'entry-duplicate',
      'attachment-duplicate',
      'folder-duplicate',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it.each([new VaultaError('LOCKED', 'gesperrt'), new VaultaError('CANCELLED', 'abgebrochen')])(
    'reicht Autorisierungsverlust sofort durch und erzeugt keinen Teilreport',
    async (error) => {
      const document = vaultDocument([]);
      const harness = createHarness(document, []);
      harness.readVaultFresh.mockRejectedValue(error);
      const service = createService(harness);

      await expect(service.scan({ yieldControl: () => Promise.resolve() })).rejects.toBe(error);
      expect(harness.inspectAudit).not.toHaveBeenCalled();
    },
  );

  it('prüft Header, sämtliche geschützten Profilmetadaten und den Public-Factor-MAC getrennt', async () => {
    const document = vaultDocument([]);
    const harness = createHarness(document, []);
    const getProtectedMetadata = vi.fn().mockRejectedValue(new Error('CANARY-Profilmetadaten'));
    const getPublicFactorData = vi.fn().mockRejectedValue(new Error('CANARY-Faktor'));
    const service = new IntegrityCheckService({
      ...harness,
      profile: {
        readPublicHeader: () => Promise.resolve({ format: 'vaulta-profile' }),
        getProtectedMetadata,
        getPublicFactorData,
      },
      now: () => NOW,
    });

    const report = await service.scan({ yieldControl: () => Promise.resolve() });

    expect(getProtectedMetadata).toHaveBeenCalledWith('integrity-probe');
    expect(getPublicFactorData).toHaveBeenCalledOnce();
    expect(report.findings.map((finding) => finding.code)).toEqual([
      'profile-factor-invalid',
      'profile-metadata-invalid',
    ]);
    expect(JSON.stringify(report)).not.toContain('CANARY');
  });
  it('gibt während großer Referenzprüfungen frei und priorisiert Abbruch vor Anhängen und Audit', async () => {
    const document = vaultDocument(
      Array.from({ length: 250 }, (_, index) =>
        credential({
          id: `entry-${String(index).padStart(4, '0')}`,
          vaultId: 'vault-a',
        }),
      ),
    );
    const harness = createHarness(document, []);
    const cancellation = new VaultaError('CANCELLED', 'Referenzprüfung abgebrochen');
    let yields = 0;

    await expect(
      createService(harness).scan({
        yieldControl: () => {
          yields += 1;
          return yields === 3 ? Promise.reject(cancellation) : Promise.resolve();
        },
      }),
    ).rejects.toBe(cancellation);

    expect(yields).toBe(3);
    expect(harness.inspectAttachment).not.toHaveBeenCalled();
    expect(harness.inspectAudit).not.toHaveBeenCalled();
  });
});

function createService(harness: Harness): IntegrityCheckService {
  return new IntegrityCheckService({ ...harness, now: () => NOW });
}

function createHarness(
  document: VaultDocument,
  storedAttachments: Array<{ vaultId: string; attachmentId: string }>,
  inspectAttachmentImplementation?: IntegrityAttachmentReader['inspectIntegrity'],
): Harness {
  const readVaultFresh = vi.fn(() => Promise.resolve(structuredClone(document)));
  const inspectAttachment = vi.fn(
    inspectAttachmentImplementation ??
      ((_vaultId: string, attachmentId: string) => {
        const expected = document.entries
          .flatMap((entry) => entry.attachments)
          .find((attachment) => attachment.id === attachmentId);
        return Promise.resolve({
          size: expected?.size ?? 0,
          sha256: expected?.sha256 ?? HASH_A,
        });
      }),
  );
  const inspectAudit = vi.fn(() => Promise.resolve(1));
  return {
    profile: {
      readPublicHeader: () => Promise.resolve({ format: 'vaulta-profile' }),
      getProtectedMetadata: () => Promise.resolve(null),
      getPublicFactorData: () => Promise.resolve(null),
    },
    vaults: {
      inspectStoredVaultInventory: () =>
        Promise.resolve({ vaultIds: [document.id], invalidEntryCount: 0 }),
      listRegisteredVaultIds: () => Promise.resolve([document.id]),
      readVaultFresh,
    },
    attachments: {
      inspectStoredAttachmentInventory: () =>
        Promise.resolve({ references: storedAttachments, invalidEntryCount: 0 }),
      inspectIntegrity: inspectAttachment,
    },
    audit: { inspectStoredDocumentFormatVersion: inspectAudit },
    readVaultFresh,
    inspectAttachment,
    inspectAudit,
  };
}

function vaultDocument(
  entries: VaultEntry[],
  folders: VaultDocument['folders'] = [
    { id: 'folder-a', name: 'Ordner', color: '#112233', createdAt: NOW.toISOString() },
  ],
): VaultDocument {
  return {
    formatVersion: 2,
    id: 'vault-a',
    name: 'CANARY-Vault-Name',
    color: '#112233',
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
    folders,
    entries,
  };
}

function credential(input: {
  id: string;
  vaultId: string;
  folderId?: string | null;
  title?: string;
  attachments?: AttachmentMetadata[];
}): VaultEntry {
  return {
    ...credentialEntry({
      id: input.id,
      vaultId: input.vaultId,
      ...(input.title === undefined ? {} : { title: input.title }),
      ...(input.attachments === undefined ? {} : { attachments: input.attachments }),
    }),
    folderId: input.folderId ?? null,
  };
}

function metadata(id: string, sha256: string): AttachmentMetadata {
  return {
    id,
    name: `CANARY-${id}.bin`,
    mediaType: 'application/octet-stream',
    size: 4_096,
    sha256,
    createdAt: NOW.toISOString(),
    previewable: false,
  };
}

function attachmentReference(vaultId: string, attachmentId: string) {
  return { vaultId, attachmentId };
}

function savedView(
  id: string,
  vaultId: string,
  folderId: string | null,
  name = 'Ansicht',
): SavedViewRecord {
  return {
    id,
    vaultId,
    name,
    filters: {
      search: '',
      view: 'all',
      types: [],
      tags: [],
      folderId,
      security: [],
      smartView: null,
    },
    order: 0,
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
  };
}
