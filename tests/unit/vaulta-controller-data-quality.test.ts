import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  MultiFileChange,
  MultiFileExecuteOptions,
} from '../../src/main/storage/multi-file-transaction';
import { VaultaController } from '../../src/main/vaulta-controller';
import {
  createDefaultEntryLifecycleMetadata,
  type VaultDocument,
  type VaultEntry,
} from '../../src/shared/models';

const electronMocks = vi.hoisted(() => ({
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
}));

vi.mock('electron', () => ({
  clipboard: electronMocks.clipboard,
  desktopCapturer: { getSources: vi.fn(() => Promise.resolve([])) },
  dialog: {
    showOpenDialog: vi.fn(),
    showSaveDialog: vi.fn(),
  },
  nativeImage: { createFromPath: vi.fn() },
}));

const VAULT_ID = '00000000-0000-4000-8000-000000000101';
const ENTRY_ID = '00000000-0000-4000-8000-000000000102';
const ATTACHMENT_ID = '00000000-0000-4000-8000-000000000103';
const REQUEST_ID = '00000000-0000-4000-8000-000000000104';
const RAW_URL = '  portal.example.test  ';
const NORMALIZED_URL = 'https://portal.example.test/';
const SYNTHETIC_SECRET = 'synthetic-test-secret-not-real';
const STORED_HASH = 'a'.repeat(64);
const AUTHENTICATED_HASH = 'b'.repeat(64);

interface AuthenticationHarness {
  begin(): number;
  complete(profileUnlocked: boolean, epoch: number): void;
}

interface RetentionSweepContext {
  cutoff: string;
  assertActive(): void;
}

interface ControllerHarness {
  controller: VaultaController;
  epoch: number;
  getDocument(): VaultDocument;
  setDocument(document: VaultDocument): void;
  execute: ReturnType<typeof vi.fn>;
  installCommittedDocuments: ReturnType<typeof vi.fn>;
  prepareAuditRecord: ReturnType<typeof vi.fn>;
  prepareAuditRecords: ReturnType<typeof vi.fn>;
  capturedChanges: MultiFileChange[][];
  capturedBuffers: Buffer[][];
}

const controllers: VaultaController[] = [];

beforeEach(() => {
  electronMocks.clipboard.readText.mockReturnValue('');
});

afterEach(() => {
  for (const controller of controllers) controller.dispose();
  controllers.length = 0;
  vi.restoreAllMocks();
});

describe('VaultaController Datenqualitaet', () => {
  it('redigiert fachliche Werte und authentifizierte Hashes aus dem oeffentlichen Report', async () => {
    const harness = createHarness(qualityDocument());

    const report = await harness.controller.scanDataQuality({
      vaultId: VAULT_ID,
      requestId: REQUEST_ID,
    });

    expect(report.networkUsed).toBe(false);
    expect(report.scannedEntries).toBe(1);
    const urlFinding = report.findings.find(
      (finding) => finding.code === 'url-needs-normalization',
    );
    expect(urlFinding?.reference).toMatchObject({ kind: 'entry', entryId: ENTRY_ID });
    const attachmentFinding = report.findings.find(
      (finding) => finding.code === 'attachment-metadata-mismatch',
    );
    expect(attachmentFinding?.reference).toMatchObject({
      kind: 'attachment',
      attachmentId: ATTACHMENT_ID,
    });
    for (const finding of report.findings) {
      expect(Object.keys(finding).sort()).toEqual(
        ['code', 'fixCode', 'id', 'reference', 'severity'].sort(),
      );
    }

    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain(RAW_URL.trim());
    expect(serialized).not.toContain(NORMALIZED_URL);
    expect(serialized).not.toContain(SYNTHETIC_SECRET);
    expect(serialized).not.toContain(STORED_HASH);
    expect(serialized).not.toContain(AUTHENTICATED_HASH);
    expect(serialized).not.toContain('location');
    expect(serialized).not.toContain('mutation');
  });

  it('wendet eine bestaetigte Korrektur genau einmal ueber Vault und Audit atomar an', async () => {
    const harness = createHarness(qualityDocument());
    const report = await harness.controller.scanDataQuality({
      vaultId: VAULT_ID,
      requestId: REQUEST_ID,
    });
    const finding = report.findings.find(
      (candidate) => candidate.code === 'url-needs-normalization',
    );
    expect(finding).toBeDefined();

    const preview = await harness.controller.previewDataQualityFix({
      vaultId: VAULT_ID,
      findingId: finding!.id,
    });
    expect(JSON.stringify(preview)).not.toContain(RAW_URL.trim());
    expect(JSON.stringify(preview)).not.toContain(NORMALIZED_URL);

    const result = await harness.controller.applyDataQualityFix({ token: preview.token });

    expect(result).toEqual({ affectedEntryIds: [ENTRY_ID], savedViewsChanged: 0 });
    expect(credentialWebsites(harness.getDocument().entries[0]!)).toEqual([NORMALIZED_URL]);
    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.capturedChanges).toHaveLength(1);
    expect(harness.capturedChanges[0]?.map((change) => change.relativePath)).toEqual([
      `vaults/${VAULT_ID}.vaulta`,
      'audit.vaulta',
    ]);
    expect(harness.installCommittedDocuments).toHaveBeenCalledTimes(1);
    expect(harness.prepareAuditRecord).toHaveBeenCalledWith({
      type: 'data-quality-fixed',
      vaultId: VAULT_ID,
      entryId: ENTRY_ID,
    });
    for (const buffer of harness.capturedBuffers[0] ?? []) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }

    await expect(
      harness.controller.applyDataQualityFix({ token: preview.token }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(harness.execute).toHaveBeenCalledTimes(1);
  });

  it('verbraucht eine stale Vorschau ohne Schreib- oder Cache-Commit', async () => {
    const harness = createHarness(qualityDocument());
    const report = await harness.controller.scanDataQuality({
      vaultId: VAULT_ID,
      requestId: REQUEST_ID,
    });
    const finding = report.findings.find(
      (candidate) => candidate.code === 'url-needs-normalization',
    );
    expect(finding).toBeDefined();
    const preview = await harness.controller.previewDataQualityFix({
      vaultId: VAULT_ID,
      findingId: finding!.id,
    });

    const externallyChanged = harness.getDocument();
    externallyChanged.entries[0]!.updatedAt = '2026-07-26T12:05:00.000Z';
    externallyChanged.updatedAt = '2026-07-26T12:05:00.000Z';
    harness.setDocument(externallyChanged);

    await expect(
      harness.controller.applyDataQualityFix({ token: preview.token }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      harness.controller.applyDataQualityFix({ token: preview.token }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(harness.execute).not.toHaveBeenCalled();
    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
    expect(credentialWebsites(harness.getDocument().entries[0]!)).toEqual([RAW_URL]);
  });

  it('invalidiert Befunde und Vorschau-Token unmittelbar beim Sperren', async () => {
    const harness = createHarness(qualityDocument());
    const report = await harness.controller.scanDataQuality({
      vaultId: VAULT_ID,
      requestId: REQUEST_ID,
    });
    const finding = report.findings.find(
      (candidate) => candidate.code === 'url-needs-normalization',
    );
    expect(finding).toBeDefined();
    const preview = await harness.controller.previewDataQualityFix({
      vaultId: VAULT_ID,
      findingId: finding!.id,
    });

    await harness.controller.lock();

    expect(privateMap(harness.controller, 'dataQualityFindings').size).toBe(0);
    expect(privateMap(harness.controller, 'pendingDataQualityFixes').size).toBe(0);
    await expect(
      harness.controller.applyDataQualityFix({ token: preview.token }),
    ).rejects.toMatchObject({ code: 'LOCKED' });
    expect(harness.execute).not.toHaveBeenCalled();
  });
});

describe('VaultaController automatische Papierkorb-Retention', () => {
  it('committet Vault, Anhangsloeschung und Audit in genau einer Transaktion', async () => {
    const document = retentionDocument();
    const harness = createHarness(document);
    const sweep = privateMethod<(context: RetentionSweepContext, epoch: number) => Promise<void>>(
      harness.controller,
      'sweepExpiredTrash',
    );

    await sweep.call(
      harness.controller,
      {
        cutoff: '2026-06-01T00:00:00.000Z',
        assertActive: vi.fn(),
      },
      harness.epoch,
    );

    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.capturedChanges[0]?.map((change) => change.relativePath)).toEqual([
      `vaults/${VAULT_ID}.vaulta`,
      `attachments/${VAULT_ID}/${ATTACHMENT_ID}.vatt`,
      'audit.vaulta',
    ]);
    expect(harness.prepareAuditRecords).toHaveBeenCalledWith([
      {
        type: 'trash-auto-purged',
        vaultId: VAULT_ID,
        entryId: ENTRY_ID,
      },
    ]);
    expect(harness.getDocument().entries.map((entry) => entry.id)).toEqual([
      '00000000-0000-4000-8000-000000000105',
    ]);
    expect(harness.installCommittedDocuments).toHaveBeenCalledTimes(1);
    for (const buffer of harness.capturedBuffers[0] ?? []) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }
  });

  it('installiert bei Transaktionsfehler keinen teilweisen Retention-Zustand', async () => {
    const original = retentionDocument();
    const harness = createHarness(original);
    harness.execute.mockRejectedValueOnce(new Error('synthetischer Commit-Abbruch'));
    const sweep = privateMethod<(context: RetentionSweepContext, epoch: number) => Promise<void>>(
      harness.controller,
      'sweepExpiredTrash',
    );

    await expect(
      sweep.call(
        harness.controller,
        {
          cutoff: '2026-06-01T00:00:00.000Z',
          assertActive: vi.fn(),
        },
        harness.epoch,
      ),
    ).rejects.toThrow('synthetischer Commit-Abbruch');

    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
    expect(harness.getDocument()).toEqual(original);
    for (const buffer of harness.capturedBuffers[0] ?? []) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }
  });

  it('bricht einen laufenden Retention-Sweep nach Sperren vor dem Commit ab', async () => {
    const harness = createHarness(retentionDocument());
    const vaults = privateValue<{ readVault(vaultId: string): Promise<VaultDocument> }>(
      harness.controller,
      'vaults',
    );
    vi.spyOn(vaults, 'readVault').mockImplementationOnce(async () => {
      const snapshot = harness.getDocument();
      await harness.controller.lock();
      return snapshot;
    });
    const sweep = privateMethod<(context: RetentionSweepContext, epoch: number) => Promise<void>>(
      harness.controller,
      'sweepExpiredTrash',
    );

    await expect(
      sweep.call(
        harness.controller,
        {
          cutoff: '2026-06-01T00:00:00.000Z',
          assertActive: vi.fn(),
        },
        harness.epoch,
      ),
    ).rejects.toMatchObject({ code: 'LOCKED' });

    expect(harness.execute).not.toHaveBeenCalled();
    expect(harness.prepareAuditRecords).not.toHaveBeenCalled();
    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
  });
});

function createHarness(initialDocument: VaultDocument): ControllerHarness {
  let document = structuredClone(initialDocument);
  let profileUnlocked = true;
  const capturedChanges: MultiFileChange[][] = [];
  const capturedBuffers: Buffer[][] = [];
  const installCommittedDocuments = vi.fn((documents: readonly VaultDocument[]) => {
    document = structuredClone(documents[0]!);
  });
  const prepareAuditRecord = vi.fn(() =>
    Promise.resolve({
      events: [],
      relativePath: 'audit.vaulta',
      contents: Buffer.from('encrypted-audit-generation'),
      expectedSha256: null,
    }),
  );
  const prepareAuditRecords = vi.fn(() =>
    Promise.resolve({
      events: [],
      relativePath: 'audit.vaulta',
      contents: Buffer.from('encrypted-audit-generation'),
      expectedSha256: null,
    }),
  );
  const execute = vi.fn(
    async (changes: readonly MultiFileChange[], options: MultiFileExecuteOptions = {}) => {
      capturedChanges.push([...changes]);
      capturedBuffers.push(
        changes.flatMap((change) => (change.type === 'write' ? [change.contents] : [])),
      );
      await options.assertAuthorized?.();
      return {
        transactionId: '00000000-0000-4000-8000-000000000199',
        changedPaths: changes.map((change) => change.relativePath),
      };
    },
  );
  const controller = new VaultaController({
    rootDir: 'C:\\vaulta-controller-quality-test',
    version: 'test',
    getWindow: () =>
      ({
        isDestroyed: () => false,
        webContents: { send: vi.fn() },
        setContentProtection: vi.fn(),
      }) as never,
    getOrigin: () => 'https://vaulta.invalid',
    onStateChanged: vi.fn(),
    onLocked: vi.fn(),
    onClipboardCleared: vi.fn(),
    onBackgroundWarning: vi.fn(),
  });
  controllers.push(controller);

  Reflect.set(controller, 'profile', {
    isUnlocked: () => profileUnlocked,
    hasProfile: () => Promise.resolve(true),
    lock: () => {
      profileUnlocked = false;
    },
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    prepareProtectedMetadataUpdates: vi.fn(),
  });
  Reflect.set(controller, 'vaults', {
    readVault: vi.fn(() => Promise.resolve(structuredClone(document))),
    listVaults: vi.fn(() =>
      Promise.resolve([
        {
          id: document.id,
          name: document.name,
          color: document.color,
          entryCount: document.entries.filter((entry) => entry.deletedAt === null).length,
          deletedCount: document.entries.filter((entry) => entry.deletedAt !== null).length,
          updatedAt: document.updatedAt,
        },
      ]),
    ),
    withExclusiveVaults: <T>(_vaultIds: readonly string[], operation: () => Promise<T>) =>
      operation(),
    prepareDocumentWrite: vi.fn((nextDocument: VaultDocument) =>
      Promise.resolve({
        document: structuredClone(nextDocument),
        relativePath: `vaults/${nextDocument.id}.vaulta`,
        contents: Buffer.from(JSON.stringify(nextDocument)),
        expectedSha256: 'c'.repeat(64),
      }),
    ),
    installCommittedDocuments,
    clearCachedDocuments: vi.fn(),
  });
  Reflect.set(controller, 'attachments', {
    listStoredAttachmentReferences: vi.fn(() =>
      Promise.resolve([{ vaultId: VAULT_ID, attachmentId: ATTACHMENT_ID }]),
    ),
    readAuthenticatedMetadata: vi.fn(() =>
      Promise.resolve({ size: 99, sha256: AUTHENTICATED_HASH }),
    ),
  });
  Reflect.set(controller, 'audit', {
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    prepareRecord: prepareAuditRecord,
    prepareRecords: prepareAuditRecords,
  });
  Reflect.set(controller, 'transactions', { execute });
  Reflect.set(
    controller,
    'emitState',
    vi.fn(() => Promise.resolve({})),
  );

  const authentication = privateValue<AuthenticationHarness>(controller, 'authentication');
  const epoch = authentication.begin();
  authentication.complete(profileUnlocked, epoch);

  return {
    controller,
    epoch,
    getDocument: () => structuredClone(document),
    setDocument: (nextDocument) => {
      document = structuredClone(nextDocument);
    },
    execute,
    installCommittedDocuments,
    prepareAuditRecord,
    prepareAuditRecords,
    capturedChanges,
    capturedBuffers,
  };
}

function qualityDocument(): VaultDocument {
  const entry = baseEntry({
    websites: [RAW_URL],
    deletedAt: null,
  });
  entry.attachments = [
    {
      id: ATTACHMENT_ID,
      name: 'synthetic.bin',
      mediaType: 'application/octet-stream',
      size: 12,
      sha256: STORED_HASH,
      createdAt: '2026-07-20T12:00:00.000Z',
      previewable: false,
    },
  ];
  return documentWith([entry]);
}

function retentionDocument(): VaultDocument {
  const expired = baseEntry({
    deletedAt: '2026-05-01T00:00:00.000Z',
    websites: ['https://expired.example.test'],
  });
  expired.attachments = [
    {
      id: ATTACHMENT_ID,
      name: 'synthetic.bin',
      mediaType: 'application/octet-stream',
      size: 12,
      sha256: STORED_HASH,
      createdAt: '2026-04-01T00:00:00.000Z',
      previewable: false,
    },
  ];
  const recent = baseEntry({
    id: '00000000-0000-4000-8000-000000000105',
    deletedAt: '2026-07-20T00:00:00.000Z',
    websites: ['https://recent.example.test'],
  });
  return documentWith([expired, recent]);
}

function documentWith(entries: VaultEntry[]): VaultDocument {
  return {
    formatVersion: 2,
    id: VAULT_ID,
    name: 'Testtresor',
    color: '#22d3c5',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-07-20T12:00:00.000Z',
    folders: [],
    entries,
  };
}

function baseEntry(options: {
  id?: string;
  websites: string[];
  deletedAt: string | null;
}): VaultEntry {
  return {
    id: options.id ?? ENTRY_ID,
    vaultId: VAULT_ID,
    title: 'Synthetischer Testeintrag',
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    attachments: [],
    data: {
      type: 'credential',
      value: {
        username: 'synthetic-user@example.test',
        password: SYNTHETIC_SECRET,
        websites: options.websites,
        appNames: [],
      },
    },
    lifecycle: createDefaultEntryLifecycleMetadata(),
    createdAt: '2026-07-20T12:00:00.000Z',
    updatedAt: '2026-07-20T12:00:00.000Z',
    secretChangedAt: '2026-07-20T12:00:00.000Z',
    lastUsedAt: null,
    deletedAt: options.deletedAt,
  };
}

function credentialWebsites(entry: VaultEntry): string[] {
  if (entry.data.type !== 'credential') throw new Error('Unerwarteter Testeintragstyp.');
  return entry.data.value.websites;
}

function privateValue<T>(controller: VaultaController, key: string): T {
  return Reflect.get(controller, key) as T;
}

function privateMethod<T extends (...args: never[]) => unknown>(
  controller: VaultaController,
  key: string,
): T {
  return privateValue<T>(controller, key);
}

function privateMap(controller: VaultaController, key: string): Map<unknown, unknown> {
  return privateValue<Map<unknown, unknown>>(controller, key);
}
