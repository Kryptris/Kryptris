import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  MultiFileChange,
  MultiFileExecuteOptions,
} from '../../src/main/storage/multi-file-transaction';
import type { EntryViewService } from '../../src/main/services/entry-view-service';
import type { SecurityScanOptions } from '../../src/main/services/security-check-service';
import { VaultaController } from '../../src/main/vaulta-controller';
import {
  DEFAULT_SETTINGS,
  type EntryListQuery,
  type VaultDocument,
  type VaultEntry,
} from '../../src/shared/models';
import { credentialEntry } from './service-fixtures';

const electronMocks = vi.hoisted(() => ({
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
  showSaveDialog: vi.fn(),
}));

vi.mock('electron', () => ({
  clipboard: electronMocks.clipboard,
  desktopCapturer: { getSources: vi.fn(() => Promise.resolve([])) },
  dialog: {
    showOpenDialog: vi.fn(),
    showSaveDialog: electronMocks.showSaveDialog,
  },
  nativeImage: { createFromPath: vi.fn() },
}));

const VAULT_ID = '00000000-0000-4000-8000-000000000301';
const controllers: VaultaController[] = [];

afterEach(() => {
  for (const controller of controllers) controller.dispose();
  controllers.length = 0;
  vi.restoreAllMocks();
});

describe('VaultaController Sicherheitszentrale', () => {
  it('aggregiert den revisionsgebundenen lokalen Stand ohne doppelte Berechnung', async () => {
    const harness = createHarness();
    const security = privateValue<{ scanAsync: (...args: never[]) => Promise<unknown> }>(
      harness.controller,
      'security',
    );
    const scanSpy = vi.spyOn(security, 'scanAsync');

    const first = await harness.controller.scanSecurityCenter({
      requestId: '00000000-0000-4000-8000-000000000302',
    });
    const cached = await harness.controller.scanSecurityCenter({
      requestId: '00000000-0000-4000-8000-000000000303',
    });

    expect(cached).toEqual(first);
    expect(first.cards).toHaveLength(8);
    expect(first.networkUsed).toBe(false);
    expect(scanSpy).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(first)).not.toContain('synthetic-secret');
    expect(harness.progressEvents.some((event) => event.job === 'security-center')).toBe(true);
  });

  it('committet Integritätsstatus und redigiertes Audit atomar und verwirft Report-Token beim Sperren', async () => {
    const harness = createHarness();

    const report = await harness.controller.scanIntegrity({
      requestId: '00000000-0000-4000-8000-000000000304',
      refresh: true,
    });

    expect(report).toMatchObject({
      success: true,
      scannedVaults: 1,
      scannedEntries: 0,
      scannedAttachments: 0,
      findings: [],
      networkUsed: false,
    });
    expect(Object.keys(report)).not.toContain('path');
    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.changes[0]?.map((change) => change.relativePath)).toEqual([
      'profile.json',
      'audit.vaulta',
    ]);
    expect(harness.prepareAudit).toHaveBeenCalledWith({
      type: 'integrity-check-completed',
    });
    expect(privateMap(harness.controller, 'pendingIntegrityReports').size).toBe(1);
    for (const buffer of harness.buffers[0] ?? []) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }

    await harness.controller.lock();

    expect(privateMap(harness.controller, 'pendingIntegrityReports').size).toBe(0);
    await expect(
      harness.controller.saveIntegrityReport({ reportId: report.reportId }),
    ).rejects.toMatchObject({ code: 'LOCKED' });
  });
  it('liefert lokale Erinnerungskategorien nur als abbrechbare, namenlose Aggregate', async () => {
    const dueRotation = credentialEntry({
      id: '00000000-0000-4000-8000-000000000311',
      vaultId: VAULT_ID,
      title: 'Darf nicht in der Erinnerung erscheinen',
    });
    dueRotation.lifecycle = {
      ...dueRotation.lifecycle,
      rotationIntervalDays: 90,
      nextRotationDate: '2000-01-01',
    };
    const dueExpiry: VaultEntry = {
      ...credentialEntry({
        id: '00000000-0000-4000-8000-000000000312',
        vaultId: VAULT_ID,
        title: 'Auch dieser Titel bleibt lokal',
      }),
      data: {
        type: 'credit-card',
        value: {
          cardName: 'Synthetische Karte',
          cardholder: '',
          number: '',
          expiryMonth: 12,
          expiryYear: 2030,
          cvc: '',
          pin: '',
          issuer: '',
          cardType: '',
          billingAddress: '',
          servicePhone: '',
          website: '',
        },
      },
      lifecycle: {
        ...credentialEntry().lifecycle,
        expiryReminderDate: '2000-01-01',
      },
    };
    const harness = createHarness({ ...emptyDocument(), entries: [dueRotation, dueExpiry] });
    Reflect.set(harness.controller, 'settings', {
      ...DEFAULT_SETTINGS,
      localReminders: { rotation: true, expiry: true, backup: false },
    });

    const snapshot = await harness.controller.getLocalReminderSnapshot();

    expect(snapshot).toEqual({ rotationDue: 1, expirationDue: 1, staleBackup: false });
    expect(JSON.stringify(snapshot)).not.toContain('Darf nicht in der Erinnerung erscheinen');
    await expect(
      harness.controller.getLocalReminderSnapshot(() => {
        throw new Error('Erinnerung abgebrochen');
      }),
    ).rejects.toThrow('Erinnerung abgebrochen');
  });

  it('verwirft eine späte 10.000-Eintrag-Kaltliste beim Sperren samt Sicherheitscache', async () => {
    const entries = Array.from({ length: 10_000 }, (_value, index) =>
      credentialEntry({
        id: '00000000-0000-4000-8000-' + String(index).padStart(12, '0'),
        vaultId: VAULT_ID,
        title: 'Synthetischer Eintrag ' + index,
      }),
    );
    const harness = createHarness({ ...emptyDocument(), entries });
    const entryViews = privateValue<EntryViewService>(harness.controller, 'entryViews');
    let announceScanStarted: () => void = () => undefined;
    const scanStarted = new Promise<void>((resolve) => {
      announceScanStarted = resolve;
    });
    let releaseScan: () => void = () => undefined;
    const waitForRelease = new Promise<void>((resolve) => {
      releaseScan = resolve;
    });
    let lateResultReturned = false;
    const scanAsync = vi.fn(
      async (activeEntries: readonly VaultEntry[], options: SecurityScanOptions) => {
        expect(activeEntries).toHaveLength(10_000);
        expect(options.batchSize).toBe(10);
        expect(options.assertAuthorized).toEqual(expect.any(Function));
        options.assertAuthorized?.();
        announceScanStarted();
        await waitForRelease;
        lateResultReturned = true;
        return {
          generatedAt: '2026-07-26T12:00:00.000Z',
          score: 100,
          counts: { good: activeEntries.length, info: 0, warning: 0, critical: 0 },
          findings: [],
          networkUsed: false,
        };
      },
    );
    Reflect.set(entryViews, 'security', { scanAsync });

    const pending = harness.controller.listEntries(listQuery(VAULT_ID));
    await scanStarted;
    await harness.controller.lock();
    releaseScan();

    await expect(pending).rejects.toMatchObject({ code: 'LOCKED' });
    expect(lateResultReturned).toBe(true);
    expect(scanAsync).toHaveBeenCalledTimes(1);
    expect(privateSecurityReports(entryViews).size).toBe(0);
    await expect(harness.controller.listEntries(listQuery(VAULT_ID))).rejects.toMatchObject({
      code: 'LOCKED',
    });
    expect(scanAsync).toHaveBeenCalledTimes(1);
  });
});

function createHarness(inputDocument?: VaultDocument): {
  controller: VaultaController;
  execute: ReturnType<typeof vi.fn>;
  prepareAudit: ReturnType<typeof vi.fn>;
  changes: MultiFileChange[][];
  buffers: Buffer[][];
  progressEvents: Array<{ job: string }>;
} {
  let unlocked = true;
  const changes: MultiFileChange[][] = [];
  const buffers: Buffer[][] = [];
  const progressEvents: Array<{ job: string }> = [];
  const document = inputDocument ?? emptyDocument();
  const preparedProfile = vi.fn(() =>
    Promise.resolve({
      relativePath: 'profile.json',
      contents: Buffer.from('encrypted-profile-generation'),
      expectedSha256: 'a'.repeat(64),
    }),
  );
  const prepareAudit = vi.fn(() =>
    Promise.resolve({
      events: [],
      relativePath: 'audit.vaulta',
      contents: Buffer.from('encrypted-audit-generation'),
      expectedSha256: 'b'.repeat(64),
    }),
  );
  const execute = vi.fn(
    async (input: readonly MultiFileChange[], options: MultiFileExecuteOptions = {}) => {
      changes.push([...input]);
      buffers.push(input.flatMap((change) => (change.type === 'write' ? [change.contents] : [])));
      await options.assertAuthorized?.();
      return {
        transactionId: '00000000-0000-4000-8000-000000000399',
        changedPaths: input.map((change) => change.relativePath),
      };
    },
  );
  const controller = new VaultaController({
    rootDir: 'C:\\vaulta-controller-security-test',
    version: 'test',
    getWindow: () =>
      ({
        isDestroyed: () => false,
        setContentProtection: vi.fn(),
        webContents: {
          send: vi.fn((_channel: string, event: { job: string }) => {
            progressEvents.push(event);
          }),
        },
      }) as never,
    getOrigin: () => 'https://vaulta.invalid',
    onStateChanged: vi.fn(),
    onLocked: vi.fn(),
    onClipboardCleared: vi.fn(),
    onBackgroundWarning: vi.fn(),
  });
  controllers.push(controller);

  Reflect.set(controller, 'profile', {
    isUnlocked: () => unlocked,
    lock: () => {
      unlocked = false;
    },
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    readPublicHeader: () =>
      Promise.resolve({
        format: 'vaulta-profile',
        version: 1,
        profileId: '00000000-0000-4000-8000-000000000398',
        createdAt: '2026-07-26T10:00:00.000Z',
        updatedAt: '2026-07-26T12:00:00.000Z',
        access: {
          kdf: {
            salt: 'c2FsdC1mb3ItdGVzdGluZw==',
            parameters: {
              algorithm: 'argon2id',
              memorySizeKiB: 262_144,
              iterations: 3,
              parallelism: 1,
              hashLength: 32,
            },
          },
        },
      }),
    getProtectedMetadata: () => Promise.resolve(null),
    getPublicFactorData: () => Promise.resolve({}),
    prepareProtectedMetadataUpdates: preparedProfile,
  });
  Reflect.set(controller, 'factors', {
    getStatus: () =>
      Promise.resolve({
        totpEnabled: true,
        securityKeys: [],
        recoveryEnabled: false,
      }),
    clearPending: vi.fn(),
  });
  Reflect.set(controller, 'vaults', {
    listVaults: () =>
      Promise.resolve([
        {
          id: document.id,
          name: document.name,
          color: document.color,
          entryCount: 0,
          deletedCount: 0,
          updatedAt: document.updatedAt,
        },
      ]),
    readVault: () => Promise.resolve(structuredClone(document)),
    inspectStoredVaultInventory: () =>
      Promise.resolve({ vaultIds: [VAULT_ID], invalidEntryCount: 0 }),
    listRegisteredVaultIds: () => Promise.resolve([VAULT_ID]),
    readVaultFresh: () => Promise.resolve(structuredClone(document)),
    withExclusiveVaults: <T>(_vaultIds: readonly string[], operation: () => Promise<T>) =>
      operation(),
    clearCachedDocuments: vi.fn(),
  });
  Reflect.set(controller, 'attachments', {
    listStoredAttachmentReferences: () => Promise.resolve([]),
    inspectStoredAttachmentInventory: () =>
      Promise.resolve({ references: [], invalidEntryCount: 0 }),
  });
  Reflect.set(controller, 'audit', {
    inspectStoredDocumentFormatVersion: () => Promise.resolve(1),
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    prepareRecord: prepareAudit,
  });
  Reflect.set(controller, 'transactions', { execute });
  Reflect.set(
    controller,
    'emitState',
    vi.fn(() => Promise.resolve({})),
  );

  const authentication = privateValue<{
    begin(): number;
    complete(profileUnlocked: boolean, epoch: number): void;
  }>(controller, 'authentication');
  const epoch = authentication.begin();
  authentication.complete(true, epoch);

  return { controller, execute, prepareAudit, changes, buffers, progressEvents };
}

function emptyDocument(): VaultDocument {
  return {
    formatVersion: 2,
    id: VAULT_ID,
    name: 'Synthetischer Tresor',
    color: '#22d3c5',
    createdAt: '2026-07-26T10:00:00.000Z',
    updatedAt: '2026-07-26T12:00:00.000Z',
    folders: [],
    entries: [],
  };
}

function privateValue<T>(controller: VaultaController, key: string): T {
  return Reflect.get(controller, key) as T;
}

function privateMap(controller: VaultaController, key: string): Map<unknown, unknown> {
  return privateValue<Map<unknown, unknown>>(controller, key);
}

function privateSecurityReports(entryViews: EntryViewService): Map<string, unknown> {
  return Reflect.get(entryViews, 'securityReports') as Map<string, unknown>;
}

function listQuery(vaultId: string): EntryListQuery {
  return {
    vaultId,
    search: '',
    view: 'all',
    types: [],
    tags: [],
    folderId: null,
    security: [],
  };
}
