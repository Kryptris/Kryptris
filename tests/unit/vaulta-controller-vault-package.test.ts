import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import type * as FsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { EncryptAttachmentBufferToStagingInput } from '../../src/main/services/attachment-service';
import type {
  ExportVaultPackageInput,
  PreparedVaultPackageImport,
  PrepareVaultPackageImportInput,
} from '../../src/main/services/vault-package-service';
import type {
  MultiFileChange,
  MultiFileExecuteOptions,
  MultiFileTransactionService,
} from '../../src/main/storage/multi-file-transaction';
import { VaultaController } from '../../src/main/vaulta-controller';
import {
  createDefaultEntryLifecycleMetadata,
  type AttachmentMetadata,
  type VaultDocument,
} from '../../src/shared/models';

const electronMocks = vi.hoisted(() => ({
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
  showOpenDialog: vi.fn(),
  showSaveDialog: vi.fn(),
}));

const fsMocks = vi.hoisted(() => ({
  lstat: vi.fn(),
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  fsMocks.lstat.mockImplementation(actual.lstat);
  return { ...actual, lstat: fsMocks.lstat };
});

vi.mock('electron', () => ({
  clipboard: electronMocks.clipboard,
  desktopCapturer: { getSources: vi.fn(() => Promise.resolve([])) },
  dialog: {
    showOpenDialog: electronMocks.showOpenDialog,
    showSaveDialog: electronMocks.showSaveDialog,
  },
  nativeImage: { createFromPath: vi.fn() },
}));

const PACKAGE_PASSWORD = 'Synthetisches-Paketpasswort-713';
const SOURCE_VAULT_ID = '00000000-0000-4000-8000-000000000711';
const ATTACHMENT_ID = '00000000-0000-4000-8000-000000000712';
const FIXTURE_TIME = '2026-08-09T10:00:00.000Z';
const STAGING_ID = '00000000-0000-4000-8000-000000000713';

interface AuthenticationHarness {
  begin(): number;
  complete(profileUnlocked: boolean, epoch: number): void;
}

interface PackagePlanHarness {
  readonly document: VaultDocument;
  readonly attachmentContents: Buffer;
  readonly dispose: ReturnType<typeof vi.fn>;
  readonly assertUsable: ReturnType<typeof vi.fn>;
}

interface ControllerHarness {
  readonly controller: VaultaController;
  readonly rootDir: string;
  readonly packagePath: string;
  readonly exportPath: string;
  readonly inspectPackage: ReturnType<typeof vi.fn>;
  readonly prepareImport: ReturnType<typeof vi.fn>;
  readonly exportPackage: ReturnType<typeof vi.fn>;
  readonly execute: ReturnType<typeof vi.fn>;
  readonly installCommittedDocuments: ReturnType<typeof vi.fn>;
  readonly emitState: ReturnType<typeof vi.fn>;
  readonly invalidateLocalJobs: ReturnType<typeof vi.fn>;
  readonly clearCachedDocuments: ReturnType<typeof vi.fn>;
  readonly clearEntryViewCaches: ReturnType<typeof vi.fn>;
  readonly capturedChanges: MultiFileChange[][];
  readonly capturedBuffers: Buffer[][];
  reauthenticate(): void;
  failNextTransaction(error: Error): void;
  lockImmediatelyAfterNextCommittedTransaction(): void;
  lastPlan(): PackagePlanHarness | null;
}

interface CreateHarnessOptions {
  readonly rootDir?: string;
  readonly useRealTransactions?: boolean;
}

const harnesses: ControllerHarness[] = [];

beforeEach(() => {
  electronMocks.clipboard.readText.mockReturnValue('');
  electronMocks.showOpenDialog.mockReset();
  electronMocks.showSaveDialog.mockReset();
  fsMocks.lstat.mockClear();
});

afterEach(async () => {
  vi.useRealTimers();
  for (const harness of harnesses) harness.controller.dispose();
  await Promise.all(
    harnesses.splice(0).map((harness) => rm(harness.rootDir, { recursive: true, force: true })),
  );
  vi.restoreAllMocks();
});

describe('VaultaController Tresor-Pakete', () => {
  it('uebergibt Export- und Vorschaupfade nur im Main-Prozess und gibt pfadlose DTOs zurueck', async () => {
    const harness = await createHarness();
    electronMocks.showSaveDialog.mockResolvedValueOnce({
      canceled: false,
      filePath: harness.exportPath,
    });
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });

    const exported = await harness.controller.exportVaultPackage({
      vaultId: SOURCE_VAULT_ID,
      exportPassword: PACKAGE_PASSWORD,
      includeAttachments: true,
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });

    expect(harness.exportPackage).toHaveBeenCalledWith(
      expect.objectContaining({
        vaultId: SOURCE_VAULT_ID,
        destination: harness.exportPath,
        replaceExisting: true,
      }),
    );
    expect(harness.inspectPackage).toHaveBeenCalledWith(
      expect.objectContaining({ packagePath: harness.packagePath }),
    );
    expect(exported).toEqual({
      createdAt: FIXTURE_TIME,
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');
    const { token, ...previewData } = preview;
    expect(typeof token).toBe('string');
    expect(previewData).toEqual({
      createdAt: FIXTURE_TIME,
      vaultName: 'Anonymisierte Reise',
      color: '#2DD4BF',
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
      nameConflict: false,
    });
    expect(Object.keys(exported ?? {}).sort()).toEqual(
      ['createdAt', 'entryCount', 'attachmentCount', 'includesAttachments'].sort(),
    );
    expect(Object.keys(preview ?? {}).sort()).toEqual(
      [
        'token',
        'createdAt',
        'vaultName',
        'color',
        'entryCount',
        'attachmentCount',
        'includesAttachments',
        'nameConflict',
      ].sort(),
    );
    expect(JSON.stringify({ exported, preview })).not.toContain(harness.packagePath);
    expect(JSON.stringify({ exported, preview })).not.toContain(harness.exportPath);
    expect(JSON.stringify({ exported, preview })).not.toContain(PACKAGE_PASSWORD);
  });

  it('entwertet eine Paketvorschau beim Sperren, bevor ein Import vorbereitet wird', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');

    await harness.controller.lock();
    harness.reauthenticate();

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(harness.prepareImport).not.toHaveBeenCalled();
  });

  it('entwertet eine abgelaufene Paketvorschau, bevor entschluesselte Daten verarbeitet werden', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(FIXTURE_TIME));
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');

    vi.advanceTimersByTime(5 * 60 * 1_000 + 1);

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(harness.prepareImport).not.toHaveBeenCalled();
  });

  it('rollt einen fehlgeschlagenen Paketimport ohne Cache-Publikation oder Rest-Staging zurueck', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');
    harness.failNextTransaction(new Error('synthetischer atomarer Paketimport-Abbruch'));

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).rejects.toThrow('synthetischer atomarer Paketimport-Abbruch');

    const plan = harness.lastPlan();
    expect(plan).not.toBeNull();
    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
    expect(
      harness.capturedChanges[0]?.map((change) => ({
        type: change.type,
        relativePath: change.relativePath,
      })),
    ).toEqual([
      { type: 'write', relativePath: `vaults/${plan?.document.id}.vaulta` },
      { type: 'write', relativePath: 'profile.json' },
      {
        type: 'write-file',
        relativePath: `attachments/${plan?.document.id}/${ATTACHMENT_ID}.vatt`,
      },
      { type: 'write', relativePath: 'audit.vaulta' },
    ]);
    expect(plan?.dispose).toHaveBeenCalledTimes(1);
    expect(plan?.attachmentContents.every((byte) => byte === 0)).toBe(true);
    for (const buffer of harness.capturedBuffers[0] ?? []) {
      expect(buffer.every((byte) => byte === 0)).toBe(true);
    }
    expect(await packageStagingEntries(harness.rootDir)).toEqual([]);
  });

  it('liefert den committen Paketimport trotz fehlgeschlagener Nachbereinigung erfolgreich zurueck', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');

    const cleanup = vi.fn(() =>
      Promise.reject(new Error('synthetische unsichere Staging-Nachbereinigung')),
    );
    Reflect.set(harness.controller, 'removeVaultPackageImportStagingDirectory', cleanup);

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).resolves.toMatchObject({
      vaultName: 'Anonymisierte Kopie',
      entryCount: 1,
      attachmentCount: 1,
    });

    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.installCommittedDocuments).toHaveBeenCalledTimes(1);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(
      Reflect.get(harness.controller, 'onBackgroundWarning') as ReturnType<typeof vi.fn>,
    ).toHaveBeenCalledWith(expect.stringContaining('Verschluesselte temporaere Paketdaten'));
  });

  it('liefert den committen Paketimport bei einem Lock direkt danach erfolgreich zurueck und publiziert keine neuen Geheim-Caches', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');
    harness.lockImmediatelyAfterNextCommittedTransaction();

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).resolves.toMatchObject({
      vaultName: 'Anonymisierte Kopie',
      entryCount: 1,
      attachmentCount: 1,
    });

    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
    expect(harness.invalidateLocalJobs).not.toHaveBeenCalled();
    expect(harness.clearCachedDocuments).toHaveBeenCalledTimes(1);
    expect(harness.clearEntryViewCaches).toHaveBeenCalledTimes(1);
    expect(harness.emitState).toHaveBeenCalledTimes(1);
  });

  it('liefert den committen Paketimport trotz fehlgeschlagener UI-Nachbereitung erfolgreich zurueck', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');
    harness.emitState.mockRejectedValueOnce(
      new Error('synthetische UI-Nachbereitung fehlgeschlagen'),
    );

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).resolves.toMatchObject({
      vaultName: 'Anonymisierte Kopie',
      entryCount: 1,
      attachmentCount: 1,
    });

    expect(harness.installCommittedDocuments).toHaveBeenCalledTimes(1);
    expect(harness.clearCachedDocuments).toHaveBeenCalledTimes(1);
    expect(harness.clearEntryViewCaches).toHaveBeenCalledTimes(2);
    expect(
      Reflect.get(harness.controller, 'onBackgroundWarning') as ReturnType<typeof vi.fn>,
    ).toHaveBeenCalledWith(expect.stringContaining('lokale Ansicht'));
  });

  it('lehnt nicht absolute und symlinkartige Drag-and-drop-Pfade vor jedem Lesen ab', async () => {
    const harness = await createHarness();
    const vaults = Reflect.get(harness.controller, 'vaults') as {
      readVault?: ReturnType<typeof vi.fn>;
    };
    const readVault = vi.fn();
    vaults.readVault = readVault;

    await expect(
      harness.controller.previewDroppedImport({
        vaultId: SOURCE_VAULT_ID,
        sourcePath: 'relative-import.csv',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(fsMocks.lstat).not.toHaveBeenCalled();
    expect(readVault).not.toHaveBeenCalled();

    fsMocks.lstat.mockResolvedValueOnce({
      isSymbolicLink: () => true,
      isFile: () => true,
    });
    await expect(
      harness.controller.previewDroppedImport({
        vaultId: SOURCE_VAULT_ID,
        sourcePath: harness.packagePath,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(fsMocks.lstat).toHaveBeenCalledWith(harness.packagePath);
    expect(readVault).not.toHaveBeenCalled();
  });

  it('verweigert einen direkten oder Junction-Alias als Paket-Staging vor jedem Schreiben', async () => {
    const harness = await createHarness();
    const securityDirectory = path.join(harness.rootDir, 'security');
    const outside = path.join(harness.rootDir, 'outside');
    const sentinel = path.join(outside, 'sentinel.txt');
    await mkdir(securityDirectory, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');

    const linked = await createDirectoryAlias(
      outside,
      path.join(securityDirectory, '.vault-package-import-staging'),
    );
    if (!linked) return;

    const create = privateValue<() => Promise<unknown>>(
      harness.controller,
      'createVaultPackageImportStagingDirectory',
    );
    await expect(create.call(harness.controller)).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readdir(outside)).resolves.toEqual(['sentinel.txt']);
  });

  it('importiert ein Paket mit echter Transaktion unter einem Parent-Junction-Alias', async () => {
    const outerRoot = await mkdtemp(path.join(os.tmpdir(), 'kryptris-parent-junction-'));
    const physicalParent = path.join(outerRoot, 'physical-parent');
    const physicalRoot = path.join(physicalParent, 'app-root');
    const parentAlias = path.join(outerRoot, 'parent-alias');
    const logicalRoot = path.join(parentAlias, 'app-root');
    await mkdir(physicalRoot, { recursive: true, mode: 0o700 });
    const linked = await createDirectoryAlias(physicalParent, parentAlias);
    if (!linked) {
      await rm(outerRoot, { recursive: true, force: true });
      return;
    }
    const harness = await createHarness({ rootDir: logicalRoot, useRealTransactions: true });

    try {
      const transactions = privateValue<MultiFileTransactionService>(
        harness.controller,
        'transactions',
      );
      const execute = vi.spyOn(transactions, 'execute');
      electronMocks.showOpenDialog.mockResolvedValueOnce({
        canceled: false,
        filePaths: [harness.packagePath],
      });
      const preview = await harness.controller.previewVaultPackage({
        exportPassword: PACKAGE_PASSWORD,
      });
      if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');

      await expect(
        harness.controller.importVaultPackage({
          token: preview.token,
          exportPassword: PACKAGE_PASSWORD,
          targetVaultName: 'Anonymisierte Parent-Junction-Kopie',
          allowNameConflict: false,
        }),
      ).resolves.toMatchObject({
        vaultName: 'Anonymisierte Parent-Junction-Kopie',
        attachmentCount: 1,
      });

      const writeFileChange = execute.mock.calls[0]?.[0].find(
        (change): change is Extract<MultiFileChange, { type: 'write-file' }> =>
          change.type === 'write-file',
      );
      expect(writeFileChange?.sourcePath).toBeDefined();
      expect(writeFileChange?.sourcePath).not.toContain(parentAlias);
      await expect(packageStagingEntries(physicalRoot)).resolves.toEqual([]);
    } finally {
      await rm(parentAlias, { recursive: true, force: true });
      await rm(outerRoot, { recursive: true, force: true });
    }
  });

  it('verwirft einen spaet eingehängten Paket-Staging-Alias ohne externe Dateien zu bereinigen', async () => {
    const harness = await createHarness();
    const create = privateValue<() => Promise<PackageStagingCapability>>(
      harness.controller,
      'createVaultPackageImportStagingDirectory',
    );
    const staging = await create.call(harness.controller);
    const outside = path.join(harness.rootDir, 'outside');
    const sentinel = path.join(outside, 'sentinel.txt');
    const externalAttachment = path.join(outside, `${ATTACHMENT_ID}.vatt`);
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');
    await writeFile(externalAttachment, 'extern-verschluesselt-bleibt-erhalten');
    await rm(staging.directory, { recursive: true, force: true });
    const linked = await createDirectoryAlias(outside, staging.directory);
    if (!linked) return;

    const remove = privateValue<(input: PackageStagingCapability) => Promise<void>>(
      harness.controller,
      'removeVaultPackageImportStagingDirectory',
    );
    await expect(remove.call(harness.controller, staging)).rejects.toMatchObject({
      code: 'UNSAFE_PATH',
    });
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readFile(externalAttachment, 'utf8')).resolves.toBe(
      'extern-verschluesselt-bleibt-erhalten',
    );
  });

  it('verwirft Aliasreste beim Start-Cleanup ohne externe Paketdateien zu loeschen', async () => {
    const harness = await createHarness();
    const stagingRoot = path.join(harness.rootDir, 'security', '.vault-package-import-staging');
    const outside = path.join(harness.rootDir, 'outside');
    const sentinel = path.join(outside, 'sentinel.txt');
    const externalAttachment = path.join(outside, `${ATTACHMENT_ID}.vatt`);
    await mkdir(stagingRoot, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');
    await writeFile(externalAttachment, 'extern-verschluesselt-bleibt-erhalten');
    const linked = await createDirectoryAlias(outside, path.join(stagingRoot, STAGING_ID));
    if (!linked) return;

    const cleanup = privateValue<() => Promise<void>>(
      harness.controller,
      'cleanupVaultPackageImportStaging',
    );
    await expect(cleanup.call(harness.controller)).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readFile(externalAttachment, 'utf8')).resolves.toBe(
      'extern-verschluesselt-bleibt-erhalten',
    );
  });

  it('verwirft einen Swap vor dem Transaktions-Source-Read und behaelt externe Dateien', async () => {
    const harness = await createHarness();
    const outside = path.join(harness.rootDir, 'outside');
    const probeAlias = path.join(harness.rootDir, 'junction-probe');
    const sentinel = path.join(outside, 'sentinel.txt');
    const externalAttachment = path.join(outside, `${ATTACHMENT_ID}.vatt`);
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');
    await writeFile(externalAttachment, 'extern-verschluesselt-bleibt-erhalten');
    const supported = await createDirectoryAlias(outside, probeAlias);
    if (!supported) return;
    await rm(probeAlias, { recursive: true, force: true });

    let stagingDirectory: string | null = null;
    Reflect.set(harness.controller, 'attachments', {
      encryptBufferToStaging: async (
        input: EncryptAttachmentBufferToStagingInput,
      ): Promise<AttachmentMetadata> => {
        stagingDirectory = input.stagingDirectory;
        await writeFile(input.stagingPath, 'synthetischer-verschluesselter-anhang', {
          mode: 0o600,
        });
        return {
          id: input.targetAttachmentId,
          name: input.name,
          mediaType: input.mediaType,
          size: input.contents.length,
          sha256: createHash('sha256').update(input.contents).digest('hex'),
          createdAt: input.createdAt ?? FIXTURE_TIME,
          previewable: true,
        };
      },
    });
    Reflect.set(harness.controller, 'transactions', {
      execute: async (
        _changes: readonly MultiFileChange[],
        options: MultiFileExecuteOptions = {},
      ) => {
        if (stagingDirectory === null) throw new Error('Paket-Staging wurde nicht angelegt.');
        await rm(stagingDirectory, { recursive: true, force: true });
        const linked = await createDirectoryAlias(outside, stagingDirectory);
        if (!linked) throw new Error('Die kontrollierte Junction konnte nicht angelegt werden.');
        await options.assertAuthorized?.();
        return {
          transactionId: '00000000-0000-4000-8000-000000000799',
          changedPaths: [],
        };
      },
    });
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.packagePath],
    });
    const preview = await harness.controller.previewVaultPackage({
      exportPassword: PACKAGE_PASSWORD,
    });
    if (preview === null) throw new Error('Die synthetische Paketvorschau fehlt.');

    await expect(
      harness.controller.importVaultPackage({
        token: preview.token,
        exportPassword: PACKAGE_PASSWORD,
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    ).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
    expect(harness.installCommittedDocuments).not.toHaveBeenCalled();
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readFile(externalAttachment, 'utf8')).resolves.toBe(
      'extern-verschluesselt-bleibt-erhalten',
    );
  });
});

interface PackageStagingCapability {
  readonly directory: string;
}

async function createHarness(options: CreateHarnessOptions = {}): Promise<ControllerHarness> {
  const rootDir =
    options.rootDir ??
    (await mkdtemp(path.join(os.tmpdir(), 'kryptris-controller-vault-package-')));
  await mkdir(rootDir, { recursive: true, mode: 0o700 });
  const packagePath = path.resolve(rootDir, 'synthetisches-paket.kryptris-vault');
  const exportPath = path.resolve(rootDir, 'exportziel.kryptris-vault');
  await writeFile(packagePath, 'synthetic encrypted package fixture', { mode: 0o600 });

  let profileUnlocked = true;
  let transactionFailure: Error | null = null;
  let afterNextCommittedTransaction: (() => Promise<void>) | null = null;
  let latestPlan: PackagePlanHarness | null = null;
  const capturedChanges: MultiFileChange[][] = [];
  const capturedBuffers: Buffer[][] = [];
  const inspectPackage = vi.fn(() =>
    Promise.resolve({
      createdAt: FIXTURE_TIME,
      vaultName: 'Anonymisierte Reise',
      color: '#2DD4BF',
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
      nameConflict: false,
    }),
  );
  const exportPackage = vi.fn((input: ExportVaultPackageInput) =>
    Promise.resolve({
      path: input.destination,
      createdAt: FIXTURE_TIME,
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
    }),
  );
  const prepareImport = vi.fn((input: PrepareVaultPackageImportInput) => {
    const attachmentContents = Buffer.from('synthetic-main-process-attachment-data', 'utf8');
    const attachment = {
      attachmentId: ATTACHMENT_ID,
      name: 'anonymisierte-anlage.txt',
      mediaType: 'text/plain',
      size: attachmentContents.length,
      sha256: createHash('sha256').update(attachmentContents).digest('hex'),
      createdAt: FIXTURE_TIME,
      previewable: true,
      contents: attachmentContents,
    };
    const document = packageDocument(input.targetVaultId, input.targetVaultName, attachment);
    const dispose = vi.fn(() => attachmentContents.fill(0));
    const assertUsable = vi.fn();
    latestPlan = { document, attachmentContents, dispose, assertUsable };
    return Promise.resolve({
      document,
      attachments: [attachment],
      preview: {
        createdAt: FIXTURE_TIME,
        vaultName: 'Anonymisierte Reise',
        color: '#2DD4BF',
        entryCount: 1,
        attachmentCount: 1,
        includesAttachments: true,
        nameConflict: false,
      },
      dispose,
      assertUsable,
    } as unknown as PreparedVaultPackageImport);
  });
  const prepareNewVaultWrite = vi.fn((document: VaultDocument) =>
    Promise.resolve({
      document: structuredClone(document),
      relativePath: `vaults/${document.id}.vaulta`,
      contents: Buffer.from('synthetic-encrypted-new-vault'),
      expectedSha256: null,
      profileWrite: {
        relativePath: 'profile.json',
        contents: Buffer.from('synthetic-encrypted-profile'),
        expectedSha256: null,
      },
      vaultKey: Buffer.alloc(32, 0x5a),
    }),
  );
  const installCommittedDocuments = vi.fn();
  const clearCachedDocuments = vi.fn();
  const emitState = vi.fn(() => Promise.resolve({}));
  const invalidateLocalJobs = vi.fn();
  const clearEntryViewCaches = vi.fn();
  const encryptBufferToStaging = vi.fn(
    async (input: EncryptAttachmentBufferToStagingInput): Promise<AttachmentMetadata> => {
      await mkdir(path.dirname(input.stagingPath), { recursive: true, mode: 0o700 });
      await writeFile(input.stagingPath, 'synthetic-encrypted-attachment', { mode: 0o600 });
      return {
        id: input.targetAttachmentId,
        name: input.name,
        mediaType: input.mediaType,
        size: input.contents.length,
        sha256: createHash('sha256').update(input.contents).digest('hex'),
        createdAt: input.createdAt ?? FIXTURE_TIME,
        previewable: true,
      };
    },
  );
  const execute = vi.fn(
    async (changes: readonly MultiFileChange[], options: MultiFileExecuteOptions = {}) => {
      capturedChanges.push([...changes]);
      capturedBuffers.push(
        changes.flatMap((change) => (change.type === 'write' ? [change.contents] : [])),
      );
      await options.assertAuthorized?.();
      if (transactionFailure !== null) {
        const error = transactionFailure;
        transactionFailure = null;
        throw error;
      }
      const afterCommit = afterNextCommittedTransaction;
      afterNextCommittedTransaction = null;
      await afterCommit?.();
      return {
        transactionId: '00000000-0000-4000-8000-000000000799',
        changedPaths: changes.map((change) => change.relativePath),
      };
    },
  );
  const prepareAuditRecord = vi.fn(() =>
    Promise.resolve({
      events: [],
      relativePath: 'audit.vaulta',
      contents: Buffer.from('synthetic-encrypted-audit'),
      expectedSha256: null,
    }),
  );
  const controller = new VaultaController({
    rootDir,
    version: 'test',
    getWindow: () =>
      ({
        isDestroyed: () => false,
        webContents: { send: vi.fn() },
        setContentProtection: vi.fn(),
      }) as never,
    getOrigin: () => 'https://kryptris.invalid',
    onStateChanged: vi.fn(),
    onLocked: vi.fn(),
    onClipboardCleared: vi.fn(),
    onBackgroundWarning: vi.fn(),
  });

  Reflect.set(controller, 'profile', {
    isUnlocked: () => profileUnlocked,
    lock: () => {
      profileUnlocked = false;
    },
    withExclusiveWrite: <T>(operation: () => Promise<T>): Promise<T> => operation(),
  });
  Reflect.set(controller, 'vaults', {
    listVaults: vi.fn(() => Promise.resolve([])),
    withExclusiveRegistryWrite: <T>(operation: () => Promise<T>): Promise<T> => operation(),
    withExclusiveVaults: <T>(_: readonly string[], operation: () => Promise<T>): Promise<T> =>
      operation(),
    prepareNewVaultWrite,
    installCommittedDocuments,
    clearCachedDocuments,
  });
  Reflect.set(controller, 'attachments', { encryptBufferToStaging });
  Reflect.set(controller, 'vaultPackages', { inspectPackage, exportPackage, prepareImport });
  Reflect.set(controller, 'audit', {
    record: vi.fn(() => Promise.resolve()),
    withExclusiveWrite: <T>(operation: () => Promise<T>): Promise<T> => operation(),
    prepareRecord: prepareAuditRecord,
  });
  if (!options.useRealTransactions) Reflect.set(controller, 'transactions', { execute });
  Reflect.set(controller, 'emitState', emitState);
  Reflect.set(controller, 'localJobs', { invalidate: invalidateLocalJobs, clear: vi.fn() });
  Reflect.set(controller, 'entryViews', { clearCaches: clearEntryViewCaches });

  const authentication = privateValue<AuthenticationHarness>(controller, 'authentication');
  const reauthenticate = () => {
    profileUnlocked = true;
    const epoch = authentication.begin();
    authentication.complete(true, epoch);
  };
  reauthenticate();

  const harness: ControllerHarness = {
    controller,
    rootDir,
    packagePath,
    exportPath,
    inspectPackage,
    prepareImport,
    exportPackage,
    execute,
    installCommittedDocuments,
    emitState,
    invalidateLocalJobs,
    clearCachedDocuments,
    clearEntryViewCaches,
    capturedChanges,
    capturedBuffers,
    reauthenticate,
    failNextTransaction: (error) => {
      transactionFailure = error;
    },
    lockImmediatelyAfterNextCommittedTransaction: () => {
      afterNextCommittedTransaction = () => controller.lock();
    },
    lastPlan: () => latestPlan,
  };
  harnesses.push(harness);
  return harness;
}

function packageDocument(
  vaultId: string,
  vaultName: string,
  attachment: {
    attachmentId: string;
    name: string;
    mediaType: string;
    size: number;
    sha256: string;
    createdAt: string;
    previewable: boolean;
  },
): VaultDocument {
  return {
    formatVersion: 2,
    id: vaultId,
    name: vaultName,
    color: '#2DD4BF',
    createdAt: FIXTURE_TIME,
    updatedAt: FIXTURE_TIME,
    folders: [],
    entries: [
      {
        id: '00000000-0000-4000-8000-000000000714',
        vaultId,
        title: 'Anonymisierte Buchung',
        folderId: null,
        tags: [],
        favorite: false,
        note: '',
        customFields: [],
        attachments: [
          {
            id: attachment.attachmentId,
            name: attachment.name,
            mediaType: attachment.mediaType,
            size: attachment.size,
            sha256: attachment.sha256,
            createdAt: attachment.createdAt,
            previewable: attachment.previewable,
          },
        ],
        data: {
          type: 'credential',
          value: {
            username: 'anonymisiert@example.invalid',
            password: 'synthetic-package-value-not-real',
            websites: [],
            appNames: [],
          },
        },
        lifecycle: createDefaultEntryLifecycleMetadata(),
        createdAt: FIXTURE_TIME,
        updatedAt: FIXTURE_TIME,
        secretChangedAt: FIXTURE_TIME,
        lastUsedAt: null,
        deletedAt: null,
      },
    ],
  };
}

async function packageStagingEntries(rootDir: string): Promise<string[]> {
  const directory = path.resolve(rootDir, 'security', '.vault-package-import-staging');
  return readdir(directory).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
}

async function createDirectoryAlias(target: string, alias: string): Promise<boolean> {
  try {
    await symlink(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') return false;
    throw error;
  }
}

function privateValue<T>(controller: VaultaController, key: string): T {
  return Reflect.get(controller, key) as T;
}
