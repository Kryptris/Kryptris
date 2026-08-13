import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  BREACH_LIST_INDEX_RELATIVE_PATH,
  BREACH_LIST_NAMESPACE,
  type BreachListManifest,
} from '../../src/main/services/breach-list-manifest-service';
import type {
  OfflineBreachIndexBuildInput,
  OfflineBreachIndexBuildResult,
  OfflineBreachScanInput,
  OfflineBreachScanResult,
} from '../../src/main/services/offline-breach-service';
import type {
  MultiFileChange,
  MultiFileExecuteOptions,
} from '../../src/main/storage/multi-file-transaction';
import { VaultaController } from '../../src/main/vaulta-controller';
import {
  createDefaultEntryLifecycleMetadata,
  type BreachListStatusDto,
  type BreachScanReportDto,
  type VaultDocument,
  type VaultEntry,
} from '../../src/shared/models';

const electronMocks = vi.hoisted(() => ({
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
  showOpenDialog: vi.fn(),
}));

vi.mock('electron', () => ({
  clipboard: electronMocks.clipboard,
  desktopCapturer: { getSources: vi.fn(() => Promise.resolve([])) },
  dialog: {
    showOpenDialog: electronMocks.showOpenDialog,
    showSaveDialog: vi.fn(),
  },
  nativeImage: { createFromPath: vi.fn() },
}));

const VAULT_ID = '00000000-0000-4000-8000-000000000301';
const ENTRY_ID = '00000000-0000-4000-8000-000000000302';
const IMPORT_REQUEST_ID = '00000000-0000-4000-8000-000000000303';
const SCAN_REQUEST_ID = '00000000-0000-4000-8000-000000000304';
const CANCEL_REQUEST_ID = '00000000-0000-4000-8000-000000000305';
const SOURCE_LABEL = 'Anonymisierte lokale Testliste';
const SOURCE_DATE = '2026-07-01';
const SOURCE_SHA256 = 'a'.repeat(64);
const INDEX_SHA256 = 'b'.repeat(64);
const SYNTHETIC_SECRET = 'synthetic-breach-password-not-real';
const SYNTHETIC_SOURCE_DIGEST = 'C'.repeat(40);
const INDEX_CONTENTS = Buffer.from('synthetic-offline-index-without-real-secrets', 'utf8');

interface AuthenticationHarness {
  begin(): number;
  complete(profileUnlocked: boolean, epoch: number): void;
}

interface LocalJobHarness {
  abortAndWait(jobKey: string): Promise<boolean>;
  activeCount(): number;
}

interface ControllerHarness {
  readonly controller: VaultaController;
  readonly rootDir: string;
  readonly sourcePath: string;
  readonly indexPath: string;
  readonly buildIndex: ReturnType<
    typeof vi.fn<(input: OfflineBreachIndexBuildInput) => Promise<OfflineBreachIndexBuildResult>>
  >;
  readonly scan: ReturnType<
    typeof vi.fn<(input: OfflineBreachScanInput) => Promise<OfflineBreachScanResult>>
  >;
  readonly execute: ReturnType<
    typeof vi.fn<
      (
        changes: readonly MultiFileChange[],
        options?: MultiFileExecuteOptions,
      ) => Promise<{ transactionId: string; changedPaths: readonly string[] }>
    >
  >;
  readonly prepareProtectedMetadataUpdates: ReturnType<typeof vi.fn>;
  readonly prepareAuditRecord: ReturnType<typeof vi.fn>;
  readonly capturedChanges: MultiFileChange[][];
  readonly capturedBuffers: Buffer[][];
  getManifest(): BreachListManifest | null;
  getDocument(): VaultDocument;
  setDocument(document: VaultDocument): void;
  failNextTransaction(error: Error): void;
}

const harnesses: ControllerHarness[] = [];

beforeEach(() => {
  electronMocks.clipboard.readText.mockReturnValue('');
  electronMocks.showOpenDialog.mockReset();
});

afterEach(async () => {
  for (const harness of harnesses) harness.controller.dispose();
  await Promise.all(
    harnesses.map((harness) => rm(harness.rootDir, { recursive: true, force: true })),
  );
  harnesses.length = 0;
  vi.restoreAllMocks();
});

describe('VaultaController Offline-Datenleckliste', () => {
  it('committet Index, geschuetztes Profil und Audit beim Import in einer Transaktion', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.sourcePath],
    });

    const status = await harness.controller.importBreachList({
      requestId: IMPORT_REQUEST_ID,
      sourceLabel: `  ${SOURCE_LABEL}  `,
      sourceDate: SOURCE_DATE,
    });

    expect(status).toMatchObject({
      state: 'ready',
      sourceLabel: SOURCE_LABEL,
      sourceDate: SOURCE_DATE,
      recordCount: 1,
      corpusSha256: SOURCE_SHA256,
      networkUsed: false,
    });
    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(
      harness.capturedChanges[0]?.map((change) => ({
        type: change.type,
        relativePath: change.relativePath,
      })),
    ).toEqual([
      { type: 'write-file', relativePath: BREACH_LIST_INDEX_RELATIVE_PATH },
      { type: 'write', relativePath: 'profile.json' },
      { type: 'write', relativePath: 'audit.vaulta' },
    ]);
    expect(harness.prepareProtectedMetadataUpdates).toHaveBeenCalledTimes(1);
    expect(harness.prepareAuditRecord).toHaveBeenCalledWith({
      type: 'breach-list-imported',
    });
    expect(await readFile(harness.indexPath)).toEqual(INDEX_CONTENTS);
    expect(harness.getManifest()).toMatchObject({
      sourceLabel: SOURCE_LABEL,
      sourceDate: SOURCE_DATE,
      indexSha256: INDEX_SHA256,
    });
    expect(await breachImportStagingFiles(harness.rootDir)).toEqual([]);
    expectBuffersErased(harness.capturedBuffers[0]);
  });

  it('hinterlaesst bei einem fehlgeschlagenen Import weder Teilzustand noch Stagingdatei', async () => {
    const harness = await createHarness();
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.sourcePath],
    });
    harness.failNextTransaction(new Error('synthetischer Commit-Abbruch'));

    await expect(
      harness.controller.importBreachList({
        requestId: IMPORT_REQUEST_ID,
        sourceLabel: SOURCE_LABEL,
        sourceDate: SOURCE_DATE,
      }),
    ).rejects.toThrow('synthetischer Commit-Abbruch');

    expect(harness.execute).toHaveBeenCalledTimes(1);
    expect(await fileExists(harness.indexPath)).toBe(false);
    expect(harness.getManifest()).toBeNull();
    expect(await breachImportStagingFiles(harness.rootDir)).toEqual([]);
    expectBuffersErased(harness.capturedBuffers[0]);
  });

  it('folgt beim Start-Cleanup keinem Junction- oder Symlink-Sicherheitsverzeichnis', async () => {
    const harness = await createHarness();
    const actualSecurityDirectory = path.resolve(harness.rootDir, 'actual-security');
    const aliasedSecurityDirectory = path.resolve(harness.rootDir, 'security');
    const stagingSentinel = path.resolve(
      actualSecurityDirectory,
      '.breach-import-00000000-0000-4000-8000-000000000398.tmp',
    );
    await mkdir(actualSecurityDirectory);
    await writeFile(stagingSentinel, 'nicht-loeschen', { encoding: 'utf8' });
    await symlink(
      actualSecurityDirectory,
      aliasedSecurityDirectory,
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    const cleanup = privateValue<() => Promise<void>>(
      harness.controller,
      'cleanupBreachImportStaging',
    );
    await expect(cleanup.call(harness.controller)).rejects.toMatchObject({
      code: 'UNSAFE_PATH',
    });

    expect(await readFile(stagingSentinel, 'utf8')).toBe('nicht-loeschen');
  });

  it('legt auch beim Import keine Stagingdatei ueber einen Junction- oder Symlink-Alias an', async () => {
    const harness = await createHarness();
    const actualSecurityDirectory = path.resolve(harness.rootDir, 'actual-security');
    const aliasedSecurityDirectory = path.resolve(harness.rootDir, 'security');
    await mkdir(actualSecurityDirectory);
    await symlink(
      actualSecurityDirectory,
      aliasedSecurityDirectory,
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.sourcePath],
    });

    await expect(
      harness.controller.importBreachList({
        requestId: IMPORT_REQUEST_ID,
        sourceLabel: SOURCE_LABEL,
        sourceDate: SOURCE_DATE,
      }),
    ).rejects.toMatchObject({ code: 'UNSAFE_PATH' });

    expect(harness.buildIndex).not.toHaveBeenCalled();
    expect(await readdir(actualSecurityDirectory)).toEqual([]);
  });

  it('gibt beim Scan ausschliesslich redigierte Befunde ohne Passwort, Hash oder Dateipfad aus', async () => {
    const harness = await createHarness(configuredManifest());
    harness.scan.mockImplementationOnce((input) =>
      Promise.resolve({
        checkedCandidates: input.candidates.length,
        matches: input.candidates.map((candidate) => ({ ...candidate.reference })),
        networkUsed: false,
      }),
    );

    const report = await harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });

    const scanInput = harness.scan.mock.calls[0]?.[0];
    expect(scanInput?.expectedIndexSha256).toBe(INDEX_SHA256);
    expect(scanInput?.indexPath).toBe(harness.indexPath);
    expect(scanInput?.candidates).toEqual([
      {
        reference: {
          vaultId: VAULT_ID,
          entryId: ENTRY_ID,
          updatedAt: '2026-07-20T12:00:00.000Z',
        },
        password: SYNTHETIC_SECRET,
        deletedAt: null,
      },
    ]);
    expect(report).toMatchObject({
      checkedEntries: 1,
      checkedPasswords: 1,
      networkUsed: false,
      findings: [
        {
          vaultId: VAULT_ID,
          vaultName: 'Synthetischer Tresor',
          entryId: ENTRY_ID,
          entryTitle: 'Synthetischer Zugang',
          entryUpdatedAt: '2026-07-20T12:00:00.000Z',
          code: 'known-breached-password',
          severity: 'critical',
        },
      ],
    });
    expect(Object.keys(report.findings[0]!).sort()).toEqual(
      [
        'id',
        'vaultId',
        'vaultName',
        'entryId',
        'entryTitle',
        'entryUpdatedAt',
        'code',
        'severity',
      ].sort(),
    );
    expectRedactedReport(report, harness);
    expectRedactedReport(
      privateValue<BreachScanReportDto>(harness.controller, 'lastBreachReport'),
      harness,
    );
  });

  it.each([
    {
      mutation: 'Eintragsänderung',
      apply: (document: VaultDocument) => {
        document.entries[0]!.title = 'Geänderter synthetischer Zugang';
        document.entries[0]!.updatedAt = '2026-07-21T12:00:00.000Z';
        document.updatedAt = '2026-07-21T12:00:00.000Z';
      },
    },
    {
      mutation: 'Passwortänderung',
      apply: (document: VaultDocument) => {
        if (document.entries[0]!.data.type !== 'credential') {
          throw new Error('Unerwartete Testfixture.');
        }
        document.entries[0]!.data.value.password = 'changed-synthetic-password-not-real';
        document.entries[0]!.updatedAt = '2026-07-22T12:00:00.000Z';
        document.updatedAt = '2026-07-22T12:00:00.000Z';
      },
    },
    {
      mutation: 'Papierkorbverschiebung',
      apply: (document: VaultDocument) => {
        document.entries[0]!.deletedAt = '2026-07-23T12:00:00.000Z';
        document.entries[0]!.updatedAt = '2026-07-23T12:00:00.000Z';
        document.updatedAt = '2026-07-23T12:00:00.000Z';
      },
    },
    {
      mutation: 'endgültige Löschung',
      apply: (document: VaultDocument) => {
        document.entries = [];
        document.updatedAt = '2026-07-24T12:00:00.000Z';
      },
    },
  ])(
    'verwendet einen Befundreport nach $mutation nicht im Sicherheitscenter wieder',
    async ({ apply }) => {
      const manifest = configuredManifest();
      const harness = await createHarness(manifest);
      await harness.controller.scanBreachList({
        requestId: SCAN_REQUEST_ID,
        refresh: true,
      });
      const changedDocument = harness.getDocument();
      apply(changedDocument);
      harness.setDocument(changedDocument);

      const report = currentBreachReport(
        harness.controller,
        [changedDocument],
        manifest,
        readyBreachStatus(),
      );

      expect(report).toBeNull();
      expect(privateValue(harness.controller, 'lastBreachReport')).toBeNull();
      expect(privateValue(harness.controller, 'lastBreachReportRevision')).toBeNull();
    },
  );

  it('verwirft den Befundreport nach einem Restore ohne lokalen Index', async () => {
    const manifest = configuredManifest();
    const harness = await createHarness(manifest);
    await harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });
    await rm(harness.indexPath, { force: true });

    const status = await harness.controller.getBreachListStatus();
    const report = currentBreachReport(
      harness.controller,
      [harness.getDocument()],
      manifest,
      status,
    );

    expect(status.state).toBe('missing');
    expect(report).toBeNull();
    expect(privateValue(harness.controller, 'lastBreachReportRevision')).toBeNull();
  });

  it('bricht einen laufenden Scan vor einem Import sofort ab und startet den Dateiaufbau erst danach', async () => {
    const harness = await createHarness(configuredManifest());
    const started = deferred<void>();
    const events: string[] = [];
    harness.scan.mockImplementationOnce(async (input) => {
      events.push('scan-started');
      started.resolve();
      try {
        await new Promise<void>((resolve) => {
          input.context?.signal?.addEventListener('abort', () => resolve(), { once: true });
        });
        await input.context?.assertAuthorized?.();
        throw new Error('Abbruch-Assertion hätte werfen müssen.');
      } finally {
        events.push('scan-finished');
      }
    });
    harness.buildIndex.mockImplementationOnce(async (input) => {
      events.push('import-build');
      await writeFile(input.stagingPath, INDEX_CONTENTS, { mode: 0o600 });
      return buildResult(input);
    });
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.sourcePath],
    });

    const pendingScan = harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });
    await started.promise;
    const pendingImport = harness.controller.importBreachList({
      requestId: IMPORT_REQUEST_ID,
      sourceLabel: SOURCE_LABEL,
      sourceDate: SOURCE_DATE,
    });

    await expect(pendingScan).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(pendingImport).resolves.toMatchObject({ state: 'ready' });
    expect(events).toEqual(['scan-started', 'scan-finished', 'import-build']);
  });

  it('laesst einen Scan erst nach dem atomaren Import auf den Index zugreifen', async () => {
    const harness = await createHarness();
    const buildStarted = deferred<void>();
    const releaseBuild = deferred<void>();
    harness.buildIndex.mockImplementationOnce(async (input) => {
      buildStarted.resolve();
      await releaseBuild.promise;
      await writeFile(input.stagingPath, INDEX_CONTENTS, { mode: 0o600 });
      return buildResult(input);
    });
    electronMocks.showOpenDialog.mockResolvedValueOnce({
      canceled: false,
      filePaths: [harness.sourcePath],
    });

    const pendingImport = harness.controller.importBreachList({
      requestId: IMPORT_REQUEST_ID,
      sourceLabel: SOURCE_LABEL,
      sourceDate: SOURCE_DATE,
    });
    await buildStarted.promise;
    const pendingScan = harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(harness.scan).not.toHaveBeenCalled();
    releaseBuild.resolve();
    await expect(pendingImport).resolves.toMatchObject({ state: 'ready' });
    await expect(pendingScan).resolves.toMatchObject({ networkUsed: false });
    expect(harness.scan).toHaveBeenCalledTimes(1);
  });

  it('entfernt Index, Profilverweis und Audit atomar und invalidiert abhaengige Jobs', async () => {
    const manifest = configuredManifest();
    const harness = await createHarness(manifest);
    const localJobs = privateValue<LocalJobHarness>(harness.controller, 'localJobs');
    const abortAndWait = vi.spyOn(localJobs, 'abortAndWait');

    const status = await harness.controller.removeBreachList();

    expect(status).toEqual({
      state: 'not-configured',
      sourceLabel: null,
      sourceDate: null,
      importedAt: null,
      recordCount: 0,
      corpusSha256: null,
      networkUsed: false,
    });
    expect(
      harness.capturedChanges[0]?.map((change) => ({
        type: change.type,
        relativePath: change.relativePath,
      })),
    ).toEqual([
      { type: 'delete', relativePath: BREACH_LIST_INDEX_RELATIVE_PATH },
      { type: 'write', relativePath: 'profile.json' },
      { type: 'write', relativePath: 'audit.vaulta' },
    ]);
    expect(harness.prepareProtectedMetadataUpdates).toHaveBeenCalledWith({
      [BREACH_LIST_NAMESPACE]: null,
    });
    expect(harness.prepareAuditRecord).toHaveBeenCalledWith({
      type: 'breach-list-removed',
    });
    expect(abortAndWait.mock.calls.map(([jobKey]) => jobKey)).toEqual([
      'breach-scan',
      'breach-import',
      'security-center',
    ]);
    expect(await fileExists(harness.indexPath)).toBe(false);
    expect(harness.getManifest()).toBeNull();
    expectBuffersErased(harness.capturedBuffers[0]);
  });

  it('bewahrt bei einem fehlgeschlagenen Entfernen den vollstaendigen Ausgangszustand', async () => {
    const manifest = configuredManifest();
    const harness = await createHarness(manifest);
    const originalIndex = await readFile(harness.indexPath);
    harness.failNextTransaction(new Error('synthetischer Remove-Abbruch'));

    await expect(harness.controller.removeBreachList()).rejects.toThrow(
      'synthetischer Remove-Abbruch',
    );

    expect(await readFile(harness.indexPath)).toEqual(originalIndex);
    expect(harness.getManifest()).toEqual(manifest);
    await expect(harness.controller.getBreachListStatus()).resolves.toMatchObject({
      state: 'ready',
      corpusSha256: SOURCE_SHA256,
    });
    expectBuffersErased(harness.capturedBuffers[0]);
  });

  it('bricht einen laufenden Scan vor dem Entfernen sofort ab', async () => {
    const harness = await createHarness(configuredManifest());
    const started = deferred<void>();
    harness.scan.mockImplementationOnce(async (input) => {
      started.resolve();
      await new Promise<void>((resolve) => {
        input.context?.signal?.addEventListener('abort', () => resolve(), { once: true });
      });
      await input.context?.assertAuthorized?.();
      throw new Error('Abbruch-Assertion hätte werfen müssen.');
    });

    const pendingScan = harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });
    await started.promise;
    const pendingRemove = harness.controller.removeBreachList();

    await expect(pendingScan).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(pendingRemove).resolves.toMatchObject({ state: 'not-configured' });
    expect(await fileExists(harness.indexPath)).toBe(false);
    expect(harness.getManifest()).toBeNull();
  });

  it('bricht einen laufenden Scan ueber die Request-ID ab und installiert keinen Teilreport', async () => {
    const harness = await createHarness(configuredManifest());
    const started = deferred<void>();
    const release = deferred<void>();
    harness.scan.mockImplementationOnce(async (input) => {
      started.resolve();
      await release.promise;
      await input.context?.yieldControl?.();
      return {
        checkedCandidates: input.candidates.length,
        matches: input.candidates.map((candidate) => ({ ...candidate.reference })),
        networkUsed: false,
      };
    });

    const pendingScan = harness.controller.scanBreachList({
      requestId: CANCEL_REQUEST_ID,
      refresh: true,
    });
    await started.promise;

    expect(harness.controller.cancelLocalJob(CANCEL_REQUEST_ID)).toBe(true);
    release.resolve();
    await expect(pendingScan).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(privateValue(harness.controller, 'lastBreachReport')).toBeNull();
    expect(privateValue<LocalJobHarness>(harness.controller, 'localJobs').activeCount()).toBe(0);
  });

  it('loescht den letzten Befundreport beim unmittelbaren Sperren', async () => {
    const harness = await createHarness(configuredManifest());
    harness.scan.mockImplementationOnce((input) =>
      Promise.resolve({
        checkedCandidates: input.candidates.length,
        matches: input.candidates.map((candidate) => ({ ...candidate.reference })),
        networkUsed: false,
      }),
    );
    await harness.controller.scanBreachList({
      requestId: SCAN_REQUEST_ID,
      refresh: true,
    });
    expect(privateValue(harness.controller, 'lastBreachReport')).not.toBeNull();

    await harness.controller.lock();

    expect(privateValue(harness.controller, 'lastBreachReport')).toBeNull();
    expect(privateValue<LocalJobHarness>(harness.controller, 'localJobs').activeCount()).toBe(0);
    await expect(
      harness.controller.scanBreachList({
        requestId: CANCEL_REQUEST_ID,
        refresh: true,
      }),
    ).rejects.toMatchObject({ code: 'LOCKED' });
  });
});

async function createHarness(
  initialManifest: BreachListManifest | null = null,
): Promise<ControllerHarness> {
  const rootDir = await mkdtemp(path.join(os.tmpdir(), 'kryptris-controller-breach-'));
  const sourcePath = path.resolve(rootDir, 'anonymized-source.txt');
  const indexPath = path.resolve(rootDir, ...BREACH_LIST_INDEX_RELATIVE_PATH.split('/'));
  await writeFile(sourcePath, `${SYNTHETIC_SOURCE_DIGEST}:1\n`, { mode: 0o600 });
  if (initialManifest !== null) {
    await mkdir(path.dirname(indexPath), { recursive: true, mode: 0o700 });
    await writeFile(indexPath, INDEX_CONTENTS, { mode: 0o600 });
  }

  let profileUnlocked = true;
  let storedManifest = initialManifest === null ? null : structuredClone(initialManifest);
  let pendingManifest: BreachListManifest | null | undefined;
  let transactionFailure: Error | null = null;
  const capturedChanges: MultiFileChange[][] = [];
  const capturedBuffers: Buffer[][] = [];
  const preparedProfileUpdates: Record<string, unknown>[] = [];
  const preparedAuditEvents: Record<string, unknown>[] = [];

  const buildIndex = vi.fn(
    async (input: OfflineBreachIndexBuildInput): Promise<OfflineBreachIndexBuildResult> => {
      await input.context?.assertAuthorized?.();
      await writeFile(input.stagingPath, INDEX_CONTENTS, { mode: 0o600 });
      const sourceInfo = await stat(input.sourcePath);
      return {
        format: 'sha1-count-v1',
        version: 1,
        recordCount: 1,
        sourceSha256: SOURCE_SHA256,
        indexSha256: INDEX_SHA256,
        indexBytes: INDEX_CONTENTS.length,
        sourceBytes: sourceInfo.size,
        stagingPath: input.stagingPath,
      };
    },
  );
  const scan = vi.fn((input: OfflineBreachScanInput): Promise<OfflineBreachScanResult> =>
    Promise.resolve({
      checkedCandidates: input.candidates.length,
      matches: [],
      networkUsed: false,
    }),
  );
  const prepareProtectedMetadataUpdates = vi.fn((updates: Record<string, unknown>) => {
    preparedProfileUpdates.push(structuredClone(updates));
    if (Object.hasOwn(updates, BREACH_LIST_NAMESPACE)) {
      const next = updates[BREACH_LIST_NAMESPACE];
      pendingManifest =
        next === null || next === undefined ? null : (structuredClone(next) as BreachListManifest);
    }
    return Promise.resolve({
      relativePath: 'profile.json',
      contents: Buffer.from('encrypted-profile-generation'),
      expectedSha256: null,
    });
  });
  const prepareAuditRecord = vi.fn((event: Record<string, unknown>) => {
    preparedAuditEvents.push(structuredClone(event));
    return Promise.resolve({
      events: [],
      relativePath: 'audit.vaulta',
      contents: Buffer.from('encrypted-audit-generation'),
      expectedSha256: null,
    });
  });
  const execute = vi.fn(
    async (
      changes: readonly MultiFileChange[],
      options: MultiFileExecuteOptions = {},
    ): Promise<{ transactionId: string; changedPaths: readonly string[] }> => {
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

      for (const change of changes) {
        const target = path.resolve(rootDir, ...change.relativePath.split('/'));
        if (change.type === 'delete') {
          await rm(target, { force: true });
          continue;
        }
        await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
        if (change.type === 'write-file') await copyFile(change.sourcePath, target);
        else await writeFile(target, change.contents, { mode: 0o600 });
      }
      if (pendingManifest !== undefined) {
        storedManifest = pendingManifest === null ? null : structuredClone(pendingManifest);
        pendingManifest = undefined;
      }
      return {
        transactionId: '00000000-0000-4000-8000-000000000399',
        changedPaths: changes.map((change) => change.relativePath),
      };
    },
  );

  let document = breachDocument();
  const controller = new VaultaController({
    rootDir,
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

  Reflect.set(controller, 'profile', {
    isUnlocked: () => profileUnlocked,
    hasProfile: () => Promise.resolve(true),
    lock: () => {
      profileUnlocked = false;
    },
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    getProtectedMetadata: vi.fn((namespace: string) =>
      Promise.resolve(
        namespace === BREACH_LIST_NAMESPACE && storedManifest !== null
          ? structuredClone(storedManifest)
          : null,
      ),
    ),
    prepareProtectedMetadataUpdates,
  });
  Reflect.set(controller, 'vaults', {
    listVaults: vi.fn(() =>
      Promise.resolve([
        {
          id: document.id,
          name: document.name,
          color: document.color,
          entryCount: 1,
          deletedCount: 0,
          updatedAt: document.updatedAt,
        },
      ]),
    ),
    readVault: vi.fn(() => Promise.resolve(structuredClone(document))),
    clearCachedDocuments: vi.fn(),
  });
  Reflect.set(controller, 'audit', {
    withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
    prepareRecord: prepareAuditRecord,
  });
  Reflect.set(controller, 'transactions', { execute });
  Reflect.set(controller, 'offlineBreach', { buildIndex, scan });
  Reflect.set(
    controller,
    'emitState',
    vi.fn(() => Promise.resolve({})),
  );

  const authentication = privateValue<AuthenticationHarness>(controller, 'authentication');
  const epoch = authentication.begin();
  authentication.complete(profileUnlocked, epoch);

  const harness: ControllerHarness = {
    controller,
    rootDir,
    sourcePath,
    indexPath,
    buildIndex,
    scan,
    execute,
    prepareProtectedMetadataUpdates,
    prepareAuditRecord,
    capturedChanges,
    capturedBuffers,
    getManifest: () => (storedManifest === null ? null : structuredClone(storedManifest)),
    getDocument: () => structuredClone(document),
    setDocument: (nextDocument) => {
      document = structuredClone(nextDocument);
    },
    failNextTransaction: (error) => {
      transactionFailure = error;
    },
  };
  harnesses.push(harness);
  return harness;
}

function buildResult(input: OfflineBreachIndexBuildInput): OfflineBreachIndexBuildResult {
  return {
    format: 'sha1-count-v1',
    version: 1,
    recordCount: 1,
    sourceSha256: SOURCE_SHA256,
    indexSha256: INDEX_SHA256,
    indexBytes: INDEX_CONTENTS.length,
    sourceBytes: INDEX_CONTENTS.length,
    stagingPath: input.stagingPath,
  };
}

function readyBreachStatus(): BreachListStatusDto {
  return {
    state: 'ready',
    sourceLabel: SOURCE_LABEL,
    sourceDate: SOURCE_DATE,
    importedAt: '2026-07-20T12:00:00.000Z',
    recordCount: 1,
    corpusSha256: SOURCE_SHA256,
    networkUsed: false,
  };
}

function currentBreachReport(
  controller: VaultaController,
  documents: readonly VaultDocument[],
  manifest: BreachListManifest | null,
  status: BreachListStatusDto,
): BreachScanReportDto | null {
  const operation = privateValue<
    (
      documents: readonly VaultDocument[],
      manifest: BreachListManifest | null,
      status: BreachListStatusDto,
    ) => BreachScanReportDto | null
  >(controller, 'currentBreachReport');
  return operation.call(controller, documents, manifest, status);
}

function configuredManifest(): BreachListManifest {
  return {
    format: 'kryptris-offline-breach-manifest',
    version: 1,
    listFormat: 'sha1-count-v1',
    sourceLabel: SOURCE_LABEL,
    sourceDate: SOURCE_DATE,
    importedAt: '2026-07-20T12:00:00.000Z',
    sourceSha256: SOURCE_SHA256,
    indexSha256: INDEX_SHA256,
    recordCount: 1,
    indexBytes: INDEX_CONTENTS.length,
  };
}

function breachDocument(): VaultDocument {
  const entry: VaultEntry = {
    id: ENTRY_ID,
    vaultId: VAULT_ID,
    title: 'Synthetischer Zugang',
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
        websites: ['https://offline.example.test'],
        appNames: [],
      },
    },
    lifecycle: createDefaultEntryLifecycleMetadata(),
    createdAt: '2026-07-20T12:00:00.000Z',
    updatedAt: '2026-07-20T12:00:00.000Z',
    secretChangedAt: '2026-07-20T12:00:00.000Z',
    lastUsedAt: null,
    deletedAt: null,
  };
  return {
    formatVersion: 2,
    id: VAULT_ID,
    name: 'Synthetischer Tresor',
    color: '#22d3c5',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-07-20T12:00:00.000Z',
    folders: [],
    entries: [entry],
  };
}

function expectRedactedReport(report: BreachScanReportDto, harness: ControllerHarness): void {
  const serialized = JSON.stringify(report);
  expect(serialized).not.toContain(SYNTHETIC_SECRET);
  expect(serialized).not.toContain(SYNTHETIC_SOURCE_DIGEST);
  expect(serialized).not.toContain(SOURCE_SHA256);
  expect(serialized).not.toContain(INDEX_SHA256);
  expect(serialized).not.toContain(path.basename(harness.sourcePath));
  expect(serialized).not.toContain(path.basename(harness.indexPath));
  expect(serialized).not.toContain('"password":');
  expect(serialized).not.toContain('indexPath');
}

function expectBuffersErased(buffers: Buffer[] | undefined): void {
  expect(buffers).toBeDefined();
  for (const buffer of buffers ?? []) {
    expect(buffer.every((byte) => byte === 0)).toBe(true);
  }
}

async function breachImportStagingFiles(rootDir: string): Promise<string[]> {
  const directory = path.resolve(rootDir, 'security');
  const entries = await readdir(directory).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  return entries.filter((entry) => /^\.breach-import-.*\.tmp$/u.test(entry));
}

async function fileExists(filePath: string): Promise<boolean> {
  return stat(filePath)
    .then(() => true)
    .catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    });
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return { promise, resolve };
}

function privateValue<T = unknown>(controller: VaultaController, key: string): T {
  return Reflect.get(controller, key) as T;
}
