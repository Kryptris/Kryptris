// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { BackupView } from '../../src/renderer/components/BackupAuditViews';
import type { VaultaApi } from '../../src/shared/ipc';
import type {
  AppState,
  BackupHealthSnapshot,
  LocalJobProgressEvent,
} from '../../src/shared/models';
import { DEFAULT_SETTINGS } from '../../src/shared/models';

const healthSnapshot: BackupHealthSnapshot = {
  targetReachable: true,
  sameDriveWarning: true,
  backupCount: 8,
  unreadableBackupCount: 1,
  totalSize: 4096,
  generations: { daily: 3, weekly: 2, monthly: 1 },
  latestBackup: {
    createdAt: '2026-08-09T10:00:00.000Z',
    size: 1024,
    vaultCount: 2,
    attachmentCount: 4,
    automatic: false,
  },
  lastSuccessfulBackupAt: '2026-08-09T10:00:00.000Z',
  lastFailure: { occurredAt: '2026-08-08T10:00:00.000Z', code: 'UNSAFE_PATH' },
  lastSemanticVerificationAt: '2026-08-09T10:05:00.000Z',
};

const state: AppState = {
  hasProfile: true,
  locked: false,
  activeVaultId: 'vault-1',
  vaults: [
    {
      id: 'vault-1',
      name: 'Privat',
      color: '#25d2c8',
      entryCount: 0,
      deletedCount: 0,
      updatedAt: '2026-08-09T10:00:00.000Z',
    },
  ],
  factorStatus: { totpEnabled: false, securityKeys: [], recoveryEnabled: true },
  settings: DEFAULT_SETTINGS,
  autoLockAt: '2099-01-01T00:00:00.000Z',
  version: '1.0.0',
};

interface TestApi {
  api: VaultaApi;
  getHealth: ReturnType<typeof vi.fn>;
  dryRun: ReturnType<typeof vi.fn>;
  restore: ReturnType<typeof vi.fn>;
  cancelJob: ReturnType<typeof vi.fn>;
  emitProgress: (event: LocalJobProgressEvent) => void;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function createApi(overrides: { dryRun?: ReturnType<typeof vi.fn> } = {}): TestApi {
  let progressListener: ((event: LocalJobProgressEvent) => void) | null = null;
  const getHealth = vi.fn(() => Promise.resolve(healthSnapshot));
  const dryRun = overrides.dryRun ?? vi.fn(() => Promise.resolve(null));
  const restore = vi.fn(() => Promise.resolve(null));
  const cancelJob = vi.fn(() => Promise.resolve(true));
  const api = {
    backup: {
      create: vi.fn(() => Promise.resolve(null)),
      getHealth,
      dryRun,
      restore,
      chooseFolder: vi.fn(() => Promise.resolve(null)),
    },
    settings: { update: vi.fn(() => Promise.resolve(DEFAULT_SETTINGS)) },
    quality: { cancelJob },
    events: {
      onLocalJobProgress: vi.fn((listener: (event: LocalJobProgressEvent) => void) => {
        progressListener = listener;
        return vi.fn();
      }),
    },
  } as unknown as VaultaApi;
  return {
    api,
    getHealth,
    dryRun,
    restore,
    cancelJob,
    emitProgress: (event) => progressListener?.(event),
  };
}

beforeEach(() => {
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => 'backup-request-1') });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Backup-Sicherheitsstatus', () => {
  it('zeigt nur pfadfreie Statusdaten, Generationen und einen übersetzten Fehlercode', async () => {
    const testApi = createApi();
    window.vaulta = testApi.api;

    render(<BackupView state={state} notify={vi.fn()} onStateChange={vi.fn()} />);

    expect(await screen.findByText('Sicherungsziel erreichbar')).toBeInTheDocument();
    expect(screen.getByText('Getrennten Speicherort verwenden')).toBeInTheDocument();
    expect(screen.getByText('Nicht alle Sicherungen lesbar')).toBeInTheDocument();
    expect(screen.getByText('Tägliche Generationen')).toBeInTheDocument();
    expect(screen.getByText('Wöchentliche Generationen')).toBeInTheDocument();
    expect(screen.getByText('Monatliche Generationen')).toBeInTheDocument();
    expect(
      screen.getByText(/Das Sicherungsziel wurde aus Sicherheitsgründen abgelehnt/u),
    ).toBeInTheDocument();
    expect(screen.queryByText(/C:\\|\/Users\/|backup-secret/u)).not.toBeInTheDocument();
    expect(testApi.getHealth).toHaveBeenCalledWith({
      requestId: 'backup-request-1',
      refresh: false,
    });

    fireEvent.click(screen.getByRole('button', { name: 'Aktualisieren' }));
    await waitFor(() =>
      expect(testApi.getHealth).toHaveBeenLastCalledWith({
        requestId: 'backup-request-1',
        refresh: true,
      }),
    );
  });

  it('führt einen abbrechbaren Probelauf aus, ohne die Wiederherstellung aufzurufen', async () => {
    const dryRunDeferred = deferred<{
      profileId: string;
      createdAt: string;
      fileCount: number;
      vaultCount: number;
      attachmentCount: number;
      automatic: boolean;
      verifiedAt: string;
      semanticallyVerified: true;
    } | null>();
    const dryRun = vi.fn(() => dryRunDeferred.promise);
    const testApi = createApi({ dryRun });
    window.vaulta = testApi.api;

    render(<BackupView state={state} notify={vi.fn()} onStateChange={vi.fn()} />);
    await screen.findByText('Sicherungsziel erreichbar');

    fireEvent.click(screen.getByRole('button', { name: 'Probelauf starten' }));
    const dialog = screen.getByRole('dialog', { name: 'Verschlüsseltes Backup probeweise prüfen' });
    fireEvent.change(
      within(dialog).getByLabelText('Master-Passwort des Backups für den Probelauf'),
      {
        target: { value: 'Synthetisches-Testpasswort-123!' },
      },
    );
    fireEvent.click(
      within(dialog).getByRole('button', { name: 'Backup auswählen und probeweise prüfen' }),
    );

    await waitFor(() =>
      expect(dryRun).toHaveBeenCalledWith({
        requestId: 'backup-request-1',
        credential: { type: 'master', value: 'Synthetisches-Testpasswort-123!' },
      }),
    );
    testApi.emitProgress({
      requestId: 'backup-request-1',
      job: 'backup-dry-run',
      phase: 'semantisch-pruefen',
      completed: 1,
      total: 2,
    });
    await waitFor(() =>
      expect(
        within(dialog).getByRole('progressbar', {
          name: /Profil, Tresore, Anhänge und Protokoll werden geprüft/u,
        }),
      ).toHaveAttribute('aria-valuetext', '1 von 2 Schritten abgeschlossen'),
    );

    fireEvent.click(within(dialog).getByRole('button', { name: 'Probelauf abbrechen' }));
    await waitFor(() =>
      expect(testApi.cancelJob).toHaveBeenCalledWith({ requestId: 'backup-request-1' }),
    );
    expect(testApi.restore).not.toHaveBeenCalled();

    dryRunDeferred.resolve({
      profileId: 'synthetisches-profil',
      createdAt: '2026-08-09T10:00:00.000Z',
      fileCount: 4,
      vaultCount: 2,
      attachmentCount: 4,
      automatic: false,
      verifiedAt: '2026-08-09T10:05:00.000Z',
      semanticallyVerified: true,
    });
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Verschlüsseltes Backup probeweise prüfen' }),
      ).not.toBeInTheDocument(),
    );
    expect(testApi.restore).not.toHaveBeenCalled();
  });

  it('prüft einen Probelauf auch mit Wiederherstellungsschlüssel, ohne ein neues Passwort anzufordern', async () => {
    const dryRun = vi.fn(() => Promise.resolve(null));
    const testApi = createApi({ dryRun });
    window.vaulta = testApi.api;

    render(<BackupView state={state} notify={vi.fn()} onStateChange={vi.fn()} />);
    await screen.findByText('Sicherungsziel erreichbar');
    fireEvent.click(screen.getByRole('button', { name: 'Probelauf starten' }));
    const dialog = screen.getByRole('dialog', { name: 'Verschlüsseltes Backup probeweise prüfen' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Wiederherstellungsschlüssel' }));

    expect(within(dialog).queryByLabelText('Neues Master-Passwort')).not.toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('Wiederherstellungsschlüssel'), {
      target: { value: 'SYNTHETISCHER-RECOVERY-SCHLUESSEL' },
    });
    fireEvent.click(
      within(dialog).getByRole('button', { name: 'Backup auswählen und probeweise prüfen' }),
    );

    await waitFor(() =>
      expect(dryRun).toHaveBeenCalledWith({
        requestId: 'backup-request-1',
        credential: { type: 'recovery', value: 'SYNTHETISCHER-RECOVERY-SCHLUESSEL' },
      }),
    );
    expect(testApi.restore).not.toHaveBeenCalled();
  });
});
