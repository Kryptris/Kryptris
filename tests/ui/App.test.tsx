// @vitest-environment jsdom
/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/unbound-method */

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../../src/renderer/App';
import type { VaultaApi } from '../../src/shared/ipc';
import {
  DEFAULT_SETTINGS,
  type AppState,
  type EntryDetail,
  type EntrySummary,
  type ImportPreview,
  type SecurityCenterCardId,
} from '../../src/shared/models';

const SECURITY_CENTER_CARD_IDS: SecurityCenterCardId[] = [
  'credentials',
  'data-quality',
  'factors',
  'backup',
  'recovery',
  'kdf',
  'integrity',
  'breach-list',
];

const EXISTING_PROFILE_SETTINGS = { ...DEFAULT_SETTINGS, onboardingCompleted: true };

const unlockedState: AppState = {
  hasProfile: true,
  locked: false,
  activeVaultId: 'vault-1',
  vaults: [
    {
      id: 'vault-1',
      name: 'Privat',
      color: '#25d2c8',
      entryCount: 1,
      deletedCount: 0,
      updatedAt: '2026-07-14T02:00:00.000Z',
    },
  ],
  factorStatus: { totpEnabled: false, securityKeys: [], recoveryEnabled: true },
  settings: EXISTING_PROFILE_SETTINGS,
  autoLockAt: '2099-01-01T00:05:00.000Z',
  version: '1.0.0',
};

const entrySummary: EntrySummary = {
  id: 'entry-1',
  vaultId: 'vault-1',
  type: 'credential',
  title: 'GitHub',
  subtitle: 'lauri@example.de',
  favorite: true,
  tags: ['Entwicklung'],
  folderId: null,
  securityState: 'good',
  updatedAt: '2026-07-14T02:00:00.000Z',
  deletedAt: null,
};

const entryDetail: EntryDetail = {
  id: 'entry-1',
  vaultId: 'vault-1',
  type: 'credential',
  title: 'GitHub',
  favorite: true,
  tags: ['Entwicklung'],
  folderId: null,
  note: '',
  fields: [
    {
      path: 'data.password',
      label: 'Passwort',
      kind: 'secret',
      secret: true,
      copyable: true,
      openable: false,
    },
  ],
  attachments: [],
  lifecycle: {
    rotationIntervalDays: null,
    nextRotationDate: null,
    rotationExcluded: false,
    twoFactorStatus: 'unknown',
    expiryReminderDate: null,
  },
  createdAt: '2026-07-14T02:00:00.000Z',
  updatedAt: '2026-07-14T02:00:00.000Z',
  deletedAt: null,
};

function createApi(state: AppState): VaultaApi {
  return {
    system: {
      getState: vi.fn(async () => state),
      lock: vi.fn(async () => undefined),
      clearClipboard: vi.fn(async () => true),
    },
    setup: {
      begin: vi.fn(async () => ({ pendingId: 'pending-1', recovery: null })),
      complete: vi.fn(async () => unlockedState),
    },
    auth: {
      unlock: vi.fn(async () => ({ status: 'unlocked' as const })),
      completeSecurityKey: vi.fn(async () => ({ verified: true, unlocked: true })),
      cancelSecurityKey: vi.fn(async () => undefined),
      recover: vi.fn(async () => unlockedState),
      changeMasterPassword: vi.fn(async () => undefined),
    },
    vaults: {
      list: vi.fn(async () => state.vaults),
      create: vi.fn(async ({ name, color }) => ({
        id: 'vault-2',
        name,
        color,
        entryCount: 0,
        deletedCount: 0,
        updatedAt: '2026-07-14T02:00:00.000Z',
      })),
      update: vi.fn(async ({ id, name, color }) => ({
        id,
        name,
        color,
        entryCount: 0,
        deletedCount: 0,
        updatedAt: '2026-07-14T02:00:00.000Z',
      })),
      delete: vi.fn(async () => undefined),
      select: vi.fn(async () => undefined),
      listFolders: vi.fn(async () => []),
      createFolder: vi.fn(async ({ name, color }) => ({
        id: 'folder-1',
        name,
        color,
        createdAt: '2026-07-14T02:00:00.000Z',
      })),
      updateFolder: vi.fn(async ({ id, name, color }) => ({
        id,
        name,
        color,
        createdAt: '2026-07-14T02:00:00.000Z',
      })),
      deleteFolder: vi.fn(async () => undefined),
    },
    entries: {
      list: vi.fn(async () => [entrySummary]),
      getDetail: vi.fn(async () => entryDetail),
      getEditModel: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      create: vi.fn(async () => entrySummary),
      update: vi.fn(async () => entrySummary),
      moveToTrash: vi.fn(async () => undefined),
      restore: vi.fn(async () => undefined),
      purge: vi.fn(async () => undefined),
      toggleFavorite: vi.fn(async () => false),
      reveal: vi.fn(async () => 'nicht-protokolliertes-geheimnis'),
      copy: vi.fn(async () => undefined),
      exportPrivateKey: vi.fn(async () => true),
      wifiQr: vi.fn(async () => 'data:image/png;base64,AA=='),
    },
    attachments: {
      add: vi.fn(async () => null),
      remove: vi.fn(async () => undefined),
      export: vi.fn(async () => true),
      preview: vi.fn(async () => ({ kind: 'text' as const, mediaType: 'text/plain', data: '' })),
    },
    generator: {
      generate: vi.fn(async () => ({
        value: 'generated',
        score: 4,
        label: 'Stark',
        crackTime: 'sehr lange',
      })),
    },
    totp: {
      getCode: vi.fn(async () => {
        throw new Error('Kein TOTP');
      }),
      copy: vi.fn(async () => undefined),
      importQr: vi.fn(async () => null),
    },
    security: {
      scan: vi.fn(async () => ({
        generatedAt: '2026-07-14T02:00:00.000Z',
        score: 100,
        counts: { good: 1, info: 0, warning: 0, critical: 0 },
        findings: [],
        networkUsed: false as const,
      })),
      scanCenter: vi.fn(async () => ({
        generatedAt: '2026-07-14T02:00:00.000Z',
        score: 100,
        cards: SECURITY_CENTER_CARD_IDS.map((id) => ({
          id,
          severity: 'good' as const,
          findingCodes: [],
          count: 0,
          calculatedAt: '2026-07-14T02:00:00.000Z',
          action: 'none' as const,
        })),
        entryFindings: [],
        networkUsed: false as const,
      })),
      getRecoveryReadiness: vi.fn(async () => ({
        state: 'ready' as const,
        lastTestedAt: '2026-07-14T02:00:00.000Z',
        lastTestSucceeded: true,
        staleAfterDays: 180,
      })),
      testRecoveryReadiness: vi.fn(async () => ({
        state: 'ready' as const,
        lastTestedAt: '2026-07-14T02:00:00.000Z',
        lastTestSucceeded: true,
        staleAfterDays: 180,
      })),
      scanIntegrity: vi.fn(async () => ({
        reportId: 'integrity-report-1',
        generatedAt: '2026-07-14T02:00:00.000Z',
        success: true,
        scannedVaults: 1,
        scannedEntries: 1,
        scannedAttachments: 0,
        findings: [],
        networkUsed: false as const,
      })),
      saveIntegrityReport: vi.fn(async () => true),
      getBreachListStatus: vi.fn(async () => ({
        state: 'not-configured' as const,
        sourceLabel: null,
        sourceDate: null,
        importedAt: null,
        recordCount: 0,
        corpusSha256: null,
        networkUsed: false as const,
      })),
      importBreachList: vi.fn(async () => null),
      scanBreachList: vi.fn(async () => ({
        generatedAt: '2026-07-14T02:00:00.000Z',
        checkedEntries: 0,
        checkedPasswords: 0,
        findings: [],
        networkUsed: false as const,
      })),
      removeBreachList: vi.fn(async () => ({
        state: 'not-configured' as const,
        sourceLabel: null,
        sourceDate: null,
        importedAt: null,
        recordCount: 0,
        corpusSha256: null,
        networkUsed: false as const,
      })),
    },
    backup: {
      create: vi.fn(async () => null),
      getHealth: vi.fn(async () => ({
        targetReachable: false,
        sameDriveWarning: false,
        backupCount: 0,
        unreadableBackupCount: 0,
        totalSize: 0,
        generations: { daily: 0, weekly: 0, monthly: 0 },
        latestBackup: null,
        lastSuccessfulBackupAt: null,
        lastFailure: null,
        lastSemanticVerificationAt: null,
      })),
      dryRun: vi.fn(async () => null),
      restore: vi.fn(async () => null),
      chooseFolder: vi.fn(async () => null),
    },
    transfer: {
      previewImport: vi.fn(async () => null),
      previewDroppedImport: vi.fn(async () => null),
      onDroppedImport: vi.fn(() => vi.fn()),
      remapImport: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      executeImport: vi.fn(async () => ({
        imported: 0,
        skipped: 0,
        summary: { newEntries: 0, skippedEntries: 0, duplicates: 0, warnings: 0, invalidRows: 0 },
        entryIds: [],
      })),
      listMappingProfiles: vi.fn(async () => []),
      saveMappingProfile: vi.fn(async ({ id, name, mapping }) => ({
        id: id ?? 'mapping-profile-1',
        name,
        mapping,
        updatedAt: '2026-07-14T02:00:00.000Z',
      })),
      removeMappingProfile: vi.fn(async () => true),
      exportVaultPackage: vi.fn(async () => null),
      previewVaultPackage: vi.fn(async () => null),
      importVaultPackage: vi.fn(async () => ({
        vaultId: '00000000-0000-4000-8000-000000000711',
        vaultName: 'Anonymisierter Ziel-Tresor',
        entryCount: 0,
        attachmentCount: 0,
      })),
      export: vi.fn(async () => null),
    },
    audit: { list: vi.fn(async () => []) },
    settings: {
      get: vi.fn(async () => EXISTING_PROFILE_SETTINGS),
      update: vi.fn(async ({ settings }) => settings),
    },
    factors: {
      status: vi.fn(async () => state.factorStatus),
      beginTotp: vi.fn(async () => ({
        setupId: 'totp-1',
        secret: 'SECRET',
        uri: 'otpauth://totp/Vaulta',
        qrDataUrl: 'data:image/png;base64,AA==',
        explanation: 'Lokale Zusatzsperre',
      })),
      completeTotp: vi.fn(async () => undefined),
      removeTotp: vi.fn(async () => undefined),
      beginSecurityKey: vi.fn(async () => ({ challengeId: 'key-1', options: {}, prfSalt: 'AA' })),
      completeSecurityKey: vi.fn(async () => ({
        verified: true,
        mode: 'prf' as const,
        warning: null,
      })),
      removeSecurityKey: vi.fn(async () => undefined),
      rotateRecovery: vi.fn(async () => ({
        pendingId: 'recovery-rotation-1',
        recovery: {
          displayKey: 'AAAA-BBBB',
          groups: ['AAAA', 'BBBB'],
          confirmationIndexes: [0],
        },
      })),
      completeRecoveryRotation: vi.fn(async () => undefined),
    },
    templates: {
      list: vi.fn(async () => []),
      save: vi.fn(async (template) => ({
        ...template,
        id: template.id ?? 'template-1',
        createdAt: '2026-07-14T02:00:00.000Z',
        updatedAt: '2026-07-14T02:00:00.000Z',
      })),
      delete: vi.fn(async () => undefined),
    },
    reports: {
      generate: vi.fn(async () => ({
        generatedAt: '2026-07-14T02:00:00.000Z',
        vaultCount: 1,
        entryCount: 1,
        favoriteCount: 1,
        trashCount: 0,
        attachmentCount: 0,
        attachmentBytes: 0,
        typeCounts: {
          credential: 1,
          'secure-note': 0,
          'credit-card': 0,
          identity: 0,
          wifi: 0,
          'software-license': 0,
          'ssh-key': 0,
          file: 0,
          custom: 0,
        },
        security: {
          generatedAt: '2026-07-14T02:00:00.000Z',
          score: 100,
          counts: { good: 1, info: 0, warning: 0, critical: 0 },
          findings: [],
          networkUsed: false as const,
        },
        oldestEntries: [],
        networkUsed: false as const,
      })),
    },
    productivity: {
      batch: vi.fn(async ({ entryIds }) => ({ affected: entryIds.length, entryIds })),
      listSavedViews: vi.fn(async () => []),
      saveSavedView: vi.fn(async ({ id, vaultId, name, filters }) => ({
        id: id ?? 'saved-view-1',
        vaultId,
        name,
        filters,
        order: 0,
        createdAt: '2026-07-14T02:00:00.000Z',
        updatedAt: '2026-07-14T02:00:00.000Z',
        invalidReferences: { folder: false, tags: [] },
      })),
      reorderSavedViews: vi.fn(async () => []),
      deleteSavedView: vi.fn(async () => undefined),
      listTags: vi.fn(async () => []),
      renameTag: vi.fn(async () => 0),
      mergeTags: vi.fn(async () => 0),
      deleteTag: vi.fn(async () => 0),
    },
    quality: {
      scanDuplicates: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      describeDuplicateMerge: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      mergeDuplicates: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      scanDataQuality: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      previewDataQualityFix: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      applyDataQualityFix: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      cancelJob: vi.fn(async () => false),
    },
    window: {
      minimize: vi.fn(async () => undefined),
      toggleMaximize: vi.fn(async () => true),
      close: vi.fn(async () => undefined),
    },
    events: {
      onLocked: vi.fn(() => vi.fn()),
      onStateChanged: vi.fn(() => vi.fn()),
      onClipboardCleared: vi.fn(() => vi.fn()),
      onBackgroundWarning: vi.fn(() => vi.fn()),
      onLocalJobProgress: vi.fn(() => vi.fn()),
    },
  };
}

beforeEach(() => {
  vi.stubGlobal('crypto', { randomUUID: () => 'generated-id' });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Vaulta Renderer', () => {
  it('zeigt bei einem neuen Profil die sichere Ersteinrichtung', async () => {
    const state: AppState = {
      ...unlockedState,
      hasProfile: false,
      locked: true,
      activeVaultId: null,
      vaults: [],
      settings: null,
    };
    window.vaulta = createApi(state);

    render(<App />);

    expect(
      await screen.findByRole('heading', { name: 'Dein sicherer, lokaler Tresor' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/keine Hintertür/i)).toBeInTheDocument();
    expect(
      screen.getByRole('checkbox', { name: /Wiederherstellungsschlüssel erzeugen/i }),
    ).toBeChecked();
    expect(screen.getByRole('button', { name: 'Backup wiederherstellen' })).toBeInTheDocument();
  });

  it('verwirft einen angezeigten Wiederherstellungsschlüssel beim Sperren', async () => {
    const state: AppState = {
      ...unlockedState,
      hasProfile: false,
      locked: true,
      activeVaultId: null,
      vaults: [],
      settings: null,
    };
    const api = createApi(state);
    const lockedListeners: Array<() => void> = [];
    vi.mocked(api.events.onLocked).mockImplementation((listener) => {
      lockedListeners.push(listener);
      return vi.fn();
    });
    vi.mocked(api.setup.begin).mockResolvedValue({
      pendingId: 'pending-recovery',
      recovery: {
        displayKey: 'AAAA-BBBB-CCCC',
        groups: ['AAAA', 'BBBB', 'CCCC'],
        confirmationIndexes: [0],
      },
    });
    window.vaulta = api;
    render(<App />);

    fireEvent.change(await screen.findByLabelText('Master-Passwort', { exact: true }), {
      target: { value: 'Sehr-langes-Master-Passwort!123' },
    });
    fireEvent.change(screen.getByLabelText('Master-Passwort wiederholen'), {
      target: { value: 'Sehr-langes-Master-Passwort!123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Profil sicher einrichten' }));

    expect(
      await screen.findByRole('heading', { name: 'Wiederherstellungsschlüssel sichern' }),
    ).toBeInTheDocument();
    expect(screen.getByText('AAAA')).toBeInTheDocument();

    act(() => {
      for (const listener of lockedListeners) listener();
    });

    expect(
      await screen.findByRole('heading', { name: 'Dein sicherer, lokaler Tresor' }),
    ).toBeInTheDocument();
    expect(screen.queryByText('AAAA')).not.toBeInTheDocument();
  });

  it('stellt auf einem frischen System ein vollständiges Backup wieder her', async () => {
    const state: AppState = {
      ...unlockedState,
      hasProfile: false,
      locked: true,
      activeVaultId: null,
      vaults: [],
      settings: null,
    };
    const api = createApi(state);
    vi.mocked(api.backup.restore).mockResolvedValue({ ...unlockedState, locked: true });
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Backup wiederherstellen' }));
    fireEvent.change(screen.getByLabelText('Master-Passwort des Backups'), {
      target: { value: 'Backup-Master-Passwort!123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Backup auswählen und prüfen' }));

    await waitFor(() =>
      expect(api.backup.restore).toHaveBeenCalledWith({
        credential: { type: 'master', value: 'Backup-Master-Passwort!123' },
      }),
    );
  });

  it('entsperrt ausschließlich über die typisierte Vaulta-API', async () => {
    const lockedState = { ...unlockedState, locked: true };
    const api = createApi(lockedState);
    vi.mocked(api.system.getState)
      .mockResolvedValueOnce(lockedState)
      .mockResolvedValue(unlockedState);
    window.vaulta = api;

    render(<App />);

    const password = await screen.findByLabelText('Master-Passwort');
    fireEvent.change(password, { target: { value: 'sehr-langes-master-passwort' } });
    fireEvent.click(screen.getByRole('button', { name: 'Kryptris entsperren' }));

    await waitFor(() =>
      expect(api.auth.unlock).toHaveBeenCalledWith({
        masterPassword: 'sehr-langes-master-passwort',
      }),
    );
    expect(await screen.findByPlaceholderText('Tresor durchsuchen')).toBeInTheDocument();
  });

  it('maskiert Geheimnisse und kopiert sie ohne Wert-Rückgabe', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;

    render(<App />);

    expect(await screen.findByRole('heading', { name: 'GitHub' })).toBeInTheDocument();
    expect(screen.getByLabelText('Maskierter Wert')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Passwort kopieren' }));

    await waitFor(() =>
      expect(api.entries.copy).toHaveBeenCalledWith({
        vaultId: 'vault-1',
        entryId: 'entry-1',
        fieldPath: 'data.password',
      }),
    );
    expect(api.entries.reveal).not.toHaveBeenCalled();
  });

  it('beschriftet die Zugangsdatenfelder im neuen Eintrag eindeutig', async () => {
    const api = createApi(unlockedState);
    vi.mocked(api.entries.list).mockResolvedValue([]);
    window.vaulta = api;
    render(<App />);

    const entryList = await screen.findByLabelText('Eintragsliste');
    fireEvent.click(await within(entryList).findByRole('button', { name: 'Neuer Eintrag' }));
    const dialog = screen.getByRole('dialog', { name: 'Neuen Eintrag anlegen' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Zugangsdaten' }));

    expect(within(dialog).getByLabelText('Titel', { exact: true })).toBeInTheDocument();
    expect(
      within(dialog).getByLabelText('Benutzername oder E-Mail', { exact: true }),
    ).toHaveAttribute('name', 'username');
    expect(within(dialog).getByLabelText('Passwort', { exact: true })).toHaveAttribute(
      'name',
      'password',
    );
  });

  it('bietet exakt die festgelegten Auto-Sperrzeiten an', async () => {
    window.vaulta = createApi(unlockedState);
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Einstellungen öffnen' }));
    const select = await screen.findByLabelText('Sperren nach Inaktivität');
    const options = within(select).getAllByRole('option');

    expect(options.map((option) => option.getAttribute('value'))).toEqual([
      '0',
      '60',
      '300',
      '600',
      '900',
      '1800',
    ]);
    fireEvent.change(select, { target: { value: '0' } });
    expect(screen.getByText(/sobald die App verlassen oder minimiert wird/i)).toBeInTheDocument();
  });

  it('aktiviert die Papierkorb-Aufbewahrung erst nach erklärter Backup-Bestätigung', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Einstellungen öffnen' }));
    const backupTab = within(
      screen.getByRole('tablist', { name: 'Einstellungsbereiche' }),
    ).getByRole('tab', { name: 'Backups' });
    fireEvent.click(backupTab);
    expect(backupTab).toHaveClass('is-active');
    expect(
      screen.getByRole('heading', { name: 'Automatische Backups' }).closest('section'),
    ).toHaveTextContent('Papierkorb-Aufbewahrung');

    const retention = await screen.findByLabelText('Papierkorb automatisch leeren');
    expect(
      within(retention)
        .getAllByRole('option')
        .map((option) => option.getAttribute('value')),
    ).toEqual(['', '30', '90', '180', '365']);

    fireEvent.change(retention, { target: { value: '30' } });
    expect(
      screen.getByText(/Wiederherstellung ist danach nur aus einem zuvor erstellten/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Automatische Backups sind nicht aktiv/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));

    const acknowledgement = screen.getByRole('checkbox', {
      name: /Ich habe verstanden, dass abgelaufene Papierkorb-Einträge endgültig gelöscht werden/i,
    });
    expect(acknowledgement).toHaveFocus();
    expect(api.settings.update).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('Bestätigung erforderlich');

    fireEvent.click(acknowledgement);
    fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));

    await waitFor(() =>
      expect(api.settings.update).toHaveBeenCalledWith({
        settings: { ...EXISTING_PROFILE_SETTINGS, trashRetentionDays: 30 },
      }),
    );
  });

  it('fragt vor einer schwächeren Sicherheitseinstellung das Master-Passwort ab', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Einstellungen öffnen' }));
    fireEvent.change(await screen.findByLabelText('Sperren nach Inaktivität'), {
      target: { value: '1800' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));

    const dialog = screen.getByRole('dialog', {
      name: 'Sicherheitseinstellungen abschwächen?',
    });
    fireEvent.change(within(dialog).getByLabelText('Master-Passwort'), {
      target: { value: 'Master-Bestätigung!123' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Einstellungen speichern' }));

    await waitFor(() =>
      expect(api.settings.update).toHaveBeenCalledWith({
        settings: { ...EXISTING_PROFILE_SETTINGS, autoLockSeconds: 1_800 },
        masterPassword: 'Master-Bestätigung!123',
      }),
    );
  });

  it('legt freie Ordner über die Vaulta-API an', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Ordner' }));
    fireEvent.click(screen.getByRole('button', { name: 'Neuer Ordner' }));
    fireEvent.change(screen.getByLabelText('Ordnername'), { target: { value: 'Arbeit' } });
    fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));

    await waitFor(() =>
      expect(api.vaults.createFolder).toHaveBeenCalledWith({
        vaultId: 'vault-1',
        name: 'Arbeit',
        color: '#25d2c8',
      }),
    );
  });

  it('verwendet eine eigene Vorlage als vorausgefüllten neuen Eintrag', async () => {
    const api = createApi(unlockedState);
    vi.mocked(api.templates.list).mockResolvedValue([
      {
        id: 'template-1',
        name: 'Serverzugang',
        entryType: 'ssh-key',
        fields: [
          {
            label: 'Notfall-PIN',
            type: 'secret',
            secret: true,
            defaultValue: '4711',
          },
        ],
        createdAt: '2026-07-14T02:00:00.000Z',
        updatedAt: '2026-07-14T02:00:00.000Z',
      },
    ]);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Eigene Vorlagen' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Eintrag erstellen' }));

    expect(screen.getByRole('dialog', { name: 'Neuen Eintrag anlegen' })).toBeInTheDocument();
    expect(screen.getByLabelText('Titel')).toHaveValue('Serverzugang');
    expect(screen.getByDisplayValue('Notfall-PIN')).toBeInTheDocument();
    expect(screen.getByDisplayValue('4711')).toHaveAttribute('type', 'password');
  });

  it('rendert boolesche Felder und sicheres Markdown korrekt', async () => {
    const api = createApi(unlockedState);
    vi.mocked(api.entries.getDetail).mockResolvedValue({
      ...entryDetail,
      fields: [
        {
          path: 'custom.enabled',
          label: 'Aktiv',
          kind: 'boolean',
          secret: false,
          copyable: true,
          openable: false,
          value: 'true',
        },
        {
          path: 'data.markdown',
          label: 'Inhalt',
          kind: 'markdown',
          secret: false,
          copyable: true,
          openable: false,
          value: '# Geheime Überschrift\n[Vaulta Dokumentation](https://example.invalid/vaulta)',
        },
        {
          path: 'data.websites.0',
          label: 'Website',
          kind: 'url',
          secret: false,
          copyable: true,
          openable: true,
          value: 'https://example.invalid',
        },
      ],
    });
    window.vaulta = api;
    render(<App />);

    expect(await screen.findByText('Ja')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Geheime Überschrift', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText('Vaulta Dokumentation').closest('a, button')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Website extern öffnen' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Website kopieren' })).toBeInTheDocument();
  });

  it('öffnet die sichere Befehlspalette und behandelt globale Tastaturkürzel konfliktfrei', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;
    render(<App />);

    const search = await screen.findByLabelText('Tresor durchsuchen');
    fireEvent.keyDown(window, { key: 'f', ctrlKey: true });
    expect(search).toHaveFocus();

    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const palette = await screen.findByRole('dialog', { name: 'Befehlspalette' });
    const paletteSearch = within(palette).getByPlaceholderText('Navigation oder Aktion suchen');
    expect(paletteSearch).toHaveFocus();
    expect(within(palette).queryByText('nicht-protokolliertes-geheimnis')).not.toBeInTheDocument();
    fireEvent.change(paletteSearch, { target: { value: 'Tastaturhilfe' } });
    expect(
      within(palette).getByRole('option', { name: 'Tastaturhilfe öffnen' }),
    ).toBeInTheDocument();
    fireEvent.keyDown(paletteSearch, { key: 'Enter' });

    const help = await screen.findByRole('dialog', { name: 'Tastaturhilfe' });
    expect(within(help).getByText('Strg + S')).toBeInTheDocument();
    fireEvent.click(within(help).getByRole('button', { name: 'Verstanden' }));

    fireEvent.keyDown(window, { key: 'n', ctrlKey: true });
    const editor = await screen.findByRole('dialog', { name: 'Neuen Eintrag anlegen' });
    fireEvent.change(within(editor).getByLabelText('Titel', { exact: true }), {
      target: { value: 'Shortcut-Eintrag' },
    });
    fireEvent.keyDown(window, { key: 's', ctrlKey: true });
    await waitFor(() => expect(api.entries.create).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Neuen Eintrag anlegen' }),
      ).not.toBeInTheDocument(),
    );

    fireEvent.keyDown(window, { key: 'n', ctrlKey: true });
    expect(
      await screen.findByRole('dialog', { name: 'Neuen Eintrag anlegen' }),
    ).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Neuen Eintrag anlegen' }),
      ).not.toBeInTheDocument(),
    );

    fireEvent.keyDown(window, { key: 'l', ctrlKey: true });
    expect(api.system.lock).toHaveBeenCalledTimes(1);
  });

  it('wählt mit Strg und Umschalt mehrere Einträge und übergibt den Zieltresor exakt', async () => {
    const state: AppState = {
      ...unlockedState,
      vaults: [
        ...unlockedState.vaults,
        {
          id: 'vault-2',
          name: 'Arbeit',
          color: '#8b5cf6',
          entryCount: 0,
          deletedCount: 0,
          updatedAt: '2026-07-14T02:00:00.000Z',
        },
      ],
    };
    const api = createApi(state);
    const summaries = [
      { ...entrySummary, id: 'entry-1', title: 'Alpha', updatedAt: '2026-07-16T00:00:00.000Z' },
      { ...entrySummary, id: 'entry-2', title: 'Beta', updatedAt: '2026-07-15T00:00:00.000Z' },
      { ...entrySummary, id: 'entry-3', title: 'Gamma', updatedAt: '2026-07-14T00:00:00.000Z' },
    ];
    vi.mocked(api.entries.list).mockResolvedValue(summaries);
    window.vaulta = api;
    render(<App />);

    const entryList = await screen.findByLabelText('Eintragsliste');
    const options = await within(entryList).findAllByRole('option');
    fireEvent.click(options[0]!);
    fireEvent.click(options[1]!, { ctrlKey: true });
    fireEvent.click(options[2]!, { ctrlKey: true, shiftKey: true });

    const toolbar = await screen.findByLabelText('Batch-Aktionen');
    expect(within(toolbar).getByText('3 ausgewählt')).toBeInTheDocument();
    fireEvent.click(within(toolbar).getByRole('button', { name: 'In Tresor kopieren' }));
    let dialog = screen.getByRole('dialog', { name: 'In anderen Tresor kopieren' });
    fireEvent.keyDown(window, { key: 'f', ctrlKey: true });
    expect(screen.getByLabelText('Tresor durchsuchen')).not.toHaveFocus();
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'In anderen Tresor kopieren' }),
      ).not.toBeInTheDocument(),
    );
    expect(within(toolbar).getByText('3 ausgewählt')).toBeInTheDocument();

    fireEvent.click(within(toolbar).getByRole('button', { name: 'In Tresor kopieren' }));
    dialog = screen.getByRole('dialog', { name: 'In anderen Tresor kopieren' });
    expect(within(dialog).getByLabelText('Zieltresor')).toHaveValue('vault-2');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Kopieren' }));

    await waitFor(() =>
      expect(api.productivity.batch).toHaveBeenCalledWith({
        vaultId: 'vault-1',
        entryIds: ['entry-1', 'entry-2', 'entry-3'],
        action: { type: 'copy-to-vault', targetVaultId: 'vault-2' },
      }),
    );
  });

  it('speichert Ansichten und verwaltet normalisierte Tags über die Productivity-API', async () => {
    const api = createApi(unlockedState);
    vi.mocked(api.productivity.listTags).mockResolvedValue([
      { name: 'Entwicklung', normalizedName: 'entwicklung', usageCount: 1 },
    ]);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Aktuelle Ansicht speichern' }));
    const saveDialog = screen.getByRole('dialog', { name: 'Aktuelle Ansicht speichern' });
    fireEvent.change(within(saveDialog).getByLabelText('Name der Ansicht'), {
      target: { value: 'Meine Arbeit' },
    });
    fireEvent.click(within(saveDialog).getByRole('button', { name: 'Ansicht speichern' }));
    await waitFor(() =>
      expect(api.productivity.saveSavedView).toHaveBeenCalledWith(
        expect.objectContaining({
          vaultId: 'vault-1',
          name: 'Meine Arbeit',
          filters: expect.objectContaining({ smartView: null, view: 'all' }),
        }),
      ),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Tags verwalten' }));
    const tagDialog = await screen.findByRole('dialog', { name: 'Tags verwalten' });
    const name = within(tagDialog).getByLabelText('Tag Entwicklung umbenennen');
    fireEvent.change(name, { target: { value: 'Arbeit' } });
    fireEvent.click(within(tagDialog).getByRole('button', { name: 'Umbenennen' }));
    await waitFor(() =>
      expect(api.productivity.renameTag).toHaveBeenCalledWith({
        vaultId: 'vault-1',
        tag: 'Entwicklung',
        name: 'Arbeit',
      }),
    );
  });

  it('öffnet einen Sicherheitsbefund im referenzierten Tresor', async () => {
    const secondVault = {
      id: 'vault-2',
      name: 'Arbeit',
      color: '#8b5cf6',
      entryCount: 1,
      deletedCount: 0,
      updatedAt: '2026-07-14T02:00:00.000Z',
    };
    const state = { ...unlockedState, vaults: [...unlockedState.vaults, secondVault] };
    const api = createApi(state);
    vi.mocked(api.system.getState)
      .mockResolvedValueOnce(state)
      .mockResolvedValue({ ...state, activeVaultId: secondVault.id });
    vi.mocked(api.security.scanCenter).mockResolvedValue({
      generatedAt: '2026-07-14T02:00:00.000Z',
      score: 82,
      cards: SECURITY_CENTER_CARD_IDS.map((id) => ({
        id,
        severity: id === 'credentials' ? ('warning' as const) : ('good' as const),
        findingCodes: id === 'credentials' ? (['credential-findings'] as const) : [],
        count: id === 'credentials' ? 1 : 0,
        calculatedAt: '2026-07-14T02:00:00.000Z',
        action: id === 'credentials' ? ('review-credentials' as const) : ('none' as const),
      })),
      entryFindings: [
        {
          id: 'finding-cross-vault',
          vaultId: secondVault.id,
          vaultName: secondVault.name,
          entryId: 'entry-work',
          entryTitle: 'Synthetischer Arbeitszugang',
          kind: 'old',
          severity: 'warning',
          title: 'Rotation im Arbeitstresor prüfen',
          recommendation: 'Prüfe das Änderungsdatum beim Dienst.',
        },
      ],
      networkUsed: false,
    });
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Sicherheitszentrale' }));
    fireEvent.click(
      await screen.findByRole('button', { name: /Rotation im Arbeitstresor prüfen/u }),
    );

    await waitFor(() => expect(api.vaults.select).toHaveBeenCalledWith(secondVault.id));
    expect(api.system.getState).toHaveBeenCalledTimes(2);
  });

  it('uebergibt beim abgelegten Import nur den Preload-Token, nie einen Dateipfad', async () => {
    const api = createApi(unlockedState);
    let droppedImportListener: ((drop: { token: string }) => void) | undefined;
    vi.mocked(api.transfer.onDroppedImport).mockImplementation((listener) => {
      droppedImportListener = listener;
      return vi.fn();
    });
    const droppedPreview: ImportPreview = {
      token: '00000000-0000-4000-8000-000000000713',
      format: 'bitwarden-json',
      sourceName: 'synthetic-import.csv',
      candidates: [],
      errors: [],
      detectedColumns: [],
      mapping: null,
    };
    vi.mocked(api.transfer.previewDroppedImport).mockResolvedValue(droppedPreview);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Import' }));
    await screen.findByRole('heading', { name: 'Daten importieren' });
    await waitFor(() => expect(droppedImportListener).toBeDefined());
    act(() => droppedImportListener?.({ token: '00000000-0000-4000-8000-000000000712' }));

    await waitFor(() => expect(api.transfer.previewDroppedImport).toHaveBeenCalledTimes(1));
    const input = vi.mocked(api.transfer.previewDroppedImport).mock.calls[0]?.[0];
    expect(input).toMatchObject({
      token: '00000000-0000-4000-8000-000000000712',
      vaultId: 'vault-1',
      format: 'bitwarden-json',
    });
    expect(JSON.stringify(input)).not.toContain('sourcePath');
    expect(
      await screen.findByRole('heading', { name: 'synthetic-import.csv' }),
    ).toBeInTheDocument();
  });

  it('prueft und importiert ein Tresor-Paket ueber den pfadlosen Renderer-Vertrag', async () => {
    const api = createApi(unlockedState);
    vi.mocked(api.transfer.previewVaultPackage).mockResolvedValue({
      token: '00000000-0000-4000-8000-000000000715',
      createdAt: '2026-08-09T10:00:00.000Z',
      vaultName: 'Anonymisierte Reise',
      color: '#2DD4BF',
      entryCount: 1,
      attachmentCount: 1,
      includesAttachments: true,
      nameConflict: false,
    });
    vi.mocked(api.transfer.importVaultPackage).mockResolvedValue({
      vaultId: '00000000-0000-4000-8000-000000000716',
      vaultName: 'Anonymisierte Kopie',
      entryCount: 1,
      attachmentCount: 1,
    });
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Import' }));
    expect(
      await screen.findByRole('heading', { name: 'Kryptris-Tresor-Paket importieren' }),
    ).toBeInTheDocument();
    const packagePasswordField = screen.getByText('Exportpasswort des Pakets').closest('label');
    const packagePassword = packagePasswordField?.querySelector<HTMLInputElement>('input');
    if (packagePassword === null || packagePassword === undefined) {
      throw new Error('Das Paketpasswortfeld fehlt.');
    }
    fireEvent.change(packagePassword, {
      target: { value: 'Synthetisches-Paketpasswort-715' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Paket auswaehlen und pruefen' }));

    await waitFor(() =>
      expect(api.transfer.previewVaultPackage).toHaveBeenCalledWith({
        exportPassword: 'Synthetisches-Paketpasswort-715',
      }),
    );
    expect(screen.getByText('Anonymisierte Reise')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Name des neuen Tresors'), {
      target: { value: 'Anonymisierte Kopie' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Als neuen Tresor importieren' }));

    await waitFor(() =>
      expect(api.transfer.importVaultPackage).toHaveBeenCalledWith({
        token: '00000000-0000-4000-8000-000000000715',
        exportPassword: 'Synthetisches-Paketpasswort-715',
        targetVaultName: 'Anonymisierte Kopie',
        allowNameConflict: false,
      }),
    );
    expect(JSON.stringify(vi.mocked(api.transfer.previewVaultPackage).mock.calls)).not.toContain(
      'packagePath',
    );
    expect(JSON.stringify(vi.mocked(api.transfer.importVaultPackage).mock.calls)).not.toContain(
      'packagePath',
    );
  });

  it('zeigt neue Windows- und Sichtschutzoptionen als bedienbare Tabs an', async () => {
    const api = createApi(unlockedState);
    window.vaulta = api;
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Einstellungen öffnen' }));
    const tabs = screen.getByRole('tablist', { name: 'Einstellungsbereiche' });
    const securityTab = within(tabs).getByRole('tab', { name: 'Sicherheit' });
    fireEvent.keyDown(securityTab, { key: 'ArrowRight' });
    const clipboardTab = within(tabs).getByRole('tab', { name: 'Zwischenablage' });
    await waitFor(() => expect(clipboardTab).toHaveFocus());
    fireEvent.keyDown(clipboardTab, { key: 'ArrowRight' });

    const windowsTab = within(tabs).getByRole('tab', { name: 'Windows & Sichtschutz' });
    await waitFor(() => expect(windowsTab).toHaveFocus());
    expect(windowsTab).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', 'settings-tab-windows');

    fireEvent.keyDown(windowsTab, { key: 'End' });
    const advancedTab = within(tabs).getByRole('tab', { name: 'Erweitert' });
    await waitFor(() => expect(advancedTab).toHaveFocus());
    expect(advancedTab).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(advancedTab, { key: 'Home' });
    await waitFor(() => expect(securityTab).toHaveFocus());
    expect(securityTab).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(securityTab, { key: 'ArrowRight' });
    await waitFor(() => expect(clipboardTab).toHaveFocus());
    fireEvent.keyDown(clipboardTab, { key: 'ArrowRight' });
    await waitFor(() => expect(windowsTab).toHaveFocus());

    fireEvent.click(screen.getByRole('checkbox', { name: /^Fokusmodus/u }));
    fireEvent.click(screen.getByRole('checkbox', { name: /^Reduzierte Bewegung/u }));
    fireEvent.click(screen.getByRole('checkbox', { name: /^An Ablaufdaten erinnern/u }));
    fireEvent.click(screen.getByRole('button', { name: 'Speichern' }));

    await waitFor(() =>
      expect(api.settings.update).toHaveBeenCalledWith({
        settings: {
          ...EXISTING_PROFILE_SETTINGS,
          focusMode: true,
          reducedMotion: true,
          localReminders: {
            ...EXISTING_PROFILE_SETTINGS.localReminders,
            expiry: true,
          },
        },
      }),
    );
    await waitFor(() =>
      expect(document.documentElement).toHaveAttribute('data-reduced-motion', 'true'),
    );
  });

  it('blendet Fokusmodus-Metadaten und Vorschau-Aktionen aus dem Renderbaum aus', async () => {
    const state: AppState = {
      ...unlockedState,
      settings: { ...EXISTING_PROFILE_SETTINGS, focusMode: true },
    };
    const api = createApi(state);
    vi.mocked(api.entries.getDetail).mockResolvedValue({
      ...entryDetail,
      tags: ['Entwicklung'],
      note: 'Synthetische lokale Vorschau',
      attachments: [
        {
          id: 'attachment-focus-1',
          name: 'synthetische-vorschau.txt',
          mediaType: 'text/plain',
          size: 12,
          sha256: 'a'.repeat(64),
          createdAt: '2026-08-09T10:00:00.000Z',
          previewable: true,
        },
      ],
    });
    window.vaulta = api;
    render(<App />);

    await screen.findByLabelText('Eintragsliste');
    await waitFor(() => expect(api.entries.getDetail).toHaveBeenCalled());

    expect(screen.getByText('Fokusmodus aktiv')).toBeInTheDocument();
    expect(screen.queryByText('lauri@example.de')).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /lauri@example\.de/u })).not.toBeInTheDocument();
    expect(screen.queryByText('Entwicklung')).not.toBeInTheDocument();
    expect(screen.queryByText('Synthetische lokale Vorschau')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'synthetische-vorschau.txt sicher ansehen' }),
    ).not.toBeInTheDocument();
  });

  it('zeigt die überspringbare Einführung nur für ein neues Profil und speichert ihren Abschluss', async () => {
    const state: AppState = {
      ...unlockedState,
      settings: { ...EXISTING_PROFILE_SETTINGS, onboardingCompleted: false },
    };
    const api = createApi(state);
    window.vaulta = api;
    render(<App />);

    const onboarding = await screen.findByRole('dialog', { name: 'Willkommen bei Kryptris' });
    expect(within(onboarding).getByText('Sichtschutz bewusst wählen')).toBeInTheDocument();
    fireEvent.click(within(onboarding).getByRole('button', { name: 'Einführung überspringen' }));

    await waitFor(() =>
      expect(api.settings.update).toHaveBeenCalledWith({
        settings: { ...state.settings!, onboardingCompleted: true },
      }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Willkommen bei Kryptris' }),
      ).not.toBeInTheDocument(),
    );
  });

  it('lässt die Einführung nach einem lokalen Speicherfehler geöffnet und erneut bedienbar', async () => {
    const state: AppState = {
      ...unlockedState,
      settings: { ...EXISTING_PROFILE_SETTINGS, onboardingCompleted: false },
    };
    const api = createApi(state);
    vi.mocked(api.settings.update).mockRejectedValueOnce(new Error('synthetischer Speicherfehler'));
    window.vaulta = api;
    render(<App />);

    const onboarding = await screen.findByRole('dialog', { name: 'Willkommen bei Kryptris' });
    const skip = within(onboarding).getByRole('button', { name: 'Einführung überspringen' });
    fireEvent.click(skip);

    await waitFor(() => expect(api.settings.update).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(skip).not.toBeDisabled());
    expect(screen.getByRole('dialog', { name: 'Willkommen bei Kryptris' })).toBeInTheDocument();
    expect(screen.getByText('Einführung konnte nicht abgeschlossen werden')).toBeInTheDocument();
  });

  it('schließt die Offcanvas-Navigation per Escape und stellt den Auslöserfokus wieder her', async () => {
    vi.stubGlobal('matchMedia', () => ({
      matches: true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
    window.vaulta = createApi(unlockedState);
    render(<App />);

    const menu = await screen.findByRole('button', { name: 'Navigation öffnen' });
    const navigation = document.querySelector<HTMLElement>('aside.sidebar');
    expect(navigation).not.toBeNull();
    if (!navigation) throw new Error('Hauptnavigation fehlt');
    expect(navigation).toHaveAttribute('inert');
    fireEvent.click(menu);

    await waitFor(() => expect(navigation).not.toHaveAttribute('inert'));
    await waitFor(() =>
      expect(within(navigation).getByRole('button', { name: 'Alle Einträge' })).toHaveFocus(),
    );
    fireEvent.keyDown(window, { key: 'Escape' });

    await waitFor(() => expect(navigation).toHaveAttribute('inert'));
    await waitFor(() => expect(menu).toHaveFocus());
  });

  it('navigiert den Tresorwähler per Pfeilen, Home und Ende und gibt Fokus zurück', async () => {
    const state: AppState = {
      ...unlockedState,
      vaults: [
        ...unlockedState.vaults,
        {
          id: 'vault-2',
          name: 'Arbeit',
          color: '#8b5cf6',
          entryCount: 0,
          deletedCount: 0,
          updatedAt: '2026-08-09T10:00:00.000Z',
        },
      ],
    };
    window.vaulta = createApi(state);
    render(<App />);

    const trigger = await screen.findByRole('button', { name: 'Aktiven Tresor wählen' });
    fireEvent.click(trigger);
    const picker = await screen.findByRole('listbox', { name: 'Verfügbare Tresore' });
    const privat = within(picker).getByRole('option', { name: /Privat/u });
    const arbeit = within(picker).getByRole('option', { name: /Arbeit/u });

    await waitFor(() => expect(privat).toHaveFocus());
    fireEvent.keyDown(privat, { key: 'End' });
    expect(arbeit).toHaveFocus();
    fireEvent.keyDown(arbeit, { key: 'Home' });
    expect(privat).toHaveFocus();
    fireEvent.keyDown(privat, { key: 'Escape' });

    await waitFor(() =>
      expect(screen.queryByRole('listbox', { name: 'Verfügbare Tresore' })).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('öffnet die lokale Hilfe ohne externe Verweise und führt zum Sichtschutzbereich', async () => {
    window.vaulta = createApi(unlockedState);
    render(<App />);

    fireEvent.click(await screen.findByRole('button', { name: 'Hilfe & Datenschutz' }));
    expect(await screen.findByRole('heading', { name: 'Hilfe & Datenschutz' })).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Wiederherstellung' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Backups & Wiederherstellung' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Zusätzliche Faktoren' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Klartext-Exporte sind riskant' }),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Wiederherstellung öffnen' }));
    expect(await screen.findByRole('tab', { name: 'Zugang & Faktoren' })).toHaveAttribute(
      'aria-selected',
      'true',
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Hilfe & Datenschutz' }));
    fireEvent.click(screen.getByRole('button', { name: 'Windows & Sichtschutz öffnen' }));

    expect(await screen.findByRole('tab', { name: 'Windows & Sichtschutz' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
  });

  it('verwirft ein verspätetes Detail nach einem Auswahlwechsel und mutiert nur den aktuellen Eintrag', async () => {
    const api = createApi(unlockedState);
    const secondSummary: EntrySummary = {
      ...entrySummary,
      id: 'entry-2',
      title: 'Zweiter synthetischer Eintrag',
      subtitle: 'zweiter@example.test',
      favorite: false,
    };
    const secondDetail: EntryDetail = {
      ...entryDetail,
      id: secondSummary.id,
      title: secondSummary.title,
      favorite: false,
    };
    let resolveFirstDetail: (detail: EntryDetail) => void = () => undefined;
    let resolveSecondDetail: (detail: EntryDetail) => void = () => undefined;
    const firstDetail = new Promise<EntryDetail>((resolve) => {
      resolveFirstDetail = resolve;
    });
    const secondDetailRequest = new Promise<EntryDetail>((resolve) => {
      resolveSecondDetail = resolve;
    });
    vi.mocked(api.entries.list).mockResolvedValue([entrySummary, secondSummary]);
    vi.mocked(api.entries.getDetail).mockImplementation(({ entryId }) =>
      entryId === entrySummary.id ? firstDetail : secondDetailRequest,
    );
    window.vaulta = api;

    render(<App />);

    await screen.findByRole('option', { name: new RegExp(entrySummary.title, 'u') });
    await waitFor(() =>
      expect(api.entries.getDetail).toHaveBeenCalledWith({
        vaultId: entrySummary.vaultId,
        entryId: entrySummary.id,
      }),
    );

    fireEvent.click(screen.getByRole('option', { name: new RegExp(secondSummary.title, 'u') }));
    await waitFor(() =>
      expect(api.entries.getDetail).toHaveBeenLastCalledWith({
        vaultId: secondSummary.vaultId,
        entryId: secondSummary.id,
      }),
    );

    await act(async () => {
      resolveFirstDetail(entryDetail);
      await Promise.resolve();
    });
    expect(screen.queryByRole('heading', { name: entryDetail.title })).not.toBeInTheDocument();

    await act(async () => {
      resolveSecondDetail(secondDetail);
      await Promise.resolve();
    });
    const secondPanel = await screen.findByLabelText(`Details für ${secondDetail.title}`);
    fireEvent.click(within(secondPanel).getByRole('button', { name: 'In Papierkorb verschieben' }));

    await waitFor(() =>
      expect(api.entries.moveToTrash).toHaveBeenCalledWith({
        vaultId: secondSummary.vaultId,
        entryId: secondSummary.id,
      }),
    );
  });

  it('virtualisiert 10.000 EintrÃ¤ge mit begrenztem DOM und tastaturbedienbarem Fenster', async () => {
    const state: AppState = {
      ...unlockedState,
      vaults: [{ ...unlockedState.vaults[0]!, entryCount: 10_000 }],
    };
    const api = createApi(state);
    const summaries: EntrySummary[] = Array.from({ length: 10_000 }, (_, index) => {
      const ordinal = String(index + 1).padStart(5, '0');
      return {
        ...entrySummary,
        id: `synthetic-entry-${ordinal}`,
        title: `Synthetischer Eintrag ${ordinal}`,
        subtitle: 'synthetisch@example.test',
        favorite: false,
        tags: [],
        updatedAt: '2026-07-14T02:00:00.000Z',
      };
    });
    vi.mocked(api.entries.list).mockResolvedValue(summaries);
    window.vaulta = api;

    render(<App />);
    await waitFor(() => expect(api.entries.list).toHaveBeenCalledTimes(1));

    const entryList = await screen.findByRole('listbox');
    const initialRows = await within(entryList).findAllByRole('option');
    expect(initialRows.length).toBeGreaterThan(0);
    expect(initialRows.length).toBeLessThan(40);

    initialRows[0]?.focus();
    fireEvent.keyDown(initialRows[0]!, { key: 'End' });
    const lastTitle = await within(entryList).findByText('Synthetischer Eintrag 10000');
    const lastRow = lastTitle.closest<HTMLElement>('[role="option"]');
    expect(lastRow).not.toBeNull();
    expect(lastRow).toHaveAttribute('aria-posinset', '10000');
    await waitFor(() => expect(lastRow).toHaveFocus());

    fireEvent.keyDown(lastRow!, { key: 'Home' });
    const firstTitle = await within(entryList).findByText('Synthetischer Eintrag 00001');
    const firstRow = firstTitle.closest<HTMLElement>('[role="option"]');
    expect(firstRow).not.toBeNull();
    await waitFor(() => expect(firstRow).toHaveFocus());
    expect(within(entryList).getAllByRole('option').length).toBeLessThan(40);
  });

  it('entprellt die Suche und verwirft eine verspÃ¤tete Antwort der vorherigen Abfrage', async () => {
    const api = createApi(unlockedState);
    let resolveOlderSearch: (entries: EntrySummary[]) => void = () => undefined;
    let resolveCurrentSearch: (entries: EntrySummary[]) => void = () => undefined;
    const olderSearch = new Promise<EntrySummary[]>((resolve) => {
      resolveOlderSearch = resolve;
    });
    const currentSearch = new Promise<EntrySummary[]>((resolve) => {
      resolveCurrentSearch = resolve;
    });
    vi.mocked(api.entries.list).mockImplementation((query) => {
      if (query.search === 'alt') return olderSearch;
      if (query.search === 'neu') return currentSearch;
      return Promise.resolve([entrySummary]);
    });
    window.vaulta = api;

    render(<App />);

    const search = await screen.findByLabelText('Tresor durchsuchen');
    await screen.findByRole('listbox');
    vi.mocked(api.entries.list).mockClear();
    vi.useFakeTimers();
    try {
      fireEvent.change(search, { target: { value: 'alt' } });
      await act(async () => {
        vi.advanceTimersByTime(199);
      });
      expect(api.entries.list).not.toHaveBeenCalled();

      await act(async () => {
        vi.advanceTimersByTime(1);
      });
      expect(api.entries.list).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'alt' }));

      fireEvent.change(search, { target: { value: 'neu' } });
      await act(async () => {
        resolveOlderSearch([{ ...entrySummary, title: 'Veraltetes Ergebnis' }]);
        await Promise.resolve();
      });
      expect(screen.queryByText('Veraltetes Ergebnis')).not.toBeInTheDocument();

      await act(async () => {
        vi.advanceTimersByTime(200);
      });
      expect(api.entries.list).toHaveBeenLastCalledWith(expect.objectContaining({ search: 'neu' }));

      await act(async () => {
        resolveCurrentSearch([{ ...entrySummary, title: 'Aktuelles Ergebnis' }]);
        await Promise.resolve();
      });
      expect(screen.getByText('Aktuelles Ergebnis')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
