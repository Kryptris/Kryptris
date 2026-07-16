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
} from '../../src/shared/models';

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
  settings: DEFAULT_SETTINGS,
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
    },
    backup: {
      create: vi.fn(async () => null),
      restore: vi.fn(async () => null),
      chooseFolder: vi.fn(async () => null),
    },
    transfer: {
      previewImport: vi.fn(async () => null),
      remapImport: vi.fn(async () => {
        throw new Error('In diesem Test nicht verwendet');
      }),
      executeImport: vi.fn(async () => ({ imported: 0, skipped: 0, entryIds: [] })),
      export: vi.fn(async () => null),
    },
    audit: { list: vi.fn(async () => []) },
    settings: {
      get: vi.fn(async () => DEFAULT_SETTINGS),
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
    fireEvent.click(within(entryList).getByRole('button', { name: 'Neuer Eintrag' }));
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
        settings: { ...DEFAULT_SETTINGS, autoLockSeconds: 1_800 },
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
});
