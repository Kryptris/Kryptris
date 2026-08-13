import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as ProfileServiceModule from '../../src/main/services/profile-service';
import { DEFAULT_SETTINGS, type VaultaSettings } from '../../src/shared/models';

const mocks = vi.hoisted(() => ({
  beginSetup: vi.fn(),
  completeSetup: vi.fn(),
  hasProfile: vi.fn(),
  isUnlocked: vi.fn(),
  lockProfile: vi.fn(),
  verifyMasterPassword: vi.fn(),
  setProtectedMetadata: vi.fn(),
  showOpenDialog: vi.fn(),
  setContentProtection: vi.fn(),
  auditRecord: vi.fn(),
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
}));

vi.mock('electron', () => ({
  clipboard: mocks.clipboard,
  desktopCapturer: {},
  dialog: { showOpenDialog: mocks.showOpenDialog },
  nativeImage: {},
}));

vi.mock('../../src/main/services/profile-service', async (importOriginal) => {
  const original = await importOriginal<typeof ProfileServiceModule>();
  return {
    ...original,
    ProfileService: class {
      public beginSetup = mocks.beginSetup;
      public completeSetup = mocks.completeSetup;
      public hasProfile = mocks.hasProfile;
      public isUnlocked = mocks.isUnlocked;
      public lock = mocks.lockProfile;
      public verifyMasterPassword = mocks.verifyMasterPassword;
      public setProtectedMetadata = mocks.setProtectedMetadata;
    },
  };
});

import { VaultaController, type DesktopSettingsPolicy } from '../../src/main/vaulta-controller';

const PENDING_SETUP_TIMEOUT_MS = 5 * 60 * 1_000;

function createController(desktopSettingsPolicy?: DesktopSettingsPolicy) {
  return new VaultaController({
    rootDir: 'C:\\vaulta-controller-setup-test',
    version: 'test',
    getWindow: () =>
      ({
        isDestroyed: () => false,
        setContentProtection: mocks.setContentProtection,
      }) as never,
    getOrigin: () => 'https://vaulta.invalid',
    onStateChanged: vi.fn(),
    onLocked: vi.fn(),
    onClipboardCleared: vi.fn(),
    onBackgroundWarning: vi.fn(),
    ...(desktopSettingsPolicy === undefined ? {} : { desktopSettingsPolicy }),
  });
}

function authenticateForSettings(controller: VaultaController): void {
  mocks.isUnlocked.mockReturnValue(true);
  const internals = controller as unknown as {
    authentication: {
      begin(): number;
      complete(profileUnlocked: boolean, epoch: number): void;
    };
    vaults: { listVaults(): Promise<[]>; readVault(id: string): Promise<unknown> };
    createAuditService(): { record(): Promise<void> };
  };
  const epoch = internals.authentication.begin();
  internals.authentication.complete(true, epoch);
  internals.vaults = {
    listVaults: () => Promise.resolve([]),
    readVault: (id) =>
      Promise.resolve({
        formatVersion: 1,
        id,
        name: 'Test',
        color: '#14b8a6',
        createdAt: '2026-07-21T12:00:00.000Z',
        updatedAt: '2026-07-21T12:00:00.000Z',
        folders: [],
        entries: [],
      }),
  };
  internals.createAuditService = () => ({ record: mocks.auditRecord });
}

function disableConfiguredLifecycleLocks(controller: VaultaController): void {
  const state = controller as unknown as { settings: VaultaSettings };
  state.settings = {
    ...DEFAULT_SETTINGS,
    lockOnMinimize: false,
    lockOnSystemLock: false,
    lockOnSuspend: false,
  };
}

async function beginSetup(controller: VaultaController): Promise<void> {
  await controller.beginSetup({
    masterPassword: 'Ein sehr langes Master-Passwort!',
    vaultName: 'Privat',
    enableRecovery: true,
  });
}

describe('VaultaController Pending-Setup-Sitzung', () => {
  const controllers: VaultaController[] = [];

  beforeEach(() => {
    mocks.beginSetup.mockReset().mockResolvedValue({ pendingId: 'pending-1', recovery: null });
    mocks.completeSetup.mockReset().mockRejectedValue(new Error('Bestätigung ungültig'));
    mocks.hasProfile.mockReset().mockResolvedValue(false);
    mocks.isUnlocked.mockReset().mockReturnValue(false);
    mocks.lockProfile.mockReset();
    mocks.verifyMasterPassword.mockReset().mockResolvedValue(true);
    mocks.setProtectedMetadata.mockReset().mockResolvedValue(undefined);
    mocks.showOpenDialog.mockReset();
    mocks.setContentProtection.mockReset();
    mocks.auditRecord.mockReset().mockResolvedValue(undefined);
    mocks.clipboard.readText.mockReturnValue('');
  });

  afterEach(() => {
    for (const controller of controllers) controller.dispose();
    controllers.length = 0;
    vi.useRealTimers();
  });

  function trackedController(desktopSettingsPolicy?: DesktopSettingsPolicy): VaultaController {
    const controller = createController(desktopSettingsPolicy);
    controllers.push(controller);
    return controller;
  }

  it('verwendet bis zur Bestätigung dieselbe authentifizierende Epoche', async () => {
    const controller = trackedController();
    await beginSetup(controller);

    await expect(
      controller.completeSetup({ pendingId: 'pending-1', confirmation: {} }),
    ).rejects.toThrow('Bestätigung ungültig');
    expect(mocks.completeSetup).toHaveBeenCalledWith('pending-1', {});
    await expect(beginSetup(controller)).rejects.toMatchObject({ code: 'CONFLICT' });

    await controller.lock();
    await expect(beginSetup(controller)).resolves.toBeUndefined();
  });

  it('verwirft die Pending-Einrichtung nach fünf Minuten', async () => {
    vi.useFakeTimers();
    const controller = trackedController();
    await beginSetup(controller);

    await vi.advanceTimersByTimeAsync(PENDING_SETUP_TIMEOUT_MS - 1);
    expect(mocks.lockProfile).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);

    expect(mocks.lockProfile).toHaveBeenCalled();
    await expect(
      controller.completeSetup({ pendingId: 'pending-1', confirmation: {} }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it.each([
    ['manuelles Sperren', (controller: VaultaController) => controller.lock()],
    [
      'Minimieren',
      (controller: VaultaController) => {
        controller.onWindowMinimized();
      },
    ],
    [
      'Windows-Sperre',
      (controller: VaultaController) => {
        controller.onSystemLock();
      },
    ],
    [
      'Suspend',
      (controller: VaultaController) => {
        controller.onSystemSuspend();
      },
    ],
  ])('löscht Pending-Schlüssel bei %s unabhängig von den Einstellungen', async (_name, act) => {
    const controller = trackedController();
    disableConfiguredLifecycleLocks(controller);
    await beginSetup(controller);

    await Promise.resolve(act(controller));

    expect(mocks.lockProfile).toHaveBeenCalled();
    await expect(
      controller.completeSetup({ pendingId: 'pending-1', confirmation: {} }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('akzeptiert nur den unmittelbar zuvor nativ autorisierten Backup-Ordner', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    mocks.showOpenDialog.mockResolvedValue({
      canceled: false,
      filePaths: ['C:\\Users\\Lauri\\Backups\\..\\Vaulta-Backups'],
    });

    const selected = await controller.chooseBackupFolder();
    expect(selected).toBe('C:\\Users\\Lauri\\Vaulta-Backups');
    const updated = await controller.updateSettings({
      settings: {
        ...DEFAULT_SETTINGS,
        backupFolder: selected,
      },
    });

    expect(updated.backupFolder).toBe(selected);
    await expect(
      controller.updateSettings({
        settings: {
          ...updated,
          backupFolder: 'C:\\Users\\Lauri\\Nicht-autorisiert',
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('verlangt für schwächere Sicherheitseinstellungen das Master-Passwort ohne die Pfadautorisierung bei einem Fehlversuch zu verlieren', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    mocks.showOpenDialog.mockResolvedValue({
      canceled: false,
      filePaths: ['C:\\Users\\Lauri\\Vaulta-Backups'],
    });
    const selected = await controller.chooseBackupFolder();
    const weakened = {
      ...DEFAULT_SETTINGS,
      autoLockSeconds: 1_800,
      backupFolder: selected,
    };

    await expect(controller.updateSettings({ settings: weakened })).rejects.toMatchObject({
      code: 'AUTH_FAILED',
    });
    mocks.verifyMasterPassword.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    await expect(
      controller.updateSettings({ settings: weakened, masterPassword: 'falsch' }),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });

    await expect(
      controller.updateSettings({ settings: weakened, masterPassword: 'korrekt' }),
    ).resolves.toMatchObject({ autoLockSeconds: 1_800, backupFolder: selected });
    expect(mocks.verifyMasterPassword).toHaveBeenNthCalledWith(1, 'falsch');
    expect(mocks.verifyMasterPassword).toHaveBeenNthCalledWith(2, 'korrekt');
  });

  it('setzt die Windows-Policy nach einem fehlgeschlagenen Settings-Commit zurück', async () => {
    const operations: string[] = [];
    const apply = vi.fn((settings: Readonly<VaultaSettings>) => {
      operations.push(settings.minimizeToTray ? 'neue-policy' : 'vorherige-policy');
    });
    const desktopSettingsPolicy: DesktopSettingsPolicy = {
      apply,
    };
    mocks.setProtectedMetadata.mockImplementationOnce(() => {
      operations.push('geschuetzter-commit');
      return Promise.reject(
        new Error('Geschuetzte Einstellungen konnten nicht gespeichert werden.'),
      );
    });
    const controller = trackedController(desktopSettingsPolicy);
    authenticateForSettings(controller);

    await expect(
      controller.updateSettings({
        settings: { ...DEFAULT_SETTINGS, minimizeToTray: true },
      }),
    ).rejects.toThrow('Geschuetzte Einstellungen konnten nicht gespeichert werden.');

    expect(operations).toEqual(['neue-policy', 'geschuetzter-commit', 'vorherige-policy']);
    expect(apply).toHaveBeenNthCalledWith(1, expect.objectContaining({ minimizeToTray: true }));
    expect(apply).toHaveBeenNthCalledWith(2, DEFAULT_SETTINGS);
    expect(mocks.setProtectedMetadata).toHaveBeenCalledTimes(1);
    expect(controller.getSettings()).toEqual(DEFAULT_SETTINGS);
  });

  it('verändert bei falschem Master-Passwort keine Batch-Purge-Auswahl', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    mocks.verifyMasterPassword.mockResolvedValueOnce(false);

    await expect(
      controller.runProductivityBatch({
        vaultId: '00000000-0000-4000-8000-000000000001',
        entryIds: ['00000000-0000-4000-8000-000000000002'],
        action: {
          type: 'purge',
          masterPassword: 'falsch',
          confirmationCount: 1,
        },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(mocks.verifyMasterPassword).toHaveBeenCalledWith('falsch');
  });

  it('stellt Saved-View-Snapshots nach gleichzeitigem Sperren nicht wieder her', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    let rejectWrite: ((reason: Error) => void) | undefined;
    mocks.setProtectedMetadata.mockImplementationOnce(
      () =>
        new Promise<never>((_resolve, reject) => {
          rejectWrite = reject;
        }),
    );

    const pending = controller.saveSavedView({
      vaultId: '00000000-0000-4000-8000-000000000001',
      name: 'Vertrauliche Suche',
      filters: {
        search: 'nur-im-entsperrten-cache',
        view: 'all',
        types: [],
        tags: [],
        folderId: null,
        security: [],
        smartView: null,
      },
    });
    await vi.waitFor(() => expect(rejectWrite).toBeTypeOf('function'));
    await controller.lock();
    rejectWrite?.(new Error('Schreibvorgang nach Lock abgebrochen'));
    await expect(pending).rejects.toThrow('Schreibvorgang nach Lock abgebrochen');

    const internals = controller as unknown as {
      productivity: { snapshot(): Array<{ name: string }> };
    };
    expect(internals.productivity.snapshot()).toEqual([]);
  });

  it('verbraucht eine Ordnerautorisierung einmalig und löscht sie beim Sperren', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    mocks.showOpenDialog.mockResolvedValue({
      canceled: false,
      filePaths: ['C:\\Users\\Lauri\\Vaulta-Backups'],
    });
    const selected = await controller.chooseBackupFolder();
    expect(selected).not.toBeNull();

    await controller.updateSettings({ settings: DEFAULT_SETTINGS });
    await expect(
      controller.updateSettings({
        settings: { ...DEFAULT_SETTINGS, backupFolder: selected },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    await controller.chooseBackupFolder();
    await controller.lock();
    authenticateForSettings(controller);
    await expect(
      controller.updateSettings({
        settings: { ...DEFAULT_SETTINGS, backupFolder: selected },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('lehnt auch aus dem nativen Dialog stammende Netzwerkpfade ab', async () => {
    const controller = trackedController();
    authenticateForSettings(controller);
    mocks.showOpenDialog.mockResolvedValue({
      canceled: false,
      filePaths: ['\\\\server\\freigabe\\vaulta'],
    });

    await expect(controller.chooseBackupFolder()).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
