import type { Menu, MenuItemConstructorOptions, Tray } from 'electron';
import { describe, expect, it, vi } from 'vitest';

import {
  START_MINIMIZED_ARGUMENT,
  WindowsIntegrationService,
  wasStartedMinimized,
  type WindowsIntegrationSettings,
} from '../../src/main/services/windows-integration-service';

const DEFAULT_SETTINGS: WindowsIntegrationSettings = {
  minimizeToTray: false,
  closeToTray: false,
  startWithWindows: false,
  startMinimized: false,
  localReminders: { rotation: false, expiry: false, backup: false },
};

interface TrayHarness {
  readonly tray: Tray;
  readonly setToolTip: ReturnType<typeof vi.fn>;
  readonly click: () => void;
}

function createTrayHarness(): TrayHarness {
  const setToolTip = vi.fn();
  let click = (): void => undefined;
  const tray = {
    on: vi.fn((event: string, callback: () => void) => {
      if (event === 'click') click = callback;
      return tray;
    }),
    isDestroyed: vi.fn(() => false),
    setToolTip,
    setContextMenu: vi.fn((menu: Menu) => {
      void menu;
    }),
    destroy: vi.fn(),
  } as unknown as Tray;
  return { tray, setToolTip, click: () => click() };
}

function labels(template: readonly MenuItemConstructorOptions[]): string[] {
  return template.flatMap((item) =>
    'label' in item && item.label !== undefined ? [item.label] : [],
  );
}

function findMenuItem(
  template: readonly MenuItemConstructorOptions[],
  label: string,
): MenuItemConstructorOptions {
  const item = template.find((candidate) => 'label' in candidate && candidate.label === label);
  if (item === undefined) throw new Error(`Menüeintrag ${label} fehlt.`);
  return item;
}

describe('WindowsIntegrationService', () => {
  it('lässt den Start ohne Tray fortsetzen, wenn die optionale Shell-Oberfläche fehlschlägt', () => {
    const setLoginItemSettings = vi.fn();
    const onError = vi.fn();
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings },
      createTray: () => {
        throw new Error('Kein System-Tray verfügbar.');
      },
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => undefined,
      onQuit: () => undefined,
      onError,
    });

    expect(() => service.initialize()).not.toThrow();
    expect(onError).toHaveBeenCalledWith(expect.any(Error));

    const settings = { ...DEFAULT_SETTINGS, minimizeToTray: true, startWithWindows: true };
    service.apply(settings);

    expect(service.shouldHideOnMinimize()).toBe(true);
    expect(setLoginItemSettings).toHaveBeenCalledWith({
      openAtLogin: true,
      openAsHidden: false,
      args: [],
    });
  });

  it('hält das Tray-Menü bei Statusänderungen frei von Tresor- und Eintragsdaten', async () => {
    const tray = createTrayHarness();
    const templates: MenuItemConstructorOptions[][] = [];
    const onOpen = vi.fn();
    const onLock = vi.fn(() => Promise.resolve());
    const onQuit = vi.fn(() => Promise.resolve());
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings: vi.fn() },
      createTray: () => tray.tray,
      buildMenu: (template) => {
        templates.push(template);
        return {} as Menu;
      },
      onOpen,
      onLock,
      onQuit,
    });

    service.initialize();
    service.updateState({ locked: false, settings: DEFAULT_SETTINGS });
    const unlocked = templates.at(-1);
    expect(unlocked).toBeDefined();
    expect(labels(unlocked ?? [])).toEqual([
      'Kryptris – entsperrt',
      'Öffnen',
      'Jetzt sperren',
      'Beenden',
    ]);
    expect(JSON.stringify(unlocked)).not.toMatch(/Tresor|Eintrag|Passwort|Geheim/i);

    const lockItem = findMenuItem(unlocked ?? [], 'Jetzt sperren');
    expect(lockItem.enabled).toBe(true);
    (lockItem.click as (() => void) | undefined)?.();
    await Promise.resolve();
    expect(onLock).toHaveBeenCalledOnce();
    expect(tray.setToolTip).toHaveBeenLastCalledWith('Kryptris – gesperrt');

    tray.click();
    expect(onOpen).toHaveBeenCalledOnce();
    const locked = templates.at(-1);
    expect(findMenuItem(locked ?? [], 'Jetzt sperren').enabled).toBe(false);
  });

  it('setzt Autostart pro Benutzer reversibel und nur bei einer echten Änderung', () => {
    const tray = createTrayHarness();
    const setLoginItemSettings = vi.fn();
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings },
      createTray: () => tray.tray,
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => undefined,
      onQuit: () => undefined,
    });
    const enabled = {
      ...DEFAULT_SETTINGS,
      startWithWindows: true,
      startMinimized: true,
    };

    service.apply(enabled);
    service.apply(enabled);
    service.apply(DEFAULT_SETTINGS);

    expect(setLoginItemSettings).toHaveBeenCalledTimes(2);
    expect(setLoginItemSettings).toHaveBeenNthCalledWith(1, {
      openAtLogin: true,
      openAsHidden: true,
      args: [START_MINIMIZED_ARGUMENT],
    });
    expect(setLoginItemSettings).toHaveBeenLastCalledWith({
      openAtLogin: false,
      openAsHidden: false,
      args: [],
    });
  });

  it('übernimmt Tray-Policies erst nach erfolgreicher Windows-Policy', () => {
    const tray = createTrayHarness();
    const setLoginItemSettings = vi.fn(() => {
      throw new Error('Windows verweigert den Startwert.');
    });
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings },
      createTray: () => tray.tray,
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => undefined,
      onQuit: () => undefined,
    });

    expect(() =>
      service.apply({ ...DEFAULT_SETTINGS, minimizeToTray: true, startWithWindows: true }),
    ).toThrow(/Windows verweigert/i);
    expect(service.shouldHideOnMinimize()).toBe(false);
    expect(service.shouldHideOnClose()).toBe(false);
  });

  it('behält die entschlüsselten Fenster-Policies nur im laufenden Prozess nach einem Lock', () => {
    const tray = createTrayHarness();
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings: vi.fn() },
      createTray: () => tray.tray,
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => undefined,
      onQuit: () => undefined,
    });
    const enabled = { ...DEFAULT_SETTINGS, minimizeToTray: true, closeToTray: true };

    service.updateState({ locked: false, settings: enabled });
    service.updateState({ locked: true, settings: null });

    expect(service.shouldHideOnMinimize()).toBe(true);
    expect(service.shouldHideOnClose()).toBe(true);
  });

  it('sperrt beim Schließen in den Infobereich vor dem Verbergen', async () => {
    const tray = createTrayHarness();
    const events: string[] = [];
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings: vi.fn() },
      createTray: () => tray.tray,
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => {
        events.push('lock');
        return Promise.resolve();
      },
      onQuit: () => undefined,
    });

    await service.hideAfterLock(() => events.push('hide'));

    expect(events).toEqual(['lock', 'hide']);
  });

  it('sperrt bei einer lokalen Benachrichtigung vor dem Zeigen des Fensters', async () => {
    const tray = createTrayHarness();
    const events: string[] = [];
    const service = new WindowsIntegrationService({
      app: { setLoginItemSettings: vi.fn() },
      createTray: () => tray.tray,
      buildMenu: () => ({}) as Menu,
      onOpen: () => undefined,
      onLock: () => {
        events.push('lock');
        return Promise.resolve();
      },
      onQuit: () => undefined,
    });

    await service.showAfterLock(() => events.push('show'));

    expect(events).toEqual(['lock', 'show']);
  });

  it('erkennt ausschließlich das explizite minimierte Autostart-Argument', () => {
    expect(wasStartedMinimized(['electron', 'app', START_MINIMIZED_ARGUMENT])).toBe(true);
    expect(wasStartedMinimized(['electron', 'app', '--start-minimized-extra'])).toBe(false);
    expect(wasStartedMinimized(['electron', 'app'])).toBe(false);
  });
});
