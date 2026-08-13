import type { App, Menu, MenuItemConstructorOptions, Tray } from 'electron';

export const START_MINIMIZED_ARGUMENT = '--start-minimized';

export interface LocalReminderPreferences {
  readonly rotation: boolean;
  readonly expiry: boolean;
  readonly backup: boolean;
}

/** The desktop-only subset is intentionally free of vault and entry data. */
export interface WindowsIntegrationSettings {
  readonly minimizeToTray: boolean;
  readonly closeToTray: boolean;
  readonly startWithWindows: boolean;
  readonly startMinimized: boolean;
  readonly localReminders: LocalReminderPreferences;
}

export interface WindowsIntegrationState {
  readonly locked: boolean;
  readonly settings: WindowsIntegrationSettings | null;
}

export interface WindowsIntegrationServiceOptions {
  readonly app: Pick<App, 'setLoginItemSettings'>;
  readonly createTray: () => Tray;
  readonly buildMenu: (template: MenuItemConstructorOptions[]) => Menu;
  readonly onOpen: () => void;
  readonly onLock: () => void | Promise<void>;
  readonly onQuit: () => void | Promise<void>;
  readonly onError?: (error: unknown) => void;
}

function loginItemSignature(settings: WindowsIntegrationSettings): string {
  return JSON.stringify({
    openAtLogin: settings.startWithWindows,
    openAsHidden: settings.startWithWindows && settings.startMinimized,
    args: settings.startWithWindows && settings.startMinimized ? [START_MINIMIZED_ARGUMENT] : [],
  });
}

/**
 * Owns the Windows shell surface only. Neither its tray labels nor its retained state contains
 * vault, entry, or secret data.
 */
export class WindowsIntegrationService {
  private readonly app: Pick<App, 'setLoginItemSettings'>;
  private readonly createTray: () => Tray;
  private readonly buildMenu: (template: MenuItemConstructorOptions[]) => Menu;
  private readonly onOpen: () => void;
  private readonly onLock: () => void | Promise<void>;
  private readonly onQuit: () => void | Promise<void>;
  private readonly onError: (error: unknown) => void;
  private tray: Tray | null = null;
  private settings: WindowsIntegrationSettings | null = null;
  private locked = true;
  private lastLoginItemSignature: string | null = null;

  public constructor(options: WindowsIntegrationServiceOptions) {
    this.app = options.app;
    this.createTray = options.createTray;
    this.buildMenu = options.buildMenu;
    this.onOpen = options.onOpen;
    this.onLock = options.onLock;
    this.onQuit = options.onQuit;
    this.onError = options.onError ?? (() => undefined);
  }

  public initialize(): void {
    if (this.tray !== null) return;
    let createdTray: Tray | null = null;
    try {
      createdTray = this.createTray();
      createdTray.on('click', () => this.onOpen());
      this.tray = createdTray;
      this.refreshTray();
    } catch (error) {
      this.tray = null;
      try {
        createdTray?.destroy();
      } catch {
        // Der Fehler der optionalen Shell-Oberfläche darf den App-Start nicht überdecken.
      }
      this.onError(error);
    }
  }

  /**
   * Applies the reversible per-user login item policy before settings are persisted. It throws on
   * an OS failure so the controller can keep the protected settings transaction atomic.
   */
  public apply(settings: Readonly<WindowsIntegrationSettings>): void {
    const nextSignature = loginItemSignature(settings);
    if (nextSignature !== this.lastLoginItemSignature) {
      this.app.setLoginItemSettings({
        openAtLogin: settings.startWithWindows,
        openAsHidden: settings.startWithWindows && settings.startMinimized,
        args:
          settings.startWithWindows && settings.startMinimized ? [START_MINIMIZED_ARGUMENT] : [],
      });
      this.lastLoginItemSignature = nextSignature;
    }
    this.settings = settings;
    this.refreshTray();
  }

  /** Applies state emitted after unlock/settings commits without exposing state to the tray. */
  public updateState(state: WindowsIntegrationState): void {
    this.locked = state.locked;
    if (state.settings !== null) {
      try {
        this.apply(state.settings);
      } catch (error) {
        this.onError(error);
      }
    }
    this.refreshTray();
  }

  public onLocked(): void {
    this.locked = true;
    this.refreshTray();
  }

  public shouldHideOnMinimize(): boolean {
    return this.settings?.minimizeToTray === true;
  }

  public shouldHideOnClose(): boolean {
    return this.settings?.closeToTray === true;
  }

  /** Preserves close-to-tray's lock-before-hide invariant even when the lock emits state later. */
  public async hideAfterLock(hide: () => void): Promise<void> {
    this.locked = true;
    this.refreshTray();
    try {
      await this.onLock();
    } finally {
      hide();
    }
  }

  /** Notification activation never reveals a previously unlocked workspace before locking it. */
  public async showAfterLock(show: () => void): Promise<void> {
    this.locked = true;
    this.refreshTray();
    await this.onLock();
    show();
  }

  public dispose(): void {
    this.tray?.destroy();
    this.tray = null;
    this.settings = null;
    this.lastLoginItemSignature = null;
    this.locked = true;
  }

  private refreshTray(): void {
    const tray = this.tray;
    if (tray === null || tray.isDestroyed()) return;
    const status = this.locked ? 'gesperrt' : 'entsperrt';
    tray.setToolTip(`Kryptris – ${status}`);
    tray.setContextMenu(
      this.buildMenu([
        { label: `Kryptris – ${status}`, enabled: false },
        { type: 'separator' },
        { label: 'Öffnen', click: () => this.onOpen() },
        {
          label: 'Jetzt sperren',
          enabled: !this.locked,
          click: () => {
            this.locked = true;
            this.refreshTray();
            void Promise.resolve(this.onLock()).catch((error: unknown) => this.onError(error));
          },
        },
        { type: 'separator' },
        {
          label: 'Beenden',
          click: () => {
            this.locked = true;
            this.refreshTray();
            void Promise.resolve(this.onQuit()).catch((error: unknown) => this.onError(error));
          },
        },
      ]),
    );
  }
}

/** Only the app's explicit per-user login-item argument is interpreted as a minimized launch. */
export function wasStartedMinimized(argv: readonly string[]): boolean {
  return argv.includes(START_MINIMIZED_ARGUMENT);
}
