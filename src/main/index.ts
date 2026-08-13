import path from 'node:path';

import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  nativeImage,
  Notification,
  powerMonitor,
  session,
  Tray,
} from 'electron';

import { IPC_CHANNELS } from '../shared/ipc';
import type { AppState } from '../shared/models';
import { registerIpcHandlers } from './ipc/register-handlers';
import { RendererServer } from './renderer-server';
import { LocalReminderService } from './services/local-reminder-service';
import {
  WindowsIntegrationService,
  wasStartedMinimized,
} from './services/windows-integration-service';
import { createKryptrisTrayIcon } from './tray-icon';
import { TrustedActivityReporter } from './trusted-activity-reporter';
import { VaultaController } from './vaulta-controller';

let mainWindow: BrowserWindow | null = null;
let controller: VaultaController | null = null;
let rendererServer: RendererServer | null = null;
let allowedOrigin = '';
let closingWindow = false;
let hidingToTray = false;
let quitting = false;
let windowsIntegration: WindowsIntegrationService | null = null;
let localReminders: LocalReminderService | null = null;
let reminderPreferencesSignature: string | null = null;
const startMinimized = wasStartedMinimized(process.argv);

app.setName('Kryptris');
// Bestehende Vaulta-Installationen behalten ihren Datenordner nach der Umbenennung.
if (process.env.VAULTA_E2E_MODE === undefined) {
  app.setPath('userData', path.join(app.getPath('appData'), 'Vaulta'));
}
app.enableSandbox();
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-component-update');
app.commandLine.appendSwitch('disable-domain-reliability');
app.commandLine.appendSwitch('disable-sync');

const ownsInstance = app.requestSingleInstanceLock();
if (!ownsInstance) app.quit();

function sendEvent(channel: string): void {
  const window = mainWindow;
  if (window !== null && !window.isDestroyed()) window.webContents.send(channel);
}

function sendValue<T>(channel: string, value: T): void {
  const window = mainWindow;
  if (window !== null && !window.isDestroyed()) window.webContents.send(channel, value);
}

function showMainWindow(): void {
  const window = mainWindow;
  if (window === null || window.isDestroyed()) return;
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
}

async function quitApplication(): Promise<void> {
  if (quitting) return;
  quitting = true;
  try {
    await (controller?.lock() ?? Promise.resolve());
  } finally {
    app.quit();
  }
}

function resolveTrayIcon() {
  return createKryptrisTrayIcon(nativeImage);
}

function reportWindowsIntegrationError(): void {
  sendValue(
    IPC_CHANNELS.eventBackgroundWarning,
    'Die Windows-Integration konnte nicht vollständig ausgeführt werden.',
  );
}

function syncLocalReminders(state: AppState): void {
  const reminders = localReminders;
  if (reminders === null) return;
  if (state.locked || state.settings === null) {
    reminders.stop();
    reminderPreferencesSignature = null;
    return;
  }
  const preferences = state.settings.localReminders;
  const signature = JSON.stringify(preferences);
  if (signature === reminderPreferencesSignature) return;
  reminderPreferencesSignature = signature;
  reminders.start(preferences, (context) => {
    const currentController = controller;
    if (currentController === null) {
      return Promise.resolve({ rotationDue: 0, expirationDue: 0, staleBackup: false });
    }
    return currentController.getLocalReminderSnapshot(context.assertActive);
  });
}

function onControllerStateChanged(state: AppState): void {
  sendValue(IPC_CHANNELS.eventStateChanged, state);
  windowsIntegration?.updateState({ locked: state.locked, settings: state.settings });
  syncLocalReminders(state);
}

function parseDevelopmentUrl(): URL | null {
  if (app.isPackaged) return null;
  const value = process.env.VITE_DEV_SERVER_URL;
  if (value === undefined) return null;
  const parsed = new URL(value);
  if (
    parsed.protocol !== 'http:' ||
    parsed.hostname !== 'localhost' ||
    (parsed.port.length > 0 && parsed.port !== '5173')
  ) {
    throw new Error(
      'Die Entwicklungsoberfläche muss über http://localhost:5173 bereitgestellt werden.',
    );
  }
  return parsed;
}

function isAllowedSubresource(rawUrl: string, development: boolean): boolean {
  try {
    const target = new URL(rawUrl);
    if (target.protocol === 'data:' || target.protocol === 'blob:') return true;
    if (target.origin === allowedOrigin) return true;
    if (
      development &&
      target.protocol === 'ws:' &&
      target.hostname === 'localhost' &&
      target.port === '5173'
    ) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

function isAllowedNavigation(rawUrl: string): boolean {
  try {
    const target = new URL(rawUrl);
    return target.protocol === 'http:' && target.origin === allowedOrigin;
  } catch {
    return false;
  }
}

function hardenSession(window: BrowserWindow, development: boolean): void {
  const currentSession = window.webContents.session;
  currentSession.setPermissionCheckHandler(() => false);
  currentSession.setPermissionRequestHandler((_webContents, _permission, callback) =>
    callback(false),
  );
  currentSession.setDevicePermissionHandler(() => false);
  currentSession.on('will-download', (event) => event.preventDefault());
  currentSession.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
    callback({ cancel: !isAllowedSubresource(details.url, development) });
  });
}

function hardenWebContents(
  window: BrowserWindow,
  development: boolean,
  onActivity: () => void,
): void {
  const activity = new TrustedActivityReporter(onActivity);
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => {
    if (!isAllowedNavigation(url)) {
      event.preventDefault();
      window.webContents.stop();
    }
  });
  window.webContents.on('will-redirect', (event, url) => {
    if (!isAllowedNavigation(url)) {
      event.preventDefault();
      window.webContents.stop();
    }
  });
  window.webContents.on('will-attach-webview', (event) => event.preventDefault());
  window.webContents.on('before-input-event', (event, input) => {
    activity.reportKeyboardInput();
    if (
      !development &&
      (input.key === 'F12' ||
        (input.control && input.shift && input.key.toLocaleLowerCase('en') === 'i'))
    ) {
      event.preventDefault();
    }
  });
  window.webContents.on('before-mouse-event', (_event, input) => {
    activity.reportMouseInput(input.type);
  });
}

async function resolveRendererUrl(): Promise<{ url: string; development: boolean }> {
  const developmentUrl = parseDevelopmentUrl();
  if (developmentUrl !== null) {
    allowedOrigin = developmentUrl.origin;
    return { url: developmentUrl.toString(), development: true };
  }
  rendererServer = new RendererServer(path.resolve(__dirname, '../../renderer'));
  allowedOrigin = await rendererServer.start();
  return { url: `${allowedOrigin}/`, development: false };
}

async function createWindow(): Promise<void> {
  const renderer = await resolveRendererUrl();
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1080,
    minHeight: 680,
    show: false,
    frame: false,
    backgroundColor: '#080d18',
    title: 'Kryptris',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.resolve(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      safeDialogs: true,
      navigateOnDragDrop: false,
      devTools: renderer.development,
    },
  });
  mainWindow = window;
  window.setContentProtection(true);
  hardenSession(window, renderer.development);

  windowsIntegration ??= new WindowsIntegrationService({
    app,
    createTray: () => new Tray(resolveTrayIcon()),
    buildMenu: (template) => Menu.buildFromTemplate(template),
    onOpen: showMainWindow,
    onLock: () => controller?.lock() ?? Promise.resolve(),
    onQuit: quitApplication,
    onError: reportWindowsIntegrationError,
  });
  windowsIntegration.initialize();
  localReminders ??= new LocalReminderService({
    createNotification: (options) =>
      Notification.isSupported() ? new Notification(options) : null,
    onOpenLocked: async () => {
      const integration = windowsIntegration;
      if (integration !== null) {
        await integration.showAfterLock(showMainWindow);
        return;
      }
      await (controller?.lock() ?? Promise.resolve());
      showMainWindow();
    },
    onError: reportWindowsIntegrationError,
  });

  const e2eDataRoot = process.env.KRYPTRIS_E2E_DATA_DIR;
  controller = new VaultaController({
    rootDir:
      e2eDataRoot === undefined
        ? path.join(app.getPath('userData'), 'data')
        : path.join(e2eDataRoot, 'data'),
    version: app.getVersion(),
    getWindow: () => mainWindow,
    getOrigin: () => allowedOrigin,
    onStateChanged: onControllerStateChanged,
    onLocked: () => {
      localReminders?.stop();
      reminderPreferencesSignature = null;
      windowsIntegration?.onLocked();
      sendEvent(IPC_CHANNELS.eventLocked);
    },
    onClipboardCleared: () => sendEvent(IPC_CHANNELS.eventClipboardCleared),
    onBackgroundWarning: (message) => sendValue(IPC_CHANNELS.eventBackgroundWarning, message),
    desktopSettingsPolicy: windowsIntegration,
  });
  hardenWebContents(window, renderer.development, () => controller?.activity());
  registerIpcHandlers({
    ipcMain,
    controller,
    getWindow: () => mainWindow,
    getAllowedOrigin: () => allowedOrigin,
  });
  const initialState = await controller.initialize();
  onControllerStateChanged(initialState);

  window.once('ready-to-show', () => {
    if (startMinimized) {
      window.showInactive();
      window.minimize();
      return;
    }
    window.show();
  });
  window.on('minimize', () => {
    controller?.onWindowMinimized();
    if (windowsIntegration?.shouldHideOnMinimize() === true) window.hide();
  });
  window.on('blur', () => controller?.onWindowBlur());
  window.on('close', (event) => {
    if (closingWindow || quitting) return;
    event.preventDefault();
    if (windowsIntegration?.shouldHideOnClose() === true) {
      if (hidingToTray) return;
      hidingToTray = true;
      void windowsIntegration
        .hideAfterLock(() => window.hide())
        .catch(() => reportWindowsIntegrationError())
        .finally(() => {
          hidingToTray = false;
        });
      return;
    }
    closingWindow = true;
    void (controller?.lock() ?? Promise.resolve()).finally(() => {
      if (!window.isDestroyed()) window.destroy();
    });
  });
  window.on('closed', () => {
    mainWindow = null;
    hidingToTray = false;
  });
  await window.loadURL(renderer.url);
}

if (ownsInstance) {
  app.on('second-instance', () => {
    showMainWindow();
  });

  app
    .whenReady()
    .then(async () => {
      app.setAppUserModelId('de.kryptris.desktop');
      Menu.setApplicationMenu(null);
      session.defaultSession.setUserAgent('Kryptris Desktop');
      powerMonitor.on('lock-screen', () => controller?.onSystemLock());
      powerMonitor.on('suspend', () => controller?.onSystemSuspend());
      await createWindow();
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unbekannter Startfehler';
      dialog.showErrorBox('Kryptris konnte nicht gestartet werden', message);
      app.exit(1);
    });

  app.on('window-all-closed', () => app.quit());
  app.on('will-quit', () => {
    localReminders?.dispose();
    localReminders = null;
    reminderPreferencesSignature = null;
    windowsIntegration?.dispose();
    windowsIntegration = null;
    controller?.dispose();
    controller = null;
    void rendererServer?.close();
    rendererServer = null;
  });
}
