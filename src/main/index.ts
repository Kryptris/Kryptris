import path from 'node:path';

import { app, BrowserWindow, dialog, ipcMain, Menu, powerMonitor, session } from 'electron';

import { IPC_CHANNELS } from '../shared/ipc';
import { registerIpcHandlers } from './ipc/register-handlers';
import { RendererServer } from './renderer-server';
import { TrustedActivityReporter } from './trusted-activity-reporter';
import { VaultaController } from './vaulta-controller';

let mainWindow: BrowserWindow | null = null;
let controller: VaultaController | null = null;
let rendererServer: RendererServer | null = null;
let allowedOrigin = '';
let closingWindow = false;

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

  const e2eDataRoot = process.env.KRYPTRIS_E2E_DATA_DIR;
  controller = new VaultaController({
    rootDir:
      e2eDataRoot === undefined
        ? path.join(app.getPath('userData'), 'data')
        : path.join(e2eDataRoot, 'data'),
    version: app.getVersion(),
    getWindow: () => mainWindow,
    getOrigin: () => allowedOrigin,
    onStateChanged: (state) => sendValue(IPC_CHANNELS.eventStateChanged, state),
    onLocked: () => sendEvent(IPC_CHANNELS.eventLocked),
    onClipboardCleared: () => sendEvent(IPC_CHANNELS.eventClipboardCleared),
    onBackgroundWarning: (message) => sendValue(IPC_CHANNELS.eventBackgroundWarning, message),
  });
  hardenWebContents(window, renderer.development, () => controller?.activity());
  registerIpcHandlers({
    ipcMain,
    controller,
    getWindow: () => mainWindow,
    getAllowedOrigin: () => allowedOrigin,
  });
  await controller.initialize();

  window.once('ready-to-show', () => window.show());
  window.on('minimize', () => controller?.onWindowMinimized());
  window.on('blur', () => controller?.onWindowBlur());
  window.on('close', (event) => {
    if (closingWindow) return;
    event.preventDefault();
    closingWindow = true;
    void (controller?.lock() ?? Promise.resolve()).finally(() => {
      if (!window.isDestroyed()) window.destroy();
    });
  });
  window.on('closed', () => {
    mainWindow = null;
  });
  await window.loadURL(renderer.url);
}

if (ownsInstance) {
  app.on('second-instance', () => {
    const window = mainWindow;
    if (window === null || window.isDestroyed()) return;
    if (window.isMinimized()) window.restore();
    window.show();
    window.focus();
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
    controller?.dispose();
    controller = null;
    void rendererServer?.close();
    rendererServer = null;
  });
}
