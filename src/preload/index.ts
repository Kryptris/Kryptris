import { contextBridge, ipcRenderer } from 'electron';

import { IPC_CHANNELS, type IpcResult, type VaultaApi } from '../shared/ipc';
import type { AppState } from '../shared/models';

async function invoke<T>(channel: string, input?: unknown): Promise<T> {
  const result = (await ipcRenderer.invoke(channel, input)) as IpcResult<T>;
  if (result.ok) return result.value;
  const error = new Error(result.error.message);
  Object.defineProperties(error, {
    code: { value: result.error.code, enumerable: true },
    action: { value: result.error.action, enumerable: true },
  });
  throw error;
}

function onEvent<T>(channel: string, callback: (value: T) => void): () => void {
  const listener = (_event: Electron.IpcRendererEvent, value: T): void => callback(value);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

const api: VaultaApi = {
  system: {
    getState: () => invoke(IPC_CHANNELS.systemState),
    lock: () => invoke(IPC_CHANNELS.systemLock),
    clearClipboard: () => invoke(IPC_CHANNELS.systemClearClipboard),
  },
  setup: {
    begin: (input) => invoke(IPC_CHANNELS.setupBegin, input),
    complete: (input) => invoke(IPC_CHANNELS.setupComplete, input),
  },
  auth: {
    unlock: (input) => invoke(IPC_CHANNELS.authUnlock, input),
    completeSecurityKey: (input) => invoke(IPC_CHANNELS.authSecurityKeyComplete, input),
    cancelSecurityKey: (input) => invoke(IPC_CHANNELS.authSecurityKeyCancel, input),
    recover: (input) => invoke(IPC_CHANNELS.authRecover, input),
    changeMasterPassword: (input) => invoke(IPC_CHANNELS.authChangeMasterPassword, input),
  },
  vaults: {
    list: () => invoke(IPC_CHANNELS.vaultList),
    create: (input) => invoke(IPC_CHANNELS.vaultCreate, input),
    update: (input) => invoke(IPC_CHANNELS.vaultUpdate, input),
    delete: (input) => invoke(IPC_CHANNELS.vaultDelete, input),
    select: (id) => invoke(IPC_CHANNELS.vaultSelect, id),
    listFolders: (vaultId) => invoke(IPC_CHANNELS.folderList, vaultId),
    createFolder: (input) => invoke(IPC_CHANNELS.folderCreate, input),
    updateFolder: (input) => invoke(IPC_CHANNELS.folderUpdate, input),
    deleteFolder: (input) => invoke(IPC_CHANNELS.folderDelete, input),
  },
  entries: {
    list: (query) => invoke(IPC_CHANNELS.entryList, query),
    getDetail: (input) => invoke(IPC_CHANNELS.entryDetail, input),
    getEditModel: (input) => invoke(IPC_CHANNELS.entryEditModel, input),
    create: (input) => invoke(IPC_CHANNELS.entryCreate, input),
    update: (input) => invoke(IPC_CHANNELS.entryUpdate, input),
    moveToTrash: (input) => invoke(IPC_CHANNELS.entryTrash, input),
    restore: (input) => invoke(IPC_CHANNELS.entryRestore, input),
    purge: (input) => invoke(IPC_CHANNELS.entryPurge, input),
    toggleFavorite: (input) => invoke(IPC_CHANNELS.entryToggleFavorite, input),
    reveal: (input) => invoke(IPC_CHANNELS.entryReveal, input),
    copy: (input) => invoke(IPC_CHANNELS.entryCopy, input),
    exportPrivateKey: (input) => invoke(IPC_CHANNELS.entryExportPrivateKey, input),
    wifiQr: (input) => invoke(IPC_CHANNELS.entryWifiQr, input),
  },
  attachments: {
    add: (input) => invoke(IPC_CHANNELS.attachmentAdd, input),
    remove: (input) => invoke(IPC_CHANNELS.attachmentRemove, input),
    export: (input) => invoke(IPC_CHANNELS.attachmentExport, input),
    preview: (input) => invoke(IPC_CHANNELS.attachmentPreview, input),
  },
  generator: {
    generate: (input) => invoke(IPC_CHANNELS.generatorGenerate, input),
  },
  totp: {
    getCode: (input) => invoke(IPC_CHANNELS.totpCode, input),
    copy: (input) => invoke(IPC_CHANNELS.totpCopy, input),
    importQr: (source) => invoke(IPC_CHANNELS.totpImportQr, source),
  },
  security: {
    scan: (vaultId) => invoke(IPC_CHANNELS.securityScan, vaultId),
  },
  backup: {
    create: (input) => invoke(IPC_CHANNELS.backupCreate, input),
    restore: (input) => invoke(IPC_CHANNELS.backupRestore, input),
    chooseFolder: () => invoke(IPC_CHANNELS.backupChooseFolder),
  },
  transfer: {
    previewImport: (input) => invoke(IPC_CHANNELS.importPreview, input),
    remapImport: (input) => invoke(IPC_CHANNELS.importRemap, input),
    executeImport: (input) => invoke(IPC_CHANNELS.importExecute, input),
    export: (input) => invoke(IPC_CHANNELS.exportExecute, input),
  },
  audit: {
    list: (input) => invoke(IPC_CHANNELS.auditList, input),
  },
  settings: {
    get: () => invoke(IPC_CHANNELS.settingsGet),
    update: (input) => invoke(IPC_CHANNELS.settingsUpdate, input),
  },
  factors: {
    status: () => invoke(IPC_CHANNELS.factorStatus),
    beginTotp: (input) => invoke(IPC_CHANNELS.factorTotpBegin, input),
    completeTotp: (input) => invoke(IPC_CHANNELS.factorTotpComplete, input),
    removeTotp: (input) => invoke(IPC_CHANNELS.factorTotpRemove, input),
    beginSecurityKey: (input) => invoke(IPC_CHANNELS.factorSecurityKeyBegin, input),
    completeSecurityKey: (input) => invoke(IPC_CHANNELS.factorSecurityKeyComplete, input),
    removeSecurityKey: (input) => invoke(IPC_CHANNELS.factorSecurityKeyRemove, input),
    rotateRecovery: (input) => invoke(IPC_CHANNELS.recoveryRotate, input),
    completeRecoveryRotation: (input) => invoke(IPC_CHANNELS.recoveryRotateComplete, input),
  },
  templates: {
    list: () => invoke(IPC_CHANNELS.templateList),
    save: (input) => invoke(IPC_CHANNELS.templateSave, input),
    delete: (id) => invoke(IPC_CHANNELS.templateDelete, id),
  },
  reports: {
    generate: () => invoke(IPC_CHANNELS.reportGenerate),
  },
  window: {
    minimize: () => invoke(IPC_CHANNELS.windowMinimize),
    toggleMaximize: () => invoke(IPC_CHANNELS.windowToggleMaximize),
    close: () => invoke(IPC_CHANNELS.windowClose),
  },
  events: {
    onLocked: (callback) => onEvent<void>(IPC_CHANNELS.eventLocked, callback),
    onStateChanged: (callback) => onEvent<AppState>(IPC_CHANNELS.eventStateChanged, callback),
    onClipboardCleared: (callback) => onEvent<void>(IPC_CHANNELS.eventClipboardCleared, callback),
    onBackgroundWarning: (callback) =>
      onEvent<string>(IPC_CHANNELS.eventBackgroundWarning, callback),
  },
};

contextBridge.exposeInMainWorld('vaulta', api);
