import { contextBridge, ipcRenderer, webUtils } from 'electron';

import { IPC_CHANNELS, type IpcResult, type VaultaApi } from '../shared/ipc';
import type { AppState, LocalJobProgressEvent } from '../shared/models';

const DROPPED_IMPORT_TOKEN_TTL_MS = 60_000;

interface PendingDroppedImport {
  readonly sourcePath: string;
  readonly expiresAt: number;
}

const pendingDroppedImports = new Map<string, PendingDroppedImport>();
const droppedImportListeners = new Set<(drop: { token: string }) => void>();

function isLocalWindowsFilePath(value: string): boolean {
  return /^[A-Za-z]:[\\/](?![\\/])/u.test(value) && !value.includes('\0');
}

function isImportDropTarget(target: EventTarget | null): boolean {
  const element = target as { closest?: (selector: string) => Element | null } | null;
  const closest = element?.closest?.('[data-vaulta-import-drop-target]');
  return closest !== undefined && closest !== null;
}

function pruneDroppedImports(now = Date.now()): void {
  for (const [token, pending] of pendingDroppedImports) {
    if (pending.expiresAt <= now) pendingDroppedImports.delete(token);
  }
}

function notifyDroppedImport(file: File): void {
  const sourcePath = webUtils.getPathForFile(file);
  if (!isLocalWindowsFilePath(sourcePath)) return;
  pruneDroppedImports();
  const token = globalThis.crypto.randomUUID();
  pendingDroppedImports.set(token, {
    sourcePath,
    expiresAt: Date.now() + DROPPED_IMPORT_TOKEN_TTL_MS,
  });
  for (const listener of droppedImportListeners) listener({ token });
}

function installDroppedImportCapture(): void {
  if (typeof window === 'undefined') return;
  window.addEventListener(
    'dragover',
    (event) => {
      if (isImportDropTarget(event.target) && event.dataTransfer?.types.includes('Files')) {
        event.preventDefault();
      }
    },
    true,
  );
  window.addEventListener(
    'drop',
    (event) => {
      const files = event.dataTransfer?.files;
      if (!isImportDropTarget(event.target) || files === undefined || files.length !== 1) {
        return;
      }
      event.preventDefault();
      const file = files.item(0);
      if (file !== null) notifyDroppedImport(file);
    },
    true,
  );
  window.addEventListener('beforeunload', () => pendingDroppedImports.clear(), { once: true });
  ipcRenderer.on(IPC_CHANNELS.eventLocked, () => pendingDroppedImports.clear());
}

installDroppedImportCapture();

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
    scanCenter: (input) => invoke(IPC_CHANNELS.securityCenterScan, input),
    getRecoveryReadiness: () => invoke(IPC_CHANNELS.securityRecoveryStatus),
    testRecoveryReadiness: (input) => invoke(IPC_CHANNELS.securityRecoveryTest, input),
    scanIntegrity: (input) => invoke(IPC_CHANNELS.securityIntegrityScan, input),
    saveIntegrityReport: (input) => invoke(IPC_CHANNELS.securityIntegritySaveReport, input),
    getBreachListStatus: () => invoke(IPC_CHANNELS.securityBreachStatus),
    importBreachList: (input) => invoke(IPC_CHANNELS.securityBreachImport, input),
    scanBreachList: (input) => invoke(IPC_CHANNELS.securityBreachScan, input),
    removeBreachList: () => invoke(IPC_CHANNELS.securityBreachRemove),
  },
  backup: {
    create: (input) => invoke(IPC_CHANNELS.backupCreate, input),
    getHealth: (input) => invoke(IPC_CHANNELS.backupHealth, input),
    dryRun: (input) => invoke(IPC_CHANNELS.backupDryRun, input),
    restore: (input) => invoke(IPC_CHANNELS.backupRestore, input),
    chooseFolder: () => invoke(IPC_CHANNELS.backupChooseFolder),
  },
  transfer: {
    previewImport: (input) => invoke(IPC_CHANNELS.importPreview, input),
    previewDroppedImport: (input) => {
      const safeInput = input ?? { token: '', vaultId: '' };
      pruneDroppedImports();
      const pending = pendingDroppedImports.get(safeInput.token);
      if (pending === undefined)
        return invoke(IPC_CHANNELS.importPreviewDropped, {
          vaultId: safeInput.vaultId,
          ...(safeInput.format === undefined ? {} : { format: safeInput.format }),
          ...(safeInput.mapping === undefined ? {} : { mapping: safeInput.mapping }),
          // Missing or expired tokens still reach the guarded Main boundary;
          // Zod rejects this sentinel and no renderer-controlled path is used.
          sourcePath: '',
        });
      pendingDroppedImports.delete(safeInput.token);
      return invoke(IPC_CHANNELS.importPreviewDropped, {
        vaultId: safeInput.vaultId,
        ...(safeInput.format === undefined ? {} : { format: safeInput.format }),
        ...(safeInput.mapping === undefined ? {} : { mapping: safeInput.mapping }),
        sourcePath: pending.sourcePath,
      });
    },
    onDroppedImport: (callback) => {
      if (typeof callback !== 'function') return () => undefined;
      droppedImportListeners.add(callback);
      return () => droppedImportListeners.delete(callback);
    },
    remapImport: (input) => invoke(IPC_CHANNELS.importRemap, input),
    executeImport: (input) => invoke(IPC_CHANNELS.importExecute, input),
    listMappingProfiles: () => invoke(IPC_CHANNELS.importMappingProfiles),
    saveMappingProfile: (input) => invoke(IPC_CHANNELS.importMappingProfileSave, input),
    removeMappingProfile: (input) => invoke(IPC_CHANNELS.importMappingProfileRemove, input),
    exportVaultPackage: (input) => invoke(IPC_CHANNELS.vaultPackageExport, input),
    previewVaultPackage: (input) => invoke(IPC_CHANNELS.vaultPackagePreviewImport, input),
    importVaultPackage: (input) => invoke(IPC_CHANNELS.vaultPackageImport, input),
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
  productivity: {
    batch: (input) => invoke(IPC_CHANNELS.productivityBatch, input),
    listSavedViews: (vaultId) => invoke(IPC_CHANNELS.productivitySavedViewList, vaultId),
    saveSavedView: (input) => invoke(IPC_CHANNELS.productivitySavedViewSave, input),
    reorderSavedViews: (input) => invoke(IPC_CHANNELS.productivitySavedViewReorder, input),
    deleteSavedView: (input) => invoke(IPC_CHANNELS.productivitySavedViewDelete, input),
    listTags: (vaultId) => invoke(IPC_CHANNELS.productivityTagList, vaultId),
    renameTag: (input) => invoke(IPC_CHANNELS.productivityTagRename, input),
    mergeTags: (input) => invoke(IPC_CHANNELS.productivityTagMerge, input),
    deleteTag: (input) => invoke(IPC_CHANNELS.productivityTagDelete, input),
  },
  quality: {
    scanDuplicates: (input) => invoke(IPC_CHANNELS.qualityDuplicateScan, input),
    describeDuplicateMerge: (input) => invoke(IPC_CHANNELS.qualityDuplicateDescribe, input),
    mergeDuplicates: (input) => invoke(IPC_CHANNELS.qualityDuplicateMerge, input),
    scanDataQuality: (input) => invoke(IPC_CHANNELS.qualityDataScan, input),
    previewDataQualityFix: (input) => invoke(IPC_CHANNELS.qualityDataFixPreview, input),
    applyDataQualityFix: (input) => invoke(IPC_CHANNELS.qualityDataFixApply, input),
    cancelJob: (input) => invoke(IPC_CHANNELS.localJobCancel, input),
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
    onLocalJobProgress: (callback) =>
      onEvent<LocalJobProgressEvent>(IPC_CHANNELS.eventLocalJobProgress, callback),
  },
};

contextBridge.exposeInMainWorld('vaulta', api);
