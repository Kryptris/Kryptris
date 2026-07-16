import type {
  AppState,
  AttachmentMetadata,
  AttachmentPreview,
  AuditEvent,
  BackupInfo,
  EntryDetail,
  EntryInput,
  EntryListQuery,
  EntrySummary,
  EntryTemplate,
  ExportFormat,
  FactorStatus,
  Folder,
  GeneratedSecret,
  ImportFormat,
  ImportMapping,
  ImportPreview,
  LocalReport,
  PasswordGeneratorOptions,
  RecoveryRotationStarted,
  SecurityReport,
  SetupStarted,
  TotpCode,
  TotpConfiguration,
  UnlockResult,
  VaultaSettings,
  VaultEntry,
  VaultSummary,
  WebAuthnAuthenticationResult,
  WebAuthnRegistrationResult,
} from './models';
import type { SerializedVaultaError } from './errors';

export type IpcResult<T> = { ok: true; value: T } | { ok: false; error: SerializedVaultaError };

export const IPC_CHANNELS = {
  systemState: 'vaulta:system:state',
  systemLock: 'vaulta:system:lock',
  systemClearClipboard: 'vaulta:system:clear-clipboard',
  setupBegin: 'vaulta:setup:begin',
  setupComplete: 'vaulta:setup:complete',
  authUnlock: 'vaulta:auth:unlock',
  authSecurityKeyComplete: 'vaulta:auth:security-key-complete',
  authSecurityKeyCancel: 'vaulta:auth:security-key-cancel',
  authRecover: 'vaulta:auth:recover',
  authChangeMasterPassword: 'vaulta:auth:change-master-password',
  vaultList: 'vaulta:vault:list',
  vaultCreate: 'vaulta:vault:create',
  vaultUpdate: 'vaulta:vault:update',
  vaultDelete: 'vaulta:vault:delete',
  vaultSelect: 'vaulta:vault:select',
  folderList: 'vaulta:folder:list',
  folderCreate: 'vaulta:folder:create',
  folderUpdate: 'vaulta:folder:update',
  folderDelete: 'vaulta:folder:delete',
  entryList: 'vaulta:entry:list',
  entryDetail: 'vaulta:entry:detail',
  entryEditModel: 'vaulta:entry:edit-model',
  entryCreate: 'vaulta:entry:create',
  entryUpdate: 'vaulta:entry:update',
  entryTrash: 'vaulta:entry:trash',
  entryRestore: 'vaulta:entry:restore',
  entryPurge: 'vaulta:entry:purge',
  entryToggleFavorite: 'vaulta:entry:toggle-favorite',
  entryReveal: 'vaulta:entry:reveal',
  entryCopy: 'vaulta:entry:copy',
  entryExportPrivateKey: 'vaulta:entry:export-private-key',
  entryWifiQr: 'vaulta:entry:wifi-qr',
  attachmentAdd: 'vaulta:attachment:add',
  attachmentRemove: 'vaulta:attachment:remove',
  attachmentExport: 'vaulta:attachment:export',
  attachmentPreview: 'vaulta:attachment:preview',
  generatorGenerate: 'vaulta:generator:generate',
  totpCode: 'vaulta:totp:code',
  totpCopy: 'vaulta:totp:copy',
  totpImportQr: 'vaulta:totp:import-qr',
  securityScan: 'vaulta:security:scan',
  backupCreate: 'vaulta:backup:create',
  backupRestore: 'vaulta:backup:restore',
  backupChooseFolder: 'vaulta:backup:choose-folder',
  importPreview: 'vaulta:import:preview',
  importRemap: 'vaulta:import:remap',
  importExecute: 'vaulta:import:execute',
  exportExecute: 'vaulta:export:execute',
  auditList: 'vaulta:audit:list',
  settingsGet: 'vaulta:settings:get',
  settingsUpdate: 'vaulta:settings:update',
  factorStatus: 'vaulta:factor:status',
  factorTotpBegin: 'vaulta:factor:totp-begin',
  factorTotpComplete: 'vaulta:factor:totp-complete',
  factorTotpRemove: 'vaulta:factor:totp-remove',
  factorSecurityKeyBegin: 'vaulta:factor:security-key-begin',
  factorSecurityKeyComplete: 'vaulta:factor:security-key-complete',
  factorSecurityKeyRemove: 'vaulta:factor:security-key-remove',
  recoveryRotate: 'vaulta:recovery:rotate',
  recoveryRotateComplete: 'vaulta:recovery:rotate-complete',
  templateList: 'vaulta:template:list',
  templateSave: 'vaulta:template:save',
  templateDelete: 'vaulta:template:delete',
  reportGenerate: 'vaulta:report:generate',
  windowMinimize: 'vaulta:window:minimize',
  windowToggleMaximize: 'vaulta:window:toggle-maximize',
  windowClose: 'vaulta:window:close',
  eventLocked: 'vaulta:event:locked',
  eventStateChanged: 'vaulta:event:state-changed',
  eventClipboardCleared: 'vaulta:event:clipboard-cleared',
  eventBackgroundWarning: 'vaulta:event:background-warning',
} as const;

export interface VaultaApi {
  system: {
    getState(): Promise<AppState>;
    lock(): Promise<void>;
    clearClipboard(): Promise<boolean>;
  };
  setup: {
    begin(input: {
      masterPassword: string;
      vaultName: string;
      enableRecovery: boolean;
    }): Promise<SetupStarted>;
    complete(input: { pendingId: string; confirmation: Record<string, string> }): Promise<AppState>;
  };
  auth: {
    unlock(input: { masterPassword: string; totpCode?: string }): Promise<UnlockResult>;
    completeSecurityKey(input: {
      challengeId: string;
      response: unknown;
      prfResult?: string;
    }): Promise<WebAuthnAuthenticationResult>;
    cancelSecurityKey(input: { challengeId: string }): Promise<void>;
    recover(input: { recoveryKey: string; newMasterPassword: string }): Promise<AppState>;
    changeMasterPassword(input: { currentPassword: string; newPassword: string }): Promise<void>;
  };
  vaults: {
    list(): Promise<VaultSummary[]>;
    create(input: { name: string; color: string }): Promise<VaultSummary>;
    update(input: { id: string; name: string; color: string }): Promise<VaultSummary>;
    delete(input: { id: string; masterPassword: string }): Promise<void>;
    select(id: string): Promise<void>;
    listFolders(vaultId: string): Promise<Folder[]>;
    createFolder(input: { vaultId: string; name: string; color: string }): Promise<Folder>;
    updateFolder(input: {
      vaultId: string;
      id: string;
      name: string;
      color: string;
    }): Promise<Folder>;
    deleteFolder(input: { vaultId: string; id: string }): Promise<void>;
  };
  entries: {
    list(query: EntryListQuery): Promise<EntrySummary[]>;
    getDetail(input: { vaultId: string; entryId: string }): Promise<EntryDetail>;
    getEditModel(input: { vaultId: string; entryId: string }): Promise<VaultEntry>;
    create(input: { vaultId: string; entry: EntryInput }): Promise<EntrySummary>;
    update(input: { vaultId: string; entryId: string; entry: EntryInput }): Promise<EntrySummary>;
    moveToTrash(input: { vaultId: string; entryId: string }): Promise<void>;
    restore(input: { vaultId: string; entryId: string }): Promise<void>;
    purge(input: { vaultId: string; entryId: string; masterPassword: string }): Promise<void>;
    toggleFavorite(input: { vaultId: string; entryId: string }): Promise<boolean>;
    reveal(input: {
      vaultId: string;
      entryId: string;
      fieldPath: string;
      masterPassword?: string;
    }): Promise<string>;
    copy(input: { vaultId: string; entryId: string; fieldPath: string }): Promise<void>;
    exportPrivateKey(input: {
      vaultId: string;
      entryId: string;
      masterPassword: string;
      confirmation: string;
    }): Promise<boolean>;
    wifiQr(input: { vaultId: string; entryId: string }): Promise<string>;
  };
  attachments: {
    add(input: { vaultId: string; entryId: string }): Promise<AttachmentMetadata | null>;
    remove(input: { vaultId: string; entryId: string; attachmentId: string }): Promise<void>;
    export(input: { vaultId: string; entryId: string; attachmentId: string }): Promise<boolean>;
    preview(input: {
      vaultId: string;
      entryId: string;
      attachmentId: string;
    }): Promise<AttachmentPreview>;
  };
  generator: {
    generate(options: PasswordGeneratorOptions): Promise<GeneratedSecret>;
  };
  totp: {
    getCode(input: { vaultId: string; entryId: string }): Promise<TotpCode>;
    copy(input: { vaultId: string; entryId: string }): Promise<void>;
    importQr(source: 'file' | 'screen'): Promise<TotpConfiguration | null>;
  };
  security: {
    scan(vaultId?: string): Promise<SecurityReport>;
  };
  backup: {
    create(input?: { automatic?: boolean }): Promise<BackupInfo | null>;
    restore(input: {
      credential: { type: 'master'; value: string } | { type: 'recovery'; value: string };
      newMasterPassword?: string;
    }): Promise<AppState | null>;
    chooseFolder(): Promise<string | null>;
  };
  transfer: {
    previewImport(input: {
      vaultId: string;
      format?: ImportFormat;
      mapping?: ImportMapping;
    }): Promise<ImportPreview | null>;
    remapImport(input: { token: string; mapping: ImportMapping }): Promise<ImportPreview>;
    executeImport(input: {
      token: string;
      vaultId: string;
      selectedRows: number[];
    }): Promise<{ imported: number; skipped: number; entryIds: string[] }>;
    export(input: {
      format: ExportFormat;
      vaultIds: string[];
      masterPassword?: string;
      warningAccepted: boolean;
      confirmation: string;
      includeAttachments: boolean;
    }): Promise<string | null>;
  };
  audit: {
    list(input?: { offset?: number; limit?: number }): Promise<AuditEvent[]>;
  };
  settings: {
    get(): Promise<VaultaSettings>;
    update(input: { settings: VaultaSettings; masterPassword?: string }): Promise<VaultaSettings>;
  };
  factors: {
    status(): Promise<FactorStatus>;
    beginTotp(input: { masterPassword: string }): Promise<{
      setupId: string;
      secret: string;
      uri: string;
      qrDataUrl: string;
      explanation: string;
    }>;
    completeTotp(input: { setupId: string; code: string }): Promise<void>;
    removeTotp(input: { masterPassword: string }): Promise<void>;
    beginSecurityKey(input: { name: string; masterPassword: string }): Promise<{
      challengeId: string;
      options: unknown;
      prfSalt: string;
    }>;
    completeSecurityKey(input: {
      challengeId: string;
      response: unknown;
      prfResult?: string;
    }): Promise<WebAuthnRegistrationResult>;
    removeSecurityKey(input: { id: string; masterPassword: string }): Promise<void>;
    rotateRecovery(input: { masterPassword: string }): Promise<RecoveryRotationStarted>;
    completeRecoveryRotation(input: {
      pendingId: string;
      confirmation: Record<string, string>;
    }): Promise<void>;
  };
  templates: {
    list(): Promise<EntryTemplate[]>;
    save(
      template: Omit<EntryTemplate, 'id' | 'createdAt' | 'updatedAt'> & { id?: string },
    ): Promise<EntryTemplate>;
    delete(id: string): Promise<void>;
  };
  reports: {
    generate(): Promise<LocalReport>;
  };
  window: {
    minimize(): Promise<void>;
    toggleMaximize(): Promise<boolean>;
    close(): Promise<void>;
  };
  events: {
    onLocked(callback: () => void): () => void;
    onStateChanged(callback: (state: AppState) => void): () => void;
    onClipboardCleared(callback: () => void): () => void;
    onBackgroundWarning(callback: (message: string) => void): () => void;
  };
}

declare global {
  interface Window {
    vaulta: VaultaApi;
  }
}
