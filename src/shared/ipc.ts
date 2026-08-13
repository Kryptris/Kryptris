import type {
  AppState,
  AttachmentMetadata,
  AttachmentPreview,
  AuditEvent,
  BackupHealthSnapshot,
  BackupInfo,
  BreachListStatusDto,
  BreachScanReportDto,
  BatchEntryInput,
  BatchEntryResult,
  DataQualityFixPreviewDto,
  DataQualityFixResultDto,
  DataQualityReportDto,
  DuplicateEntryReferenceDto,
  DuplicateMergeChoiceDto,
  DuplicateMergeCollectionChoiceDto,
  DuplicateMergeDescriptionDto,
  DuplicateMergeResultDto,
  DuplicateScanDto,
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
  ImportMappingProfile,
  ImportPreview,
  ImportSummary,
  IntegrityReportDto,
  LocalReport,
  LocalJobProgressEvent,
  PasswordGeneratorOptions,
  RecoveryRotationStarted,
  RecoveryReadinessStatusDto,
  RestoreDryRunResult,
  SecurityCenterReportDto,
  SecurityReport,
  SavedView,
  SavedViewFilters,
  SetupStarted,
  TotpCode,
  TotpConfiguration,
  TagSummary,
  UnlockResult,
  VaultaSettings,
  VaultEntry,
  VaultPackageExportResult,
  VaultPackageImportResult,
  VaultPackagePreviewDto,
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
  securityCenterScan: 'vaulta:security:center-scan',
  securityRecoveryStatus: 'vaulta:security:recovery-status',
  securityRecoveryTest: 'vaulta:security:recovery-test',
  securityIntegrityScan: 'vaulta:security:integrity-scan',
  securityIntegritySaveReport: 'vaulta:security:integrity-save-report',
  securityBreachStatus: 'vaulta:security:breach-status',
  securityBreachImport: 'vaulta:security:breach-import',
  securityBreachScan: 'vaulta:security:breach-scan',
  securityBreachRemove: 'vaulta:security:breach-remove',
  backupCreate: 'vaulta:backup:create',
  backupHealth: 'vaulta:backup:health',
  backupDryRun: 'vaulta:backup:dry-run',
  backupRestore: 'vaulta:backup:restore',
  backupChooseFolder: 'vaulta:backup:choose-folder',
  importPreview: 'vaulta:import:preview',
  importPreviewDropped: 'vaulta:import:preview-dropped',
  importRemap: 'vaulta:import:remap',
  importExecute: 'vaulta:import:execute',
  importMappingProfiles: 'vaulta:import:mapping-profiles',
  importMappingProfileSave: 'vaulta:import:mapping-profile-save',
  importMappingProfileRemove: 'vaulta:import:mapping-profile-remove',
  vaultPackageExport: 'vaulta:vault-package:export',
  vaultPackagePreviewImport: 'vaulta:vault-package:preview-import',
  vaultPackageImport: 'vaulta:vault-package:import',
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
  productivityBatch: 'vaulta:productivity:batch',
  productivitySavedViewList: 'vaulta:productivity:saved-view-list',
  productivitySavedViewSave: 'vaulta:productivity:saved-view-save',
  productivitySavedViewReorder: 'vaulta:productivity:saved-view-reorder',
  productivitySavedViewDelete: 'vaulta:productivity:saved-view-delete',
  productivityTagList: 'vaulta:productivity:tag-list',
  productivityTagRename: 'vaulta:productivity:tag-rename',
  productivityTagMerge: 'vaulta:productivity:tag-merge',
  productivityTagDelete: 'vaulta:productivity:tag-delete',
  qualityDuplicateScan: 'vaulta:quality:duplicate-scan',
  qualityDuplicateDescribe: 'vaulta:quality:duplicate-describe',
  qualityDuplicateMerge: 'vaulta:quality:duplicate-merge',
  qualityDataScan: 'vaulta:quality:data-scan',
  qualityDataFixPreview: 'vaulta:quality:data-fix-preview',
  qualityDataFixApply: 'vaulta:quality:data-fix-apply',
  localJobCancel: 'vaulta:job:cancel',
  windowMinimize: 'vaulta:window:minimize',
  windowToggleMaximize: 'vaulta:window:toggle-maximize',
  windowClose: 'vaulta:window:close',
  eventLocked: 'vaulta:event:locked',
  eventStateChanged: 'vaulta:event:state-changed',
  eventClipboardCleared: 'vaulta:event:clipboard-cleared',
  eventBackgroundWarning: 'vaulta:event:background-warning',
  eventLocalJobProgress: 'vaulta:event:local-job-progress',
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
    moveToTrash(input: { vaultId: string; entryId: string; updatedAt?: string }): Promise<void>;
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
    scanCenter(input: { requestId: string; refresh?: boolean }): Promise<SecurityCenterReportDto>;
    getRecoveryReadiness(): Promise<RecoveryReadinessStatusDto>;
    testRecoveryReadiness(input: { recoveryKey: string }): Promise<RecoveryReadinessStatusDto>;
    scanIntegrity(input: { requestId: string; refresh?: boolean }): Promise<IntegrityReportDto>;
    saveIntegrityReport(input: { reportId: string }): Promise<boolean>;
    getBreachListStatus(): Promise<BreachListStatusDto>;
    importBreachList(input: {
      requestId: string;
      sourceLabel: string;
      sourceDate: string;
    }): Promise<BreachListStatusDto | null>;
    scanBreachList(input: { requestId: string; refresh?: boolean }): Promise<BreachScanReportDto>;
    removeBreachList(): Promise<BreachListStatusDto>;
  };
  backup: {
    create(input?: { automatic?: boolean }): Promise<BackupInfo | null>;
    getHealth(input: { requestId: string; refresh?: boolean }): Promise<BackupHealthSnapshot>;
    dryRun(input: {
      requestId: string;
      credential: { type: 'master'; value: string } | { type: 'recovery'; value: string };
    }): Promise<RestoreDryRunResult | null>;
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
    /** A one-time, preload-minted token; the renderer never receives the file path. */
    previewDroppedImport(input: {
      token: string;
      vaultId: string;
      format?: ImportFormat;
      mapping?: ImportMapping;
    }): Promise<ImportPreview | null>;
    onDroppedImport(callback: (drop: { token: string }) => void): () => void;
    remapImport(input: { token: string; mapping: ImportMapping }): Promise<ImportPreview>;
    executeImport(input: { token: string; vaultId: string; selectedRows: number[] }): Promise<{
      imported: number;
      skipped: number;
      summary: ImportSummary;
      entryIds: string[];
    }>;
    listMappingProfiles(): Promise<ImportMappingProfile[]>;
    saveMappingProfile(input: {
      id?: string;
      name: string;
      mapping: ImportMapping;
    }): Promise<ImportMappingProfile>;
    removeMappingProfile(input: { id: string }): Promise<boolean>;
    exportVaultPackage(input: {
      vaultId: string;
      exportPassword: string;
      includeAttachments: boolean;
    }): Promise<VaultPackageExportResult | null>;
    previewVaultPackage(input: { exportPassword: string }): Promise<VaultPackagePreviewDto | null>;
    importVaultPackage(input: {
      token: string;
      exportPassword: string;
      targetVaultName: string;
      allowNameConflict: boolean;
    }): Promise<VaultPackageImportResult>;
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
  productivity: {
    batch(input: BatchEntryInput): Promise<BatchEntryResult>;
    listSavedViews(vaultId: string): Promise<SavedView[]>;
    saveSavedView(input: {
      id?: string;
      vaultId: string;
      name: string;
      filters: SavedViewFilters;
    }): Promise<SavedView>;
    reorderSavedViews(input: { vaultId: string; orderedIds: string[] }): Promise<SavedView[]>;
    deleteSavedView(input: { vaultId: string; id: string }): Promise<void>;
    listTags(vaultId: string): Promise<TagSummary[]>;
    renameTag(input: { vaultId: string; tag: string; name: string }): Promise<number>;
    mergeTags(input: {
      vaultId: string;
      sourceTags: string[];
      targetName: string;
    }): Promise<number>;
    deleteTag(input: { vaultId: string; tag: string }): Promise<number>;
  };
  quality: {
    scanDuplicates(input: {
      requestId: string;
      vaultId?: string | null;
      refresh?: boolean;
    }): Promise<DuplicateScanDto>;
    describeDuplicateMerge(input: {
      survivor: DuplicateEntryReferenceDto;
      duplicate: DuplicateEntryReferenceDto;
    }): Promise<DuplicateMergeDescriptionDto>;
    mergeDuplicates(input: {
      survivor: DuplicateEntryReferenceDto;
      duplicate: DuplicateEntryReferenceDto;
      fieldChoices: DuplicateMergeChoiceDto[];
      collectionChoices: DuplicateMergeCollectionChoiceDto[];
    }): Promise<DuplicateMergeResultDto>;
    scanDataQuality(input: {
      requestId: string;
      vaultId: string;
      refresh?: boolean;
    }): Promise<DataQualityReportDto>;
    previewDataQualityFix(input: {
      vaultId: string;
      findingId: string;
    }): Promise<DataQualityFixPreviewDto>;
    applyDataQualityFix(input: { token: string }): Promise<DataQualityFixResultDto>;
    cancelJob(input: { requestId: string }): Promise<boolean>;
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
    onLocalJobProgress(callback: (event: LocalJobProgressEvent) => void): () => void;
  };
}

declare global {
  interface Window {
    vaulta: VaultaApi;
  }
}
