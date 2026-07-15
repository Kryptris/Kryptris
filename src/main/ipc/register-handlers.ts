import type { z } from 'zod';

import { IPC_CHANNELS, type VaultaApi } from '../../shared/ipc';
import { IPC_REQUEST_SCHEMAS } from '../../shared/schemas';
import type { VaultaController } from '../vaulta-controller';
import { registerSafeHandler, type SafeHandlerContext } from './safe-handler';

export interface RegisterHandlersOptions extends SafeHandlerContext {
  controller: VaultaController;
}

function requestSchema<T>(channel: string): z.ZodType<T> {
  const schema = IPC_REQUEST_SCHEMAS[channel];
  if (schema === undefined) throw new Error(`IPC-Schema fehlt: ${channel}`);
  return schema as z.ZodType<T>;
}

export function registerIpcHandlers(options: RegisterHandlersOptions): void {
  const context: SafeHandlerContext = options;
  const controller = options.controller;

  registerSafeHandler(
    context,
    IPC_CHANNELS.systemState,
    requestSchema<undefined>(IPC_CHANNELS.systemState),
    () => controller.getState(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.systemLock,
    requestSchema<undefined>(IPC_CHANNELS.systemLock),
    () => controller.lock(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.systemClearClipboard,
    requestSchema<undefined>(IPC_CHANNELS.systemClearClipboard),
    () => controller.clearClipboard(),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.setupBegin,
    requestSchema<Parameters<VaultaApi['setup']['begin']>[0]>(IPC_CHANNELS.setupBegin),
    (input) => controller.beginSetup(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.setupComplete,
    requestSchema<Parameters<VaultaApi['setup']['complete']>[0]>(IPC_CHANNELS.setupComplete),
    (input) => controller.completeSetup(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.authUnlock,
    requestSchema<Parameters<VaultaApi['auth']['unlock']>[0]>(IPC_CHANNELS.authUnlock),
    (input) => controller.unlock(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.authSecurityKeyComplete,
    requestSchema<Parameters<VaultaApi['auth']['completeSecurityKey']>[0]>(
      IPC_CHANNELS.authSecurityKeyComplete,
    ),
    (input) => controller.completeSecurityKey(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.authSecurityKeyCancel,
    requestSchema<Parameters<VaultaApi['auth']['cancelSecurityKey']>[0]>(
      IPC_CHANNELS.authSecurityKeyCancel,
    ),
    (input) => controller.cancelSecurityKey(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.authRecover,
    requestSchema<Parameters<VaultaApi['auth']['recover']>[0]>(IPC_CHANNELS.authRecover),
    (input) => controller.recover(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.authChangeMasterPassword,
    requestSchema<Parameters<VaultaApi['auth']['changeMasterPassword']>[0]>(
      IPC_CHANNELS.authChangeMasterPassword,
    ),
    (input) => controller.changeMasterPassword(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.vaultList,
    requestSchema<undefined>(IPC_CHANNELS.vaultList),
    () => controller.listVaults(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.vaultCreate,
    requestSchema<Parameters<VaultaApi['vaults']['create']>[0]>(IPC_CHANNELS.vaultCreate),
    (input) => controller.createVault(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.vaultUpdate,
    requestSchema<Parameters<VaultaApi['vaults']['update']>[0]>(IPC_CHANNELS.vaultUpdate),
    (input) => controller.updateVault(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.vaultDelete,
    requestSchema<Parameters<VaultaApi['vaults']['delete']>[0]>(IPC_CHANNELS.vaultDelete),
    (input) => controller.deleteVault(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.vaultSelect,
    requestSchema<string>(IPC_CHANNELS.vaultSelect),
    (id) => controller.selectVault(id),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.folderList,
    requestSchema<string>(IPC_CHANNELS.folderList),
    (id) => controller.listFolders(id),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.folderCreate,
    requestSchema<Parameters<VaultaApi['vaults']['createFolder']>[0]>(IPC_CHANNELS.folderCreate),
    (input) => controller.createFolder(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.folderUpdate,
    requestSchema<Parameters<VaultaApi['vaults']['updateFolder']>[0]>(IPC_CHANNELS.folderUpdate),
    (input) => controller.updateFolder(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.folderDelete,
    requestSchema<Parameters<VaultaApi['vaults']['deleteFolder']>[0]>(IPC_CHANNELS.folderDelete),
    (input) => controller.deleteFolder(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.entryList,
    requestSchema<Parameters<VaultaApi['entries']['list']>[0]>(IPC_CHANNELS.entryList),
    (input) => controller.listEntries(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryDetail,
    requestSchema<Parameters<VaultaApi['entries']['getDetail']>[0]>(IPC_CHANNELS.entryDetail),
    (input) => controller.getEntryDetail(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryEditModel,
    requestSchema<Parameters<VaultaApi['entries']['getEditModel']>[0]>(IPC_CHANNELS.entryEditModel),
    (input) => controller.getEntryEditModel(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryCreate,
    requestSchema<Parameters<VaultaApi['entries']['create']>[0]>(IPC_CHANNELS.entryCreate),
    (input) => controller.createEntry(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryUpdate,
    requestSchema<Parameters<VaultaApi['entries']['update']>[0]>(IPC_CHANNELS.entryUpdate),
    (input) => controller.updateEntry(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryTrash,
    requestSchema<Parameters<VaultaApi['entries']['moveToTrash']>[0]>(IPC_CHANNELS.entryTrash),
    (input) => controller.moveEntryToTrash(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryRestore,
    requestSchema<Parameters<VaultaApi['entries']['restore']>[0]>(IPC_CHANNELS.entryRestore),
    (input) => controller.restoreEntry(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryPurge,
    requestSchema<Parameters<VaultaApi['entries']['purge']>[0]>(IPC_CHANNELS.entryPurge),
    (input) => controller.purgeEntry(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryToggleFavorite,
    requestSchema<Parameters<VaultaApi['entries']['toggleFavorite']>[0]>(
      IPC_CHANNELS.entryToggleFavorite,
    ),
    (input) => controller.toggleFavorite(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryReveal,
    requestSchema<Parameters<VaultaApi['entries']['reveal']>[0]>(IPC_CHANNELS.entryReveal),
    (input) => controller.revealEntryField(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryCopy,
    requestSchema<Parameters<VaultaApi['entries']['copy']>[0]>(IPC_CHANNELS.entryCopy),
    (input) => controller.copyEntryField(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryExportPrivateKey,
    requestSchema<Parameters<VaultaApi['entries']['exportPrivateKey']>[0]>(
      IPC_CHANNELS.entryExportPrivateKey,
    ),
    (input) => controller.exportPrivateKey(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.entryWifiQr,
    requestSchema<Parameters<VaultaApi['entries']['wifiQr']>[0]>(IPC_CHANNELS.entryWifiQr),
    (input) => controller.wifiQr(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.attachmentAdd,
    requestSchema<Parameters<VaultaApi['attachments']['add']>[0]>(IPC_CHANNELS.attachmentAdd),
    (input) => controller.addAttachment(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.attachmentRemove,
    requestSchema<Parameters<VaultaApi['attachments']['remove']>[0]>(IPC_CHANNELS.attachmentRemove),
    (input) => controller.removeAttachment(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.attachmentExport,
    requestSchema<Parameters<VaultaApi['attachments']['export']>[0]>(IPC_CHANNELS.attachmentExport),
    (input) => controller.exportAttachment(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.attachmentPreview,
    requestSchema<Parameters<VaultaApi['attachments']['preview']>[0]>(
      IPC_CHANNELS.attachmentPreview,
    ),
    (input) => controller.previewAttachment(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.generatorGenerate,
    requestSchema<Parameters<VaultaApi['generator']['generate']>[0]>(
      IPC_CHANNELS.generatorGenerate,
    ),
    (input) => controller.generateSecret(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.totpCode,
    requestSchema<Parameters<VaultaApi['totp']['getCode']>[0]>(IPC_CHANNELS.totpCode),
    (input) => controller.getTotpCode(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.totpCopy,
    requestSchema<Parameters<VaultaApi['totp']['copy']>[0]>(IPC_CHANNELS.totpCopy),
    (input) => controller.copyTotp(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.totpImportQr,
    requestSchema<'file' | 'screen'>(IPC_CHANNELS.totpImportQr),
    (input) => controller.importTotpQr(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.securityScan,
    requestSchema<string | undefined>(IPC_CHANNELS.securityScan),
    (input) => controller.scanSecurity(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.backupCreate,
    requestSchema<{ automatic?: boolean } | undefined>(IPC_CHANNELS.backupCreate),
    (input) => controller.createBackup(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.backupRestore,
    requestSchema<Parameters<VaultaApi['backup']['restore']>[0]>(IPC_CHANNELS.backupRestore),
    (input) => controller.restoreBackup(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.backupChooseFolder,
    requestSchema<undefined>(IPC_CHANNELS.backupChooseFolder),
    () => controller.chooseBackupFolder(),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.importPreview,
    requestSchema<Parameters<VaultaApi['transfer']['previewImport']>[0]>(
      IPC_CHANNELS.importPreview,
    ),
    (input) => controller.previewImport(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.importRemap,
    requestSchema<Parameters<VaultaApi['transfer']['remapImport']>[0]>(IPC_CHANNELS.importRemap),
    (input) => controller.remapImport(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.importExecute,
    requestSchema<Parameters<VaultaApi['transfer']['executeImport']>[0]>(
      IPC_CHANNELS.importExecute,
    ),
    (input) => controller.executeImport(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.exportExecute,
    requestSchema<Parameters<VaultaApi['transfer']['export']>[0]>(IPC_CHANNELS.exportExecute),
    (input) => controller.exportData(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.auditList,
    requestSchema<{ offset?: number; limit?: number } | undefined>(IPC_CHANNELS.auditList),
    (input) => controller.listAudit(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.settingsGet,
    requestSchema<undefined>(IPC_CHANNELS.settingsGet),
    () => controller.getSettings(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.settingsUpdate,
    requestSchema<Parameters<VaultaApi['settings']['update']>[0]>(IPC_CHANNELS.settingsUpdate),
    (input) => controller.updateSettings(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorStatus,
    requestSchema<undefined>(IPC_CHANNELS.factorStatus),
    () => controller.getFactorStatus(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorTotpBegin,
    requestSchema<Parameters<VaultaApi['factors']['beginTotp']>[0]>(IPC_CHANNELS.factorTotpBegin),
    (input) => controller.beginTotp(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorTotpComplete,
    requestSchema<Parameters<VaultaApi['factors']['completeTotp']>[0]>(
      IPC_CHANNELS.factorTotpComplete,
    ),
    (input) => controller.completeTotp(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorTotpRemove,
    requestSchema<Parameters<VaultaApi['factors']['removeTotp']>[0]>(IPC_CHANNELS.factorTotpRemove),
    (input) => controller.removeTotp(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorSecurityKeyBegin,
    requestSchema<Parameters<VaultaApi['factors']['beginSecurityKey']>[0]>(
      IPC_CHANNELS.factorSecurityKeyBegin,
    ),
    (input) => controller.beginSecurityKey(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorSecurityKeyComplete,
    requestSchema<Parameters<VaultaApi['factors']['completeSecurityKey']>[0]>(
      IPC_CHANNELS.factorSecurityKeyComplete,
    ),
    (input) => controller.completeSecurityKeyRegistration(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.factorSecurityKeyRemove,
    requestSchema<Parameters<VaultaApi['factors']['removeSecurityKey']>[0]>(
      IPC_CHANNELS.factorSecurityKeyRemove,
    ),
    (input) => controller.removeSecurityKey(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.recoveryRotate,
    requestSchema<Parameters<VaultaApi['factors']['rotateRecovery']>[0]>(
      IPC_CHANNELS.recoveryRotate,
    ),
    (input) => controller.rotateRecovery(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.recoveryRotateComplete,
    requestSchema<Parameters<VaultaApi['factors']['completeRecoveryRotation']>[0]>(
      IPC_CHANNELS.recoveryRotateComplete,
    ),
    (input) => controller.completeRecoveryRotation(input),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.templateList,
    requestSchema<undefined>(IPC_CHANNELS.templateList),
    () => controller.listTemplates(),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.templateSave,
    requestSchema<Parameters<VaultaApi['templates']['save']>[0]>(IPC_CHANNELS.templateSave),
    (input) => controller.saveTemplate(input),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.templateDelete,
    requestSchema<string>(IPC_CHANNELS.templateDelete),
    (id) => controller.deleteTemplate(id),
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.reportGenerate,
    requestSchema<undefined>(IPC_CHANNELS.reportGenerate),
    () => controller.generateReport(),
  );

  registerSafeHandler(
    context,
    IPC_CHANNELS.windowMinimize,
    requestSchema<undefined>(IPC_CHANNELS.windowMinimize),
    () => {
      options.getWindow()?.minimize();
    },
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.windowToggleMaximize,
    requestSchema<undefined>(IPC_CHANNELS.windowToggleMaximize),
    () => {
      const window = options.getWindow();
      if (window === null || window.isDestroyed()) return false;
      if (window.isMaximized()) window.unmaximize();
      else window.maximize();
      return window.isMaximized();
    },
  );
  registerSafeHandler(
    context,
    IPC_CHANNELS.windowClose,
    requestSchema<undefined>(IPC_CHANNELS.windowClose),
    async () => {
      await controller.lock();
      options.getWindow()?.close();
    },
  );
}
