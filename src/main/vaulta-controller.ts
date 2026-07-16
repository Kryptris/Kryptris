import { randomUUID } from 'node:crypto';
import { readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';

import {
  clipboard,
  desktopCapturer,
  dialog,
  nativeImage,
  type BrowserWindow,
  type NativeImage,
} from 'electron';
import jsQR from 'jsqr';
import QRCode from 'qrcode';

import { VaultaError } from '../shared/errors';
import type { VaultaApi } from '../shared/ipc';
import {
  DEFAULT_SETTINGS,
  type AppState,
  type AttachmentMetadata,
  type AttachmentPreview,
  type AuditEvent,
  type BackupInfo,
  type EntryDetail,
  type EntryListQuery,
  type EntrySummary,
  type EntryTemplate,
  type FactorStatus,
  type Folder,
  type LocalReport,
  type SecurityReport,
  type TotpConfiguration,
  type VaultaSettings,
  type VaultDocument,
  type VaultEntry,
  type VaultSummary,
} from '../shared/models';
import { entryTemplateSchema, vaultaSettingsSchema } from '../shared/schemas';
import { isSecurityWeakeningSettingsChange } from '../shared/settings-security';
import { ATTACHMENT_FORMAT_VERSION, AttachmentService } from './services/attachment-service';
import { AuthenticationSession } from './services/authentication-session';
import { AUDIT_DOCUMENT_FORMAT_VERSION, AuditService } from './services/audit-service';
import { AutoLockService } from './services/auto-lock-service';
import { BackupService } from './services/backup-service';
import { ClipboardService } from './services/clipboard-service';
import { EntryViewService } from './services/entry-view-service';
import { ExportService } from './services/export-service';
import { FactorService } from './services/factor-service';
import { ImportService } from './services/import-service';
import { PasswordGeneratorService } from './services/password-generator-service';
import { PersistentMigrationService } from './services/persistent-migration-service';
import { ProfileService, type ProtectedMetadataValue } from './services/profile-service';
import { ReportService } from './services/report-service';
import { SecurityCheckService } from './services/security-check-service';
import { TemplateService } from './services/template-service';
import { TotpService } from './services/totp-service';
import { VAULT_DOCUMENT_FORMAT_VERSION, VaultService } from './services/vault-service';
import { SerialExecutor } from './storage/serial-executor';
import { writeExclusiveCleartextFile } from './storage/cleartext-file';

type SetupBeginInput = Parameters<VaultaApi['setup']['begin']>[0];
type SetupCompleteInput = Parameters<VaultaApi['setup']['complete']>[0];
type UnlockInput = Parameters<VaultaApi['auth']['unlock']>[0];
type CompleteSecurityKeyInput = Parameters<VaultaApi['auth']['completeSecurityKey']>[0];
type CancelSecurityKeyInput = Parameters<VaultaApi['auth']['cancelSecurityKey']>[0];
type RecoverInput = Parameters<VaultaApi['auth']['recover']>[0];
type ChangeMasterPasswordInput = Parameters<VaultaApi['auth']['changeMasterPassword']>[0];
type VaultCreateInput = Parameters<VaultaApi['vaults']['create']>[0];
type VaultUpdateInput = Parameters<VaultaApi['vaults']['update']>[0];
type VaultDeleteInput = Parameters<VaultaApi['vaults']['delete']>[0];
type FolderCreateInput = Parameters<VaultaApi['vaults']['createFolder']>[0];
type FolderUpdateInput = Parameters<VaultaApi['vaults']['updateFolder']>[0];
type FolderDeleteInput = Parameters<VaultaApi['vaults']['deleteFolder']>[0];
type EntryReference = { vaultId: string; entryId: string };
type EntryCreateInput = Parameters<VaultaApi['entries']['create']>[0];
type EntryUpdateInput = Parameters<VaultaApi['entries']['update']>[0];
type EntryPurgeInput = Parameters<VaultaApi['entries']['purge']>[0];
type EntryRevealInput = Parameters<VaultaApi['entries']['reveal']>[0];
type EntryCopyInput = Parameters<VaultaApi['entries']['copy']>[0];
type PrivateKeyExportInput = Parameters<VaultaApi['entries']['exportPrivateKey']>[0];
type AttachmentReference = Parameters<VaultaApi['attachments']['preview']>[0];
type BackupRestoreInput = Parameters<VaultaApi['backup']['restore']>[0];
type ImportPreviewInput = Parameters<VaultaApi['transfer']['previewImport']>[0];
type ImportRemapInput = Parameters<VaultaApi['transfer']['remapImport']>[0];
type ImportExecuteInput = Parameters<VaultaApi['transfer']['executeImport']>[0];
type ExportInput = Parameters<VaultaApi['transfer']['export']>[0];
type TotpBeginInput = Parameters<VaultaApi['factors']['beginTotp']>[0];
type TotpCompleteInput = Parameters<VaultaApi['factors']['completeTotp']>[0];
type SecurityKeyBeginInput = Parameters<VaultaApi['factors']['beginSecurityKey']>[0];
type SecurityKeyCompleteInput = Parameters<VaultaApi['factors']['completeSecurityKey']>[0];
type SettingsUpdateInput = Parameters<VaultaApi['settings']['update']>[0];

const SETTINGS_NAMESPACE = 'settings';
const ACTIVE_VAULT_NAMESPACE = 'active-vault';
const TEMPLATES_NAMESPACE = 'templates';
const LAST_BACKUP_NAMESPACE = 'last-automatic-backup';
const AUTOMATIC_BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const AUTOMATIC_BACKUP_CHECK_MS = 60 * 60 * 1_000;
const PENDING_SETUP_TIMEOUT_MS = 5 * 60 * 1_000;
const MAX_QR_IMAGE_BYTES = 20 * 1024 * 1024;

const EMPTY_FACTORS: FactorStatus = {
  totpEnabled: false,
  securityKeys: [],
  recoveryEnabled: false,
};

const MIME_BY_EXTENSION: Readonly<Record<string, string>> = {
  '.gif': 'image/gif',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.md': 'text/markdown',
  '.pdf': 'application/pdf',
  '.png': 'image/png',
  '.txt': 'text/plain',
  '.webp': 'image/webp',
};

export interface VaultaControllerOptions {
  rootDir: string;
  version: string;
  getWindow: () => BrowserWindow | null;
  getOrigin: () => string;
  onStateChanged: (state: AppState) => void;
  onLocked: () => void;
  onClipboardCleared: () => void;
  onBackgroundWarning: (message: string) => void;
}

function protectedValue(value: unknown): ProtectedMetadataValue {
  return JSON.parse(JSON.stringify(value)) as ProtectedMetadataValue;
}

function cloneSettings(): VaultaSettings {
  return structuredClone(DEFAULT_SETTINGS);
}

function parseTemplates(value: ProtectedMetadataValue | null): EntryTemplate[] {
  if (value === null) return [];
  const parsed = entryTemplateSchema.array().safeParse(value);
  if (!parsed.success)
    throw new VaultaError('CORRUPT_DATA', 'Die gespeicherten Vorlagen sind beschädigt.');
  return parsed.data;
}

function requireEntry(document: VaultDocument, entryId: string): VaultEntry {
  const entry = document.entries.find((candidate) => candidate.id === entryId);
  if (entry === undefined) throw new VaultaError('NOT_FOUND', 'Der Eintrag wurde nicht gefunden.');
  return entry;
}

function safeFileName(value: string, fallback: string): string {
  const cleaned = Array.from(value.normalize('NFKC'), (character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || '<>:"/\\|?*'.includes(character) ? '-' : character;
  })
    .join('')
    .replace(/[. ]+$/u, '')
    .trim()
    .slice(0, 120);
  return cleaned.length > 0 ? cleaned : fallback;
}

function mediaTypeFor(filePath: string): string {
  return MIME_BY_EXTENSION[path.extname(filePath).toLowerCase()] ?? 'application/octet-stream';
}

function normalizeLocalBackupFolder(value: string): string {
  if (!path.win32.isAbsolute(value) || !/^[A-Za-z]:[\\/]$/u.test(path.win32.parse(value).root)) {
    throw new VaultaError(
      'INVALID_INPUT',
      'Automatische Backups benötigen einen lokalen absoluten Windows-Pfad.',
    );
  }
  return path.win32.normalize(value);
}

function sameWindowsPath(left: string, right: string): boolean {
  return left.toLocaleLowerCase('en-US') === right.toLocaleLowerCase('en-US');
}

function wifiEscape(value: string): string {
  return value.replace(/[\\;,:]/gu, (match) => `\\${match}`);
}

function isExpectedMagic(buffer: Buffer, mediaType: string): boolean {
  if (mediaType === 'image/png')
    return buffer.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'));
  if (mediaType === 'image/jpeg') return buffer.subarray(0, 3).equals(Buffer.from('ffd8ff', 'hex'));
  if (mediaType === 'image/gif') return /^GIF8[79]a/u.test(buffer.subarray(0, 6).toString('ascii'));
  if (mediaType === 'image/webp') {
    return (
      buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buffer.subarray(8, 12).toString('ascii') === 'WEBP'
    );
  }
  if (mediaType === 'application/pdf') return buffer.subarray(0, 5).toString('ascii') === '%PDF-';
  if (mediaType === 'text/plain' || mediaType === 'text/markdown') return !buffer.includes(0);
  return false;
}

function decodeQrImage(image: NativeImage): string | null {
  const size = image.getSize();
  if (size.width < 1 || size.height < 1 || size.width * size.height > 40_000_000) return null;
  const bgra = image.toBitmap();
  if (bgra.length !== size.width * size.height * 4) return null;
  const rgba = new Uint8ClampedArray(bgra.length);
  for (let offset = 0; offset < bgra.length; offset += 4) {
    rgba[offset] = bgra[offset + 2] ?? 0;
    rgba[offset + 1] = bgra[offset + 1] ?? 0;
    rgba[offset + 2] = bgra[offset] ?? 0;
    rgba[offset + 3] = bgra[offset + 3] ?? 255;
  }
  return jsQR(rgba, size.width, size.height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

function defaultListQuery(vaultId: string): EntryListQuery {
  return {
    vaultId,
    search: '',
    view: 'all',
    types: [],
    tags: [],
    folderId: null,
    security: [],
  };
}

export class VaultaController {
  private readonly rootDir: string;
  private readonly version: string;
  private readonly getWindow: () => BrowserWindow | null;
  private readonly getOrigin: () => string;
  private readonly onStateChanged: (state: AppState) => void;
  private readonly onLocked: () => void;
  private readonly onBackgroundWarning: (message: string) => void;
  private readonly profile: ProfileService;
  private readonly vaults: VaultService;
  private readonly attachments: AttachmentService;
  private readonly backups: BackupService;
  private readonly migrations: PersistentMigrationService;
  private readonly factors: FactorService;
  private readonly generator = new PasswordGeneratorService();
  private readonly totp = new TotpService();
  private readonly security = new SecurityCheckService();
  private readonly importer = new ImportService();
  private readonly exporter = new ExportService();
  private readonly reports = new ReportService();
  private readonly entryViews = new EntryViewService();
  private readonly clipboard: ClipboardService;
  private readonly autoLock: AutoLockService;
  private audit: AuditService;
  private templates = new TemplateService();
  private settings: VaultaSettings = cloneSettings();
  private activeVaultId: string | null = null;
  private readonly pendingVaultNames = new Map<string, string>();
  private readonly importVaults = new Map<string, string>();
  private failedUnlocks = 0;
  private blockedUntil = 0;
  private pendingFailedAuditEvents = 0;
  private pendingLockAuditEvents = 0;
  private pendingRestoredAuditEvent = false;
  private backupTimer: NodeJS.Timeout | null = null;
  private authorizedBackupFolder: string | null = null;
  private pendingSetupTimer: NodeJS.Timeout | null = null;
  private pendingSetupSession: { pendingId: string; epoch: number } | null = null;
  private automaticBackupRunning = false;
  private automaticBackupWarningSent = false;
  private readonly authentication = new AuthenticationSession();
  private readonly authenticationOperations = new SerialExecutor();
  private readonly factorOperations = new SerialExecutor();
  private readonly settingsOperations = new SerialExecutor();

  public constructor(options: VaultaControllerOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.version = options.version;
    this.getWindow = options.getWindow;
    this.getOrigin = options.getOrigin;
    this.onStateChanged = options.onStateChanged;
    this.onLocked = options.onLocked;
    this.onBackgroundWarning = options.onBackgroundWarning;
    this.profile = new ProfileService({ rootDir: this.rootDir });
    this.vaults = new VaultService({ rootDir: this.rootDir, profileService: this.profile });
    this.attachments = new AttachmentService({ rootDir: this.rootDir, vaultService: this.vaults });
    this.backups = new BackupService({ rootDir: this.rootDir, profileService: this.profile });
    this.audit = this.createAuditService(this.settings);
    this.migrations = new PersistentMigrationService({
      rootDir: this.rootDir,
      profileService: this.profile,
      backupService: this.backups,
      embeddedInspectors: [
        {
          id: 'vault-document',
          formatName: 'Vaulta-Tresorinhalt',
          currentVersion: VAULT_DOCUMENT_FORMAT_VERSION,
          matches: (relativePath) => /^vaults\/[A-Za-z0-9_-]+\.vaulta$/u.test(relativePath),
          readVersion: async (_filePath, relativePath) =>
            this.vaults.inspectStoredDocumentFormatVersion(path.basename(relativePath, '.vaulta')),
        },
        {
          id: 'audit-document',
          formatName: 'Vaulta-Aktivitätsprotokoll',
          currentVersion: AUDIT_DOCUMENT_FORMAT_VERSION,
          matches: (relativePath) => relativePath === 'audit.vaulta',
          readVersion: () => this.audit.inspectStoredDocumentFormatVersion(),
        },
        {
          id: 'attachment-footer',
          formatName: 'Vaulta-Anhangsabschluss',
          currentVersion: ATTACHMENT_FORMAT_VERSION,
          matches: (relativePath) =>
            /^attachments\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\.vatt$/u.test(relativePath),
          readVersion: async (_filePath, relativePath, assertAuthorized) => {
            const segments = relativePath.split('/');
            const vaultId = segments[1];
            const filename = segments[2];
            if (vaultId === undefined || filename === undefined) {
              throw new VaultaError('CORRUPT_DATA', 'Der Anhangspfad ist ungültig.');
            }
            return this.attachments.inspectStoredFormatVersion(
              vaultId,
              path.basename(filename, '.vatt'),
              assertAuthorized,
            );
          },
        },
      ],
    });
    this.factors = new FactorService({
      profile: this.profile,
      origin: this.getOrigin,
      onAuthenticationExpired: (challengeId) => {
        if (!this.authentication.cancelChallenge(challengeId)) return;
        this.profile.lock();
        void this.emitState().catch(() => undefined);
      },
    });
    this.clipboard = new ClipboardService({
      clipboard,
      onCleared: options.onClipboardCleared,
    });
    this.autoLock = new AutoLockService({ onLock: async () => this.lock() });
  }

  public async initialize(): Promise<AppState> {
    await this.backups.recoverInterruptedRestore();
    await this.migrations.recoverInterruptedWrites();
    await this.migrations.inspect();
    if ((await this.profile.hasProfile()) && this.profile.isUnlocked()) {
      const epoch = this.authentication.begin();
      try {
        await this.loadUnlockedData(epoch);
        this.authentication.complete(this.profile.isUnlocked(), epoch);
        this.startAuthenticatedServices();
      } catch (error) {
        this.authentication.reset();
        this.factors.clearPending();
        throw error;
      }
    }
    return this.getState();
  }

  public dispose(): void {
    this.authorizedBackupFolder = null;
    this.clearPendingSetupSession();
    this.authentication.reset();
    this.autoLock.stop();
    this.clipboard.dispose();
    this.factors.clearPending();
    this.importer.clear();
    this.vaults.clearCachedDocuments?.();
    this.profile.lock();
    if (this.backupTimer !== null) clearInterval(this.backupTimer);
    this.backupTimer = null;
  }

  public async getState(): Promise<AppState> {
    const hasProfile = await this.profile.hasProfile();
    const locked = !this.authentication.isAuthenticated(this.profile.isUnlocked());
    const epoch = locked
      ? null
      : this.authentication.requireAuthenticated(this.profile.isUnlocked());
    const factorStatus = hasProfile
      ? await this.factors.getStatus(!locked)
      : structuredClone(EMPTY_FACTORS);
    const vaults = locked ? [] : await this.vaults.listVaults();
    if (epoch !== null) this.assertAuthenticated(epoch);
    if (
      !locked &&
      this.activeVaultId !== null &&
      !vaults.some((vault) => vault.id === this.activeVaultId)
    ) {
      this.activeVaultId = vaults[0]?.id ?? null;
    }
    return {
      hasProfile,
      locked,
      activeVaultId: locked ? null : this.activeVaultId,
      vaults,
      factorStatus,
      settings: locked ? null : structuredClone(this.settings),
      autoLockAt: locked ? null : this.autoLock.getDeadline(),
      version: this.version,
    };
  }

  public activity(): void {
    if (this.authentication.isAuthenticated(this.profile.isUnlocked())) this.autoLock.activity();
  }

  public async lock(): Promise<void> {
    const previousState = this.authentication.getState();
    const wasAuthenticated = this.authentication.isAuthenticated(this.profile.isUnlocked());
    this.authorizedBackupFolder = null;
    this.clearPendingSetupSession();
    this.authentication.reset();
    if (wasAuthenticated) this.pendingLockAuditEvents += 1;
    this.autoLock.stop();
    this.clipboard.clearOwnedValue();
    this.factors.clearPending();
    this.importer.clear();
    this.importVaults.clear();
    this.pendingVaultNames.clear();
    this.vaults.clearCachedDocuments?.();
    this.profile.lock();
    this.activeVaultId = null;
    this.configureAutomaticBackups();
    if (previousState !== 'locked' || wasAuthenticated) this.onLocked();
    await this.emitState();
  }

  public clearClipboard(): boolean {
    return this.clipboard.clearManually();
  }

  public async beginSetup(input: SetupBeginInput) {
    return this.authenticationOperations.run(async () => {
      const epoch = this.authentication.begin();
      try {
        const result = await this.profile.beginSetup(input.masterPassword, input.enableRecovery);
        this.authentication.assertEpoch(epoch);
        this.pendingVaultNames.set(result.pendingId, input.vaultName.trim());
        this.pendingSetupSession = { pendingId: result.pendingId, epoch };
        this.armPendingSetupTimeout(result.pendingId, epoch);
        return result;
      } catch (error) {
        this.clearPendingSetupSession();
        this.authentication.reset();
        this.pendingVaultNames.clear();
        this.profile.lock();
        throw error;
      }
    });
  }

  public async completeSetup(input: SetupCompleteInput): Promise<AppState> {
    return this.authenticationOperations.run(async () => {
      const pendingSetup = this.pendingSetupSession;
      if (pendingSetup === null || pendingSetup.pendingId !== input.pendingId) {
        throw new VaultaError('NOT_FOUND', 'Die ausstehende Einrichtung wurde nicht gefunden.');
      }
      const epoch = pendingSetup.epoch;
      this.authentication.assertEpoch(epoch);
      try {
        const vaultName = this.pendingVaultNames.get(input.pendingId);
        if (vaultName === undefined)
          throw new VaultaError('NOT_FOUND', 'Die ausstehende Einrichtung wurde nicht gefunden.');
        await this.profile.completeSetup(input.pendingId, input.confirmation);
        this.authentication.assertEpoch(epoch);
        this.pendingVaultNames.delete(input.pendingId);
        this.settings = cloneSettings();
        await this.profile.setProtectedMetadata(SETTINGS_NAMESPACE, protectedValue(this.settings));
        this.authentication.assertEpoch(epoch);
        await this.profile.setProtectedMetadata(TEMPLATES_NAMESPACE, []);
        this.authentication.assertEpoch(epoch);
        const vault = await this.vaults.createVault(vaultName, '#14b8a6');
        this.authentication.assertEpoch(epoch);
        this.activeVaultId = vault.id;
        await this.profile.setProtectedMetadata(ACTIVE_VAULT_NAMESPACE, vault.id);
        this.authentication.assertEpoch(epoch);
        this.audit = this.createAuditService(this.settings);
        await this.audit.record({ type: 'profile-created' });
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'vault-created', vaultId: vault.id });
        this.authentication.assertEpoch(epoch);
        await this.loadUnlockedData(epoch);
        this.authentication.assertEpoch(epoch);
        this.authentication.complete(this.profile.isUnlocked(), epoch);
        this.clearPendingSetupSession();
        this.startAuthenticatedServices();
        return this.emitState();
      } catch (error) {
        const stale = !this.authentication.isAuthenticating(epoch);
        if (stale || this.profile.isUnlocked()) {
          this.clearPendingSetupSession();
          this.authentication.reset();
          this.factors.clearPending();
          this.pendingVaultNames.clear();
          this.profile.lock();
        }
        throw error;
      }
    });
  }

  public async unlock(input: UnlockInput) {
    return this.authenticationOperations.run(async () => {
      this.assertNotRateLimited();
      const epoch = this.authentication.begin();
      try {
        const result = await this.factors.beginUnlock(input.masterPassword, input.totpCode);
        this.authentication.assertEpoch(epoch);
        if (result.status === 'unlocked') await this.finishUnlock(epoch);
        else if (result.status === 'security-key-required' && result.challengeId !== undefined)
          this.authentication.awaitChallenge(result.challengeId, epoch);
        else this.authentication.reset();
        return result;
      } catch (error) {
        this.authentication.reset();
        this.factors.cancelAuthentication();
        this.profile.lock();
        this.registerUnlockFailure(error);
        throw error;
      }
    });
  }

  public async completeSecurityKey(input: CompleteSecurityKeyInput) {
    return this.authenticationOperations.run(async () => {
      this.assertNotRateLimited();
      const epoch = this.authentication.assertChallenge(input.challengeId);
      try {
        const result = await this.factors.completeUnlock(input);
        this.authentication.assertEpoch(epoch);
        if (result.unlocked) await this.finishUnlock(epoch);
        return result;
      } catch (error) {
        this.authentication.reset();
        this.factors.cancelAuthentication();
        this.profile.lock();
        this.registerUnlockFailure(error);
        throw error;
      }
    });
  }

  public async cancelSecurityKey(input: CancelSecurityKeyInput): Promise<void> {
    if (!this.authentication.cancelChallenge(input.challengeId)) return;
    this.factors.cancelAuthentication(input.challengeId);
    this.profile.lock();
    await this.emitState();
  }

  public async recover(input: RecoverInput): Promise<AppState> {
    return this.authenticationOperations.run(async () => {
      this.assertNotRateLimited();
      const epoch = this.authentication.begin();
      try {
        this.factors.clearPending();
        await this.profile.recover(input.recoveryKey, input.newMasterPassword);
        this.authentication.assertEpoch(epoch);
        await this.loadUnlockedData(epoch);
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'recovery-used' });
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'unlocked' });
        this.authentication.assertEpoch(epoch);
        this.authentication.complete(this.profile.isUnlocked(), epoch);
        this.startAuthenticatedServices();
        this.resetUnlockFailures();
        return this.emitState();
      } catch (error) {
        this.authentication.reset();
        this.factors.clearPending();
        this.profile.lock();
        this.registerUnlockFailure(error);
        throw error;
      }
    });
  }

  public async changeMasterPassword(input: ChangeMasterPasswordInput): Promise<void> {
    this.requireUnlocked();
    await this.profile.changeMasterPassword(input.currentPassword, input.newPassword);
  }

  public async listVaults(): Promise<VaultSummary[]> {
    const epoch = this.requireUnlocked();
    const vaults = await this.vaults.listVaults();
    this.assertAuthenticated(epoch);
    return vaults;
  }

  public async createVault(input: VaultCreateInput): Promise<VaultSummary> {
    this.requireUnlocked();
    const document = await this.vaults.createVault(input.name, input.color);
    this.activeVaultId = document.id;
    await this.profile.setProtectedMetadata(ACTIVE_VAULT_NAMESPACE, document.id);
    await this.audit.record({ type: 'vault-created', vaultId: document.id });
    await this.emitState();
    return this.summaryForVault(document);
  }

  public async updateVault(input: VaultUpdateInput): Promise<VaultSummary> {
    this.requireUnlocked();
    const document = await this.vaults.updateVault(input.id, {
      name: input.name,
      color: input.color,
    });
    await this.audit.record({ type: 'vault-updated', vaultId: input.id });
    await this.emitState();
    return this.summaryForVault(document);
  }

  public async deleteVault(input: VaultDeleteInput): Promise<void> {
    this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(input.masterPassword))) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    }
    const summaries = await this.vaults.listVaults();
    if (summaries.length <= 1)
      throw new VaultaError('CONFLICT', 'Der letzte Tresor kann nicht gelöscht werden.');
    await this.vaults.deleteVault(input.id);
    await rm(path.join(this.rootDir, 'attachments', input.id), { recursive: true, force: true });
    await this.audit.record({ type: 'vault-deleted', vaultId: input.id });
    if (this.activeVaultId === input.id) {
      this.activeVaultId = summaries.find((vault) => vault.id !== input.id)?.id ?? null;
      await this.profile.setProtectedMetadata(ACTIVE_VAULT_NAMESPACE, this.activeVaultId);
    }
    await this.emitState();
  }

  public async selectVault(id: string): Promise<void> {
    this.requireUnlocked();
    const summaries = await this.vaults.listVaults();
    if (!summaries.some((vault) => vault.id === id))
      throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
    this.activeVaultId = id;
    await this.profile.setProtectedMetadata(ACTIVE_VAULT_NAMESPACE, id);
    await this.emitState();
  }

  public async listFolders(vaultId: string): Promise<Folder[]> {
    const epoch = this.requireUnlocked();
    const folders = structuredClone((await this.vaults.readVault(vaultId)).folders);
    this.assertAuthenticated(epoch);
    return folders;
  }

  public async createFolder(input: FolderCreateInput): Promise<Folder> {
    this.requireUnlocked();
    const folder: Folder = {
      id: randomUUID(),
      name: input.name.trim(),
      color: input.color,
      createdAt: new Date().toISOString(),
    };
    await this.vaults.mutateVault(input.vaultId, (document) => {
      if (
        document.folders.some(
          (candidate) =>
            candidate.name.toLocaleLowerCase('de') === folder.name.toLocaleLowerCase('de'),
        )
      ) {
        throw new VaultaError('CONFLICT', 'Ein Ordner mit diesem Namen existiert bereits.');
      }
      document.folders.push(folder);
      return undefined;
    });
    return structuredClone(folder);
  }

  public async updateFolder(input: FolderUpdateInput): Promise<Folder> {
    this.requireUnlocked();
    return this.vaults.mutateVault(input.vaultId, (document) => {
      const folder = document.folders.find((candidate) => candidate.id === input.id);
      if (folder === undefined)
        throw new VaultaError('NOT_FOUND', 'Der Ordner wurde nicht gefunden.');
      const duplicate = document.folders.some(
        (candidate) =>
          candidate.id !== input.id &&
          candidate.name.toLocaleLowerCase('de') === input.name.trim().toLocaleLowerCase('de'),
      );
      if (duplicate)
        throw new VaultaError('CONFLICT', 'Ein Ordner mit diesem Namen existiert bereits.');
      folder.name = input.name.trim();
      folder.color = input.color;
      return structuredClone(folder);
    });
  }

  public async deleteFolder(input: FolderDeleteInput): Promise<void> {
    this.requireUnlocked();
    await this.vaults.mutateVault(input.vaultId, (document) => {
      if (!document.folders.some((folder) => folder.id === input.id))
        throw new VaultaError('NOT_FOUND', 'Der Ordner wurde nicht gefunden.');
      document.folders = document.folders.filter((folder) => folder.id !== input.id);
      for (const entry of document.entries) if (entry.folderId === input.id) entry.folderId = null;
      return undefined;
    });
  }

  public async listEntries(query: EntryListQuery): Promise<EntrySummary[]> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(query.vaultId);
    this.assertAuthenticated(epoch);
    const entries = this.entryViews.list(document.entries, query);
    this.assertAuthenticated(epoch);
    return entries;
  }

  public async getEntryDetail(input: EntryReference): Promise<EntryDetail> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(input.vaultId);
    this.assertAuthenticated(epoch);
    const detail = this.entryViews.detail(requireEntry(document, input.entryId));
    this.assertAuthenticated(epoch);
    return detail;
  }

  public async getEntryEditModel(input: EntryReference): Promise<VaultEntry> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(input.vaultId);
    this.assertAuthenticated(epoch);
    const entry = structuredClone(requireEntry(document, input.entryId));
    this.assertAuthenticated(epoch);
    return entry;
  }

  public async createEntry(input: EntryCreateInput): Promise<EntrySummary> {
    this.requireUnlocked();
    const entry = await this.vaults.createEntry(input.vaultId, input.entry);
    await this.audit.record({ type: 'entry-created', vaultId: input.vaultId, entryId: entry.id });
    return this.summaryForEntry(entry);
  }

  public async updateEntry(input: EntryUpdateInput): Promise<EntrySummary> {
    this.requireUnlocked();
    const entry = await this.vaults.updateEntry(input.vaultId, input.entryId, input.entry);
    await this.audit.record({
      type: 'entry-updated',
      vaultId: input.vaultId,
      entryId: input.entryId,
    });
    return this.summaryForEntry(entry);
  }

  public async moveEntryToTrash(input: EntryReference): Promise<void> {
    this.requireUnlocked();
    await this.vaults.moveEntryToTrash(input.vaultId, input.entryId);
    await this.audit.record({
      type: 'entry-moved-to-trash',
      vaultId: input.vaultId,
      entryId: input.entryId,
    });
  }

  public async restoreEntry(input: EntryReference): Promise<void> {
    this.requireUnlocked();
    await this.vaults.restoreEntry(input.vaultId, input.entryId);
    await this.audit.record({
      type: 'entry-restored',
      vaultId: input.vaultId,
      entryId: input.entryId,
    });
  }

  public async purgeEntry(input: EntryPurgeInput): Promise<void> {
    this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(input.masterPassword)))
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    if (entry.deletedAt === null)
      throw new VaultaError(
        'CONFLICT',
        'Nur Einträge im Papierkorb können endgültig gelöscht werden.',
      );
    await this.vaults.purgeEntry(input.vaultId, input.entryId);
    await Promise.all(
      entry.attachments.map((attachment) => this.attachments.remove(input.vaultId, attachment.id)),
    );
    await this.audit.record({
      type: 'entry-purged',
      vaultId: input.vaultId,
      entryId: input.entryId,
    });
  }

  public async toggleFavorite(input: EntryReference): Promise<boolean> {
    this.requireUnlocked();
    return this.vaults.toggleFavorite(input.vaultId, input.entryId);
  }

  public async revealEntryField(input: EntryRevealInput): Promise<string> {
    const epoch = this.requireUnlocked();
    if (this.settings.requireMasterForReveal) {
      if (
        input.masterPassword === undefined ||
        !(await this.profile.verifyMasterPassword(input.masterPassword))
      ) {
        throw new VaultaError(
          'AUTH_FAILED',
          'Zum Anzeigen ist das gültige Master-Passwort erforderlich.',
        );
      }
      this.assertAuthenticated(epoch);
    }
    const document = await this.vaults.readVault(input.vaultId);
    this.assertAuthenticated(epoch);
    const value = this.entryViews.fieldValue(
      requireEntry(document, input.entryId),
      input.fieldPath,
    );
    await this.markEntryUsed(input.vaultId, input.entryId);
    this.assertAuthenticated(epoch);
    return value;
  }

  public async copyEntryField(input: EntryCopyInput): Promise<void> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(input.vaultId);
    this.assertAuthenticated(epoch);
    const value = this.entryViews.fieldValue(
      requireEntry(document, input.entryId),
      input.fieldPath,
    );
    this.assertAuthenticated(epoch);
    this.clipboard.copySecret(value, this.settings.clipboardClearSeconds);
    await this.markEntryUsed(input.vaultId, input.entryId);
  }

  public async exportPrivateKey(input: PrivateKeyExportInput): Promise<boolean> {
    const epoch = this.requireUnlocked();
    if (input.confirmation !== 'PRIVATEN SCHLÜSSEL EXPORTIEREN') {
      throw new VaultaError('INVALID_INPUT', 'Die Exportbestätigung stimmt nicht.');
    }
    if (!(await this.profile.verifyMasterPassword(input.masterPassword)))
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    this.assertAuthenticated(epoch);
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    this.assertAuthenticated(epoch);
    if (entry.data.type !== 'ssh-key' || entry.data.value.privateKey.length === 0)
      throw new VaultaError('NOT_FOUND', 'Der private Schlüssel wurde nicht gefunden.');
    const privateKey = entry.data.value.privateKey;
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Privaten SSH-Schlüssel exportieren',
      defaultPath: `${safeFileName(entry.title, 'vaulta-key')}.key`,
      filters: [{ name: 'SSH-Schlüssel', extensions: ['key', 'pem'] }],
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return false;
    let exportWritten = false;
    try {
      await writeExclusiveCleartextFile(
        result.filePath,
        async (handle) => {
          await handle.writeFile(privateKey, { encoding: 'utf8' });
          this.assertAuthenticated(epoch);
        },
        { replaceExisting: true },
      );
      exportWritten = true;
      this.assertAuthenticated(epoch);
      await this.audit.record({
        type: 'private-key-exported',
        vaultId: input.vaultId,
        entryId: input.entryId,
      });
      this.assertAuthenticated(epoch);
      await this.markEntryUsed(input.vaultId, input.entryId);
      this.assertAuthenticated(epoch);
      return true;
    } catch (error) {
      if (exportWritten) await rm(result.filePath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  public async wifiQr(input: EntryReference): Promise<string> {
    const epoch = this.requireUnlocked();
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    this.assertAuthenticated(epoch);
    if (entry.data.type !== 'wifi')
      throw new VaultaError('INVALID_INPUT', 'Der Eintrag enthält keine WLAN-Daten.');
    const data = entry.data.value;
    const security = data.security === 'Offen' ? 'nopass' : data.security === 'WEP' ? 'WEP' : 'WPA';
    const payload = `WIFI:T:${security};S:${wifiEscape(data.ssid)};P:${wifiEscape(data.password)};H:${data.hidden ? 'true' : 'false'};;`;
    const result = await QRCode.toDataURL(payload, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 420,
    });
    this.assertAuthenticated(epoch);
    return result;
  }

  public async addAttachment(input: EntryReference): Promise<AttachmentMetadata | null> {
    this.requireUnlocked();
    requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    const result = await dialog.showOpenDialog(this.requireWindow(), {
      title: 'Datei verschlüsselt anhängen',
      properties: ['openFile'],
    });
    const sourcePath = result.filePaths[0];
    if (result.canceled || sourcePath === undefined) return null;
    const metadata = await this.attachments.encryptFile({
      vaultId: input.vaultId,
      sourcePath,
      name: path.basename(sourcePath),
      mediaType: mediaTypeFor(sourcePath),
      maxBytes: this.settings.attachmentMaxBytes,
    });
    try {
      await this.vaults.mutateVault(input.vaultId, (document) => {
        const entry = requireEntry(document, input.entryId);
        if (entry.deletedAt !== null)
          throw new VaultaError(
            'CONFLICT',
            'An einen gelöschten Eintrag kann nichts angehängt werden.',
          );
        entry.attachments.push(metadata);
        entry.updatedAt = new Date().toISOString();
        return undefined;
      });
    } catch (error) {
      await this.attachments.remove(input.vaultId, metadata.id).catch(() => undefined);
      throw error;
    }
    await this.audit.record({
      type: 'attachment-added',
      vaultId: input.vaultId,
      entryId: input.entryId,
    });
    return metadata;
  }

  public async removeAttachment(input: AttachmentReference): Promise<void> {
    this.requireUnlocked();
    await this.vaults.mutateVault(input.vaultId, (document) => {
      const entry = requireEntry(document, input.entryId);
      if (!entry.attachments.some((attachment) => attachment.id === input.attachmentId))
        throw new VaultaError('NOT_FOUND', 'Der Anhang wurde nicht gefunden.');
      entry.attachments = entry.attachments.filter(
        (attachment) => attachment.id !== input.attachmentId,
      );
      entry.updatedAt = new Date().toISOString();
      return undefined;
    });
    await this.attachments.remove(input.vaultId, input.attachmentId);
  }

  public async exportAttachment(input: AttachmentReference): Promise<boolean> {
    const epoch = this.requireUnlocked();
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    this.assertAuthenticated(epoch);
    const attachment = entry.attachments.find((candidate) => candidate.id === input.attachmentId);
    if (attachment === undefined)
      throw new VaultaError('NOT_FOUND', 'Der Anhang wurde nicht gefunden.');
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Anhang entschlüsselt exportieren',
      defaultPath: safeFileName(attachment.name, 'Vaulta-Anhang'),
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return false;
    let exportWritten = false;
    try {
      await this.attachments.decryptToFile(
        input.vaultId,
        input.attachmentId,
        result.filePath,
        () => this.assertAuthenticated(epoch),
        { replaceExisting: true },
      );
      exportWritten = true;
      this.assertAuthenticated(epoch);
      await this.audit.record({
        type: 'attachment-exported',
        vaultId: input.vaultId,
        entryId: input.entryId,
      });
      this.assertAuthenticated(epoch);
      return true;
    } catch (error) {
      if (exportWritten) await rm(result.filePath, { force: true }).catch(() => undefined);
      throw error;
    }
  }

  public async previewAttachment(input: AttachmentReference): Promise<AttachmentPreview> {
    const epoch = this.requireUnlocked();
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    this.assertAuthenticated(epoch);
    const metadata = entry.attachments.find((attachment) => attachment.id === input.attachmentId);
    if (metadata === undefined || !metadata.previewable)
      throw new VaultaError(
        'UNSUPPORTED_FORMAT',
        'Für diesen Anhang ist keine sichere Vorschau verfügbar.',
      );
    const maximum = metadata.mediaType.startsWith('text/') ? 2 * 1024 * 1024 : 20 * 1024 * 1024;
    if (metadata.size > maximum)
      throw new VaultaError('FILE_TOO_LARGE', 'Der Anhang ist für eine Vorschau zu groß.');
    const buffer = await this.attachments.readBuffer(input.vaultId, input.attachmentId, maximum);
    this.assertAuthenticated(epoch);
    if (!isExpectedMagic(buffer, metadata.mediaType))
      throw new VaultaError(
        'CORRUPT_DATA',
        'Dateityp und Dateiinhalt des Anhangs stimmen nicht überein.',
      );
    const preview: AttachmentPreview = metadata.mediaType.startsWith('text/')
      ? { kind: 'text', mediaType: metadata.mediaType, data: buffer.toString('utf8') }
      : {
          kind: metadata.mediaType === 'application/pdf' ? 'pdf' : 'image',
          mediaType: metadata.mediaType,
          data: `data:${metadata.mediaType};base64,${buffer.toString('base64')}`,
        };
    this.assertAuthenticated(epoch);
    return preview;
  }

  public generateSecret(options: Parameters<VaultaApi['generator']['generate']>[0]) {
    this.requireUnlocked();
    return this.generator.generate(options);
  }

  public async getTotpCode(input: EntryReference) {
    const epoch = this.requireUnlocked();
    const entry = requireEntry(await this.vaults.readVault(input.vaultId), input.entryId);
    this.assertAuthenticated(epoch);
    if (entry.data.type !== 'credential' || entry.data.value.totp === undefined)
      throw new VaultaError('NOT_FOUND', 'Für diesen Eintrag ist kein TOTP eingerichtet.');
    const code = this.totp.getCode(entry.data.value.totp);
    this.assertAuthenticated(epoch);
    return code;
  }

  public async copyTotp(input: EntryReference): Promise<void> {
    const epoch = this.requireUnlocked();
    const code = await this.getTotpCode(input);
    this.assertAuthenticated(epoch);
    this.clipboard.copySecret(code.code, this.settings.clipboardClearSeconds);
    await this.markEntryUsed(input.vaultId, input.entryId);
  }

  public async importTotpQr(source: 'file' | 'screen'): Promise<TotpConfiguration | null> {
    const epoch = this.requireUnlocked();
    let values: string[] = [];
    if (source === 'file') {
      const result = await dialog.showOpenDialog(this.requireWindow(), {
        title: 'TOTP-QR-Code lokal einlesen',
        properties: ['openFile'],
        filters: [{ name: 'Bilder', extensions: ['png', 'jpg', 'jpeg', 'webp'] }],
      });
      const filePath = result.filePaths[0];
      this.assertAuthenticated(epoch);
      if (result.canceled || filePath === undefined) return null;
      const info = await stat(filePath);
      this.assertAuthenticated(epoch);
      if (!info.isFile() || info.size > MAX_QR_IMAGE_BYTES)
        throw new VaultaError('FILE_TOO_LARGE', 'Das QR-Bild ist zu groß.');
      const decoded = decodeQrImage(nativeImage.createFromPath(filePath));
      if (decoded !== null) values = [decoded];
    } else {
      const sources = await desktopCapturer.getSources({
        types: ['screen'],
        thumbnailSize: { width: 3840, height: 2160 },
        fetchWindowIcons: false,
      });
      this.assertAuthenticated(epoch);
      values = sources.flatMap((capture) => {
        const decoded = decodeQrImage(capture.thumbnail);
        return decoded === null ? [] : [decoded];
      });
    }
    const otpUri = values.find((value) => value.startsWith('otpauth://totp/'));
    if (otpUri === undefined)
      throw new VaultaError('NOT_FOUND', 'Im gewählten Bild wurde kein TOTP-QR-Code gefunden.');
    const configuration = this.totp.parseOtpAuthUri(otpUri);
    this.assertAuthenticated(epoch);
    return configuration;
  }

  public async scanSecurity(vaultId?: string): Promise<SecurityReport> {
    const epoch = this.requireUnlocked();
    const documents =
      vaultId === undefined ? await this.readAllVaults() : [await this.vaults.readVault(vaultId)];
    this.assertAuthenticated(epoch);
    const report = await this.security.scanAsync(
      documents.flatMap((document) => document.entries).filter((entry) => entry.deletedAt === null),
    );
    this.assertAuthenticated(epoch);
    return report;
  }

  public async createBackup(input?: { automatic?: boolean }): Promise<BackupInfo | null> {
    const epoch = this.requireUnlocked();
    if (input?.automatic === true) return this.createAutomaticBackup();
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Verschlüsseltes Vaulta-Backup erstellen',
      defaultPath: `Vaulta-${new Date().toISOString().slice(0, 10)}.vaulta-backup`,
      filters: [{ name: 'Vaulta-Backup', extensions: ['vaulta-backup'] }],
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return null;
    const backup = await this.backups.createBackup({
      destination: result.filePath,
      replaceExisting: true,
      assertAuthorized: () => this.assertAuthenticated(epoch),
      validateLiveState: () => this.validateBackupLiveState(epoch),
    });
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'backup-created' });
    this.assertAuthenticated(epoch);
    return backup;
  }

  public async restoreBackup(input: BackupRestoreInput): Promise<AppState | null> {
    const result = await dialog.showOpenDialog(this.requireWindow(), {
      title: 'Verschlüsseltes Vaulta-Backup wiederherstellen',
      properties: ['openFile'],
      filters: [{ name: 'Vaulta-Backup', extensions: ['vaulta-backup'] }],
    });
    const backupPath = result.filePaths[0];
    if (result.canceled || backupPath === undefined) return null;
    if (input.credential.type === 'recovery' && input.newMasterPassword === undefined) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Nach Wiederherstellung mit dem Wiederherstellungsschlüssel ist ein neues Master-Passwort erforderlich.',
      );
    }
    await this.backups.inspectBackup(backupPath, input.credential);
    const confirmation = await dialog.showMessageBox(this.requireWindow(), {
      type: 'warning',
      title: 'Lokale Daten ersetzen?',
      message: 'Die geprüfte Sicherung ersetzt das aktuelle lokale Vaulta-Profil vollständig.',
      detail:
        'Dieser Vorgang kann nicht rückgängig gemacht werden. Vaulta prüft Integrität und Zugangsschlüssel vor dem Austausch.',
      buttons: ['Abbrechen', 'Wiederherstellen'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
    });
    if (confirmation.response !== 1) return null;
    await this.lock();
    return this.authenticationOperations.run(async () => {
      if (input.credential.type !== 'recovery') {
        try {
          await this.backups.restoreBackup({
            backupPath,
            credential: input.credential,
            replaceExisting: true,
          });
          this.pendingRestoredAuditEvent = true;
          this.settings = cloneSettings();
          this.activeVaultId = null;
          this.profile.lock();
          return this.emitState();
        } catch (error) {
          this.authentication.reset();
          this.factors.clearPending();
          this.profile.lock();
          await this.emitState();
          throw error;
        }
      }

      const epoch = this.authentication.begin();
      try {
        await this.backups.restoreBackup({
          backupPath,
          credential: input.credential,
          replaceExisting: true,
        });
        this.authentication.assertEpoch(epoch);
        this.pendingRestoredAuditEvent = true;
        await this.profile.recover(input.credential.value, input.newMasterPassword as string);
        this.authentication.assertEpoch(epoch);
        await this.loadUnlockedData(epoch);
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'backup-restored' });
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'recovery-used' });
        this.authentication.assertEpoch(epoch);
        await this.audit.record({ type: 'unlocked' });
        this.authentication.assertEpoch(epoch);
        this.pendingRestoredAuditEvent = false;
        this.authentication.complete(this.profile.isUnlocked(), epoch);
        this.startAuthenticatedServices();
        this.resetUnlockFailures();
        return this.emitState();
      } catch (error) {
        this.authentication.reset();
        this.factors.clearPending();
        this.profile.lock();
        await this.emitState();
        throw error;
      }
    });
  }

  public async chooseBackupFolder(): Promise<string | null> {
    const epoch = this.requireUnlocked();
    this.authorizedBackupFolder = null;
    const result = await dialog.showOpenDialog(this.requireWindow(), {
      title: 'Ordner für automatische Backups wählen',
      properties: ['openDirectory', 'createDirectory'],
    });
    this.assertAuthenticated(epoch);
    const selected = result.filePaths[0];
    if (result.canceled || selected === undefined) return null;
    const normalized = normalizeLocalBackupFolder(selected);
    this.authorizedBackupFolder = normalized;
    return normalized;
  }

  public async previewImport(input: ImportPreviewInput) {
    const epoch = this.requireUnlocked();
    try {
      const result = await dialog.showOpenDialog(this.requireWindow(), {
        title: 'Passwortdaten importieren',
        properties: ['openFile'],
        filters: [
          { name: 'Passwort-Exporte', extensions: ['json', 'csv'] },
          { name: 'Alle Dateien', extensions: ['*'] },
        ],
      });
      this.assertAuthenticated(epoch);
      const sourcePath = result.filePaths[0];
      if (result.canceled || sourcePath === undefined) return null;
      const info = await stat(sourcePath);
      this.assertAuthenticated(epoch);
      if (!info.isFile() || info.size > 50 * 1024 * 1024)
        throw new VaultaError('FILE_TOO_LARGE', 'Die Importdatei ist zu groß.');
      const content = await readFile(sourcePath, 'utf8');
      this.assertAuthenticated(epoch);
      const format = input.format ?? this.importer.detectFormat(path.basename(sourcePath), content);
      if (format === null)
        throw new VaultaError('UNSUPPORTED_FORMAT', 'Das Importformat wurde nicht erkannt.');
      const document = await this.vaults.readVault(input.vaultId);
      this.assertAuthenticated(epoch);
      const source = {
        format,
        content,
        sourceName: path.basename(sourcePath),
        existingEntries: document.entries,
        ...(input.mapping === undefined ? {} : { mapping: input.mapping }),
      };
      const preview = this.importer.preview(source);
      this.importVaults.set(preview.token, input.vaultId);
      this.assertAuthenticated(epoch);
      return preview;
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) {
        this.importer.clear();
        this.importVaults.clear();
      }
      throw error;
    }
  }

  public async remapImport(input: ImportRemapInput) {
    const epoch = this.requireUnlocked();
    const vaultId = this.importVaults.get(input.token);
    if (vaultId === undefined)
      throw new VaultaError('NOT_FOUND', 'Die Importvorschau ist abgelaufen.');
    const entries = (await this.vaults.readVault(vaultId)).entries;
    this.assertAuthenticated(epoch);
    const preview = this.importer.remap(input.token, input.mapping, entries);
    this.assertAuthenticated(epoch);
    return preview;
  }

  public async executeImport(
    input: ImportExecuteInput,
  ): Promise<{ imported: number; skipped: number; entryIds: string[] }> {
    this.requireUnlocked();
    if (this.importVaults.get(input.token) !== input.vaultId)
      throw new VaultaError(
        'INVALID_INPUT',
        'Importvorschau und Ziel-Tresor passen nicht zusammen.',
      );
    const prepared = this.importer.materialize(input.token, input.selectedRows);
    const importedEntryIds: string[] = [];
    const imported = await this.vaults.mutateVault(input.vaultId, (document) => {
      const now = new Date().toISOString();
      const foldersByName = new Map(
        document.folders.map((folder) => [folder.name.toLocaleLowerCase('de'), folder.id]),
      );
      for (const candidate of prepared) {
        const folderName = candidate.folderName.trim().slice(0, 200);
        let folderId: string | null = null;
        if (folderName.length > 0) {
          const normalized = folderName.toLocaleLowerCase('de');
          folderId = foldersByName.get(normalized) ?? null;
          if (folderId === null) {
            folderId = randomUUID();
            document.folders.push({
              id: folderId,
              name: folderName,
              color: '#64748b',
              createdAt: now,
            });
            foldersByName.set(normalized, folderId);
          }
        }
        const { id: requestedId, ...source } = candidate.entry;
        const entryId = requestedId ?? randomUUID();
        if (document.entries.some((entry) => entry.id === entryId)) {
          throw new VaultaError('CONFLICT', 'Ein zu importierender Eintrag existiert bereits.');
        }
        document.entries.push({
          ...structuredClone(source),
          id: entryId,
          vaultId: input.vaultId,
          folderId,
          attachments: [],
          createdAt: now,
          updatedAt: now,
          secretChangedAt: now,
          lastUsedAt: null,
          deletedAt: null,
        });
        importedEntryIds.push(entryId);
      }
      return prepared.length;
    });
    this.importer.discard(input.token);
    this.importVaults.delete(input.token);
    await this.audit.record({ type: 'import-completed', vaultId: input.vaultId });
    return {
      imported,
      skipped: Math.max(0, input.selectedRows.length - imported),
      entryIds: importedEntryIds,
    };
  }

  public async exportData(input: ExportInput): Promise<string | null> {
    const epoch = this.requireUnlocked();
    if (input.format === 'vaulta-backup') return (await this.createBackup())?.path ?? null;
    if (!input.warningAccepted || input.confirmation !== 'EXPORTIEREN')
      throw new VaultaError(
        'INVALID_INPUT',
        'Der Klartext-Export wurde nicht vollständig bestätigt.',
      );
    if (
      input.masterPassword === undefined ||
      !(await this.profile.verifyMasterPassword(input.masterPassword))
    ) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    }
    this.assertAuthenticated(epoch);
    const documents = await Promise.all(input.vaultIds.map((id) => this.vaults.readVault(id)));
    this.assertAuthenticated(epoch);
    const prepared = this.exporter.prepare(input.format, documents, {
      includeAttachmentMetadata: input.includeAttachments,
    });
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Unverschlüsselte Daten exportieren',
      defaultPath: `Vaulta-Klartext-Export.${prepared.extension}`,
      filters: [{ name: prepared.extension.toUpperCase(), extensions: [prepared.extension] }],
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return null;
    const attachmentFolder = input.includeAttachments
      ? this.cleartextAttachmentFolder(result.filePath)
      : null;
    let exportWritten = false;
    try {
      await writeExclusiveCleartextFile(
        result.filePath,
        async (handle) => {
          await handle.writeFile(prepared.content, { encoding: 'utf8' });
          this.assertAuthenticated(epoch);
        },
        { replaceExisting: true },
      );
      exportWritten = true;
      this.assertAuthenticated(epoch);
      if (attachmentFolder !== null) {
        await this.exportCleartextAttachments(documents, attachmentFolder, () =>
          this.assertAuthenticated(epoch),
        );
        this.assertAuthenticated(epoch);
      }
      await this.audit.record({ type: 'export-completed' });
      this.assertAuthenticated(epoch);
      return result.filePath;
    } catch (error) {
      if (exportWritten) await rm(result.filePath, { force: true }).catch(() => undefined);
      if (attachmentFolder !== null)
        await rm(attachmentFolder, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }
  }

  public async listAudit(input?: { offset?: number; limit?: number }): Promise<AuditEvent[]> {
    const epoch = this.requireUnlocked();
    const events = await this.audit.list(input);
    this.assertAuthenticated(epoch);
    return events;
  }

  public getSettings(): VaultaSettings {
    this.requireUnlocked();
    return structuredClone(this.settings);
  }

  public updateSettings(input: SettingsUpdateInput): Promise<VaultaSettings> {
    return this.settingsOperations.run(() => this.commitSettings(input));
  }

  private async commitSettings(input: SettingsUpdateInput): Promise<VaultaSettings> {
    const epoch = this.requireUnlocked();
    const authorizedBackupFolder = this.authorizedBackupFolder;
    const parsed = vaultaSettingsSchema.parse(input.settings);
    const currentBackupFolder =
      this.settings.backupFolder === null
        ? null
        : normalizeLocalBackupFolder(this.settings.backupFolder);
    const requestedBackupFolder =
      parsed.backupFolder === null ? null : normalizeLocalBackupFolder(parsed.backupFolder);
    const folderUnchanged =
      currentBackupFolder === requestedBackupFolder ||
      (currentBackupFolder !== null &&
        requestedBackupFolder !== null &&
        sameWindowsPath(currentBackupFolder, requestedBackupFolder));
    const folderAuthorized =
      requestedBackupFolder !== null &&
      authorizedBackupFolder !== null &&
      sameWindowsPath(authorizedBackupFolder, requestedBackupFolder);
    if (!folderUnchanged && requestedBackupFolder !== null && !folderAuthorized) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Der Backup-Ordner muss unmittelbar zuvor im nativen Ordnerdialog ausgewählt werden.',
      );
    }
    parsed.backupFolder = requestedBackupFolder;
    if (
      isSecurityWeakeningSettingsChange(this.settings, parsed) &&
      (input.masterPassword === undefined ||
        !(await this.profile.verifyMasterPassword(input.masterPassword)))
    ) {
      throw new VaultaError(
        'AUTH_FAILED',
        'Zum Abschwächen von Sicherheitseinstellungen ist das gültige Master-Passwort erforderlich.',
      );
    }
    this.assertAuthenticated(epoch);
    await this.profile.setProtectedMetadata(SETTINGS_NAMESPACE, protectedValue(parsed));
    this.authorizedBackupFolder = null;
    this.assertAuthenticated(epoch);
    this.settings = structuredClone(parsed);
    this.audit = this.createAuditService(this.settings);
    this.autoLock.updateTimeout(this.settings.autoLockSeconds);
    this.requireWindow().setContentProtection(this.settings.contentProtection);
    this.configureAutomaticBackups();
    await this.audit.record({ type: 'settings-updated' });
    this.assertAuthenticated(epoch);
    await this.emitState();
    return this.getSettings();
  }

  public async getFactorStatus(): Promise<FactorStatus> {
    if (!(await this.profile.hasProfile())) return structuredClone(EMPTY_FACTORS);
    const authenticated = this.authentication.isAuthenticated(this.profile.isUnlocked());
    const epoch = authenticated
      ? this.authentication.requireAuthenticated(this.profile.isUnlocked())
      : null;
    const status = await this.factors.getStatus(authenticated);
    if (epoch !== null) this.assertAuthenticated(epoch);
    return status;
  }

  public async beginTotp(input: TotpBeginInput) {
    const epoch = this.requireUnlocked();
    try {
      const result = await this.factors.beginTotpSetup(input.masterPassword);
      this.assertAuthenticated(epoch);
      return result;
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked()))
        this.factors.clearPending();
      throw error;
    }
  }

  public async completeTotp(input: TotpCompleteInput): Promise<void> {
    const epoch = this.requireUnlocked();
    await this.factorOperations.run(() =>
      this.factors.completeTotpSetup(input.setupId, input.code),
    );
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'factor-added' });
    this.assertAuthenticated(epoch);
    await this.emitState();
  }

  public async removeTotp(input: { masterPassword: string }): Promise<void> {
    const epoch = this.requireUnlocked();
    await this.factorOperations.run(() => this.factors.removeTotp(input.masterPassword));
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'factor-removed' });
    this.assertAuthenticated(epoch);
    await this.emitState();
  }

  public async beginSecurityKey(input: SecurityKeyBeginInput) {
    const epoch = this.requireUnlocked();
    try {
      const result = await this.factors.beginSecurityKeyRegistration(input);
      this.assertAuthenticated(epoch);
      return result;
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked()))
        this.factors.clearPending();
      throw error;
    }
  }

  public async completeSecurityKeyRegistration(input: SecurityKeyCompleteInput) {
    const epoch = this.requireUnlocked();
    const result = await this.factorOperations.run(() =>
      this.factors.completeSecurityKeyRegistration(input),
    );
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'factor-added' });
    this.assertAuthenticated(epoch);
    await this.emitState();
    return result;
  }

  public async removeSecurityKey(input: { id: string; masterPassword: string }): Promise<void> {
    const epoch = this.requireUnlocked();
    await this.factorOperations.run(() =>
      this.factors.removeSecurityKey(input.id, input.masterPassword),
    );
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'factor-removed' });
    this.assertAuthenticated(epoch);
    await this.emitState();
  }

  public async rotateRecovery(input: { masterPassword: string }) {
    const epoch = this.requireUnlocked();
    try {
      const result = await this.profile.beginRecoveryRotation(input.masterPassword);
      this.assertAuthenticated(epoch);
      return result;
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) this.profile.lock();
      throw error;
    }
  }

  public async completeRecoveryRotation(input: {
    pendingId: string;
    confirmation: Record<string, string>;
  }): Promise<void> {
    const epoch = this.requireUnlocked();
    await this.profile.completeRecoveryRotation(input.pendingId, input.confirmation);
    this.assertAuthenticated(epoch);
    await this.audit.record({ type: 'recovery-rotated' });
    this.assertAuthenticated(epoch);
    await this.emitState();
  }

  public listTemplates(): EntryTemplate[] {
    this.requireUnlocked();
    return this.templates.list();
  }

  public async saveTemplate(
    input: Parameters<VaultaApi['templates']['save']>[0],
  ): Promise<EntryTemplate> {
    this.requireUnlocked();
    const template = this.templates.save(input);
    await this.persistTemplates();
    return template;
  }

  public async deleteTemplate(id: string): Promise<void> {
    this.requireUnlocked();
    this.templates.delete(id);
    await this.persistTemplates();
  }

  public async generateReport(): Promise<LocalReport> {
    const epoch = this.requireUnlocked();
    const vaults = await this.readAllVaults();
    this.assertAuthenticated(epoch);
    const report = await this.reports.generateAsync(vaults);
    this.assertAuthenticated(epoch);
    return report;
  }

  public onWindowMinimized(): void {
    const state = this.authentication.getState();
    if (state === 'locked') return;
    if (this.pendingSetupSession !== null) {
      void this.lock();
      return;
    }
    if (this.settings.lockOnMinimize || (state === 'authenticating' && this.isImmediateLock())) {
      void this.lock();
      return;
    }
    if (state === 'authenticated') this.autoLock.lockWhenLeavingIfImmediate();
  }

  public onWindowBlur(): void {
    const state = this.authentication.getState();
    if (state === 'locked' || !this.isImmediateLock()) return;
    if (state === 'authenticating') void this.lock();
    else this.autoLock.lockWhenLeavingIfImmediate();
  }

  public onSystemLock(): void {
    if (
      this.authentication.getState() !== 'locked' &&
      (this.pendingSetupSession !== null || this.settings.lockOnSystemLock)
    )
      void this.lock();
  }

  public onSystemSuspend(): void {
    if (
      this.authentication.getState() !== 'locked' &&
      (this.pendingSetupSession !== null || this.settings.lockOnSuspend)
    )
      void this.lock();
  }

  private armPendingSetupTimeout(pendingId: string, epoch: number): void {
    if (this.pendingSetupTimer !== null) clearTimeout(this.pendingSetupTimer);
    this.pendingSetupTimer = setTimeout(() => {
      this.pendingSetupTimer = null;
      const pendingSetup = this.pendingSetupSession;
      if (
        pendingSetup === null ||
        pendingSetup.pendingId !== pendingId ||
        pendingSetup.epoch !== epoch ||
        !this.authentication.isAuthenticating(epoch)
      ) {
        return;
      }
      void this.lock().catch(() => undefined);
    }, PENDING_SETUP_TIMEOUT_MS);
    this.pendingSetupTimer.unref();
  }

  private clearPendingSetupSession(): void {
    if (this.pendingSetupTimer !== null) clearTimeout(this.pendingSetupTimer);
    this.pendingSetupTimer = null;
    this.pendingSetupSession = null;
  }

  private requireUnlocked(): number {
    return this.authentication.requireAuthenticated(this.profile.isUnlocked());
  }

  private assertAuthenticated(epoch: number): void {
    this.authentication.assertAuthenticated(epoch, this.profile.isUnlocked());
  }

  private isImmediateLock(): boolean {
    return this.settings.autoLockSeconds === 0;
  }

  private requireWindow(): BrowserWindow {
    const window = this.getWindow();
    if (window === null || window.isDestroyed())
      throw new VaultaError('INTERNAL', 'Das Vaulta-Hauptfenster ist nicht verfügbar.');
    return window;
  }

  private createAuditService(settings: VaultaSettings): AuditService {
    return new AuditService({
      rootDir: this.rootDir,
      profileService: this.profile,
      maxEvents: settings.auditMaxEvents,
      retentionDays: settings.auditRetentionDays,
    });
  }

  private async loadUnlockedData(epoch: number): Promise<void> {
    if (!this.profile.isUnlocked()) throw new VaultaError('LOCKED', 'Vaulta ist gesperrt.');
    await this.migrations.migrate(() => this.authentication.assertEpoch(epoch));
    this.authentication.assertEpoch(epoch);
    const rawSettings =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(SETTINGS_NAMESPACE);
    this.authentication.assertEpoch(epoch);
    const parsed =
      rawSettings === null
        ? vaultaSettingsSchema.parse(cloneSettings())
        : vaultaSettingsSchema.safeParse(rawSettings);
    if ('success' in parsed && !parsed.success)
      throw new VaultaError('CORRUPT_DATA', 'Die gespeicherten Einstellungen sind beschädigt.');
    this.settings = structuredClone('success' in parsed ? parsed.data : parsed);
    const rawTemplates =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(TEMPLATES_NAMESPACE);
    this.authentication.assertEpoch(epoch);
    this.templates = new TemplateService(parseTemplates(rawTemplates));
    const summaries = await this.vaults.listVaults();
    this.authentication.assertEpoch(epoch);
    if (summaries.length === 0) {
      const created = await this.vaults.createVault('Privat', '#14b8a6');
      this.authentication.assertEpoch(epoch);
      summaries.push(this.summaryForVault(created));
    }
    const storedActive =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(ACTIVE_VAULT_NAMESPACE);
    this.authentication.assertEpoch(epoch);
    this.activeVaultId =
      typeof storedActive === 'string' && summaries.some((vault) => vault.id === storedActive)
        ? storedActive
        : (summaries[0]?.id ?? null);
    if (this.activeVaultId !== null) {
      await this.profile.setProtectedMetadata(ACTIVE_VAULT_NAMESPACE, this.activeVaultId);
      this.authentication.assertEpoch(epoch);
    }
    this.audit = this.createAuditService(this.settings);
    await this.backups.finalizeInterruptedRestore(() =>
      this.validateProtectedLiveState(() => this.authentication.assertEpoch(epoch)),
    );
    this.authentication.assertEpoch(epoch);
    this.requireWindow().setContentProtection(this.settings.contentProtection);
  }

  private async finishUnlock(epoch: number): Promise<void> {
    await this.loadUnlockedData(epoch);
    for (let index = 0; index < this.pendingLockAuditEvents; index += 1) {
      await this.audit.record({ type: 'locked' });
      this.authentication.assertEpoch(epoch);
    }
    this.pendingLockAuditEvents = 0;
    for (let index = 0; index < this.pendingFailedAuditEvents; index += 1) {
      await this.audit.record({ type: 'unlock-failed' });
      this.authentication.assertEpoch(epoch);
    }
    this.pendingFailedAuditEvents = 0;
    if (this.pendingRestoredAuditEvent) {
      await this.audit.record({ type: 'backup-restored' });
      this.authentication.assertEpoch(epoch);
      this.pendingRestoredAuditEvent = false;
    }
    await this.audit.record({ type: 'unlocked' });
    this.authentication.assertEpoch(epoch);
    this.authentication.complete(this.profile.isUnlocked(), epoch);
    this.startAuthenticatedServices();
    this.resetUnlockFailures();
    await this.emitState();
  }

  private startAuthenticatedServices(): void {
    if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) return;
    this.autoLock.start(this.settings.autoLockSeconds);
    this.configureAutomaticBackups();
  }

  private assertNotRateLimited(): void {
    const remaining = this.blockedUntil - Date.now();
    if (remaining > 0) {
      throw new VaultaError(
        'AUTH_RATE_LIMITED',
        `Zu viele fehlgeschlagene Versuche. Warte noch ${Math.ceil(remaining / 1_000)} Sekunden.`,
      );
    }
  }

  private registerUnlockFailure(error: unknown): void {
    if (
      !(error instanceof VaultaError) ||
      !['AUTH_FAILED', 'AUTH_FACTOR_REQUIRED'].includes(error.code)
    )
      return;
    this.failedUnlocks += 1;
    this.pendingFailedAuditEvents += 1;
    if (this.failedUnlocks >= 5) {
      this.blockedUntil = Date.now() + Math.min(60, 2 ** (this.failedUnlocks - 5)) * 1_000;
    }
  }

  private resetUnlockFailures(): void {
    this.failedUnlocks = 0;
    this.blockedUntil = 0;
  }

  private async markEntryUsed(vaultId: string, entryId: string): Promise<void> {
    await this.vaults.mutateVault(vaultId, (document) => {
      const entry = requireEntry(document, entryId);
      entry.lastUsedAt = new Date().toISOString();
      return undefined;
    });
  }

  private summaryForEntry(entry: VaultEntry): EntrySummary {
    const summary = this.entryViews.list([entry], defaultListQuery(entry.vaultId))[0];
    if (summary === undefined)
      throw new VaultaError('INTERNAL', 'Die Eintragsübersicht konnte nicht erstellt werden.');
    return summary;
  }

  private summaryForVault(document: VaultDocument): VaultSummary {
    return {
      id: document.id,
      name: document.name,
      color: document.color,
      entryCount: document.entries.filter((entry) => entry.deletedAt === null).length,
      deletedCount: document.entries.filter((entry) => entry.deletedAt !== null).length,
      updatedAt: document.updatedAt,
    };
  }

  private async readAllVaults(): Promise<VaultDocument[]> {
    const summaries = await this.vaults.listVaults();
    return Promise.all(summaries.map((summary) => this.vaults.readVault(summary.id)));
  }

  private async validateBackupLiveState(epoch: number): Promise<void> {
    await this.validateProtectedLiveState(() => this.assertAuthenticated(epoch));
  }

  private async validateProtectedLiveState(assertAuthorized: () => void): Promise<void> {
    assertAuthorized();
    const documents = await this.vaults.validateStorageConsistency(assertAuthorized);
    assertAuthorized();
    await this.attachments.validateStorageConsistency(
      documents.flatMap((document) =>
        document.entries.flatMap((entry) =>
          entry.attachments.map((attachment) => ({
            vaultId: document.id,
            attachmentId: attachment.id,
          })),
        ),
      ),
      assertAuthorized,
    );
    assertAuthorized();
    await this.audit.inspectStoredDocumentFormatVersion();
    assertAuthorized();
  }

  private async persistTemplates(): Promise<void> {
    await this.profile.setProtectedMetadata(
      TEMPLATES_NAMESPACE,
      protectedValue(this.templates.snapshot()),
    );
  }

  private async exportCleartextAttachments(
    documents: readonly VaultDocument[],
    folder: string,
    assertAuthorized: () => void,
  ): Promise<void> {
    for (const document of documents) {
      for (const entry of document.entries.filter((candidate) => candidate.deletedAt === null)) {
        for (const attachment of entry.attachments) {
          assertAuthorized();
          const target = path.join(
            folder,
            safeFileName(document.name, document.id),
            safeFileName(entry.title, entry.id),
            `${attachment.id.slice(0, 8)}-${safeFileName(attachment.name, 'Anhang')}`,
          );
          await this.attachments.decryptToFile(
            document.id,
            attachment.id,
            target,
            assertAuthorized,
          );
          assertAuthorized();
        }
      }
    }
  }

  private cleartextAttachmentFolder(exportPath: string): string {
    return `${exportPath.slice(0, -path.extname(exportPath).length)}-Anhaenge-${randomUUID().slice(0, 8)}`;
  }

  private configureAutomaticBackups(): void {
    if (this.backupTimer !== null) clearInterval(this.backupTimer);
    this.backupTimer = null;
    if (
      !this.authentication.isAuthenticated(this.profile.isUnlocked()) ||
      !this.settings.automaticBackups ||
      this.settings.backupFolder === null
    )
      return;
    this.backupTimer = setInterval(() => {
      void this.createAutomaticBackup().catch(() => this.reportAutomaticBackupFailure());
    }, AUTOMATIC_BACKUP_CHECK_MS);
    void this.createAutomaticBackup().catch(() => this.reportAutomaticBackupFailure());
  }

  private async createAutomaticBackup(): Promise<BackupInfo | null> {
    if (
      this.automaticBackupRunning ||
      !this.authentication.isAuthenticated(this.profile.isUnlocked()) ||
      !this.settings.automaticBackups ||
      this.settings.backupFolder === null
    ) {
      return null;
    }
    const epoch = this.requireUnlocked();
    const last =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(LAST_BACKUP_NAMESPACE);
    this.assertAuthenticated(epoch);
    if (typeof last === 'string' && Date.now() - Date.parse(last) < AUTOMATIC_BACKUP_INTERVAL_MS)
      return null;
    this.automaticBackupRunning = true;
    try {
      const backup = await this.backups.createBackup({
        destination: this.settings.backupFolder,
        automatic: true,
        rotation: this.settings.backupRotation,
        assertAuthorized: () => this.assertAuthenticated(epoch),
        validateLiveState: () => this.validateBackupLiveState(epoch),
      });
      this.assertAuthenticated(epoch);
      await this.profile.setProtectedMetadata(LAST_BACKUP_NAMESPACE, backup.createdAt);
      await this.audit.record({ type: 'backup-created' });
      this.automaticBackupWarningSent = false;
      return backup;
    } finally {
      this.automaticBackupRunning = false;
    }
  }

  private reportAutomaticBackupFailure(): void {
    if (this.automaticBackupWarningSent) return;
    this.automaticBackupWarningSent = true;
    this.onBackgroundWarning(
      'Die automatische Sicherung ist fehlgeschlagen. Prüfe Zielordner und freien Speicherplatz.',
    );
  }

  private async emitState(): Promise<AppState> {
    const state = await this.getState();
    this.onStateChanged(state);
    return state;
  }
}
