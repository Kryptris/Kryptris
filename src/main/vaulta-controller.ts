import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, rm, rmdir, stat } from 'node:fs/promises';
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
import { IPC_CHANNELS, type VaultaApi } from '../shared/ipc';
import {
  createDefaultEntryLifecycleMetadata,
  DEFAULT_SETTINGS,
  type AppState,
  type AttachmentMetadata,
  type AttachmentPreview,
  type AuditEvent,
  type AuditEventType,
  type BackupHealthSnapshot,
  type BackupInfo,
  type BatchEntryInput,
  type BatchEntryResult,
  type BreachListStatusDto,
  type BreachScanReportDto,
  type DataQualityFixPreviewDto,
  type DataQualityFixResultDto,
  type DataQualityReportDto,
  type DuplicateCandidateSideDto,
  type DuplicateMergeDescriptionDto,
  type DuplicateScanDto,
  type EntryDetail,
  type EntryListQuery,
  type EntrySummary,
  type EntryTemplate,
  type FactorStatus,
  type Folder,
  type IntegrityReportDto,
  type LocalReport,
  type LocalJobKind,
  type RecoveryReadinessStatusDto,
  type SecurityCenterReportDto,
  type SecurityReport,
  type SavedView,
  type SavedViewRecord,
  type TagSummary,
  type TotpConfiguration,
  type VaultaSettings,
  type VaultDocument,
  type VaultEntry,
  type VaultPackageExportResult,
  type VaultPackageImportResult,
  type VaultPackagePreviewDto,
  type VaultSummary,
} from '../shared/models';
import {
  entryTemplateSchema,
  savedViewRecordSchema,
  vaultaSettingsSchema,
} from '../shared/schemas';
import { isSecurityWeakeningSettingsChange } from '../shared/settings-security';
import { normalizeTags } from '../shared/tags';
import { ATTACHMENT_FORMAT_VERSION, AttachmentService } from './services/attachment-service';
import { AuthenticationSession } from './services/authentication-session';
import { AUDIT_DOCUMENT_FORMAT_VERSION, AuditService } from './services/audit-service';
import { AutoLockService } from './services/auto-lock-service';
import { BackupHealthService } from './services/backup-health-service';
import { BackupService } from './services/backup-service';
import {
  BREACH_LIST_INDEX_RELATIVE_PATH,
  BREACH_LIST_NAMESPACE,
  BreachListManifestService,
  type BreachListManifest,
} from './services/breach-list-manifest-service';
import { ClipboardService } from './services/clipboard-service';
import { DataQualityFixService } from './services/data-quality-fix-service';
import {
  DataQualityError,
  DataQualityService,
  type AttachmentTechnicalCheck,
  type DataQualityFinding,
  type DataQualityFixPlan,
} from './services/data-quality-service';
import { DuplicateMergeCoordinator } from './services/duplicate-merge-coordinator';
import type { DuplicateMergeRequest } from './services/duplicate-merge-coordinator';
import {
  DUPLICATE_MERGE_COLLECTION_FIELDS,
  DUPLICATE_MERGE_SCALAR_FIELDS,
  DuplicateService,
  type DuplicateMergeCollectionField,
  type DuplicateMergeDescription,
  type DuplicateMergeScalarField,
  type DuplicateScanResult,
} from './services/duplicate-service';
import { EntryTransactionService } from './services/entry-transaction-service';
import { EntryLifecycleService } from './services/entry-lifecycle-service';
import { EntryViewService } from './services/entry-view-service';
import { ExportService } from './services/export-service';
import { FactorService } from './services/factor-service';
import { ImportMappingProfileService } from './services/import-mapping-profile-service';
import { ImportService } from './services/import-service';
import { IntegrityCheckService } from './services/integrity-check-service';
import { LocalJobCoordinator, type LocalJobProgress } from './services/local-job-coordinator';
import { OfflineBreachService } from './services/offline-breach-service';
import { PasswordGeneratorService } from './services/password-generator-service';
import {
  createVaultDocumentEmbeddedMigrationAdapter,
  PersistentMigrationService,
} from './services/persistent-migration-service';
import { ProfileService, type ProtectedMetadataValue } from './services/profile-service';
import { ProductivityService } from './services/productivity-service';
import { ReportService } from './services/report-service';
import {
  RECOVERY_READINESS_NAMESPACE,
  RecoveryReadinessService,
} from './services/recovery-readiness-service';
import { RevisionTokenService } from './services/revision-token-service';
import {
  INTEGRITY_STATUS_NAMESPACE,
  SecurityCenterService,
  type SecurityCenterIntegrityStatus,
} from './services/security-center-service';
import { SecurityCheckService } from './services/security-check-service';
import { SafeImportSourceReader } from './services/safe-import-source-reader';
import { TemplateService } from './services/template-service';
import { TotpService } from './services/totp-service';
import {
  TrashRetentionService,
  type TrashRetentionSweepContext,
} from './services/trash-retention-service';
import { VaultService } from './services/vault-service';
import {
  VaultPackageService,
  type PreparedVaultPackageImport,
} from './services/vault-package-service';
import {
  MultiFileTransactionService,
  type MultiFileChange,
} from './storage/multi-file-transaction';
import { SerialExecutor } from './storage/serial-executor';
import { writeExclusiveCleartextFile } from './storage/cleartext-file';
import { PRODUCT_ARGON2_MEMORY_KIB } from './security/key-derivation';

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
type EntryTrashInput = Parameters<VaultaApi['entries']['moveToTrash']>[0];
type EntryPurgeInput = Parameters<VaultaApi['entries']['purge']>[0];
type EntryRevealInput = Parameters<VaultaApi['entries']['reveal']>[0];
type EntryCopyInput = Parameters<VaultaApi['entries']['copy']>[0];
type PrivateKeyExportInput = Parameters<VaultaApi['entries']['exportPrivateKey']>[0];
type AttachmentReference = Parameters<VaultaApi['attachments']['preview']>[0];
type BackupHealthInput = Parameters<VaultaApi['backup']['getHealth']>[0];
type BackupDryRunInput = Parameters<VaultaApi['backup']['dryRun']>[0];
type BackupRestoreInput = Parameters<VaultaApi['backup']['restore']>[0];
type ImportPreviewInput = Parameters<VaultaApi['transfer']['previewImport']>[0];
type DroppedImportPreviewInput = Omit<ImportPreviewInput, 'sourcePath'> & { sourcePath: string };
type ImportRemapInput = Parameters<VaultaApi['transfer']['remapImport']>[0];
type ImportExecuteInput = Parameters<VaultaApi['transfer']['executeImport']>[0];
type ImportMappingProfileSaveInput = Parameters<VaultaApi['transfer']['saveMappingProfile']>[0];
type ImportMappingProfileRemoveInput = Parameters<VaultaApi['transfer']['removeMappingProfile']>[0];
type VaultPackageExportInput = Parameters<VaultaApi['transfer']['exportVaultPackage']>[0];
type VaultPackagePreviewInput = Parameters<VaultaApi['transfer']['previewVaultPackage']>[0];
type VaultPackageImportInput = Parameters<VaultaApi['transfer']['importVaultPackage']>[0];
type ExportInput = Parameters<VaultaApi['transfer']['export']>[0];
type TotpBeginInput = Parameters<VaultaApi['factors']['beginTotp']>[0];
type TotpCompleteInput = Parameters<VaultaApi['factors']['completeTotp']>[0];
type SecurityKeyBeginInput = Parameters<VaultaApi['factors']['beginSecurityKey']>[0];
type SecurityKeyCompleteInput = Parameters<VaultaApi['factors']['completeSecurityKey']>[0];
type SettingsUpdateInput = Parameters<VaultaApi['settings']['update']>[0];
type SavedViewSaveInput = Parameters<VaultaApi['productivity']['saveSavedView']>[0];
type DuplicateScanInput = Parameters<VaultaApi['quality']['scanDuplicates']>[0];
type DuplicateDescribeInput = Parameters<VaultaApi['quality']['describeDuplicateMerge']>[0];
type DuplicateMergeInput = Parameters<VaultaApi['quality']['mergeDuplicates']>[0];
type DataQualityScanInput = Parameters<VaultaApi['quality']['scanDataQuality']>[0];
type DataQualityPreviewInput = Parameters<VaultaApi['quality']['previewDataQualityFix']>[0];
type DataQualityApplyInput = Parameters<VaultaApi['quality']['applyDataQualityFix']>[0];
type SecurityCenterScanInput = Parameters<VaultaApi['security']['scanCenter']>[0];
type IntegrityScanInput = Parameters<VaultaApi['security']['scanIntegrity']>[0];
type BreachImportInput = Parameters<VaultaApi['security']['importBreachList']>[0];
type BreachScanInput = Parameters<VaultaApi['security']['scanBreachList']>[0];

interface PendingDataQualityFix {
  readonly vaultId: string;
  readonly finding: DataQualityFinding;
  readonly plan: DataQualityFixPlan;
  readonly epoch: number;
  readonly expiresAt: number;
}

interface PendingIntegrityReport {
  readonly report: IntegrityReportDto;
  readonly epoch: number;
  readonly expiresAt: number;
}

interface PackageFileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
}

interface DirectoryIdentity {
  readonly dev: number;
  readonly ino: number;
}

/**
 * Capability for one controller-created package-import workspace. Every
 * operation re-checks the stored directory identities before it reads, writes
 * or removes a staged attachment. The paths never cross an IPC boundary.
 */
interface VaultPackageImportStagingDirectory {
  readonly securityDirectory: string;
  readonly securityIdentity: DirectoryIdentity;
  readonly stagingRoot: string;
  readonly stagingRootIdentity: DirectoryIdentity;
  readonly directory: string;
  readonly directoryIdentity: DirectoryIdentity;
}

interface VaultPackageStagedAttachment {
  readonly relativePath: string;
  readonly sourcePath: string;
  readonly identity: PackageFileIdentity;
}

interface PendingVaultPackageImport {
  readonly packagePath: string;
  readonly identity: PackageFileIdentity;
  readonly epoch: number;
  readonly expiresAt: number;
}

interface IntegrityRevisionSnapshot {
  readonly revision: string;
  /**
   * Excludes profile.json and audit.vaulta because the successful result commit
   * necessarily replaces both generations.
   */
  readonly dataRevision: string;
  /** Vault writers held while the final revision check and status commit happen. */
  readonly vaultIds: readonly string[];
}

interface IntegrityJobResult {
  readonly report: IntegrityReportDto;
  /** Null means the redacted report is usable, but persistence could not establish a safe cache key. */
  readonly cacheRevision: string | null;
}

interface SecurityCenterSnapshot {
  readonly headerUpdatedAt: string;
  readonly factorStatus: FactorStatus;
  readonly automaticBackups: boolean;
  readonly recovery: RecoveryReadinessStatusDto;
  readonly lastAutomaticBackupAt: string | null;
  readonly integrity: SecurityCenterIntegrityStatus | null;
  readonly breachList: BreachListStatusDto;
  readonly breachReport: BreachScanReportDto | null;
  readonly kdfCurrent: boolean;
}

const SETTINGS_NAMESPACE = 'settings';
const ACTIVE_VAULT_NAMESPACE = 'active-vault';
const TEMPLATES_NAMESPACE = 'templates';
const SAVED_VIEWS_NAMESPACE = 'saved-views';
const IMPORT_MAPPING_PROFILES_NAMESPACE = 'import-mapping-profiles-v1';
const LAST_BACKUP_NAMESPACE = 'last-automatic-backup';
const AUTOMATIC_BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const AUTOMATIC_BACKUP_CHECK_MS = 60 * 60 * 1_000;
const PENDING_SETUP_TIMEOUT_MS = 5 * 60 * 1_000;
const MAX_QR_IMAGE_BYTES = 20 * 1024 * 1024;
const DATA_QUALITY_FIX_TTL_MS = 5 * 60 * 1_000;
const INTEGRITY_REPORT_TTL_MS = 30 * 60 * 1_000;
const BREACH_IMPORT_STAGING_FILE = /^\.breach-import-[0-9a-f-]{36}\.tmp$/iu;
const VAULT_PACKAGE_IMPORT_PREVIEW_TTL_MS = 5 * 60 * 1_000;
const VAULT_PACKAGE_IMPORT_STAGING_DIRECTORY = '.vault-package-import-staging';
const VAULT_PACKAGE_IMPORT_STAGING_ENTRY =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function sameCanonicalPath(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === 'win32'
    ? normalizedLeft.toLocaleLowerCase('en') === normalizedRight.toLocaleLowerCase('en')
    : normalizedLeft === normalizedRight;
}

function sameDirectoryIdentity(left: DirectoryIdentity, right: DirectoryIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function samePackageFileIdentity(left: PackageFileIdentity, right: PackageFileIdentity): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

const DUPLICATE_FIELD_LABELS: Readonly<Record<string, string>> = {
  title: 'Titel',
  folderId: 'Ordner',
  favorite: 'Favorit',
  tags: 'Tags',
  note: 'Notiz',
  customFields: 'Eigene Felder',
  attachments: 'Anhänge',
  'credential.username': 'Benutzername',
  'credential.password': 'Passwort',
  'credential.totp': 'Zwei-Faktor-Konfiguration',
  'credential.websites': 'Websites',
  'credential.appNames': 'Anwendungsnamen',
  'credit-card.cardName': 'Kartenname',
  'credit-card.cardholder': 'Karteninhaber',
  'credit-card.number': 'Kartennummer',
  'credit-card.expiryMonth': 'Ablaufmonat',
  'credit-card.expiryYear': 'Ablaufjahr',
  'credit-card.cvc': 'Prüfnummer',
  'credit-card.pin': 'PIN',
  'credit-card.issuer': 'Herausgeber',
  'credit-card.cardType': 'Kartentyp',
  'credit-card.billingAddress': 'Rechnungsadresse',
  'credit-card.servicePhone': 'Servicetelefon',
  'credit-card.website': 'Website',
  'identity.salutation': 'Anrede',
  'identity.firstName': 'Vorname',
  'identity.middleName': 'Weitere Vornamen',
  'identity.lastName': 'Nachname',
  'identity.birthDate': 'Geburtsdatum',
  'identity.idNumber': 'Ausweisnummer',
  'identity.passportNumber': 'Reisepassnummer',
  'identity.taxNumber': 'Steuernummer',
  'identity.emails': 'E-Mail-Adressen',
  'identity.phones': 'Telefonnummern',
  'identity.addresses': 'Adressen',
  'wifi.ssid': 'Netzwerkname',
  'wifi.password': 'WLAN-Passwort',
  'wifi.security': 'WLAN-Sicherheit',
  'wifi.hidden': 'Verstecktes Netzwerk',
  'wifi.routerAddress': 'Router-Adresse',
  'wifi.routerUsername': 'Router-Benutzername',
  'software-license.product': 'Produkt',
  'software-license.manufacturer': 'Hersteller',
  'software-license.version': 'Version',
  'software-license.licenseKey': 'Lizenzschlüssel',
  'software-license.licensedTo': 'Lizenziert für',
  'software-license.purchaseDate': 'Kaufdatum',
  'software-license.activationDate': 'Aktivierungsdatum',
  'software-license.expiryDate': 'Ablaufdatum',
  'software-license.orderNumber': 'Bestellnummer',
  'software-license.downloadUrl': 'Download-Adresse',
  'software-license.purchasePrice': 'Kaufpreis',
  'ssh-key.host': 'SSH-Host',
  'ssh-key.port': 'SSH-Port',
  'ssh-key.username': 'SSH-Benutzername',
  'ssh-key.keyType': 'Schlüsseltyp',
  'ssh-key.fingerprint': 'Fingerabdruck',
  'ssh-key.publicKey': 'Öffentlicher Schlüssel',
  'ssh-key.privateKey': 'Privater Schlüssel',
  'ssh-key.passphrase': 'Passphrase',
  'file.description': 'Dateibeschreibung',
  'custom.description': 'Beschreibung',
  'secure-note.markdown': 'Notizinhalt',
};

const DATA_QUALITY_FIX_COPY: Readonly<
  Record<DataQualityFinding['fixCode'] & string, { title: string; description: string }>
> = {
  'normalize-url-https-whitespace': {
    title: 'Webadresse normalisieren',
    description: 'Leerzeichen werden entfernt und eine eindeutige HTTPS-Adresse wird gespeichert.',
  },
  'remove-exact-duplicate-url': {
    title: 'Doppelte Website entfernen',
    description: 'Nur die exakt doppelte Website-Zeile wird entfernt.',
  },
  'replace-unambiguous-title': {
    title: 'Eindeutigen Titel übernehmen',
    description: 'Der Platzhalter wird durch einen lokal eindeutig ableitbaren Titel ersetzt.',
  },
  'clear-orphan-folder': {
    title: 'Ungültige Ordnerzuordnung lösen',
    description: 'Der Eintrag bleibt erhalten und wird keinem Ordner mehr zugeordnet.',
  },
  'remove-saved-view-references': {
    title: 'Verwaiste Ansichtsfilter bereinigen',
    description:
      'Nur nicht mehr vorhandene Ordner- und Tag-Verweise werden aus der Ansicht entfernt.',
  },
  'update-authenticated-attachment-metadata': {
    title: 'Anhangsmetadaten berichtigen',
    description: 'Größe und Prüfsumme werden aus dem authentifiziert gelesenen Anhang übernommen.',
  },
};

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
  /**
   * Main-process-only adapter for non-secret Windows behavior such as tray
   * and login-item policy. It deliberately is not part of the IPC API.
   */
  desktopSettingsPolicy?: DesktopSettingsPolicy;
}

/**
 * Applies the effective non-secret desktop policy for a persisted settings
 * snapshot. Calling this adapter again with the prior snapshot compensates a
 * policy change when the protected settings write cannot be committed.
 */
export interface DesktopSettingsPolicy {
  apply(settings: Readonly<VaultaSettings>): Promise<void> | void;
}

function protectedValue(value: unknown): ProtectedMetadataValue {
  return JSON.parse(JSON.stringify(value)) as ProtectedMetadataValue;
}

function rethrowIntegrityPersistenceInterruption(error: unknown): void {
  if (
    error instanceof VaultaError &&
    [
      'LOCKED',
      'CANCELLED',
      'AUTH_FAILED',
      'AUTH_FACTOR_REQUIRED',
      'AUTH_RATE_LIMITED',
      'CONFLICT',
    ].includes(error.code)
  ) {
    throw error;
  }
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

function parseSavedViews(value: ProtectedMetadataValue | null): SavedViewRecord[] {
  if (value === null) return [];
  const parsed = savedViewRecordSchema.array().safeParse(value);
  if (!parsed.success)
    throw new VaultaError('CORRUPT_DATA', 'Die gespeicherten Ansichten sind beschädigt.');
  return parsed.data;
}

function requireEntry(document: VaultDocument, entryId: string): VaultEntry {
  const entry = document.entries.find((candidate) => candidate.id === entryId);
  if (entry === undefined) throw new VaultaError('NOT_FOUND', 'Der Eintrag wurde nicht gefunden.');
  return entry;
}

function requireVaultDocument(
  documents: ReadonlyMap<string, VaultDocument>,
  vaultId: string,
): VaultDocument {
  const document = documents.get(vaultId);
  if (document === undefined)
    throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
  return document;
}

function duplicateFieldLabel(field: string): string {
  return DUPLICATE_FIELD_LABELS[field] ?? 'Eintragsfeld';
}

function isDuplicateScalarField(value: string): value is DuplicateMergeScalarField {
  return (DUPLICATE_MERGE_SCALAR_FIELDS as readonly string[]).includes(value);
}

function isDuplicateCollectionField(value: string): value is DuplicateMergeCollectionField {
  return (DUPLICATE_MERGE_COLLECTION_FIELDS as readonly string[]).includes(value);
}

function duplicateScalarValue(entry: VaultEntry, field: DuplicateMergeScalarField): unknown {
  if (field === 'title') return entry.title;
  if (field === 'folderId') return entry.folderId;
  if (field === 'favorite') return entry.favorite;
  const separator = field.indexOf('.');
  if (separator < 1 || field.slice(0, separator) !== entry.data.type) return null;
  const property = field.slice(separator + 1);
  const value = entry.data.value as unknown;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return (value as Record<string, unknown>)[property];
}

function hasDuplicatePreviewValue(value: unknown): boolean {
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return value !== null && value !== undefined;
}

function duplicateScalarPreview(
  entry: VaultEntry,
  field: DuplicateMergeScalarField,
  secret: boolean,
): string {
  const value = duplicateScalarValue(entry, field);
  if (secret) return hasDuplicatePreviewValue(value) ? 'Gesetzt' : 'Leer';
  if (field === 'folderId') return value === null ? 'Kein Ordner' : 'Zugeordnet';
  if (typeof value === 'boolean') return value ? 'Ja' : 'Nein';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') {
    const normalized = value.normalize('NFKC').trim();
    return normalized.length === 0 ? 'Leer' : normalized.slice(0, 80);
  }
  if (Array.isArray(value)) return `${String(value.length)} Elemente`;
  return hasDuplicatePreviewValue(value) ? 'Ausgefüllt' : 'Leer';
}

function duplicateCollectionCount(entry: VaultEntry, field: DuplicateMergeCollectionField): number {
  if (field === 'tags') return entry.tags.length;
  if (field === 'note') return entry.note.trim().length > 0 ? 1 : 0;
  if (field === 'customFields') return entry.customFields.length;
  if (field === 'attachments') return entry.attachments.length;
  const separator = field.indexOf('.');
  if (separator < 1 || field.slice(0, separator) !== entry.data.type) return 0;
  const property = field.slice(separator + 1);
  const value = entry.data.value as unknown;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return 0;
  const collection = (value as Record<string, unknown>)[property];
  if (Array.isArray(collection)) return collection.length;
  return typeof collection === 'string' && collection.trim().length > 0 ? 1 : 0;
}

function dataQualityFindingKey(vaultId: string, findingId: string): string {
  return `${vaultId}:${findingId}`;
}

function toDataQualityError(error: unknown): never {
  if (!(error instanceof DataQualityError)) throw error;
  const code =
    error.code === 'FINDING_NOT_FOUND'
      ? 'NOT_FOUND'
      : error.code === 'STALE_REFERENCE'
        ? 'CONFLICT'
        : 'INVALID_INPUT';
  throw new VaultaError(code, error.message, null, { cause: error });
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
    smartView: null,
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
  private readonly desktopSettingsPolicy: DesktopSettingsPolicy | null;
  private readonly profile: ProfileService;
  private readonly vaults: VaultService;
  private readonly attachments: AttachmentService;
  private readonly transactions: MultiFileTransactionService;
  private readonly entryTransactions: EntryTransactionService;
  private readonly duplicates = new DuplicateService();
  private readonly duplicateMerges: DuplicateMergeCoordinator;
  private readonly dataQuality = new DataQualityService();
  private readonly dataQualityFixes = new DataQualityFixService();
  private readonly localJobs = new LocalJobCoordinator();
  private readonly revisionTokens = new RevisionTokenService();
  private readonly trashRetention: TrashRetentionService;
  private readonly lifecycle = new EntryLifecycleService();
  private readonly securityCenter = new SecurityCenterService();
  private readonly backups: BackupService;
  private readonly backupHealth: BackupHealthService;
  private readonly migrations: PersistentMigrationService;
  private readonly factors: FactorService;
  private readonly generator = new PasswordGeneratorService();
  private readonly totp = new TotpService();
  private readonly security = new SecurityCheckService();
  private readonly importer = new ImportService();
  private readonly importSourceReader = new SafeImportSourceReader();
  private readonly importMappingProfiles = new ImportMappingProfileService();
  private readonly vaultPackages: VaultPackageService;
  private readonly exporter = new ExportService();
  private readonly reports = new ReportService();
  private readonly recoveryReadiness = new RecoveryReadinessService();
  private readonly offlineBreach = new OfflineBreachService();
  private readonly breachManifests = new BreachListManifestService();
  private readonly entryViews = new EntryViewService();
  private readonly clipboard: ClipboardService;
  private readonly autoLock: AutoLockService;
  private audit: AuditService;
  private templates = new TemplateService();
  private productivity = new ProductivityService();
  private settings: VaultaSettings = cloneSettings();
  private activeVaultId: string | null = null;
  private readonly pendingVaultNames = new Map<string, string>();
  private readonly dataQualityFindings = new Map<string, DataQualityFinding>();
  private readonly pendingDataQualityFixes = new Map<string, PendingDataQualityFix>();
  private readonly pendingIntegrityReports = new Map<string, PendingIntegrityReport>();
  private lastBreachReport: BreachScanReportDto | null = null;
  private lastBreachReportRevision: string | null = null;
  private breachListKnownCorrupt = false;
  private readonly importVaults = new Map<string, string>();
  private readonly pendingVaultPackageImports = new Map<string, PendingVaultPackageImport>();
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
  private readonly productivityOperations = new SerialExecutor();
  private readonly backupOperations = new SerialExecutor();
  private readonly importMappingProfileOperations = new SerialExecutor();
  private readonly vaultPackageOperations = new SerialExecutor();
  private readonly breachOperations = new SerialExecutor();

  public constructor(options: VaultaControllerOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.version = options.version;
    this.getWindow = options.getWindow;
    this.getOrigin = options.getOrigin;
    this.onStateChanged = options.onStateChanged;
    this.onLocked = options.onLocked;
    this.onBackgroundWarning = options.onBackgroundWarning;
    this.desktopSettingsPolicy = options.desktopSettingsPolicy ?? null;
    this.profile = new ProfileService({ rootDir: this.rootDir });
    this.vaults = new VaultService({ rootDir: this.rootDir, profileService: this.profile });
    this.attachments = new AttachmentService({ rootDir: this.rootDir, vaultService: this.vaults });
    this.vaultPackages = new VaultPackageService({
      vaultService: this.vaults,
      attachmentService: this.attachments,
    });
    this.transactions = new MultiFileTransactionService({ rootDir: this.rootDir });
    this.entryTransactions = new EntryTransactionService({
      rootDir: this.rootDir,
      vaultService: this.vaults,
      attachmentService: this.attachments,
      transactions: this.transactions,
      getAuditService: () => this.audit,
    });
    this.backups = new BackupService({ rootDir: this.rootDir, profileService: this.profile });
    this.backupHealth = new BackupHealthService({
      rootDir: this.rootDir,
      profile: this.profile,
      inspector: this.backups,
    });
    this.audit = this.createAuditService(this.settings);
    this.duplicateMerges = new DuplicateMergeCoordinator({
      rootDir: this.rootDir,
      vaultService: this.vaults,
      attachmentService: this.attachments,
      getAuditService: () => this.audit,
      transactions: this.transactions,
      duplicates: this.duplicates,
      lifecycle: this.lifecycle,
    });
    this.migrations = new PersistentMigrationService({
      rootDir: this.rootDir,
      profileService: this.profile,
      backupService: this.backups,
      embeddedInspectors: [
        createVaultDocumentEmbeddedMigrationAdapter(this.vaults),
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
    this.trashRetention = new TrashRetentionService({
      onError: () =>
        this.onBackgroundWarning(
          'Die automatische Papierkorbbereinigung ist fehlgeschlagen. Es wurden keine Teiländerungen übernommen.',
        ),
    });
  }

  public async initialize(): Promise<AppState> {
    await mkdir(this.rootDir, { recursive: true, mode: 0o700 });
    await this.entryTransactions.recoverInterruptedTransaction();
    await this.cleanupBreachImportStaging();
    await this.cleanupVaultPackageImportStaging();
    await this.duplicateMerges.recoverOrphanedStaging();
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
    this.importMappingProfiles.clear();
    this.pendingVaultPackageImports.clear();
    this.localJobs.clear();
    this.recoveryReadiness.resetAfterRecoveryRotation();
    this.lastBreachReport = null;
    this.lastBreachReportRevision = null;
    this.trashRetention.stop();
    this.dataQualityFindings.clear();
    this.pendingDataQualityFixes.clear();
    this.pendingIntegrityReports.clear();
    this.entryViews.clearCaches();
    this.templates = new TemplateService();
    this.productivity = new ProductivityService();
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
    this.importMappingProfiles.clear();
    this.pendingVaultPackageImports.clear();
    this.localJobs.clear();
    this.lastBreachReport = null;
    this.lastBreachReportRevision = null;
    this.trashRetention.stop();
    this.dataQualityFindings.clear();
    this.pendingDataQualityFixes.clear();
    this.pendingIntegrityReports.clear();
    this.entryViews.clearCaches();
    this.templates = new TemplateService();
    this.productivity = new ProductivityService();
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
        await this.profile.setProtectedMetadata(SAVED_VIEWS_NAMESPACE, []);
        this.authentication.assertEpoch(epoch);
        await this.profile.setProtectedMetadata(
          IMPORT_MAPPING_PROFILES_NAMESPACE,
          this.importMappingProfiles.exportSnapshot(),
        );
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
    this.productivity.deleteSavedViewsForVault(input.id);
    await this.persistSavedViews();
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
    const entries = await this.entryViews.listAsync(document.entries, query, {
      assertAuthorized: () => this.assertAuthenticated(epoch),
    });
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

  public async moveEntryToTrash(input: EntryTrashInput): Promise<void> {
    const epoch = this.requireUnlocked();
    await this.mutateVaultWithAudit(
      input.vaultId,
      (document) => {
        const entry = requireEntry(document, input.entryId);
        if (input.updatedAt !== undefined && entry.updatedAt !== input.updatedAt) {
          throw new VaultaError(
            'CONFLICT',
            'Der Eintrag wurde seit der Dublettenprüfung geändert.',
          );
        }
        if (entry.deletedAt !== null) {
          throw new VaultaError('CONFLICT', 'Der Eintrag liegt bereits im Papierkorb.');
        }
        const timestamp = new Date().toISOString();
        entry.deletedAt = timestamp;
        entry.updatedAt = timestamp;
        return [entry.id];
      },
      'entry-moved-to-trash',
      epoch,
      (entryIds) => entryIds,
    );
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
    const epoch = this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(input.masterPassword)))
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    this.assertAuthenticated(epoch);
    await this.entryTransactions.purge(
      input.vaultId,
      (document) =>
        this.productivity.applyBatch(document, {
          vaultId: input.vaultId,
          entryIds: [input.entryId],
          action: {
            type: 'purge',
            masterPassword: input.masterPassword,
            confirmationCount: 1,
          },
        }),
      () => this.assertAuthenticated(epoch),
    );
    this.assertAuthenticated(epoch);
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

  public async scanSecurityCenter(
    input: SecurityCenterScanInput,
  ): Promise<SecurityCenterReportDto> {
    const epoch = this.requireUnlocked();
    const documents = await this.readAllVaults();
    const savedViews = this.productivity.snapshot();
    const snapshot = await this.readSecurityCenterSnapshot(epoch, documents);
    this.assertAuthenticated(epoch);
    const revision = this.securityCenterRevision(documents, savedViews, snapshot);
    const jobKey = 'security-center';
    if (input.refresh === true) this.localJobs.invalidate(jobKey);

    return this.localJobs.run(
      {
        requestId: input.requestId,
        jobKey,
        revision,
        onProgress: (progress) =>
          this.sendLocalJobProgress(input.requestId, 'security-center', progress),
      },
      async (context) => {
        const assertAuthorized = (): void => {
          context.assertActive();
          this.assertAuthenticated(epoch);
        };
        const activeEntries = documents.flatMap((document) =>
          document.entries.filter((entry) => entry.deletedAt === null),
        );
        const credentialReport = await this.security.scanAsync(activeEntries, {
          assertAuthorized,
          onProgress: (progress) =>
            context.reportProgress({
              phase: 'credentials',
              completed: progress.completed,
              total: progress.total,
            }),
          yieldControl: context.yieldToEventLoop,
        });
        assertAuthorized();

        const credentialReports = documents.map((document) => {
          const entryIds = new Set(document.entries.map((entry) => entry.id));
          return {
            vaultId: document.id,
            vaultName: document.name,
            report: {
              ...credentialReport,
              findings: credentialReport.findings.filter((finding) =>
                entryIds.has(finding.entryId),
              ),
            },
          };
        });

        let dataQualityFindingCount = 0;
        let dataQualityCalculatedAt: string | null = null;
        for (let documentIndex = 0; documentIndex < documents.length; documentIndex += 1) {
          const document = documents[documentIndex]!;
          const documentViews = savedViews.filter((view) => view.vaultId === document.id);
          const attachmentChecks = await this.collectAttachmentTechnicalChecks(
            document,
            assertAuthorized,
            (completed, total) =>
              context.reportProgress({
                phase: `data-quality-attachments-${String(documentIndex + 1)}`,
                completed,
                total,
              }),
          );
          let qualityReport;
          try {
            qualityReport = await this.dataQuality.scan(
              { document, savedViews: documentViews, attachmentChecks },
              {
                assertAuthorized,
                onProgress: (progress) =>
                  context.reportProgress({
                    phase: `data-quality-${progress.phase}-${String(documentIndex + 1)}`,
                    completed: progress.completed,
                    total: progress.total,
                  }),
                yieldControl: context.yieldToEventLoop,
              },
            );
          } catch (error) {
            toDataQualityError(error);
          }
          dataQualityFindingCount += qualityReport.findings.length;
          if (
            dataQualityCalculatedAt === null ||
            qualityReport.generatedAt > dataQualityCalculatedAt
          ) {
            dataQualityCalculatedAt = qualityReport.generatedAt;
          }
        }

        assertAuthorized();
        const currentDocuments = await this.readAllVaults();
        const currentSavedViews = this.productivity.snapshot();
        const currentSnapshot = await this.readSecurityCenterSnapshot(epoch, currentDocuments);
        assertAuthorized();
        if (
          this.securityCenterRevision(currentDocuments, currentSavedViews, currentSnapshot) !==
          revision
        ) {
          throw new VaultaError(
            'CONFLICT',
            'Die Sicherheitsdaten wurden während der lokalen Auswertung geändert.',
          );
        }

        return this.securityCenter.build({
          credentialReports,
          dataQualityFindingCount,
          dataQualityCalculatedAt,
          factorStatus: snapshot.factorStatus,
          automaticBackups: snapshot.automaticBackups,
          lastAutomaticBackupAt: snapshot.lastAutomaticBackupAt,
          recovery: snapshot.recovery,
          kdfCurrent: snapshot.kdfCurrent,
          integrity: snapshot.integrity,
          breachList: snapshot.breachList,
          breachReport: snapshot.breachReport,
        });
      },
    );
  }

  public async scanIntegrity(input: IntegrityScanInput): Promise<IntegrityReportDto> {
    const epoch = this.requireUnlocked();
    const savedViews = this.productivity.snapshot();
    const initialRevision = await this.createIntegrityRevisionSnapshot(savedViews, epoch);
    const jobKey = 'integrity';
    if (input.refresh === true) this.localJobs.invalidate(jobKey);
    this.prunePendingIntegrityReports();

    const result = await this.localJobs.run<IntegrityJobResult>(
      {
        requestId: input.requestId,
        jobKey,
        revision: initialRevision.revision,
        onProgress: (progress) => this.sendLocalJobProgress(input.requestId, 'integrity', progress),
      },
      async (context) => {
        const assertAuthorized = (): void => {
          context.assertActive();
          this.assertAuthenticated(epoch);
        };
        const scanner = new IntegrityCheckService({
          profile: this.profile,
          vaults: this.vaults,
          attachments: this.attachments,
          audit: {
            inspectStoredDocumentFormatVersion: () =>
              this.audit.inspectStoredDocumentFormatVersion(),
          },
        });
        const coreReport = await scanner.scan({
          savedViews,
          assertAuthorized,
          onProgress: (progress) =>
            context.reportProgress({
              phase: progress.phase,
              completed: progress.completed,
              total: progress.total,
            }),
          yieldControl: context.yieldToEventLoop,
        });
        assertAuthorized();
        const currentRevision = await this.createIntegrityRevisionSnapshot(
          this.productivity.snapshot(),
          epoch,
        );
        assertAuthorized();
        if (currentRevision.revision !== initialRevision.revision) {
          throw new VaultaError(
            'CONFLICT',
            'Der lokale Datenbestand wurde während der Integritätsprüfung geändert.',
          );
        }

        const completed: IntegrityReportDto = {
          reportId: randomUUID(),
          ...coreReport,
        };
        const status = this.securityCenter.createIntegrityStatus(completed);
        let cacheRevision: string | null = null;
        try {
          cacheRevision = await this.withIntegrityCommitLocks(initialRevision.vaultIds, async () =>
            this.profile.withExclusiveWrite(() =>
              this.audit.withExclusiveWrite(async () => {
                assertAuthorized();
                const beforeCommit = await this.createIntegrityRevisionSnapshot(
                  this.productivity.snapshot(),
                  epoch,
                );
                assertAuthorized();
                this.assertIntegrityRevisionUnchanged(
                  initialRevision.revision,
                  beforeCommit.revision,
                );
                await this.commitProtectedMetadataWithAuditFullyLocked(
                  INTEGRITY_STATUS_NAMESPACE,
                  status,
                  'integrity-check-completed',
                  epoch,
                  assertAuthorized,
                );
                assertAuthorized();
                const afterCommit = await this.createIntegrityRevisionSnapshot(
                  this.productivity.snapshot(),
                  epoch,
                );
                assertAuthorized();
                this.assertIntegrityRevisionUnchanged(
                  initialRevision.dataRevision,
                  afterCommit.dataRevision,
                );
                return afterCommit.revision;
              }),
            ),
          );
          this.localJobs.invalidate('security-center');
        } catch (error) {
          rethrowIntegrityPersistenceInterruption(error);
          assertAuthorized();
          /*
           * A corrupt profile or audit container is itself an integrity finding.
           * It must not suppress the already-redacted diagnostic report merely
           * because the optional status/audit write cannot be prepared.
           */
        }
        assertAuthorized();
        return { report: completed, cacheRevision };
      },
    );
    this.assertAuthenticated(epoch);
    if (result.cacheRevision === null) this.localJobs.invalidate(jobKey);
    else this.localJobs.cacheResult(jobKey, result.cacheRevision, result);
    this.pendingIntegrityReports.set(result.report.reportId, {
      report: structuredClone(result.report),
      epoch,
      expiresAt: Date.now() + INTEGRITY_REPORT_TTL_MS,
    });
    return result.report;
  }

  public async saveIntegrityReport(input: { reportId: string }): Promise<boolean> {
    const epoch = this.requireUnlocked();
    this.prunePendingIntegrityReports();
    const pending = this.pendingIntegrityReports.get(input.reportId);
    if (pending === undefined || pending.epoch !== epoch) {
      throw new VaultaError(
        'CONFLICT',
        'Der redigierte Integritätsbericht ist abgelaufen. Bitte führe die Prüfung erneut aus.',
      );
    }
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Redigierten Integritätsbericht speichern',
      defaultPath: `Kryptris-Integritaetsbericht-${pending.report.generatedAt.slice(0, 10)}.json`,
      filters: [{ name: 'JSON-Bericht', extensions: ['json'] }],
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return false;

    const serialized = Buffer.from(
      JSON.stringify(
        {
          format: 'kryptris-integrity-report',
          version: 1,
          ...pending.report,
        },
        null,
        2,
      ),
      'utf8',
    );
    let written = false;
    try {
      await writeExclusiveCleartextFile(
        result.filePath,
        async (handle) => {
          await handle.writeFile(serialized);
          this.assertAuthenticated(epoch);
        },
        { replaceExisting: true, forbiddenRoots: [this.rootDir] },
      );
      written = true;
      this.assertAuthenticated(epoch);
      return true;
    } catch (error) {
      if (written) await rm(result.filePath, { force: true }).catch(() => undefined);
      throw error;
    } finally {
      serialized.fill(0);
    }
  }

  public async scanDuplicates(input: DuplicateScanInput): Promise<DuplicateScanDto> {
    const epoch = this.requireUnlocked();
    const documents =
      input.vaultId === undefined || input.vaultId === null
        ? await this.readAllVaults()
        : [await this.vaults.readVault(input.vaultId)];
    this.assertAuthenticated(epoch);
    const scope = input.vaultId ?? 'all';
    const jobKey = `duplicates:${scope}`;
    if (input.refresh === true) this.localJobs.invalidate(jobKey);
    const revision = this.revisionTokens.create(documents);
    const entries = new Map(
      documents.flatMap((document) =>
        document.entries.map((entry) => [`${document.id}:${entry.id}`, entry] as const),
      ),
    );
    const vaultNames = new Map(documents.map((document) => [document.id, document.name] as const));
    return this.localJobs.run(
      {
        requestId: input.requestId,
        jobKey,
        revision,
        onProgress: (progress) =>
          this.sendLocalJobProgress(input.requestId, 'duplicates', progress),
      },
      async (context) => {
        const result = await this.duplicates.scan(
          documents.flatMap((document) => document.entries),
          {
            signal: context.signal,
            assertAuthorized: () => {
              context.assertActive();
              this.assertAuthenticated(epoch);
            },
            onProgress: (progress) =>
              context.reportProgress({
                phase: progress.phase,
                completed: progress.processed,
                total: progress.total,
              }),
          },
        );
        this.assertAuthenticated(epoch);
        return this.toDuplicateScanDto(result, entries, vaultNames);
      },
    );
  }

  public async describeDuplicateMerge(
    input: DuplicateDescribeInput,
  ): Promise<DuplicateMergeDescriptionDto> {
    const epoch = this.requireUnlocked();
    const documents = new Map<string, VaultDocument>();
    for (const vaultId of [...new Set([input.survivor.vaultId, input.duplicate.vaultId])].sort()) {
      documents.set(vaultId, await this.vaults.readVault(vaultId));
      this.assertAuthenticated(epoch);
    }
    const survivor = requireEntry(
      requireVaultDocument(documents, input.survivor.vaultId),
      input.survivor.entryId,
    );
    const duplicate = requireEntry(
      requireVaultDocument(documents, input.duplicate.vaultId),
      input.duplicate.entryId,
    );
    if (
      survivor.updatedAt !== input.survivor.updatedAt ||
      duplicate.updatedAt !== input.duplicate.updatedAt
    ) {
      throw new VaultaError('CONFLICT', 'Die Dubletten-Vorschau ist nicht mehr aktuell.');
    }
    this.assertAuthenticated(epoch);
    return this.toDuplicateMergeDescriptionDto(
      this.duplicates.describeMerge(survivor, duplicate),
      survivor,
      duplicate,
      documents.get(survivor.vaultId)?.name,
      documents.get(duplicate.vaultId)?.name,
    );
  }

  public async mergeDuplicates(input: DuplicateMergeInput) {
    const epoch = this.requireUnlocked();
    const fieldChoices = input.fieldChoices.map((choice) => {
      if (!isDuplicateScalarField(choice.field)) {
        throw new VaultaError('INVALID_INPUT', 'Ein ausgewähltes Dublettenfeld ist ungültig.');
      }
      return { field: choice.field, source: choice.source };
    });
    const collectionChoices = input.collectionChoices.map((choice) => {
      if (!isDuplicateCollectionField(choice.field)) {
        throw new VaultaError('INVALID_INPUT', 'Eine ausgewählte Dublettensammlung ist ungültig.');
      }
      return { field: choice.field, strategy: choice.strategy };
    });
    const request: DuplicateMergeRequest = {
      survivor: input.survivor,
      duplicate: input.duplicate,
      fieldChoices,
      collectionChoices,
    };
    const result = await this.duplicateMerges.merge(request, () => this.assertAuthenticated(epoch));
    this.assertAuthenticated(epoch);
    this.localJobs.invalidate();
    this.clearDataQualityState();
    this.entryViews.clearCaches();
    await this.emitState();
    return result;
  }

  public async scanDataQuality(input: DataQualityScanInput): Promise<DataQualityReportDto> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(input.vaultId);
    const savedViews = this.productivity
      .snapshot()
      .filter((view) => view.vaultId === input.vaultId);
    this.assertAuthenticated(epoch);
    const jobKey = `data-quality:${input.vaultId}`;
    if (input.refresh === true) this.localJobs.invalidate(jobKey);
    const revision = this.revisionTokens.create(
      [document],
      savedViews.map((view) => `${view.id}:${view.updatedAt}`),
    );
    return this.localJobs.run(
      {
        requestId: input.requestId,
        jobKey,
        revision,
        onProgress: (progress) =>
          this.sendLocalJobProgress(input.requestId, 'data-quality', progress),
      },
      async (context) => {
        const attachmentChecks = await this.collectAttachmentTechnicalChecks(
          document,
          () => {
            context.assertActive();
            this.assertAuthenticated(epoch);
          },
          (completed, total) =>
            context.reportProgress({
              phase: 'attachments',
              completed,
              total,
            }),
        );
        try {
          const report = await this.dataQuality.scan(
            { document, savedViews, attachmentChecks },
            {
              assertAuthorized: () => {
                context.assertActive();
                this.assertAuthenticated(epoch);
              },
              onProgress: (progress) =>
                context.reportProgress({
                  phase: progress.phase,
                  completed: progress.completed,
                  total: progress.total,
                }),
              yieldControl: context.yieldToEventLoop,
            },
          );
          this.assertAuthenticated(epoch);
          this.rememberDataQualityFindings(input.vaultId, report.findings);
          return {
            generatedAt: report.generatedAt,
            vaultId: report.vaultId,
            scannedEntries: report.scannedEntries,
            findings: report.findings.map((finding) => ({
              id: finding.id,
              code: finding.code,
              severity: finding.severity,
              reference: finding.reference,
              fixCode: finding.fixCode,
            })),
            networkUsed: false,
          };
        } catch (error) {
          toDataQualityError(error);
        }
      },
    );
  }

  public async previewDataQualityFix(
    input: DataQualityPreviewInput,
  ): Promise<DataQualityFixPreviewDto> {
    const epoch = this.requireUnlocked();
    const finding = this.dataQualityFindings.get(
      dataQualityFindingKey(input.vaultId, input.findingId),
    );
    if (finding === undefined) {
      throw new VaultaError(
        'NOT_FOUND',
        'Der Datenqualitätsbefund wurde nicht gefunden. Bitte prüfe den Tresor erneut.',
      );
    }
    const document = await this.vaults.readVault(input.vaultId);
    const savedViews = this.productivity
      .snapshot()
      .filter((view) => view.vaultId === input.vaultId);
    const attachmentChecks = await this.collectAttachmentTechnicalChecks(document, () =>
      this.assertAuthenticated(epoch),
    );
    this.assertAuthenticated(epoch);
    let plan: DataQualityFixPlan;
    try {
      plan = this.dataQuality.previewFix({ document, savedViews, attachmentChecks }, finding, {
        assertAuthorized: () => this.assertAuthenticated(epoch),
      });
    } catch (error) {
      toDataQualityError(error);
    }
    const copy = DATA_QUALITY_FIX_COPY[plan.fixCode];
    const token = randomUUID();
    const expiresAt = Date.now() + DATA_QUALITY_FIX_TTL_MS;
    this.pendingDataQualityFixes.set(token, {
      vaultId: input.vaultId,
      finding: structuredClone(finding),
      plan,
      epoch,
      expiresAt,
    });
    return {
      token,
      findingId: finding.id,
      title: copy.title,
      description: copy.description,
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  public async applyDataQualityFix(input: DataQualityApplyInput): Promise<DataQualityFixResultDto> {
    const epoch = this.requireUnlocked();
    const pending = this.pendingDataQualityFixes.get(input.token);
    this.pendingDataQualityFixes.delete(input.token);
    if (pending === undefined || pending.epoch !== epoch || pending.expiresAt <= Date.now()) {
      throw new VaultaError(
        'CONFLICT',
        'Die Korrekturvorschau ist abgelaufen. Bitte erstelle eine neue Vorschau.',
      );
    }
    const result = await this.commitDataQualityFix(pending, epoch);
    this.assertAuthenticated(epoch);
    this.localJobs.invalidate();
    this.clearDataQualityState();
    this.entryViews.clearCaches();
    await this.emitState();
    return result;
  }

  public cancelLocalJob(requestId: string): boolean {
    this.requireUnlocked();
    return this.localJobs.cancel(requestId);
  }

  public async createBackup(input?: { automatic?: boolean }): Promise<BackupInfo | null> {
    return this.backupOperations.run(async () => {
      if (input?.automatic === true) return this.createAutomaticBackupLocked();
      return this.createManualBackup();
    });
  }

  private async createManualBackup(): Promise<BackupInfo | null> {
    const epoch = this.requireUnlocked();
    const result = await dialog.showSaveDialog(this.requireWindow(), {
      title: 'Verschlüsseltes Vaulta-Backup erstellen',
      defaultPath: `Vaulta-${new Date().toISOString().slice(0, 10)}.vaulta-backup`,
      filters: [{ name: 'Vaulta-Backup', extensions: ['vaulta-backup'] }],
    });
    this.assertAuthenticated(epoch);
    if (result.canceled || result.filePath.length === 0) return null;
    let backup: BackupInfo;
    try {
      backup = await this.backups.createBackup({
        destination: result.filePath,
        replaceExisting: true,
        assertAuthorized: () => this.assertAuthenticated(epoch),
        validateLiveState: () => this.validateBackupLiveState(epoch),
      });
    } catch (error) {
      await this.rememberBackupFailure(error, epoch);
      throw error;
    }
    this.assertAuthenticated(epoch);
    await this.backupHealth.recordSuccessfulBackup(backup.createdAt);
    this.assertAuthenticated(epoch);
    this.localJobs.invalidate('backup-health');
    await this.audit.record({ type: 'backup-created' });
    this.assertAuthenticated(epoch);
    return backup;
  }

  public async getBackupHealth(input: BackupHealthInput): Promise<BackupHealthSnapshot> {
    const epoch = this.requireUnlocked();
    const jobKey = 'backup-health';
    if (input.refresh === true) this.localJobs.invalidate(jobKey);
    const revision = this.backupHealthRevision();
    return this.backupOperations.run(() =>
      this.localJobs.run(
        {
          requestId: input.requestId,
          jobKey,
          revision,
          onProgress: (progress) =>
            this.sendLocalJobProgress(input.requestId, 'backup-health', progress),
        },
        async (context) => {
          const assertAuthorized = (): void => {
            context.assertActive();
            this.assertAuthenticated(epoch);
          };
          assertAuthorized();
          context.reportProgress({ phase: 'Sicherungsziel wird geprüft', completed: 0, total: 1 });
          const health = await this.backupHealth.inspect(
            this.settings.backupFolder,
            assertAuthorized,
          );
          assertAuthorized();
          context.reportProgress({ phase: 'Sicherungsstatus ist aktuell', completed: 1, total: 1 });
          return health;
        },
      ),
    );
  }

  /**
   * Produces the deliberately redacted input for Windows-local reminders. This
   * remains Main-process-only: it returns aggregate counts and a boolean only,
   * never names, identifiers, paths, or decrypted field values. Callers must
   * provide their cancellation boundary so an immediate lock wins over the
   * periodic local check.
   */
  public async getLocalReminderSnapshot(assertActive: () => void = () => undefined): Promise<{
    rotationDue: number;
    expirationDue: number;
    staleBackup: boolean;
  }> {
    const epoch = this.requireUnlocked();
    const assertAuthorized = (): void => {
      assertActive();
      this.assertAuthenticated(epoch);
    };
    const preferences = this.settings.localReminders;
    let rotationDue = 0;
    let expirationDue = 0;

    if (preferences.rotation || preferences.expiry) {
      const summaries = await this.vaults.listVaults();
      assertAuthorized();
      let processedEntries = 0;
      for (const summary of summaries) {
        assertAuthorized();
        const document = await this.vaults.readVault(summary.id);
        assertAuthorized();
        for (const entry of document.entries) {
          assertAuthorized();
          if (entry.deletedAt !== null) continue;
          const lifecycle = this.lifecycle.status(entry);
          if (preferences.rotation && lifecycle.rotationDue) rotationDue += 1;
          if (preferences.expiry && lifecycle.reminderDue) expirationDue += 1;
          processedEntries += 1;
          // Keep a large local vault responsive and give locking/cancellation a
          // chance to invalidate this short-lived aggregate before it is used.
          if (processedEntries % 100 === 0) {
            await new Promise<void>((resolve) => setImmediate(resolve));
            assertAuthorized();
          }
        }
      }
    }

    let staleBackup = false;
    if (preferences.backup && this.settings.automaticBackups) {
      const health = await this.backupHealth.inspect(this.settings.backupFolder, assertAuthorized);
      assertAuthorized();
      const lastBackupAt = health.lastSuccessfulBackupAt;
      staleBackup =
        lastBackupAt === null ||
        !Number.isFinite(Date.parse(lastBackupAt)) ||
        Date.now() - Date.parse(lastBackupAt) > 48 * 60 * 60 * 1_000;
    }

    assertAuthorized();
    return { rotationDue, expirationDue, staleBackup };
  }

  public async dryRunBackup(input: BackupDryRunInput) {
    const epoch = this.requireUnlocked();
    const result = await dialog.showOpenDialog(this.requireWindow(), {
      title: 'Backup probeweise prüfen',
      properties: ['openFile'],
      filters: [{ name: 'Vaulta-Backup', extensions: ['vaulta-backup'] }],
    });
    this.assertAuthenticated(epoch);
    const backupPath = result.filePaths[0];
    if (result.canceled || backupPath === undefined) return null;
    const revision = createHash('sha256')
      .update(`${this.authentication.getState()}\0${backupPath}`)
      .digest('hex');
    return this.backupOperations.run(async () => {
      const verified = await this.localJobs.run(
        {
          requestId: input.requestId,
          jobKey: 'backup-dry-run',
          revision,
          onProgress: (progress) =>
            this.sendLocalJobProgress(input.requestId, 'backup-dry-run', progress),
        },
        (context) =>
          this.backups.dryRunBackup({
            backupPath,
            credential: input.credential,
            assertAuthorized: () => {
              context.assertActive();
              this.assertAuthenticated(epoch);
            },
            signal: context.signal,
            onProgress: context.reportProgress,
          }),
      );
      this.assertAuthenticated(epoch);
      await this.backupHealth.recordSemanticVerification(verified.verifiedAt);
      this.assertAuthenticated(epoch);
      this.localJobs.invalidate('backup-health');
      await this.audit.record({ type: 'backup-dry-run-completed' });
      this.assertAuthenticated(epoch);
      return verified;
    });
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
      return await this.previewImportSource(input, sourcePath, epoch);
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) {
        this.importer.clear();
        this.importVaults.clear();
      }
      throw error;
    }
  }

  public async previewDroppedImport(input: DroppedImportPreviewInput) {
    const epoch = this.requireUnlocked();
    try {
      return await this.previewImportSource(input, input.sourcePath, epoch);
    } catch (error) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) {
        this.importer.clear();
        this.importVaults.clear();
      }
      throw error;
    }
  }

  private async previewImportSource(input: ImportPreviewInput, sourcePath: string, epoch: number) {
    const content = await this.importSourceReader.readUtf8(sourcePath, () =>
      this.assertAuthenticated(epoch),
    );
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

  public async executeImport(input: ImportExecuteInput): Promise<{
    imported: number;
    skipped: number;
    summary: ReturnType<ImportService['summary']>;
    entryIds: string[];
  }> {
    const epoch = this.requireUnlocked();
    if (this.importVaults.get(input.token) !== input.vaultId)
      throw new VaultaError(
        'INVALID_INPUT',
        'Importvorschau und Ziel-Tresor passen nicht zusammen.',
      );
    const previewSummary = this.importer.summary(input.token, input.selectedRows);
    const prepared = this.importer.materialize(input.token, input.selectedRows);
    const importedEntryIds: string[] = [];
    const imported = await this.mutateVaultWithAudit(
      input.vaultId,
      (document) => {
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
            tags: normalizeTags(source.tags),
            id: entryId,
            vaultId: input.vaultId,
            folderId,
            attachments: [],
            lifecycle: this.lifecycle.afterSecretChange(
              source.data.type,
              source.lifecycle ?? createDefaultEntryLifecycleMetadata(),
              now,
            ),
            createdAt: now,
            updatedAt: now,
            secretChangedAt: now,
            lastUsedAt: null,
            deletedAt: null,
          });
          importedEntryIds.push(entryId);
        }
        return prepared.length;
      },
      'import-completed',
      epoch,
      () => importedEntryIds,
    );
    this.assertAuthenticated(epoch);
    this.importer.discard(input.token);
    this.importVaults.delete(input.token);
    this.localJobs.invalidate();
    return {
      imported,
      skipped: Math.max(0, input.selectedRows.length - imported),
      summary: {
        ...previewSummary,
        newEntries: imported,
        skippedEntries: Math.max(0, input.selectedRows.length - imported),
      },
      entryIds: importedEntryIds,
    };
  }

  public listImportMappingProfiles() {
    this.requireUnlocked();
    return this.importMappingProfiles.list();
  }

  public saveImportMappingProfile(input: ImportMappingProfileSaveInput) {
    return this.importMappingProfileOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const before = this.importMappingProfiles.exportSnapshot();
      const saved = this.importMappingProfiles.save(input);
      try {
        await this.commitProtectedMetadataWithAudit(
          IMPORT_MAPPING_PROFILES_NAMESPACE,
          this.importMappingProfiles.exportSnapshot(),
          'import-mapping-profile-updated',
          epoch,
        );
        this.assertAuthenticated(epoch);
        return saved;
      } catch (error) {
        this.importMappingProfiles.restoreSnapshot(before);
        throw error;
      }
    });
  }

  public removeImportMappingProfile(input: ImportMappingProfileRemoveInput) {
    return this.importMappingProfileOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const before = this.importMappingProfiles.exportSnapshot();
      const removed = this.importMappingProfiles.remove(input.id);
      if (!removed) return false;
      try {
        await this.commitProtectedMetadataWithAudit(
          IMPORT_MAPPING_PROFILES_NAMESPACE,
          this.importMappingProfiles.exportSnapshot(),
          'import-mapping-profile-updated',
          epoch,
        );
        this.assertAuthenticated(epoch);
        return true;
      } catch (error) {
        this.importMappingProfiles.restoreSnapshot(before);
        throw error;
      }
    });
  }

  public async exportVaultPackage(
    input: VaultPackageExportInput,
  ): Promise<VaultPackageExportResult | null> {
    const epoch = this.requireUnlocked();
    return this.vaultPackageOperations.run(async () => {
      const result = await dialog.showSaveDialog(this.requireWindow(), {
        title: 'Verschluesseltes Tresor-Paket exportieren',
        defaultPath: `Kryptris-Tresor-${new Date().toISOString().slice(0, 10)}.kryptris-vault`,
        filters: [{ name: 'Kryptris-Tresor-Paket', extensions: ['kryptris-vault'] }],
      });
      this.assertAuthenticated(epoch);
      if (result.canceled || result.filePath.length === 0) return null;

      const exported = await this.vaultPackages.exportPackage({
        ...input,
        destination: result.filePath,
        replaceExisting: true,
        assertAuthorized: () => this.assertAuthenticated(epoch),
      });
      this.assertAuthenticated(epoch);
      await this.audit.record({ type: 'vault-package-exported', vaultId: input.vaultId });
      this.assertAuthenticated(epoch);
      return {
        createdAt: exported.createdAt,
        entryCount: exported.entryCount,
        attachmentCount: exported.attachmentCount,
        includesAttachments: exported.includesAttachments,
      };
    });
  }

  public async previewVaultPackage(
    input: VaultPackagePreviewInput,
  ): Promise<VaultPackagePreviewDto | null> {
    const epoch = this.requireUnlocked();
    return this.vaultPackageOperations.run(async () => {
      const result = await dialog.showOpenDialog(this.requireWindow(), {
        title: 'Kryptris-Tresor-Paket auswaehlen',
        properties: ['openFile'],
        filters: [{ name: 'Kryptris-Tresor-Paket', extensions: ['kryptris-vault'] }],
      });
      this.assertAuthenticated(epoch);
      const packagePath = result.filePaths[0];
      if (result.canceled || packagePath === undefined) return null;

      const existingVaultNames = (await this.vaults.listVaults()).map((vault) => vault.name);
      this.assertAuthenticated(epoch);
      const preview = await this.vaultPackages.inspectPackage({
        packagePath,
        exportPassword: input.exportPassword,
        existingVaultNames,
        assertAuthorized: () => this.assertAuthenticated(epoch),
      });
      this.assertAuthenticated(epoch);
      const identity = await this.readVaultPackageIdentity(packagePath);
      this.assertAuthenticated(epoch);
      this.prunePendingVaultPackageImports();
      const token = randomUUID();
      this.pendingVaultPackageImports.set(token, {
        packagePath,
        identity,
        epoch,
        expiresAt: Date.now() + VAULT_PACKAGE_IMPORT_PREVIEW_TTL_MS,
      });
      return { token, ...preview };
    });
  }

  public async importVaultPackage(
    input: VaultPackageImportInput,
  ): Promise<VaultPackageImportResult> {
    const epoch = this.requireUnlocked();
    return this.vaultPackageOperations.run(async () => {
      const pending = this.takePendingVaultPackageImport(input.token, epoch);
      await this.assertVaultPackageIdentityUnchanged(pending.packagePath, pending.identity);
      this.assertAuthenticated(epoch);

      const existingVaultNames = (await this.vaults.listVaults()).map((vault) => vault.name);
      this.assertAuthenticated(epoch);
      let plan: PreparedVaultPackageImport | null = null;
      let stagingDirectory: VaultPackageImportStagingDirectory | null = null;
      let committed = false;
      let importFailure: unknown = null;
      let cleanupFailure: unknown = null;
      let imported: VaultPackageImportResult | null = null;
      try {
        const preparedPlan = await this.vaultPackages.prepareImport({
          packagePath: pending.packagePath,
          exportPassword: input.exportPassword,
          existingVaultNames,
          targetVaultId: randomUUID(),
          targetVaultName: input.targetVaultName,
          allowNameConflict: input.allowNameConflict,
          assertAuthorized: () => this.assertAuthenticated(epoch),
        });
        plan = preparedPlan;
        this.assertAuthenticated(epoch);
        const preparedStagingDirectory = await this.createVaultPackageImportStagingDirectory();
        stagingDirectory = preparedStagingDirectory;
        this.assertAuthenticated(epoch);

        const result = await this.vaults.withExclusiveRegistryWrite(async () => {
          const currentVaults = await this.vaults.listVaults();
          this.assertAuthenticated(epoch);
          return this.vaults.withExclusiveVaults(
            [...currentVaults.map((vault) => vault.id), preparedPlan.document.id],
            async () =>
              this.profile.withExclusiveWrite(() =>
                this.audit.withExclusiveWrite(async () => {
                  const assertAuthorized = () => this.assertAuthenticated(epoch);
                  assertAuthorized();
                  await this.assertVaultPackageIdentityUnchanged(
                    pending.packagePath,
                    pending.identity,
                  );
                  assertAuthorized();
                  if (!input.allowNameConflict) {
                    const targetName = preparedPlan.document.name.toLocaleLowerCase('de');
                    const currentNames = (await this.vaults.listVaults()).map((vault) =>
                      vault.name.toLocaleLowerCase('de'),
                    );
                    assertAuthorized();
                    if (currentNames.includes(targetName)) {
                      throw new VaultaError(
                        'CONFLICT',
                        'Ein Tresor mit diesem Namen existiert bereits. Bitte waehle einen anderen Namen.',
                      );
                    }
                  }

                  const preparedVault = await this.vaults.prepareNewVaultWrite(
                    preparedPlan.document,
                  );
                  const sensitiveBuffers = [
                    preparedVault.contents,
                    preparedVault.profileWrite.contents,
                    preparedVault.vaultKey,
                  ];
                  try {
                    const stagedAttachments: VaultPackageStagedAttachment[] = [];
                    for (const attachment of preparedPlan.attachments) {
                      assertAuthorized();
                      preparedPlan.assertUsable();
                      const sourcePath = this.vaultPackageAttachmentStagingPath(
                        preparedStagingDirectory,
                        attachment.attachmentId,
                      );
                      const metadata = await this.attachments.encryptBufferToStaging({
                        targetVaultId: preparedPlan.document.id,
                        targetAttachmentId: attachment.attachmentId,
                        stagingPath: sourcePath,
                        stagingDirectory: preparedStagingDirectory.directory,
                        assertStagingDirectory: () =>
                          this.assertVaultPackageImportStagingDirectory(preparedStagingDirectory),
                        name: attachment.name,
                        mediaType: attachment.mediaType,
                        contents: attachment.contents,
                        targetVaultKey: preparedVault.vaultKey,
                        createdAt: attachment.createdAt,
                        assertAuthorized,
                      });
                      this.assertPackageAttachmentMetadata(attachment, metadata);
                      attachment.contents.fill(0);
                      stagedAttachments.push({
                        relativePath: `attachments/${preparedPlan.document.id}/${attachment.attachmentId}.vatt`,
                        sourcePath,
                        identity: await this.inspectVaultPackageAttachmentStagingFile(
                          preparedStagingDirectory,
                          sourcePath,
                        ),
                      });
                    }

                    assertAuthorized();
                    const preparedAudit = await this.audit.prepareRecord({
                      type: 'vault-package-imported',
                      vaultId: preparedPlan.document.id,
                    });
                    sensitiveBuffers.push(preparedAudit.contents);
                    try {
                      const changes: MultiFileChange[] = [
                        {
                          type: 'write',
                          relativePath: preparedVault.relativePath,
                          contents: preparedVault.contents,
                          expectedSha256: preparedVault.expectedSha256,
                        },
                        {
                          type: 'write',
                          relativePath: preparedVault.profileWrite.relativePath,
                          contents: preparedVault.profileWrite.contents,
                          expectedSha256: preparedVault.profileWrite.expectedSha256,
                        },
                        ...stagedAttachments.map((attachment) => ({
                          type: 'write-file' as const,
                          relativePath: attachment.relativePath,
                          sourcePath: attachment.sourcePath,
                          expectedSha256: null,
                        })),
                        {
                          type: 'write',
                          relativePath: preparedAudit.relativePath,
                          contents: preparedAudit.contents,
                          expectedSha256: preparedAudit.expectedSha256,
                        },
                      ];
                      await this.transactions.execute(changes, {
                        assertAuthorized: async () => {
                          assertAuthorized();
                          await this.assertVaultPackageImportStagingDirectory(
                            preparedStagingDirectory,
                          );
                          for (const attachment of stagedAttachments) {
                            await this.assertVaultPackageAttachmentStagingFileIdentity(
                              preparedStagingDirectory,
                              attachment.sourcePath,
                              attachment.identity,
                            );
                          }
                          assertAuthorized();
                        },
                      });
                      committed = true;
                    } finally {
                      preparedAudit.contents.fill(0);
                    }
                  } finally {
                    for (const buffer of sensitiveBuffers) buffer.fill(0);
                  }
                  return {
                    vaultId: preparedPlan.document.id,
                    vaultName: preparedPlan.document.name,
                    entryCount: preparedPlan.document.entries.length,
                    attachmentCount: preparedPlan.attachments.length,
                  };
                }),
              ),
          );
        });
        imported = result;
        await this.publishCommittedVaultPackageImport(epoch, preparedPlan.document);
      } catch (error) {
        importFailure = error;
        throw error;
      } finally {
        try {
          plan?.dispose();
        } catch (cleanupError) {
          if (committed || importFailure !== null) {
            this.reportNonFatalVaultPackageImportPostCommitIssue(
              'Verschluesselte temporaere Paketdaten konnten nicht vollstaendig bereinigt werden. Bitte starte Kryptris neu.',
            );
          } else if (cleanupFailure === null) {
            cleanupFailure = cleanupError;
          }
        }
        if (stagingDirectory !== null) {
          try {
            await this.removeVaultPackageImportStagingDirectory(stagingDirectory);
          } catch (cleanupError) {
            if (committed || importFailure !== null) {
              // The committed vault is the authoritative result. Staging holds
              // only newly encrypted attachment bytes at this point; a hostile
              // path must not turn a completed import into a retryable failure.
              this.reportNonFatalVaultPackageImportPostCommitIssue(
                'Verschluesselte temporaere Paketdaten konnten nicht vollstaendig bereinigt werden. Bitte starte Kryptris neu.',
              );
            } else {
              cleanupFailure = cleanupError;
            }
          }
        }
      }
      if (cleanupFailure !== null) {
        if (cleanupFailure instanceof Error) throw cleanupFailure;
        throw new VaultaError(
          'INTERNAL',
          'Das Paket-Staging konnte nicht vollstaendig bereinigt werden.',
        );
      }
      if (imported === null) {
        throw new VaultaError('INTERNAL', 'Der Tresor-Paketimport wurde nicht abgeschlossen.');
      }
      return imported;
    });
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
    const previousSettings = structuredClone(this.settings);
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
    let desktopPolicyStarted = false;
    try {
      if (this.desktopSettingsPolicy !== null) {
        desktopPolicyStarted = true;
        await this.desktopSettingsPolicy.apply(structuredClone(parsed));
      }
      this.assertAuthenticated(epoch);
      await this.profile.setProtectedMetadata(SETTINGS_NAMESPACE, protectedValue(parsed));
    } catch (error) {
      if (desktopPolicyStarted) await this.restoreDesktopSettingsPolicy(previousSettings);
      throw error;
    }
    this.authorizedBackupFolder = null;
    this.assertAuthenticated(epoch);
    this.settings = structuredClone(parsed);
    this.audit = this.createAuditService(this.settings);
    this.localJobs.invalidate('backup-health');
    this.autoLock.updateTimeout(this.settings.autoLockSeconds);
    this.requireWindow().setContentProtection(this.settings.contentProtection);
    this.configureAutomaticBackups();
    this.configureTrashRetention();
    await this.audit.record({ type: 'settings-updated' });
    this.assertAuthenticated(epoch);
    await this.emitState();
    return this.getSettings();
  }

  private async restoreDesktopSettingsPolicy(previousSettings: VaultaSettings): Promise<void> {
    if (this.desktopSettingsPolicy === null) return;
    try {
      await this.desktopSettingsPolicy.apply(structuredClone(previousSettings));
    } catch {
      try {
        this.onBackgroundWarning(
          'Die Windows-Integration konnte nach einem fehlgeschlagenen Einstellungs-Speichervorgang nicht vollständig zurückgesetzt werden. Bitte Kryptris neu starten und die Einstellungen prüfen.',
        );
      } catch {
        // Warning delivery must never mask the original failed settings operation.
      }
    }
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
    await this.profile.completeRecoveryRotation(input.pendingId, input.confirmation, {
      invalidateProtectedMetadataNamespaces: [RECOVERY_READINESS_NAMESPACE],
    });
    this.assertAuthenticated(epoch);
    this.recoveryReadiness.resetAfterRecoveryRotation();
    this.localJobs.invalidate('security-center');
    await this.audit.record({ type: 'recovery-rotated' });
    this.assertAuthenticated(epoch);
    await this.emitState();
  }

  public async getRecoveryReadiness(): Promise<RecoveryReadinessStatusDto> {
    const epoch = this.requireUnlocked();
    return this.profile.withExclusiveWrite(async () => {
      const policy = await this.profile.getAccessPolicy();
      this.assertAuthenticated(epoch);
      const stored = await this.profile.getProtectedMetadata<ProtectedMetadataValue>(
        RECOVERY_READINESS_NAMESPACE,
      );
      this.assertAuthenticated(epoch);
      return this.recoveryReadiness.status(
        policy.recoveryEnabled,
        this.recoveryReadiness.parseRecord(stored),
      );
    });
  }

  public async testRecoveryReadiness(input: {
    recoveryKey: string;
  }): Promise<RecoveryReadinessStatusDto> {
    const epoch = this.requireUnlocked();
    return this.recoveryReadiness.runAttempt((attempt) =>
      this.profile.withExclusiveWrite(async () => {
        try {
          await this.profile.verifyRecoveryKey(input.recoveryKey, () =>
            this.assertAuthenticated(epoch),
          );
        } catch (error) {
          if (!(error instanceof VaultaError) || error.code !== 'AUTH_FAILED') throw error;
          attempt.authenticationFailed();
          const record = this.recoveryReadiness.createRecord(false);
          await this.commitProtectedMetadataWithAuditLocked(
            RECOVERY_READINESS_NAMESPACE,
            record,
            'recovery-readiness-failed',
            epoch,
          );
          this.localJobs.invalidate('security-center');
          throw new VaultaError(
            'AUTH_FAILED',
            'Der Wiederherstellungsschlüssel konnte nicht bestätigt werden.',
          );
        }

        const record = this.recoveryReadiness.createRecord(true);
        await this.commitProtectedMetadataWithAuditLocked(
          RECOVERY_READINESS_NAMESPACE,
          record,
          'recovery-readiness-succeeded',
          epoch,
        );
        this.localJobs.invalidate('security-center');
        const policy = await this.profile.getAccessPolicy();
        this.assertAuthenticated(epoch);
        return this.recoveryReadiness.status(policy.recoveryEnabled, record);
      }),
    );
  }

  public async getBreachListStatus(): Promise<BreachListStatusDto> {
    const epoch = this.requireUnlocked();
    return this.profile.withExclusiveWrite(() => this.getBreachListStatusLocked(epoch));
  }

  public async importBreachList(input: BreachImportInput): Promise<BreachListStatusDto | null> {
    const epoch = this.requireUnlocked();
    const result = await dialog.showOpenDialog(this.requireWindow(), {
      title: 'Lokale Datenleckliste importieren',
      properties: ['openFile'],
      filters: [{ name: 'SHA-1-Hashliste', extensions: ['txt'] }],
    });
    this.assertAuthenticated(epoch);
    const sourcePath = result.filePaths[0];
    if (result.canceled || sourcePath === undefined) return null;

    this.localJobs.abort('breach-scan');
    this.localJobs.abort('breach-import');
    this.localJobs.abort('security-center');
    return this.breachOperations.run(async () => {
      this.assertAuthenticated(epoch);
      await this.localJobs.abortAndWait('breach-scan');
      await this.localJobs.abortAndWait('breach-import');
      await this.localJobs.abortAndWait('security-center');
      this.assertAuthenticated(epoch);
      const securityDirectory = await this.requireBreachSecurityDirectory();
      const stagingPath = path.resolve(securityDirectory, `.breach-import-${randomUUID()}.tmp`);
      const jobKey = 'breach-import';
      try {
        const build = await this.localJobs.run(
          {
            requestId: input.requestId,
            jobKey,
            revision: randomUUID(),
            onProgress: (progress) =>
              this.sendLocalJobProgress(input.requestId, 'breach-import', progress),
          },
          (context) =>
            this.offlineBreach.buildIndex({
              sourcePath,
              stagingPath,
              context: {
                signal: context.signal,
                assertAuthorized: () => {
                  context.assertActive();
                  this.assertAuthenticated(epoch);
                },
                onProgress: (progress) =>
                  context.reportProgress({
                    phase: progress.phase,
                    completed: progress.completed,
                    total: progress.total,
                  }),
                yieldControl: context.yieldToEventLoop,
              },
            }),
        );
        this.assertAuthenticated(epoch);
        const manifest = this.breachManifests.create(build, input);
        await this.commitBreachListImport(manifest, stagingPath, epoch);
        this.breachListKnownCorrupt = false;
        this.lastBreachReport = null;
        this.lastBreachReportRevision = null;
        this.localJobs.invalidate('breach-scan');
        this.localJobs.invalidate('security-center');
        return this.breachManifests.status(manifest);
      } finally {
        this.localJobs.invalidate(jobKey);
        await rm(stagingPath, { force: true }).catch(() => undefined);
      }
    });
  }

  public async scanBreachList(input: BreachScanInput): Promise<BreachScanReportDto> {
    return this.breachOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const manifest = await this.profile.withExclusiveWrite(async () => {
        const current = await this.readBreachManifest(epoch);
        const status = await this.breachListStatusForManifest(current, epoch);
        if (current === null || status.state === 'not-configured') {
          throw new VaultaError(
            'NOT_FOUND',
            'Für den lokalen Datenleckabgleich ist noch keine Liste eingerichtet.',
          );
        }
        if (status.state === 'missing') {
          throw new VaultaError(
            'NOT_FOUND',
            'Die lokale Datenleckliste fehlt und muss erneut importiert werden.',
          );
        }
        if (status.state === 'corrupt') {
          throw new VaultaError(
            'CORRUPT_DATA',
            'Die lokale Datenleckliste ist beschädigt und muss ersetzt werden.',
          );
        }
        return current;
      });
      const documents = await this.readAllVaults();
      this.assertAuthenticated(epoch);
      const revision = this.revisionTokens.create(documents, [manifest.indexSha256]);
      const jobKey = 'breach-scan';
      if (input.refresh === true) this.localJobs.invalidate(jobKey);
      const candidates = documents.flatMap((document) =>
        document.entries.flatMap((entry) => {
          if (entry.deletedAt !== null) return [];
          const password =
            entry.data.type === 'credential'
              ? entry.data.value.password
              : entry.data.type === 'wifi'
                ? entry.data.value.password
                : '';
          if (password.length === 0) return [];
          return [
            {
              reference: {
                vaultId: document.id,
                entryId: entry.id,
                updatedAt: entry.updatedAt,
              },
              password,
              deletedAt: entry.deletedAt,
            },
          ];
        }),
      );
      const entries = new Map(
        documents.flatMap((document) =>
          document.entries.map(
            (entry) =>
              [
                JSON.stringify([document.id, entry.id, entry.updatedAt]),
                { document, entry },
              ] as const,
          ),
        ),
      );

      try {
        const report = await this.localJobs.run(
          {
            requestId: input.requestId,
            jobKey,
            revision,
            onProgress: (progress) =>
              this.sendLocalJobProgress(input.requestId, 'breach-scan', progress),
          },
          async (context) => {
            const result = await this.offlineBreach.scan({
              indexPath: this.breachIndexPath(),
              expectedIndexSha256: manifest.indexSha256,
              candidates,
              context: {
                signal: context.signal,
                assertAuthorized: () => {
                  context.assertActive();
                  this.assertAuthenticated(epoch);
                },
                onProgress: (progress) =>
                  context.reportProgress({
                    phase: progress.phase,
                    completed: progress.completed,
                    total: progress.total,
                  }),
                yieldControl: context.yieldToEventLoop,
              },
            });
            this.assertAuthenticated(epoch);
            const currentDocuments = await this.readAllVaults();
            this.assertAuthenticated(epoch);
            if (this.revisionTokens.create(currentDocuments, [manifest.indexSha256]) !== revision) {
              throw new VaultaError(
                'CONFLICT',
                'Die Tresordaten wurden während des Datenleckabgleichs geändert.',
              );
            }
            const currentManifest = await this.readBreachManifest(epoch);
            if (currentManifest?.indexSha256 !== manifest.indexSha256) {
              throw new VaultaError(
                'CONFLICT',
                'Die lokale Datenleckliste wurde während des Abgleichs ersetzt.',
              );
            }
            const generatedAt = new Date().toISOString();
            return {
              generatedAt,
              checkedEntries: candidates.length,
              checkedPasswords: result.checkedCandidates,
              findings: result.matches.map((reference) => {
                const matched = entries.get(
                  JSON.stringify([reference.vaultId, reference.entryId, reference.updatedAt]),
                );
                if (matched === undefined) {
                  throw new VaultaError(
                    'CONFLICT',
                    'Ein Datenleckbefund verweist auf eine veraltete Tresorrevision.',
                  );
                }
                return {
                  id: randomUUID(),
                  vaultId: reference.vaultId,
                  vaultName: matched.document.name,
                  entryId: reference.entryId,
                  entryTitle: matched.entry.title,
                  entryUpdatedAt: reference.updatedAt,
                  code: 'known-breached-password' as const,
                  severity: 'critical' as const,
                };
              }),
              networkUsed: false as const,
            };
          },
        );
        this.assertAuthenticated(epoch);
        this.breachListKnownCorrupt = false;
        this.lastBreachReport = structuredClone(report);
        this.lastBreachReportRevision = revision;
        this.localJobs.invalidate('security-center');
        return report;
      } catch (error) {
        if (
          error instanceof VaultaError &&
          ['CORRUPT_DATA', 'UNSUPPORTED_FORMAT', 'UNSAFE_PATH'].includes(error.code)
        ) {
          this.breachListKnownCorrupt = true;
          this.lastBreachReport = null;
          this.lastBreachReportRevision = null;
          this.localJobs.invalidate('security-center');
        }
        throw error;
      }
    });
  }

  public async removeBreachList(): Promise<BreachListStatusDto> {
    const epoch = this.requireUnlocked();
    this.localJobs.abort('breach-scan');
    this.localJobs.abort('breach-import');
    this.localJobs.abort('security-center');
    return this.breachOperations.run(async () => {
      this.assertAuthenticated(epoch);
      await this.localJobs.abortAndWait('breach-scan');
      await this.localJobs.abortAndWait('breach-import');
      await this.localJobs.abortAndWait('security-center');
      this.assertAuthenticated(epoch);
      await this.profile.withExclusiveWrite(() =>
        this.audit.withExclusiveWrite(async () => {
          const preparedProfile = await this.profile.prepareProtectedMetadataUpdates({
            [BREACH_LIST_NAMESPACE]: null,
          });
          const preparedAudit = await this.audit.prepareRecord({ type: 'breach-list-removed' });
          const sensitiveBuffers = [preparedProfile.contents, preparedAudit.contents];
          try {
            this.assertAuthenticated(epoch);
            await this.transactions.execute(
              [
                { type: 'delete', relativePath: BREACH_LIST_INDEX_RELATIVE_PATH },
                {
                  type: 'write',
                  relativePath: preparedProfile.relativePath,
                  contents: preparedProfile.contents,
                  expectedSha256: preparedProfile.expectedSha256,
                },
                {
                  type: 'write',
                  relativePath: preparedAudit.relativePath,
                  contents: preparedAudit.contents,
                  expectedSha256: preparedAudit.expectedSha256,
                },
              ],
              { assertAuthorized: () => this.assertAuthenticated(epoch) },
            );
          } finally {
            for (const buffer of sensitiveBuffers) buffer.fill(0);
          }
        }),
      );
      this.breachListKnownCorrupt = false;
      this.lastBreachReport = null;
      this.lastBreachReportRevision = null;
      this.localJobs.invalidate('breach-scan');
      this.localJobs.invalidate('security-center');
      return this.breachManifests.status(null);
    });
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

  public async runProductivityBatch(input: BatchEntryInput): Promise<BatchEntryResult> {
    const epoch = this.requireUnlocked();
    if (
      input.action.type === 'purge' &&
      !(await this.profile.verifyMasterPassword(input.action.masterPassword))
    ) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    }
    this.assertAuthenticated(epoch);
    if (input.action.type === 'copy-to-vault' || input.action.type === 'move-to-vault') {
      const transfer = await this.entryTransactions.transfer(
        {
          vaultId: input.vaultId,
          entryIds: input.entryIds,
          action: input.action,
        },
        () => this.assertAuthenticated(epoch),
      );
      this.assertAuthenticated(epoch);
      this.entryViews.clearCaches();
      await this.emitState();
      return {
        affected: transfer.affected,
        entryIds: transfer.targetEntryIds,
      };
    }
    const auditType =
      input.action.type === 'trash'
        ? ('entry-moved-to-trash' as const)
        : input.action.type === 'restore'
          ? ('entry-restored' as const)
          : input.action.type === 'purge'
            ? ('entry-purged' as const)
            : ('entry-updated' as const);
    const mutation =
      input.action.type === 'purge'
        ? await this.entryTransactions.purge(
            input.vaultId,
            (document) => this.productivity.applyBatch(document, input),
            () => this.assertAuthenticated(epoch),
            auditType,
          )
        : await this.mutateVaultWithAudit(
            input.vaultId,
            (document) => this.productivity.applyBatch(document, input),
            auditType,
            epoch,
            (result) => result.entryIds,
          );
    this.assertAuthenticated(epoch);
    this.entryViews.clearCaches();
    await this.emitState();
    return { affected: mutation.affected, entryIds: mutation.entryIds };
  }

  public async listSavedViews(vaultId: string): Promise<SavedView[]> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(vaultId);
    this.assertAuthenticated(epoch);
    return this.productivity.listSavedViews(vaultId, document);
  }

  public async saveSavedView(input: SavedViewSaveInput): Promise<SavedView> {
    return this.productivityOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const document = await this.vaults.readVault(input.vaultId);
      this.assertAuthenticated(epoch);
      const previous = this.productivity.snapshot();
      const saved = this.productivity.saveSavedView(input);
      try {
        await this.persistSavedViews();
        this.assertAuthenticated(epoch);
        return (
          this.productivity
            .listSavedViews(input.vaultId, document)
            .find((view) => view.id === saved.id) ??
          (() => {
            throw new VaultaError(
              'INTERNAL',
              'Die gespeicherte Ansicht konnte nicht geladen werden.',
            );
          })()
        );
      } catch (error) {
        this.restoreProductivitySnapshot(epoch, previous);
        throw error;
      }
    });
  }

  public async reorderSavedViews(input: {
    vaultId: string;
    orderedIds: string[];
  }): Promise<SavedView[]> {
    return this.productivityOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const document = await this.vaults.readVault(input.vaultId);
      this.assertAuthenticated(epoch);
      const previous = this.productivity.snapshot();
      try {
        this.productivity.reorderSavedViews(input.vaultId, input.orderedIds);
        await this.persistSavedViews();
        this.assertAuthenticated(epoch);
        return this.productivity.listSavedViews(input.vaultId, document);
      } catch (error) {
        this.restoreProductivitySnapshot(epoch, previous);
        throw error;
      }
    });
  }

  public async deleteSavedView(input: { vaultId: string; id: string }): Promise<void> {
    return this.productivityOperations.run(async () => {
      const epoch = this.requireUnlocked();
      const previous = this.productivity.snapshot();
      try {
        this.productivity.deleteSavedView(input.vaultId, input.id);
        await this.persistSavedViews();
        this.assertAuthenticated(epoch);
      } catch (error) {
        this.restoreProductivitySnapshot(epoch, previous);
        throw error;
      }
    });
  }

  public async listTags(vaultId: string): Promise<TagSummary[]> {
    const epoch = this.requireUnlocked();
    const document = await this.vaults.readVault(vaultId);
    this.assertAuthenticated(epoch);
    return this.productivity.listTags(document);
  }

  public async renameTag(input: { vaultId: string; tag: string; name: string }): Promise<number> {
    return this.mutateTags(input.vaultId, (document) =>
      this.productivity.renameTag(document, input.tag, input.name),
    );
  }

  public async mergeTags(input: {
    vaultId: string;
    sourceTags: string[];
    targetName: string;
  }): Promise<number> {
    return this.mutateTags(input.vaultId, (document) =>
      this.productivity.mergeTags(document, input.sourceTags, input.targetName),
    );
  }

  public async deleteTag(input: { vaultId: string; tag: string }): Promise<number> {
    return this.mutateTags(input.vaultId, (document) =>
      this.productivity.deleteTag(document, input.tag),
    );
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

  /**
   * A package transaction is already durable when this point is reached. A
   * concurrent lock must therefore suppress cache/UI publication, not turn the
   * completed import into a retryable failure.
   */
  private isAuthenticationCurrent(epoch: number): boolean {
    try {
      this.assertAuthenticated(epoch);
      return true;
    } catch {
      return false;
    }
  }

  /** Publishes only non-durable post-commit state and never changes the import result. */
  private async publishCommittedVaultPackageImport(
    epoch: number,
    document: VaultDocument,
  ): Promise<void> {
    try {
      if (!this.isAuthenticationCurrent(epoch)) return;
      this.vaults.installCommittedDocuments([document]);
      this.localJobs.invalidate();
      this.entryViews.clearCaches();
      await this.emitState();
    } catch {
      // A partially refreshed decrypted cache is less safe than a cold cache.
      // Lock also follows this branch if it races with the asynchronous state
      // emission, so cleanup must remain best-effort and non-publishing.
      try {
        this.vaults.clearCachedDocuments();
      } catch {
        // Do not let post-commit cache hygiene overwrite the durable result.
      }
      try {
        this.entryViews.clearCaches();
      } catch {
        // Do not let post-commit cache hygiene overwrite the durable result.
      }
      if (!this.isAuthenticationCurrent(epoch)) return;
      this.reportNonFatalVaultPackageImportPostCommitIssue(
        'Der Tresor-Paketimport wurde gespeichert, aber die lokale Ansicht konnte nicht aktualisiert werden. Bitte sperre und entsperre Kryptris erneut.',
      );
    }
  }

  private reportNonFatalVaultPackageImportPostCommitIssue(message: string): void {
    try {
      this.onBackgroundWarning(message);
    } catch {
      // Warning delivery is non-authoritative and must not make a committed
      // import appear retryable.
    }
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
        ? vaultaSettingsSchema.parse({
            ...cloneSettings(),
            // A profile without this namespace necessarily predates the
            // onboarding flow. Do not surprise an existing user with it.
            onboardingCompleted: true,
          })
        : vaultaSettingsSchema.safeParse(rawSettings);
    if ('success' in parsed && !parsed.success)
      throw new VaultaError('CORRUPT_DATA', 'Die gespeicherten Einstellungen sind beschädigt.');
    this.settings = structuredClone('success' in parsed ? parsed.data : parsed);
    const rawTemplates =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(TEMPLATES_NAMESPACE);
    this.authentication.assertEpoch(epoch);
    this.templates = new TemplateService(parseTemplates(rawTemplates));
    const rawSavedViews =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(SAVED_VIEWS_NAMESPACE);
    this.authentication.assertEpoch(epoch);
    this.productivity = new ProductivityService(parseSavedViews(rawSavedViews));
    const rawImportMappingProfiles =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(
        IMPORT_MAPPING_PROFILES_NAMESPACE,
      );
    this.authentication.assertEpoch(epoch);
    if (rawImportMappingProfiles === null) this.importMappingProfiles.clear();
    else this.importMappingProfiles.restoreSnapshot(rawImportMappingProfiles);
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
    this.configureTrashRetention();
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

  private toDuplicateCandidateSide(
    entry: VaultEntry,
    vaultName?: string,
  ): DuplicateCandidateSideDto {
    const summary = this.summaryForEntry(entry);
    return {
      vaultId: entry.vaultId,
      entryId: entry.id,
      updatedAt: entry.updatedAt,
      title: summary.title,
      subtitle: summary.subtitle,
      ...(vaultName === undefined ? {} : { vaultName }),
    };
  }

  private toDuplicateScanDto(
    result: DuplicateScanResult,
    entries: ReadonlyMap<string, VaultEntry>,
    vaultNames: ReadonlyMap<string, string>,
  ): DuplicateScanDto {
    return {
      candidates: result.candidates.map((candidate) => {
        const left = entries.get(`${candidate.left.vaultId}:${candidate.left.entryId}`);
        const right = entries.get(`${candidate.right.vaultId}:${candidate.right.entryId}`);
        if (left === undefined || right === undefined) {
          throw new VaultaError(
            'CONFLICT',
            'Ein Dublettenkandidat gehört nicht mehr zur geprüften Revision.',
          );
        }
        return {
          left: this.toDuplicateCandidateSide(left, vaultNames.get(left.vaultId)),
          right: this.toDuplicateCandidateSide(right, vaultNames.get(right.vaultId)),
          type: candidate.type,
          confidence: candidate.confidence,
          reasons: [...candidate.reasons],
        };
      }),
      activeEntryCount: result.activeEntryCount,
      truncated: result.truncated,
    };
  }

  private toDuplicateMergeDescriptionDto(
    description: DuplicateMergeDescription,
    survivor: VaultEntry,
    duplicate: VaultEntry,
    survivorVaultName?: string,
    duplicateVaultName?: string,
  ): DuplicateMergeDescriptionDto {
    return {
      survivor: this.toDuplicateCandidateSide(survivor, survivorVaultName),
      duplicate: this.toDuplicateCandidateSide(duplicate, duplicateVaultName),
      type: description.type,
      scalarFields: description.scalarFields.map(({ field, secret }) => ({
        field,
        label: duplicateFieldLabel(field),
        secret,
        survivorPreview: duplicateScalarPreview(survivor, field, secret),
        duplicatePreview: duplicateScalarPreview(duplicate, field, secret),
      })),
      collectionFields: description.collectionFields.map(({ field, supportsUnion }) => ({
        field,
        label: duplicateFieldLabel(field),
        survivorCount: duplicateCollectionCount(survivor, field),
        duplicateCount: duplicateCollectionCount(duplicate, field),
        supportsUnion,
      })),
      potentialAttachmentDuplicates: description.potentialAttachmentDuplicates.length,
      duplicateDisposition: description.duplicateDisposition,
    };
  }

  private async collectAttachmentTechnicalChecks(
    document: VaultDocument,
    assertAuthorized: () => void,
    onProgress: (completed: number, total: number) => void = () => undefined,
  ): Promise<AttachmentTechnicalCheck[]> {
    assertAuthorized();
    const stored = await this.attachments.listStoredAttachmentReferences(assertAuthorized);
    const allExpected = new Set(
      document.entries.flatMap((entry) =>
        entry.attachments.map((attachment) => `${document.id}:${attachment.id}`),
      ),
    );
    const activeAttachments = document.entries
      .filter((entry) => entry.deletedAt === null)
      .flatMap((entry) =>
        entry.attachments.map((attachment) => ({
          entry,
          attachment,
        })),
      );
    const checks: AttachmentTechnicalCheck[] = [];
    onProgress(0, activeAttachments.length);
    for (let index = 0; index < activeAttachments.length; index += 1) {
      assertAuthorized();
      const { entry, attachment } = activeAttachments[index]!;
      const base = {
        vaultId: document.id,
        entryId: entry.id,
        attachmentId: attachment.id,
        entryUpdatedAt: entry.updatedAt,
      };
      try {
        const verifiedMetadata = await this.attachments.readAuthenticatedMetadata(
          document.id,
          attachment.id,
          assertAuthorized,
        );
        if (
          verifiedMetadata.size !== attachment.size ||
          verifiedMetadata.sha256.toLowerCase() !== attachment.sha256.toLowerCase()
        ) {
          checks.push({ ...base, status: 'metadata-mismatch', verifiedMetadata });
        }
      } catch (error) {
        if (error instanceof VaultaError && error.code === 'NOT_FOUND') {
          checks.push({ ...base, status: 'missing-file' });
        } else if (error instanceof VaultaError && error.code === 'CORRUPT_DATA') {
          checks.push({ ...base, status: 'corrupt-file' });
        } else {
          throw error;
        }
      }
      onProgress(index + 1, activeAttachments.length);
    }
    for (const reference of stored) {
      assertAuthorized();
      if (
        reference.vaultId === document.id &&
        !allExpected.has(`${reference.vaultId}:${reference.attachmentId}`)
      ) {
        checks.push({
          status: 'orphan-file',
          vaultId: document.id,
          attachmentId: reference.attachmentId,
          vaultUpdatedAt: document.updatedAt,
        });
      }
    }
    return checks;
  }

  private rememberDataQualityFindings(
    vaultId: string,
    findings: readonly DataQualityFinding[],
  ): void {
    for (const key of this.dataQualityFindings.keys()) {
      if (key.startsWith(`${vaultId}:`)) this.dataQualityFindings.delete(key);
    }
    for (const [token, pending] of this.pendingDataQualityFixes) {
      if (pending.vaultId === vaultId) this.pendingDataQualityFixes.delete(token);
    }
    for (const finding of findings) {
      this.dataQualityFindings.set(
        dataQualityFindingKey(vaultId, finding.id),
        structuredClone(finding),
      );
    }
  }

  private clearDataQualityState(): void {
    this.dataQualityFindings.clear();
    this.pendingDataQualityFixes.clear();
  }

  private async commitDataQualityFix(
    pending: PendingDataQualityFix,
    epoch: number,
  ): Promise<DataQualityFixResultDto> {
    try {
      return await this.vaults.withExclusiveVaults([pending.vaultId], async () =>
        this.profile.withExclusiveWrite(async () =>
          this.audit.withExclusiveWrite(async () => {
            this.assertAuthenticated(epoch);
            const document = await this.vaults.readVault(pending.vaultId);
            const allSavedViews = this.productivity.snapshot();
            const vaultSavedViews = allSavedViews.filter(
              (view) => view.vaultId === pending.vaultId,
            );
            const applied = this.dataQualityFixes.apply(
              { document, savedViews: vaultSavedViews },
              pending.plan,
              { assertAuthorized: () => this.assertAuthenticated(epoch) },
            );
            const previousEntries = new Map(
              document.entries.map((entry) => [entry.id, entry.updatedAt] as const),
            );
            const affectedEntryIds = applied.document.entries
              .filter((entry) => previousEntries.get(entry.id) !== entry.updatedAt)
              .map((entry) => entry.id);
            const previousViews = new Map(
              vaultSavedViews.map((view) => [view.id, view.updatedAt] as const),
            );
            const savedViewsChanged = applied.savedViews.filter(
              (view) => previousViews.get(view.id) !== view.updatedAt,
            ).length;
            const nextSavedViews =
              savedViewsChanged === 0
                ? allSavedViews
                : [
                    ...allSavedViews.filter((view) => view.vaultId !== pending.vaultId),
                    ...applied.savedViews,
                  ];
            const preparedDocument = await this.vaults.prepareDocumentWrite(applied.document);
            const preparedProfile =
              savedViewsChanged === 0
                ? null
                : await this.profile.prepareProtectedMetadataUpdates({
                    [SAVED_VIEWS_NAMESPACE]: protectedValue(nextSavedViews),
                  });
            const preparedAudit = await this.audit.prepareRecord({
              type: 'data-quality-fixed',
              vaultId: pending.vaultId,
              entryId: affectedEntryIds[0] ?? null,
            });
            const sensitiveBuffers = [
              preparedDocument.contents,
              preparedAudit.contents,
              ...(preparedProfile === null ? [] : [preparedProfile.contents]),
            ];
            try {
              const changes: MultiFileChange[] = [
                {
                  type: 'write',
                  relativePath: preparedDocument.relativePath,
                  contents: preparedDocument.contents,
                  expectedSha256: preparedDocument.expectedSha256,
                },
                ...(preparedProfile === null
                  ? []
                  : [
                      {
                        type: 'write' as const,
                        relativePath: preparedProfile.relativePath,
                        contents: preparedProfile.contents,
                        expectedSha256: preparedProfile.expectedSha256,
                      },
                    ]),
                {
                  type: 'write',
                  relativePath: preparedAudit.relativePath,
                  contents: preparedAudit.contents,
                  expectedSha256: preparedAudit.expectedSha256,
                },
              ];
              this.assertAuthenticated(epoch);
              await this.transactions.execute(changes, {
                assertAuthorized: () => this.assertAuthenticated(epoch),
              });
              this.vaults.installCommittedDocuments([applied.document]);
              if (savedViewsChanged > 0) {
                this.productivity = new ProductivityService(nextSavedViews);
              }
              return { affectedEntryIds, savedViewsChanged };
            } finally {
              for (const buffer of sensitiveBuffers) buffer.fill(0);
            }
          }),
        ),
      );
    } catch (error) {
      toDataQualityError(error);
    }
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

  private async readSecurityCenterSnapshot(
    epoch: number,
    documents: readonly VaultDocument[],
  ): Promise<SecurityCenterSnapshot> {
    return this.profile.withExclusiveWrite(async () => {
      const header = await this.profile.readPublicHeader();
      this.assertAuthenticated(epoch);
      const factorStatus = await this.factors.getStatus(true);
      this.assertAuthenticated(epoch);
      const recoveryRecord = await this.profile.getProtectedMetadata<ProtectedMetadataValue>(
        RECOVERY_READINESS_NAMESPACE,
      );
      this.assertAuthenticated(epoch);
      const lastBackup =
        await this.profile.getProtectedMetadata<ProtectedMetadataValue>(LAST_BACKUP_NAMESPACE);
      this.assertAuthenticated(epoch);
      if (
        lastBackup !== null &&
        (typeof lastBackup !== 'string' || !Number.isFinite(Date.parse(lastBackup)))
      ) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Der gespeicherte Zeitpunkt der automatischen Sicherung ist beschädigt.',
        );
      }
      const integrityValue = await this.profile.getProtectedMetadata<ProtectedMetadataValue>(
        INTEGRITY_STATUS_NAMESPACE,
      );
      this.assertAuthenticated(epoch);
      const breachManifest = await this.readBreachManifest(epoch);
      const breachList = await this.breachListStatusForManifest(breachManifest, epoch);
      this.assertAuthenticated(epoch);
      const parameters = header.access.kdf.parameters;
      const kdfCurrent =
        parameters.algorithm === 'argon2id' &&
        parameters.hashLength === 32 &&
        Number.isSafeInteger(parameters.memorySizeKiB) &&
        parameters.memorySizeKiB >= PRODUCT_ARGON2_MEMORY_KIB &&
        Number.isSafeInteger(parameters.iterations) &&
        parameters.iterations >= 1 &&
        Number.isSafeInteger(parameters.parallelism) &&
        parameters.parallelism >= 1;
      return {
        headerUpdatedAt: header.updatedAt,
        factorStatus,
        automaticBackups: this.settings.automaticBackups,
        recovery: this.recoveryReadiness.status(
          factorStatus.recoveryEnabled,
          this.recoveryReadiness.parseRecord(recoveryRecord),
        ),
        lastAutomaticBackupAt: lastBackup,
        integrity: this.securityCenter.parseIntegrityStatus(integrityValue),
        breachList,
        breachReport: this.currentBreachReport(documents, breachManifest, breachList),
        kdfCurrent,
      };
    });
  }

  private securityCenterRevision(
    documents: readonly VaultDocument[],
    savedViews: readonly SavedViewRecord[],
    snapshot: SecurityCenterSnapshot,
  ): string {
    return this.revisionTokens.create(documents, [
      `profile:${snapshot.headerUpdatedAt}`,
      `automatic-backups:${String(snapshot.automaticBackups)}`,
      `recovery:${snapshot.recovery.state}:${snapshot.recovery.lastTestedAt ?? 'none'}`,
      `integrity:${snapshot.integrity?.checkedAt ?? 'none'}:${String(
        snapshot.integrity?.findingCount ?? 0,
      )}`,
      `breach:${snapshot.breachList.state}:${snapshot.breachList.corpusSha256 ?? 'none'}`,
      `breach-report:${snapshot.breachReport?.generatedAt ?? 'none'}:${String(
        snapshot.breachReport?.findings.length ?? 0,
      )}`,
      ...savedViews.map((view) => `view:${view.id}:${view.updatedAt}`),
    ]);
  }

  private async createIntegrityRevisionSnapshot(
    savedViews: readonly SavedViewRecord[],
    epoch: number,
  ): Promise<IntegrityRevisionSnapshot> {
    const assertAuthorized = (): void => this.assertAuthenticated(epoch);
    const vaultInventory = await this.vaults.inspectStoredVaultInventory(assertAuthorized);
    const attachmentInventory =
      await this.attachments.inspectStoredAttachmentInventory(assertAuthorized);
    const dataState: string[] = [
      `vault-invalid:${String(vaultInventory.invalidEntryCount)}`,
      `attachment-invalid:${String(attachmentInventory.invalidEntryCount)}`,
      ...savedViews.map((view) => `view:${view.id}:${view.vaultId}:${view.updatedAt}`),
    ];
    const protectedState: string[] = [];
    const appendFileState = async (
      target: string[],
      label: string,
      filePath: string,
    ): Promise<void> => {
      assertAuthorized();
      const info = await lstat(filePath).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
      assertAuthorized();
      if (info === null) {
        target.push(`${label}:missing`);
        return;
      }
      target.push(
        `${label}:${info.isSymbolicLink() ? 'symlink' : info.isFile() ? 'file' : 'other'}:${String(
          info.size,
        )}:${String(info.mtimeMs)}:${String(info.ctimeMs)}`,
      );
    };

    await appendFileState(protectedState, 'profile', path.resolve(this.rootDir, 'profile.json'));
    await appendFileState(protectedState, 'audit', path.resolve(this.rootDir, 'audit.vaulta'));
    for (const vaultId of vaultInventory.vaultIds) {
      await appendFileState(
        dataState,
        `vault:${vaultId}`,
        path.resolve(this.rootDir, 'vaults', `${vaultId}.vaulta`),
      );
    }
    for (const reference of attachmentInventory.references) {
      await appendFileState(
        dataState,
        `attachment:${reference.vaultId}:${reference.attachmentId}`,
        this.attachments.getEncryptedPath(reference.vaultId, reference.attachmentId),
      );
    }
    assertAuthorized();
    return {
      revision: this.revisionTokens.create([], [...protectedState, ...dataState]),
      dataRevision: this.revisionTokens.create([], dataState),
      vaultIds: vaultInventory.vaultIds,
    };
  }

  /**
   * A final integrity result is only publishable if no entry or attachment writer can change the
   * inspected data between the last revision check and the atomic profile/audit commit. Profile
   * serialization additionally blocks vault creation and deletion while this short critical
   * section is held.
   */
  private async withIntegrityCommitLocks<T>(
    vaultIds: readonly string[],
    operation: () => Promise<T>,
  ): Promise<T> {
    if (vaultIds.length === 0) return operation();
    return this.vaults.withExclusiveVaults(vaultIds, operation);
  }

  private assertIntegrityRevisionUnchanged(expected: string, current: string): void {
    if (current !== expected) {
      throw new VaultaError(
        'CONFLICT',
        'Der lokale Datenbestand wurde während der Integritätsprüfung geändert.',
      );
    }
  }

  private prunePendingIntegrityReports(): void {
    const now = Date.now();
    for (const [reportId, pending] of this.pendingIntegrityReports) {
      if (pending.expiresAt <= now) this.pendingIntegrityReports.delete(reportId);
    }
  }

  private async commitProtectedMetadataWithAudit(
    namespace: string,
    value: unknown,
    auditType: AuditEventType,
    epoch: number,
    assertAuthorized: () => void = () => this.assertAuthenticated(epoch),
  ): Promise<void> {
    await this.profile.withExclusiveWrite(() =>
      this.commitProtectedMetadataWithAuditLocked(
        namespace,
        value,
        auditType,
        epoch,
        assertAuthorized,
      ),
    );
  }

  /** Caller must hold the profile writer across any decision that produced `value`. */
  private async commitProtectedMetadataWithAuditLocked(
    namespace: string,
    value: unknown,
    auditType: AuditEventType,
    epoch: number,
    assertAuthorized: () => void = () => this.assertAuthenticated(epoch),
  ): Promise<void> {
    await this.audit.withExclusiveWrite(() =>
      this.commitProtectedMetadataWithAuditFullyLocked(
        namespace,
        value,
        auditType,
        epoch,
        assertAuthorized,
      ),
    );
  }

  /** Caller must hold both the profile and audit writers. */
  private async commitProtectedMetadataWithAuditFullyLocked(
    namespace: string,
    value: unknown,
    auditType: AuditEventType,
    epoch: number,
    assertAuthorized: () => void = () => this.assertAuthenticated(epoch),
  ): Promise<void> {
    assertAuthorized();
    const preparedProfile = await this.profile.prepareProtectedMetadataUpdates({
      [namespace]: protectedValue(value),
    });
    const preparedAudit = await this.audit.prepareRecord({ type: auditType });
    const sensitiveBuffers = [preparedProfile.contents, preparedAudit.contents];
    try {
      assertAuthorized();
      await this.transactions.execute(
        [
          {
            type: 'write',
            relativePath: preparedProfile.relativePath,
            contents: preparedProfile.contents,
            expectedSha256: preparedProfile.expectedSha256,
          },
          {
            type: 'write',
            relativePath: preparedAudit.relativePath,
            contents: preparedAudit.contents,
            expectedSha256: preparedAudit.expectedSha256,
          },
        ],
        { assertAuthorized },
      );
      assertAuthorized();
    } finally {
      for (const buffer of sensitiveBuffers) buffer.fill(0);
    }
  }

  private async readBreachManifest(epoch: number): Promise<BreachListManifest | null> {
    const stored =
      await this.profile.getProtectedMetadata<ProtectedMetadataValue>(BREACH_LIST_NAMESPACE);
    this.assertAuthenticated(epoch);
    return this.breachManifests.parse(stored);
  }

  private async getBreachListStatusLocked(epoch: number): Promise<BreachListStatusDto> {
    const manifest = await this.readBreachManifest(epoch);
    return this.breachListStatusForManifest(manifest, epoch);
  }

  private async breachListStatusForManifest(
    manifest: BreachListManifest | null,
    epoch: number,
  ): Promise<BreachListStatusDto> {
    if (manifest === null) return this.breachManifests.status(null);
    if (this.breachListKnownCorrupt) return this.breachManifests.status(manifest, 'corrupt');
    const stored = await lstat(this.breachIndexPath()).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    this.assertAuthenticated(epoch);
    if (stored === null) return this.breachManifests.status(manifest, 'missing');
    if (stored.isSymbolicLink() || !stored.isFile() || stored.size !== manifest.indexBytes) {
      return this.breachManifests.status(manifest, 'corrupt');
    }
    return this.breachManifests.status(manifest);
  }

  private currentBreachReport(
    documents: readonly VaultDocument[],
    manifest: BreachListManifest | null,
    status: BreachListStatusDto,
  ): BreachScanReportDto | null {
    if (
      manifest === null ||
      status.state !== 'ready' ||
      this.lastBreachReport === null ||
      this.lastBreachReportRevision === null ||
      this.revisionTokens.create(documents, [manifest.indexSha256]) !==
        this.lastBreachReportRevision
    ) {
      this.lastBreachReport = null;
      this.lastBreachReportRevision = null;
      return null;
    }
    return structuredClone(this.lastBreachReport);
  }

  private async commitBreachListImport(
    manifest: BreachListManifest,
    stagingPath: string,
    epoch: number,
  ): Promise<void> {
    await this.profile.withExclusiveWrite(() =>
      this.audit.withExclusiveWrite(async () => {
        this.assertAuthenticated(epoch);
        const preparedProfile = await this.profile.prepareProtectedMetadataUpdates({
          [BREACH_LIST_NAMESPACE]: protectedValue(manifest),
        });
        const preparedAudit = await this.audit.prepareRecord({ type: 'breach-list-imported' });
        const sensitiveBuffers = [preparedProfile.contents, preparedAudit.contents];
        try {
          await this.transactions.execute(
            [
              {
                type: 'write-file',
                relativePath: BREACH_LIST_INDEX_RELATIVE_PATH,
                sourcePath: stagingPath,
              },
              {
                type: 'write',
                relativePath: preparedProfile.relativePath,
                contents: preparedProfile.contents,
                expectedSha256: preparedProfile.expectedSha256,
              },
              {
                type: 'write',
                relativePath: preparedAudit.relativePath,
                contents: preparedAudit.contents,
                expectedSha256: preparedAudit.expectedSha256,
              },
            ],
            { assertAuthorized: () => this.assertAuthenticated(epoch) },
          );
          this.assertAuthenticated(epoch);
        } finally {
          for (const buffer of sensitiveBuffers) buffer.fill(0);
        }
      }),
    );
  }

  private breachIndexPath(): string {
    return path.resolve(this.rootDir, ...BREACH_LIST_INDEX_RELATIVE_PATH.split('/'));
  }

  private async cleanupBreachImportStaging(): Promise<void> {
    const directory = await this.inspectBreachSecurityDirectory(false);
    if (directory === null) return;
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return [];
        throw error;
      },
    );
    for (const entry of entries) {
      if (!BREACH_IMPORT_STAGING_FILE.test(entry.name)) continue;
      if (entry.isSymbolicLink() || !entry.isFile()) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das interne Stagingverzeichnis enthält einen unsicheren Eintrag.',
        );
      }
      await rm(path.resolve(directory, entry.name), { force: true });
    }
  }

  /** Removes only encrypted, controller-owned package staging left by an interrupted import. */
  private async cleanupVaultPackageImportStaging(): Promise<void> {
    const securityDirectory = await this.inspectBreachSecurityDirectory(false);
    if (securityDirectory === null) return;
    const securityIdentity = await this.inspectDirectVaultPackageDirectory(
      securityDirectory,
      'Das interne Stagingverzeichnis ist nicht sicher.',
    );
    if (securityIdentity === null) return;
    const stagingRoot = path.resolve(securityDirectory, VAULT_PACKAGE_IMPORT_STAGING_DIRECTORY);
    const stagingRootIdentity = await this.inspectDirectVaultPackageDirectory(
      stagingRoot,
      'Das interne Tresor-Paket-Stagingverzeichnis ist nicht sicher.',
    );
    if (stagingRootIdentity === null) return;
    await this.assertVaultPackageImportStagingRoot(
      securityDirectory,
      securityIdentity,
      stagingRoot,
      stagingRootIdentity,
    );
    const entries = await readdir(stagingRoot, { withFileTypes: true });
    for (const entry of entries) {
      await this.assertVaultPackageImportStagingRoot(
        securityDirectory,
        securityIdentity,
        stagingRoot,
        stagingRootIdentity,
      );
      if (!VAULT_PACKAGE_IMPORT_STAGING_ENTRY.test(entry.name)) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das interne Tresor-Paket-Stagingverzeichnis enthaelt einen unsicheren Eintrag.',
        );
      }
      const directory = path.resolve(stagingRoot, entry.name);
      const directoryIdentity = await this.inspectDirectVaultPackageDirectory(
        directory,
        'Das Paket-Stagingziel ist nicht sicher.',
      );
      if (directoryIdentity === null) continue;
      await this.removeVaultPackageImportStagingDirectory({
        securityDirectory,
        securityIdentity,
        stagingRoot,
        stagingRootIdentity,
        directory,
        directoryIdentity,
      });
    }
    await this.removeEmptyVaultPackageImportStagingRoot(
      securityDirectory,
      securityIdentity,
      stagingRoot,
      stagingRootIdentity,
    );
  }

  private async createVaultPackageImportStagingDirectory(): Promise<VaultPackageImportStagingDirectory> {
    const securityDirectory = await this.requireBreachSecurityDirectory();
    const securityIdentity = await this.requireDirectVaultPackageDirectory(
      securityDirectory,
      'Das interne Stagingverzeichnis ist nicht sicher.',
    );
    const stagingRoot = path.resolve(securityDirectory, VAULT_PACKAGE_IMPORT_STAGING_DIRECTORY);
    let stagingRootIdentity = await this.inspectDirectVaultPackageDirectory(
      stagingRoot,
      'Das interne Tresor-Paket-Stagingverzeichnis ist nicht sicher.',
    );
    if (stagingRootIdentity === null) {
      await this.assertVaultPackageImportStagingSecurityDirectory(
        securityDirectory,
        securityIdentity,
      );
      await mkdir(stagingRoot, { recursive: false, mode: 0o700 });
      stagingRootIdentity = await this.requireDirectVaultPackageDirectory(
        stagingRoot,
        'Das interne Tresor-Paket-Stagingverzeichnis ist nicht sicher.',
      );
    }
    await this.assertVaultPackageImportStagingRoot(
      securityDirectory,
      securityIdentity,
      stagingRoot,
      stagingRootIdentity,
    );
    const directory = path.resolve(stagingRoot, randomUUID());
    if (path.dirname(directory) !== stagingRoot) {
      throw new VaultaError('INTERNAL', 'Das Paket-Stagingziel konnte nicht bestimmt werden.');
    }
    let staging: VaultPackageImportStagingDirectory | null = null;
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 });
      const directoryIdentity = await this.requireDirectVaultPackageDirectory(
        directory,
        'Das Paket-Stagingziel ist nicht sicher.',
      );
      staging = {
        securityDirectory,
        securityIdentity,
        stagingRoot,
        stagingRootIdentity,
        directory,
        directoryIdentity,
      };
      await this.assertVaultPackageImportStagingDirectory(staging);
      return staging;
    } catch (error) {
      if (staging !== null) {
        await this.removeVaultPackageImportStagingDirectory(staging).catch(() => undefined);
      }
      throw error;
    }
  }

  private async removeVaultPackageImportStagingDirectory(
    staging: VaultPackageImportStagingDirectory,
  ): Promise<void> {
    await this.assertVaultPackageImportStagingDirectory(staging);
    const entries = await readdir(staging.directory, { withFileTypes: true });
    for (const entry of entries) {
      if (!/^[0-9a-f-]{36}\.vatt$/iu.test(entry.name)) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das Paket-Stagingziel enthaelt einen unsicheren Eintrag.',
        );
      }
      await this.removeVaultPackageAttachmentStagingFile(
        staging,
        path.resolve(staging.directory, entry.name),
      );
    }
    await this.assertVaultPackageImportStagingDirectory(staging);
    const remaining = await readdir(staging.directory);
    if (remaining.length > 0) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das Paket-Stagingziel wurde waehrend der Bereinigung geaendert.',
      );
    }
    await rmdir(staging.directory).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return;
      throw error;
    });
  }

  private vaultPackageAttachmentStagingPath(
    staging: VaultPackageImportStagingDirectory,
    attachmentId: string,
  ): string {
    if (!VAULT_PACKAGE_IMPORT_STAGING_ENTRY.test(attachmentId)) {
      throw new VaultaError('UNSAFE_PATH', 'Die Paket-Anhangs-ID ist ungueltig.');
    }
    const sourcePath = path.resolve(staging.directory, `${attachmentId}.vatt`);
    if (path.dirname(sourcePath) !== staging.directory) {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Anhangspfad ist ungueltig.');
    }
    return sourcePath;
  }

  private async assertVaultPackageImportStagingSecurityDirectory(
    securityDirectory: string,
    securityIdentity: DirectoryIdentity,
  ): Promise<void> {
    const current = await this.requireDirectVaultPackageDirectory(
      securityDirectory,
      'Das interne Stagingverzeichnis wurde waehrend der Paketverarbeitung geaendert.',
    );
    if (!sameDirectoryIdentity(current, securityIdentity)) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das interne Stagingverzeichnis wurde waehrend der Paketverarbeitung geaendert.',
      );
    }
  }

  private async assertVaultPackageImportStagingRoot(
    securityDirectory: string,
    securityIdentity: DirectoryIdentity,
    stagingRoot: string,
    stagingRootIdentity: DirectoryIdentity,
  ): Promise<void> {
    if (
      path.dirname(stagingRoot) !== securityDirectory ||
      path.basename(stagingRoot) !== VAULT_PACKAGE_IMPORT_STAGING_DIRECTORY
    ) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das interne Tresor-Paket-Stagingverzeichnis ist ungueltig.',
      );
    }
    await this.assertVaultPackageImportStagingSecurityDirectory(
      securityDirectory,
      securityIdentity,
    );
    const current = await this.requireDirectVaultPackageDirectory(
      stagingRoot,
      'Das interne Tresor-Paket-Stagingverzeichnis wurde waehrend der Paketverarbeitung geaendert.',
    );
    if (!sameDirectoryIdentity(current, stagingRootIdentity)) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das interne Tresor-Paket-Stagingverzeichnis wurde waehrend der Paketverarbeitung geaendert.',
      );
    }
    await this.assertVaultPackageImportStagingSecurityDirectory(
      securityDirectory,
      securityIdentity,
    );
  }

  private async assertVaultPackageImportStagingDirectory(
    staging: VaultPackageImportStagingDirectory,
  ): Promise<void> {
    if (
      path.dirname(staging.directory) !== staging.stagingRoot ||
      !VAULT_PACKAGE_IMPORT_STAGING_ENTRY.test(path.basename(staging.directory))
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Das Paket-Stagingziel ist ungueltig.');
    }
    await this.assertVaultPackageImportStagingRoot(
      staging.securityDirectory,
      staging.securityIdentity,
      staging.stagingRoot,
      staging.stagingRootIdentity,
    );
    const current = await this.requireDirectVaultPackageDirectory(
      staging.directory,
      'Das Paket-Stagingziel wurde waehrend der Paketverarbeitung geaendert.',
    );
    if (!sameDirectoryIdentity(current, staging.directoryIdentity)) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das Paket-Stagingziel wurde waehrend der Paketverarbeitung geaendert.',
      );
    }
    await this.assertVaultPackageImportStagingRoot(
      staging.securityDirectory,
      staging.securityIdentity,
      staging.stagingRoot,
      staging.stagingRootIdentity,
    );
  }

  private async inspectVaultPackageAttachmentStagingFile(
    staging: VaultPackageImportStagingDirectory,
    sourcePath: string,
  ): Promise<PackageFileIdentity> {
    await this.assertVaultPackageImportStagingDirectory(staging);
    const resolved = path.resolve(sourcePath);
    if (
      path.dirname(resolved) !== staging.directory ||
      !/^[0-9a-f-]{36}\.vatt$/iu.test(path.basename(resolved))
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der Paket-Anhangspfad ist ungueltig.');
    }
    const initial = await lstat(resolved).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Der verschluesselte Paket-Anhang wurde nicht angelegt.',
        );
      }
      throw error;
    });
    if (initial.isSymbolicLink() || !initial.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Der verschluesselte Paket-Anhang ist nicht sicher.');
    }
    const canonical = await realpath(resolved).catch((error) => {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Der verschluesselte Paket-Anhang ist nicht sicher.',
        null,
        {
          cause: error,
        },
      );
    });
    const current = await lstat(resolved);
    if (
      current.isSymbolicLink() ||
      !current.isFile() ||
      !samePackageFileIdentity(initial, current) ||
      !sameCanonicalPath(canonical, resolved)
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der verschluesselte Paket-Anhang wurde ausgetauscht.');
    }
    await this.assertVaultPackageImportStagingDirectory(staging);
    return {
      dev: current.dev,
      ino: current.ino,
      size: current.size,
      mtimeMs: current.mtimeMs,
      ctimeMs: current.ctimeMs,
    };
  }

  private async assertVaultPackageAttachmentStagingFileIdentity(
    staging: VaultPackageImportStagingDirectory,
    sourcePath: string,
    expected: PackageFileIdentity,
  ): Promise<void> {
    const current = await this.inspectVaultPackageAttachmentStagingFile(staging, sourcePath);
    if (!samePackageFileIdentity(current, expected)) {
      throw new VaultaError(
        'CONFLICT',
        'Der verschluesselte Paket-Anhang wurde vor dem Import ausgetauscht.',
      );
    }
  }

  private async removeVaultPackageAttachmentStagingFile(
    staging: VaultPackageImportStagingDirectory,
    sourcePath: string,
  ): Promise<void> {
    const expected = await this.inspectVaultPackageAttachmentStagingFile(staging, sourcePath);
    const handle = await open(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW).catch(
      (error) => {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Der verschluesselte Paket-Anhang ist nicht sicher.',
          null,
          {
            cause: error,
          },
        );
      },
    );
    try {
      const opened = await handle.stat();
      const current = await this.inspectVaultPackageAttachmentStagingFile(staging, sourcePath);
      if (
        !samePackageFileIdentity(opened, expected) ||
        !samePackageFileIdentity(current, expected)
      ) {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Der verschluesselte Paket-Anhang wurde waehrend der Bereinigung ausgetauscht.',
        );
      }
    } finally {
      await handle.close().catch(() => undefined);
    }
    await this.assertVaultPackageAttachmentStagingFileIdentity(staging, sourcePath, expected);
    await rm(sourcePath, { force: false }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return;
      throw error;
    });
  }

  private async removeEmptyVaultPackageImportStagingRoot(
    securityDirectory: string,
    securityIdentity: DirectoryIdentity,
    stagingRoot: string,
    stagingRootIdentity: DirectoryIdentity,
  ): Promise<void> {
    await this.assertVaultPackageImportStagingRoot(
      securityDirectory,
      securityIdentity,
      stagingRoot,
      stagingRootIdentity,
    );
    const entries = await readdir(stagingRoot);
    if (entries.length > 0) return;
    await rmdir(stagingRoot).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return;
      if (error.code === 'ENOTEMPTY') {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Das interne Tresor-Paket-Stagingverzeichnis wurde waehrend der Bereinigung geaendert.',
        );
      }
      throw error;
    });
  }

  private async inspectDirectVaultPackageDirectory(
    directory: string,
    message: string,
  ): Promise<DirectoryIdentity | null> {
    const resolved = path.resolve(directory);
    const initial = await lstat(resolved).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (initial === null) return null;
    if (initial.isSymbolicLink() || !initial.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', message);
    }
    const canonical = await realpath(resolved).catch((error) => {
      throw new VaultaError('UNSAFE_PATH', message, null, { cause: error });
    });
    const current = await lstat(resolved).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (
      current === null ||
      current.isSymbolicLink() ||
      !current.isDirectory() ||
      !sameDirectoryIdentity(initial, current) ||
      !sameCanonicalPath(canonical, resolved)
    ) {
      throw new VaultaError('UNSAFE_PATH', message);
    }
    return { dev: current.dev, ino: current.ino };
  }

  private async requireDirectVaultPackageDirectory(
    directory: string,
    message: string,
  ): Promise<DirectoryIdentity> {
    const identity = await this.inspectDirectVaultPackageDirectory(directory, message);
    if (identity === null) throw new VaultaError('UNSAFE_PATH', message);
    return identity;
  }

  private prunePendingVaultPackageImports(): void {
    const now = Date.now();
    for (const [token, pending] of this.pendingVaultPackageImports) {
      if (pending.expiresAt <= now) this.pendingVaultPackageImports.delete(token);
    }
  }

  private takePendingVaultPackageImport(token: string, epoch: number): PendingVaultPackageImport {
    this.prunePendingVaultPackageImports();
    const pending = this.pendingVaultPackageImports.get(token);
    this.pendingVaultPackageImports.delete(token);
    if (pending === undefined || pending.epoch !== epoch) {
      throw new VaultaError(
        'CONFLICT',
        'Die Tresor-Paket-Vorschau ist abgelaufen. Bitte waehle das Paket erneut aus.',
      );
    }
    return pending;
  }

  private async readVaultPackageIdentity(packagePath: string): Promise<PackageFileIdentity> {
    const info = await lstat(packagePath).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Das Tresor-Paket wurde nicht gefunden.');
      }
      throw error;
    });
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Tresor-Paket ist keine regulaere Datei.');
    }
    return {
      dev: info.dev,
      ino: info.ino,
      size: info.size,
      mtimeMs: info.mtimeMs,
      ctimeMs: info.ctimeMs,
    };
  }

  private async assertVaultPackageIdentityUnchanged(
    packagePath: string,
    expected: PackageFileIdentity,
  ): Promise<void> {
    const current = await this.readVaultPackageIdentity(packagePath);
    if (
      current.dev !== expected.dev ||
      current.ino !== expected.ino ||
      current.size !== expected.size ||
      current.mtimeMs !== expected.mtimeMs ||
      current.ctimeMs !== expected.ctimeMs
    ) {
      throw new VaultaError(
        'CONFLICT',
        'Das Tresor-Paket wurde seit der Vorschau geaendert. Bitte pruefe es erneut.',
      );
    }
  }

  private assertPackageAttachmentMetadata(
    expected: {
      readonly attachmentId: string;
      readonly name: string;
      readonly mediaType: string;
      readonly size: number;
      readonly sha256: string;
      readonly createdAt: string;
      readonly previewable: boolean;
    },
    actual: AttachmentMetadata,
  ): void {
    if (
      actual.id !== expected.attachmentId ||
      actual.name !== expected.name ||
      actual.mediaType !== expected.mediaType ||
      actual.size !== expected.size ||
      actual.sha256 !== expected.sha256 ||
      actual.createdAt !== expected.createdAt ||
      actual.previewable !== expected.previewable
    ) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Ein Paket-Anhang konnte nicht mit den geprueften Metadaten verschluesselt werden.',
      );
    }
  }

  private async requireBreachSecurityDirectory(): Promise<string> {
    const directory = await this.inspectBreachSecurityDirectory(true);
    if (directory === null) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das interne Stagingverzeichnis ist nicht sicher verfügbar.',
      );
    }
    return directory;
  }

  private async inspectBreachSecurityDirectory(create: boolean): Promise<string | null> {
    const directory = path.resolve(this.rootDir, 'security');
    let info = await lstat(directory).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (info === null && create) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      info = await lstat(directory).catch((error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
    }
    if (info === null) return null;
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das interne Stagingverzeichnis ist kein reguläres Verzeichnis.',
      );
    }
    return directory;
  }

  private async persistTemplates(): Promise<void> {
    await this.profile.setProtectedMetadata(
      TEMPLATES_NAMESPACE,
      protectedValue(this.templates.snapshot()),
    );
  }

  private async persistSavedViews(): Promise<void> {
    await this.profile.setProtectedMetadata(
      SAVED_VIEWS_NAMESPACE,
      protectedValue(this.productivity.snapshot()),
    );
  }

  private restoreProductivitySnapshot(epoch: number, snapshot: SavedViewRecord[]): void {
    try {
      this.assertAuthenticated(epoch);
      this.productivity = new ProductivityService(snapshot);
    } catch {
      // Lock/dispose already installed the authoritative empty state; never revive it.
    }
  }

  private async mutateVaultWithAudit<T>(
    vaultId: string,
    mutation: (document: VaultDocument) => T,
    auditType: AuditEventType,
    epoch: number,
    entryIdsOf: (result: T) => readonly string[],
  ): Promise<T> {
    return this.vaults.withExclusiveVaults([vaultId], async () =>
      this.audit.withExclusiveWrite(async () => {
        this.assertAuthenticated(epoch);
        const document = await this.vaults.readVault(vaultId);
        const result = mutation(document);
        const entryIds = [...entryIdsOf(result)];
        if (entryIds.length === 0) return result;
        document.updatedAt = new Date().toISOString();
        const preparedDocument = await this.vaults.prepareDocumentWrite(document);
        const preparedAudit = await this.audit.prepareRecords(
          entryIds.map((entryId) => ({ type: auditType, vaultId, entryId })),
        );
        const sensitiveBuffers = [preparedDocument.contents, preparedAudit.contents];
        try {
          this.assertAuthenticated(epoch);
          const changes: MultiFileChange[] = [
            {
              type: 'write',
              relativePath: preparedDocument.relativePath,
              contents: preparedDocument.contents,
              expectedSha256: preparedDocument.expectedSha256,
            },
            {
              type: 'write',
              relativePath: preparedAudit.relativePath,
              contents: preparedAudit.contents,
              expectedSha256: preparedAudit.expectedSha256,
            },
          ];
          await this.transactions.execute(changes, {
            assertAuthorized: () => this.assertAuthenticated(epoch),
          });
          this.vaults.installCommittedDocuments([document]);
          return result;
        } finally {
          for (const buffer of sensitiveBuffers) buffer.fill(0);
        }
      }),
    );
  }

  private async mutateTags(
    vaultId: string,
    mutation: (document: VaultDocument) => string[],
  ): Promise<number> {
    const epoch = this.requireUnlocked();
    const affected = await this.mutateVaultWithAudit(
      vaultId,
      mutation,
      'entry-updated',
      epoch,
      (entryIds) => entryIds,
    );
    return affected.length;
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

  private configureTrashRetention(): void {
    this.trashRetention.stop();
    if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) return;
    const epoch = this.requireUnlocked();
    this.trashRetention.start(this.settings.trashRetentionDays, (context) =>
      this.sweepExpiredTrash(context, epoch),
    );
  }

  private async sweepExpiredTrash(
    context: TrashRetentionSweepContext,
    epoch: number,
  ): Promise<void> {
    context.assertActive();
    this.assertAuthenticated(epoch);
    const vaultIds = (await this.vaults.listVaults()).map((vault) => vault.id);
    context.assertActive();
    this.assertAuthenticated(epoch);
    if (vaultIds.length === 0) return;
    await this.vaults.withExclusiveVaults(vaultIds, async () =>
      this.audit.withExclusiveWrite(async () => {
        const assertAuthorized = () => {
          context.assertActive();
          this.assertAuthenticated(epoch);
        };
        assertAuthorized();
        const documents = await Promise.all(
          vaultIds.map((vaultId) => this.vaults.readVault(vaultId)),
        );
        const timestamp = new Date().toISOString();
        const purged: Array<{
          vaultId: string;
          entryId: string;
          attachmentIds: string[];
        }> = [];
        const changedDocuments: VaultDocument[] = [];
        for (const document of documents) {
          assertAuthorized();
          const expired = document.entries.filter(
            (entry) => entry.deletedAt !== null && entry.deletedAt <= context.cutoff,
          );
          if (expired.length === 0) continue;
          const expiredIds = new Set(expired.map((entry) => entry.id));
          document.entries = document.entries.filter((entry) => !expiredIds.has(entry.id));
          document.updatedAt = timestamp;
          changedDocuments.push(document);
          purged.push(
            ...expired.map((entry) => ({
              vaultId: document.id,
              entryId: entry.id,
              attachmentIds: entry.attachments.map((attachment) => attachment.id),
            })),
          );
        }
        if (purged.length === 0) return;
        const preparedDocuments = await Promise.all(
          changedDocuments.map((document) => this.vaults.prepareDocumentWrite(document)),
        );
        const preparedAudit = await this.audit.prepareRecords(
          purged.map(({ vaultId, entryId }) => ({
            type: 'trash-auto-purged',
            vaultId,
            entryId,
          })),
        );
        const sensitiveBuffers = [
          ...preparedDocuments.map((prepared) => prepared.contents),
          preparedAudit.contents,
        ];
        try {
          const changes: MultiFileChange[] = [
            ...preparedDocuments.map((prepared) => ({
              type: 'write' as const,
              relativePath: prepared.relativePath,
              contents: prepared.contents,
              expectedSha256: prepared.expectedSha256,
            })),
            ...purged.flatMap(({ vaultId, attachmentIds }) =>
              attachmentIds.map((attachmentId): MultiFileChange => ({
                type: 'delete',
                relativePath: path.posix.join('attachments', vaultId, `${attachmentId}.vatt`),
              })),
            ),
            {
              type: 'write',
              relativePath: preparedAudit.relativePath,
              contents: preparedAudit.contents,
              expectedSha256: preparedAudit.expectedSha256,
            },
          ];
          assertAuthorized();
          await this.transactions.execute(changes, { assertAuthorized });
          assertAuthorized();
          this.vaults.installCommittedDocuments(changedDocuments);
          this.localJobs.invalidate();
          this.clearDataQualityState();
          this.entryViews.clearCaches();
        } finally {
          for (const buffer of sensitiveBuffers) buffer.fill(0);
        }
      }),
    );
    context.assertActive();
    this.assertAuthenticated(epoch);
    await this.emitState();
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
      void this.createAutomaticBackup().catch((error: unknown) =>
        this.handleAutomaticBackupFailure(error),
      );
    }, AUTOMATIC_BACKUP_CHECK_MS);
    void this.createAutomaticBackup().catch((error: unknown) =>
      this.handleAutomaticBackupFailure(error),
    );
  }

  private async createAutomaticBackup(): Promise<BackupInfo | null> {
    return this.backupOperations.run(() => this.createAutomaticBackupLocked());
  }

  private async createAutomaticBackupLocked(): Promise<BackupInfo | null> {
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
      this.assertAuthenticated(epoch);
      await this.backupHealth.recordSuccessfulBackup(backup.createdAt);
      this.assertAuthenticated(epoch);
      this.localJobs.invalidate('backup-health');
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

  private async handleAutomaticBackupFailure(error: unknown): Promise<void> {
    const authenticated = this.authentication.isAuthenticated(this.profile.isUnlocked());
    if (authenticated) {
      try {
        const epoch = this.requireUnlocked();
        await this.rememberBackupFailure(error, epoch);
      } catch {
        // Locking wins over best-effort background status persistence. The
        // generic, path-free warning below remains sufficient for the user.
      }
    }
    this.reportAutomaticBackupFailure();
  }

  private async rememberBackupFailure(error: unknown, epoch: number): Promise<void> {
    try {
      this.assertAuthenticated(epoch);
      await this.backupHealth.recordBackupFailure(error);
      this.assertAuthenticated(epoch);
      this.localJobs.invalidate('backup-health');
    } catch (recordError) {
      if (!this.authentication.isAuthenticated(this.profile.isUnlocked())) return;
      if (recordError instanceof VaultaError && recordError.code === 'LOCKED') return;
      this.onBackgroundWarning(
        'Der Status der letzten Sicherung konnte lokal nicht aktualisiert werden.',
      );
    }
  }

  private backupHealthRevision(): string {
    return createHash('sha256')
      .update(
        JSON.stringify({
          backupFolder: this.settings.backupFolder,
          automaticBackups: this.settings.automaticBackups,
          rotation: this.settings.backupRotation,
        }),
      )
      .digest('hex');
  }

  private sendLocalJobProgress(
    requestId: string,
    job: LocalJobKind,
    progress: LocalJobProgress,
  ): void {
    this.getWindow()?.webContents.send(IPC_CHANNELS.eventLocalJobProgress, {
      requestId,
      job,
      ...progress,
    });
  }

  private async emitState(): Promise<AppState> {
    const state = await this.getState();
    this.onStateChanged(state);
    return state;
  }
}
