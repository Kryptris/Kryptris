export const ENTRY_TYPES = [
  'credential',
  'secure-note',
  'credit-card',
  'identity',
  'wifi',
  'software-license',
  'ssh-key',
  'file',
  'custom',
] as const;

export type EntryType = (typeof ENTRY_TYPES)[number];

export const ENTRY_TYPE_LABELS: Record<EntryType, string> = {
  credential: 'Zugangsdaten',
  'secure-note': 'Sichere Notizen',
  'credit-card': 'Kreditkarten',
  identity: 'Identitäten',
  wifi: 'WLAN',
  'software-license': 'Softwarelizenzen',
  'ssh-key': 'SSH-Schlüssel',
  file: 'Dateien',
  custom: 'Sonstige',
};

export type CustomFieldType = 'text' | 'secret' | 'url' | 'number' | 'date' | 'boolean';

export interface CustomField {
  id: string;
  label: string;
  type: CustomFieldType;
  value: string | number | boolean;
  secret: boolean;
  searchable: boolean;
  order: number;
}

export interface AttachmentMetadata {
  id: string;
  name: string;
  mediaType: string;
  size: number;
  sha256: string;
  createdAt: string;
  previewable: boolean;
}

export interface TotpConfiguration {
  secret: string;
  issuer: string;
  account: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
}

export interface CredentialData {
  username: string;
  password: string;
  websites: string[];
  appNames: string[];
  totp?: TotpConfiguration;
}

export interface SecureNoteData {
  markdown: string;
}

export interface CreditCardData {
  cardName: string;
  cardholder: string;
  number: string;
  expiryMonth: number;
  expiryYear: number;
  cvc: string;
  pin: string;
  issuer: string;
  cardType: string;
  billingAddress: string;
  servicePhone: string;
  website: string;
}

export interface IdentityAddress {
  id: string;
  label: string;
  street: string;
  postalCode: string;
  city: string;
  region: string;
  country: string;
}

export interface IdentityData {
  salutation: string;
  firstName: string;
  middleName: string;
  lastName: string;
  birthDate: string;
  emails: string[];
  phones: string[];
  addresses: IdentityAddress[];
  idNumber: string;
  passportNumber: string;
  taxNumber: string;
}

export interface WifiData {
  ssid: string;
  password: string;
  security: 'WPA3' | 'WPA2' | 'WPA' | 'WEP' | 'Offen' | 'Andere';
  hidden: boolean;
  routerAddress: string;
  routerUsername: string;
}

export interface SoftwareLicenseData {
  product: string;
  manufacturer: string;
  version: string;
  licenseKey: string;
  licensedTo: string;
  purchaseDate: string;
  activationDate: string;
  expiryDate: string;
  orderNumber: string;
  downloadUrl: string;
  purchasePrice: string;
}

export interface SshKeyData {
  host: string;
  port: number;
  username: string;
  keyType: string;
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  passphrase: string;
}

export interface FileData {
  description: string;
}

export interface CustomData {
  description: string;
}

export type EntryData =
  | { type: 'credential'; value: CredentialData }
  | { type: 'secure-note'; value: SecureNoteData }
  | { type: 'credit-card'; value: CreditCardData }
  | { type: 'identity'; value: IdentityData }
  | { type: 'wifi'; value: WifiData }
  | { type: 'software-license'; value: SoftwareLicenseData }
  | { type: 'ssh-key'; value: SshKeyData }
  | { type: 'file'; value: FileData }
  | { type: 'custom'; value: CustomData };

export interface EntryLifecycleMetadata {
  rotationIntervalDays: number | null;
  nextRotationDate: string | null;
  rotationExcluded: boolean;
  twoFactorStatus: 'unknown' | 'active' | 'inactive';
  expiryReminderDate: string | null;
}

export const DEFAULT_ENTRY_LIFECYCLE_METADATA: Readonly<EntryLifecycleMetadata> = Object.freeze({
  rotationIntervalDays: null,
  nextRotationDate: null,
  rotationExcluded: false,
  twoFactorStatus: 'unknown',
  expiryReminderDate: null,
});

export function createDefaultEntryLifecycleMetadata(): EntryLifecycleMetadata {
  return { ...DEFAULT_ENTRY_LIFECYCLE_METADATA };
}

export interface VaultEntry {
  id: string;
  vaultId: string;
  title: string;
  folderId: string | null;
  tags: string[];
  favorite: boolean;
  note: string;
  customFields: CustomField[];
  attachments: AttachmentMetadata[];
  data: EntryData;
  lifecycle: EntryLifecycleMetadata;
  createdAt: string;
  updatedAt: string;
  secretChangedAt: string;
  lastUsedAt: string | null;
  deletedAt: string | null;
}

export type EntryInput = Omit<
  VaultEntry,
  | 'id'
  | 'vaultId'
  | 'attachments'
  | 'lifecycle'
  | 'createdAt'
  | 'updatedAt'
  | 'secretChangedAt'
  | 'lastUsedAt'
  | 'deletedAt'
> & {
  id?: string;
  lifecycle?: EntryLifecycleMetadata;
};

export interface Folder {
  id: string;
  name: string;
  color: string;
  createdAt: string;
}

export type VaultEntryV1 = Omit<VaultEntry, 'lifecycle'>;

export interface VaultDocumentV1 {
  formatVersion: 1;
  id: string;
  name: string;
  color: string;
  createdAt: string;
  updatedAt: string;
  folders: Folder[];
  entries: VaultEntryV1[];
}

export interface VaultDocument {
  formatVersion: 2;
  id: string;
  name: string;
  color: string;
  createdAt: string;
  updatedAt: string;
  folders: Folder[];
  entries: VaultEntry[];
}

export interface VaultSummary {
  id: string;
  name: string;
  color: string;
  entryCount: number;
  deletedCount: number;
  updatedAt: string;
}

export interface EntrySummary {
  id: string;
  vaultId: string;
  type: EntryType;
  title: string;
  subtitle: string;
  favorite: boolean;
  tags: string[];
  folderId: string | null;
  securityState: SecuritySeverity;
  updatedAt: string;
  deletedAt: string | null;
}

export type DisplayFieldKind =
  'text' | 'secret' | 'url' | 'multiline' | 'markdown' | 'boolean' | 'date';

export interface DisplayField {
  path: string;
  label: string;
  kind: DisplayFieldKind;
  secret: boolean;
  value?: string;
  copyable: boolean;
  openable: boolean;
}

export interface EntryDetail {
  id: string;
  vaultId: string;
  type: EntryType;
  title: string;
  favorite: boolean;
  tags: string[];
  folderId: string | null;
  note: string;
  fields: DisplayField[];
  attachments: AttachmentMetadata[];
  lifecycle: EntryLifecycleMetadata;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

export type EntryView = 'all' | 'favorites' | 'trash' | 'recent';

export interface EntryListQuery {
  vaultId: string;
  search: string;
  view: EntryView;
  types: EntryType[];
  tags: string[];
  folderId: string | null;
  security: SecuritySeverity[];
  smartView?: SmartViewKind | null;
}

export const SMART_VIEW_KINDS = [
  'recently-changed',
  'without-folder',
  'without-tags',
  'rotation-due',
  'without-two-factor',
  'with-attachments',
] as const;

export type SmartViewKind = (typeof SMART_VIEW_KINDS)[number];

export const SMART_VIEW_LABELS: Record<SmartViewKind, string> = {
  'recently-changed': 'Kürzlich geändert',
  'without-folder': 'Ohne Ordner',
  'without-tags': 'Ohne Tags',
  'rotation-due': 'Rotation fällig',
  'without-two-factor': 'Ohne Zwei-Faktor-Schutz',
  'with-attachments': 'Mit Anhängen',
};

export interface SavedViewFilters {
  search: string;
  view: EntryView;
  types: EntryType[];
  tags: string[];
  folderId: string | null;
  security: SecuritySeverity[];
  smartView: SmartViewKind | null;
}

export interface SavedViewRecord {
  id: string;
  vaultId: string;
  name: string;
  filters: SavedViewFilters;
  order: number;
  createdAt: string;
  updatedAt: string;
}

export interface SavedView extends SavedViewRecord {
  invalidReferences: {
    folder: boolean;
    tags: string[];
  };
}

export interface TagSummary {
  name: string;
  normalizedName: string;
  usageCount: number;
}

export type BatchEntryAction =
  | { type: 'favorite'; value: boolean }
  | { type: 'tags-add'; tags: string[] }
  | { type: 'tags-remove'; tags: string[] }
  | { type: 'folder-set'; folderId: string | null }
  | { type: 'trash' }
  | { type: 'restore' }
  | { type: 'purge'; masterPassword: string; confirmationCount: number }
  | { type: 'copy-to-vault'; targetVaultId: string }
  | { type: 'move-to-vault'; targetVaultId: string };

export interface BatchEntryInput {
  vaultId: string;
  entryIds: string[];
  action: BatchEntryAction;
}

export interface BatchEntryResult {
  affected: number;
  entryIds: string[];
}

export const DUPLICATE_REASON_CODES = [
  'title',
  'credential-username',
  'credential-website-host',
  'credential-app-name',
  'credential-password',
  'credential-totp-secret',
  'secure-note-content',
  'credit-card-number',
  'credit-card-cardholder',
  'credit-card-issuer',
  'credit-card-expiry',
  'credit-card-website-host',
  'identity-name',
  'identity-email',
  'identity-phone',
  'identity-address',
  'identity-government-id',
  'wifi-ssid',
  'wifi-router-host',
  'wifi-router-username',
  'wifi-password',
  'software-product',
  'software-order-number',
  'software-download-host',
  'software-license-key',
  'ssh-host',
  'ssh-username',
  'ssh-fingerprint',
  'ssh-public-key',
  'ssh-private-key',
  'file-description',
  'file-attachment',
  'custom-description',
  'custom-field',
  'custom-secret-field',
] as const;

export type DuplicateReasonCode = (typeof DUPLICATE_REASON_CODES)[number];

export interface DuplicateEntryReferenceDto {
  vaultId: string;
  entryId: string;
  updatedAt: string;
}

export interface DuplicateCandidateSideDto extends DuplicateEntryReferenceDto {
  title: string;
  subtitle: string;
  vaultName?: string;
}

export interface DuplicateCandidateDto {
  left: DuplicateCandidateSideDto;
  right: DuplicateCandidateSideDto;
  type: EntryType;
  confidence: 'possible' | 'likely';
  reasons: DuplicateReasonCode[];
}

export interface DuplicateScanDto {
  candidates: DuplicateCandidateDto[];
  activeEntryCount: number;
  truncated: boolean;
}

export interface DuplicateMergeFieldDto {
  field: string;
  label: string;
  secret: boolean;
  survivorPreview: string;
  duplicatePreview: string;
}

export interface DuplicateMergeCollectionDto {
  field: string;
  label: string;
  survivorCount: number;
  duplicateCount: number;
  supportsUnion: true;
}

export interface DuplicateMergeDescriptionDto {
  survivor: DuplicateCandidateSideDto;
  duplicate: DuplicateCandidateSideDto;
  type: EntryType;
  scalarFields: DuplicateMergeFieldDto[];
  collectionFields: DuplicateMergeCollectionDto[];
  potentialAttachmentDuplicates: number;
  duplicateDisposition: 'trash';
}

export interface DuplicateMergeChoiceDto {
  field: string;
  source: 'survivor' | 'duplicate';
}

export interface DuplicateMergeCollectionChoiceDto {
  field: string;
  strategy: 'survivor' | 'duplicate' | 'union';
}

export interface DuplicateMergeResultDto {
  survivor: DuplicateEntryReferenceDto;
  duplicate: DuplicateEntryReferenceDto;
  copiedAttachments: number;
  deduplicatedAttachments: number;
}

export type DataQualityFindingCode =
  | 'invalid-url'
  | 'url-needs-normalization'
  | 'duplicate-website'
  | 'similar-website'
  | 'empty-title'
  | 'import-placeholder-title'
  | 'expired-credit-card'
  | 'expired-license'
  | 'unusual-totp-parameters'
  | 'attachment-metadata-mismatch'
  | 'attachment-file-missing'
  | 'attachment-file-corrupt'
  | 'attachment-file-orphan'
  | 'orphan-folder-reference'
  | 'saved-view-orphan-reference';

export type DataQualityFixCode =
  | 'normalize-url-https-whitespace'
  | 'remove-exact-duplicate-url'
  | 'replace-unambiguous-title'
  | 'clear-orphan-folder'
  | 'remove-saved-view-references'
  | 'update-authenticated-attachment-metadata';

export type DataQualityReferenceDto =
  | { kind: 'entry'; vaultId: string; entryId: string; updatedAt: string }
  | {
      kind: 'saved-view';
      vaultId: string;
      savedViewId: string;
      updatedAt: string;
    }
  | {
      kind: 'attachment';
      vaultId: string;
      entryId: string | null;
      attachmentId: string;
      updatedAt: string;
    };

export interface DataQualityFindingDto {
  id: string;
  code: DataQualityFindingCode;
  severity: 'info' | 'warning';
  reference: DataQualityReferenceDto;
  fixCode: DataQualityFixCode | null;
}

export interface DataQualityReportDto {
  generatedAt: string;
  vaultId: string;
  scannedEntries: number;
  findings: DataQualityFindingDto[];
  networkUsed: false;
}

export interface DataQualityFixPreviewDto {
  token: string;
  findingId: string;
  title: string;
  description: string;
  expiresAt: string;
}

export interface DataQualityFixResultDto {
  affectedEntryIds: string[];
  savedViewsChanged: number;
}

export type LocalJobKind =
  | 'duplicates'
  | 'data-quality'
  | 'security-center'
  | 'integrity'
  | 'breach-import'
  | 'breach-scan'
  | 'backup-health'
  | 'backup-dry-run';

export interface LocalJobProgressEvent {
  requestId: string;
  job: LocalJobKind;
  phase: string;
  completed: number;
  total: number;
}

export interface PasswordGeneratorOptions {
  mode: 'password' | 'passphrase';
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeSimilar: boolean;
  excludedCharacters: string;
  requiredCharacters: string;
  minimumUppercase: number;
  minimumLowercase: number;
  minimumNumbers: number;
  minimumSymbols: number;
  wordCount: number;
  separator: string;
  capitalizeWords: boolean;
  includeNumber: boolean;
}

export interface GeneratedSecret {
  value: string;
  score: number;
  label: string;
  crackTime: string;
}

export interface TotpCode {
  code: string;
  period: number;
  remainingSeconds: number;
}

export type SecuritySeverity = 'good' | 'info' | 'warning' | 'critical';

export type SecurityFindingKind =
  | 'weak'
  | 'reused'
  | 'old'
  | 'incomplete'
  | 'unprotected-key'
  | 'sensitive-field'
  | 'rotation-due'
  | 'two-factor-missing'
  | 'expiry-reminder-due';

export interface SecurityFinding {
  id: string;
  entryId: string;
  entryTitle: string;
  kind: SecurityFindingKind;
  severity: SecuritySeverity;
  title: string;
  recommendation: string;
}

export interface SecurityReport {
  generatedAt: string;
  score: number;
  counts: Record<SecuritySeverity, number>;
  findings: SecurityFinding[];
  networkUsed: false;
}

export type SecurityCenterCardId =
  | 'credentials'
  | 'data-quality'
  | 'factors'
  | 'backup'
  | 'recovery'
  | 'kdf'
  | 'integrity'
  | 'breach-list';

export type SecurityCenterFindingCode =
  | 'credential-findings'
  | 'data-quality-findings'
  | 'additional-factor-missing'
  | 'automatic-backup-disabled'
  | 'automatic-backup-missing'
  | 'automatic-backup-stale'
  | 'recovery-not-configured'
  | 'recovery-never-tested'
  | 'recovery-test-failed'
  | 'recovery-test-stale'
  | 'kdf-outdated'
  | 'integrity-not-run'
  | 'integrity-failed'
  | 'breach-list-not-configured'
  | 'breach-list-missing'
  | 'breach-list-corrupt'
  | 'breached-passwords-found';

export type SecurityCenterAction =
  | 'review-credentials'
  | 'review-data-quality'
  | 'open-factor-settings'
  | 'open-backups'
  | 'test-recovery'
  | 'change-master-password'
  | 'run-integrity'
  | 'configure-breach-list'
  | 'review-breach-findings'
  | 'none';

export interface SecurityCenterCardDto {
  id: SecurityCenterCardId;
  severity: SecuritySeverity;
  findingCodes: SecurityCenterFindingCode[];
  count: number;
  calculatedAt: string | null;
  action: SecurityCenterAction;
}

export interface SecurityCenterEntryFindingDto extends SecurityFinding {
  vaultId: string;
  vaultName: string;
}

export interface SecurityCenterReportDto {
  generatedAt: string;
  score: number;
  cards: SecurityCenterCardDto[];
  entryFindings: SecurityCenterEntryFindingDto[];
  networkUsed: false;
}

export type RecoveryReadinessState =
  'not-configured' | 'never-tested' | 'failed' | 'stale' | 'ready';

export interface RecoveryReadinessStatusDto {
  state: RecoveryReadinessState;
  lastTestedAt: string | null;
  lastTestSucceeded: boolean | null;
  staleAfterDays: number;
}

export type IntegrityFindingCode =
  | 'profile-invalid'
  | 'profile-metadata-invalid'
  | 'profile-factor-invalid'
  | 'vault-registry-mismatch'
  | 'vault-container-invalid'
  | 'audit-invalid'
  | 'duplicate-vault-id'
  | 'duplicate-folder-id'
  | 'duplicate-entry-id'
  | 'entry-vault-mismatch'
  | 'folder-reference-invalid'
  | 'saved-view-reference-invalid'
  | 'attachment-reference-duplicate'
  | 'attachment-missing'
  | 'attachment-orphan'
  | 'attachment-container-invalid'
  | 'attachment-metadata-mismatch';

export interface IntegrityFindingDto {
  id: string;
  code: IntegrityFindingCode;
  severity: 'warning' | 'critical';
  scope: 'profile' | 'vault' | 'audit' | 'attachment' | 'reference';
}

export interface IntegrityReportDto {
  reportId: string;
  generatedAt: string;
  success: boolean;
  scannedVaults: number;
  scannedEntries: number;
  scannedAttachments: number;
  findings: IntegrityFindingDto[];
  networkUsed: false;
}

export type BreachListState = 'not-configured' | 'ready' | 'missing' | 'corrupt';

export interface BreachListStatusDto {
  state: BreachListState;
  sourceLabel: string | null;
  sourceDate: string | null;
  importedAt: string | null;
  recordCount: number;
  corpusSha256: string | null;
  networkUsed: false;
}

export interface BreachFindingDto {
  id: string;
  vaultId: string;
  vaultName: string;
  entryId: string;
  entryTitle: string;
  entryUpdatedAt: string;
  code: 'known-breached-password';
  severity: 'critical';
}

export interface BreachScanReportDto {
  generatedAt: string;
  checkedEntries: number;
  checkedPasswords: number;
  findings: BreachFindingDto[];
  networkUsed: false;
}

export type AuditEventType =
  | 'profile-created'
  | 'unlocked'
  | 'unlock-failed'
  | 'locked'
  | 'vault-created'
  | 'vault-updated'
  | 'vault-deleted'
  | 'entry-created'
  | 'entry-updated'
  | 'entry-moved-to-trash'
  | 'entry-restored'
  | 'entry-purged'
  | 'entry-copied-to-vault'
  | 'entry-moved-to-vault'
  | 'entries-merged'
  | 'data-quality-fixed'
  | 'trash-auto-purged'
  | 'attachment-added'
  | 'attachment-exported'
  | 'private-key-exported'
  | 'import-completed'
  | 'export-completed'
  | 'backup-created'
  | 'backup-restored'
  | 'backup-dry-run-completed'
  | 'import-mapping-profile-updated'
  | 'vault-package-exported'
  | 'vault-package-imported'
  | 'settings-updated'
  | 'factor-added'
  | 'factor-removed'
  | 'recovery-rotated'
  | 'recovery-used'
  | 'recovery-readiness-succeeded'
  | 'recovery-readiness-failed'
  | 'integrity-check-completed'
  | 'breach-list-imported'
  | 'breach-list-removed';

export interface AuditEvent {
  id: string;
  occurredAt: string;
  type: AuditEventType;
  vaultId: string | null;
  entryId: string | null;
  summary: string;
}

export interface BackupRotation {
  daily: number;
  weekly: number;
  monthly: number;
}

/** Opt-in categories for local Windows notifications. */
export interface LocalReminderSettings {
  rotation: boolean;
  expiry: boolean;
  backup: boolean;
}

export interface VaultaSettings {
  autoLockSeconds: number;
  lockOnMinimize: boolean;
  lockOnSystemLock: boolean;
  lockOnSuspend: boolean;
  clipboardClearSeconds: number;
  requireMasterForReveal: boolean;
  contentProtection: boolean;
  attachmentMaxBytes: number;
  backupFolder: string | null;
  automaticBackups: boolean;
  backupRotation: BackupRotation;
  auditMaxEvents: number;
  auditRetentionDays: number;
  trashRetentionDays: number | null;
  reducedMotion: boolean;
  minimizeToTray: boolean;
  closeToTray: boolean;
  startWithWindows: boolean;
  startMinimized: boolean;
  focusMode: boolean;
  localReminders: LocalReminderSettings;
  /** False only for profiles created after the W11 introduction. */
  onboardingCompleted: boolean;
}

export const DEFAULT_SETTINGS: VaultaSettings = {
  autoLockSeconds: 300,
  lockOnMinimize: false,
  lockOnSystemLock: true,
  lockOnSuspend: true,
  clipboardClearSeconds: 30,
  requireMasterForReveal: false,
  contentProtection: true,
  attachmentMaxBytes: 100 * 1024 * 1024,
  backupFolder: null,
  automaticBackups: false,
  backupRotation: { daily: 7, weekly: 4, monthly: 6 },
  auditMaxEvents: 5_000,
  auditRetentionDays: 180,
  trashRetentionDays: null,
  reducedMotion: false,
  minimizeToTray: false,
  closeToTray: false,
  startWithWindows: false,
  startMinimized: false,
  focusMode: false,
  localReminders: {
    rotation: false,
    expiry: false,
    backup: false,
  },
  onboardingCompleted: false,
};

export interface FactorStatus {
  totpEnabled: boolean;
  securityKeys: Array<{
    id: string;
    name: string;
    mode: 'prf' | 'presence';
    createdAt: string;
  }>;
  recoveryEnabled: boolean;
}

export interface AppState {
  hasProfile: boolean;
  locked: boolean;
  activeVaultId: string | null;
  vaults: VaultSummary[];
  factorStatus: FactorStatus;
  settings: VaultaSettings | null;
  autoLockAt: string | null;
  version: string;
}

export interface RecoverySetup {
  displayKey: string;
  groups: string[];
  confirmationIndexes: number[];
}

export interface RecoveryRotationStarted {
  pendingId: string;
  recovery: RecoverySetup;
}

export interface SetupStarted {
  pendingId: string;
  recovery: RecoverySetup | null;
}

export interface UnlockResult {
  status: 'unlocked' | 'totp-required' | 'security-key-required';
  securityKeyOptions?: unknown;
  challengeId?: string;
}

export type ImportFormat =
  | 'bitwarden-json'
  | 'onepassword-csv'
  | 'lastpass-csv'
  | 'keepass-csv'
  | 'protonpass-json'
  | 'dashlane-csv'
  | 'nordpass-csv'
  | 'roboform-csv'
  | 'chrome-csv'
  | 'edge-csv'
  | 'firefox-csv'
  | 'generic-csv'
  | 'generic-json';

export interface ImportMapping {
  title: string;
  username: string;
  password: string;
  url: string;
  note: string;
  folder: string;
  tags: string;
}

export interface ImportCandidate {
  sourceIndex: number;
  title: string;
  username: string;
  website: string;
  type: EntryType;
  duplicateOf: string | null;
  warnings: string[];
  selected: boolean;
}

export interface ImportPreview {
  token: string;
  format: ImportFormat;
  sourceName: string;
  candidates: ImportCandidate[];
  errors: Array<{ row: number; message: string }>;
  detectedColumns: string[];
  mapping: ImportMapping | null;
}

/** Reusable column selectors only; imported field values are never persisted here. */
export interface ImportMappingProfile {
  id: string;
  name: string;
  mapping: ImportMapping;
  updatedAt: string;
}

/** Redacted result counts for an import preview or completed import. */
export interface ImportSummary {
  newEntries: number;
  skippedEntries: number;
  duplicates: number;
  warnings: number;
  invalidRows: number;
}

export type ExportFormat = 'vaulta-backup' | 'json' | 'csv';

export interface BackupInfo {
  path: string;
  createdAt: string;
  size: number;
  vaultCount: number;
  attachmentCount: number;
  automatic: boolean;
}

export interface BackupGenerationCounts {
  daily: number;
  weekly: number;
  monthly: number;
}

export type BackupHealthFailureCode =
  | 'AUTH_FAILED'
  | 'AUTH_FACTOR_REQUIRED'
  | 'AUTH_RATE_LIMITED'
  | 'CORRUPT_DATA'
  | 'INVALID_INPUT'
  | 'LOCKED'
  | 'NOT_FOUND'
  | 'CANCELLED'
  | 'CONFLICT'
  | 'FILE_TOO_LARGE'
  | 'UNSUPPORTED_FORMAT'
  | 'UNSAFE_PATH'
  | 'INTERNAL';

/** Path-free backup status. File names and target locations stay Main-only. */
export interface BackupHealthSnapshot {
  targetReachable: boolean;
  sameDriveWarning: boolean;
  backupCount: number;
  unreadableBackupCount: number;
  totalSize: number;
  generations: BackupGenerationCounts;
  latestBackup: {
    createdAt: string;
    size: number;
    vaultCount: number;
    attachmentCount: number;
    automatic: boolean;
  } | null;
  lastSuccessfulBackupAt: string | null;
  lastFailure: { occurredAt: string; code: BackupHealthFailureCode } | null;
  lastSemanticVerificationAt: string | null;
}

export interface RestoreDryRunResult {
  profileId: string;
  createdAt: string;
  fileCount: number;
  vaultCount: number;
  attachmentCount: number;
  automatic: boolean;
  verifiedAt: string;
  semanticallyVerified: true;
}

export interface VaultPackageExportResult {
  createdAt: string;
  entryCount: number;
  attachmentCount: number;
  includesAttachments: boolean;
}

/** Redacted package information; it never includes a source path or secret. */
export interface VaultPackagePreviewDto {
  token: string;
  createdAt: string;
  vaultName: string;
  color: string;
  entryCount: number;
  attachmentCount: number;
  includesAttachments: boolean;
  nameConflict: boolean;
}

export interface VaultPackageImportResult {
  vaultId: string;
  vaultName: string;
  entryCount: number;
  attachmentCount: number;
}

export interface EntryTemplate {
  id: string;
  name: string;
  entryType: EntryType;
  fields: Array<{
    label: string;
    type: CustomFieldType;
    secret: boolean;
    defaultValue: string | number | boolean;
  }>;
  createdAt: string;
  updatedAt: string;
}

export interface LocalReport {
  generatedAt: string;
  vaultCount: number;
  entryCount: number;
  favoriteCount: number;
  trashCount: number;
  attachmentCount: number;
  attachmentBytes: number;
  typeCounts: Record<EntryType, number>;
  security: SecurityReport;
  oldestEntries: EntrySummary[];
  networkUsed: false;
}

export interface AttachmentPreview {
  kind: 'text' | 'image' | 'pdf';
  mediaType: string;
  data: string;
}

export interface WebAuthnRegistrationResult {
  verified: boolean;
  mode: 'prf' | 'presence';
  warning: string | null;
}

export interface WebAuthnAuthenticationResult {
  verified: boolean;
  unlocked: boolean;
}
