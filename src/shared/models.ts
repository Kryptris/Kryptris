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
  | 'createdAt'
  | 'updatedAt'
  | 'secretChangedAt'
  | 'lastUsedAt'
  | 'deletedAt'
> & {
  id?: string;
};

export interface Folder {
  id: string;
  name: string;
  color: string;
  createdAt: string;
}

export interface VaultDocument {
  formatVersion: 1;
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
  'weak' | 'reused' | 'old' | 'incomplete' | 'unprotected-key' | 'sensitive-field';

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
  | 'attachment-added'
  | 'attachment-exported'
  | 'private-key-exported'
  | 'import-completed'
  | 'export-completed'
  | 'backup-created'
  | 'backup-restored'
  | 'settings-updated'
  | 'factor-added'
  | 'factor-removed'
  | 'recovery-rotated'
  | 'recovery-used';

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
  reducedMotion: boolean;
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
  reducedMotion: false,
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

export type ExportFormat = 'vaulta-backup' | 'json' | 'csv';

export interface BackupInfo {
  path: string;
  createdAt: string;
  size: number;
  vaultCount: number;
  attachmentCount: number;
  automatic: boolean;
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
