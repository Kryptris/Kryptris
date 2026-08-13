import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type {
  AttachmentMetadata,
  CustomField,
  EntryType,
  IdentityAddress,
  VaultEntry,
} from '../../shared/models';
import { normalizeTags } from '../../shared/tags';

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

export interface DuplicateEntryReference {
  vaultId: string;
  entryId: string;
  updatedAt: string;
}

export interface DuplicateCandidate {
  left: DuplicateEntryReference;
  right: DuplicateEntryReference;
  type: EntryType;
  confidence: 'possible' | 'likely';
  reasons: DuplicateReasonCode[];
}

export interface DuplicateScanProgress {
  phase: 'indexing' | 'matching';
  processed: number;
  total: number;
  candidates: number;
}

export interface DuplicateScanOptions {
  candidateLimit?: number;
  assertAuthorized?: () => void;
  onProgress?: (progress: DuplicateScanProgress) => void;
  signal?: AbortSignal;
}

export interface DuplicateScanResult {
  candidates: DuplicateCandidate[];
  activeEntryCount: number;
  truncated: boolean;
}

export interface DuplicateServiceDependencies {
  /** Transfers ownership of a fresh writable key to the service. The service erases it. */
  createHmacKey: () => Buffer;
  yieldControl: () => Promise<void>;
}

/**
 * A short-lived, in-memory matcher for pipelines which already operate synchronously.
 *
 * Implementations retain transient entry references and normalized comparison features only for
 * the duration of the {@link DuplicateService.withMatcher} callback which created them.
 */
export interface DuplicateMatcher {
  /**
   * Compares the entry with active entries previously added to this matcher and then indexes it.
   * Deleted entries are ignored.
   */
  add(entry: VaultEntry): DuplicateCandidate[];
}

export const DUPLICATE_MERGE_SCALAR_FIELDS = [
  'title',
  'folderId',
  'favorite',
  'credential.username',
  'credential.password',
  'credential.totp',
  'credit-card.cardName',
  'credit-card.cardholder',
  'credit-card.number',
  'credit-card.expiryMonth',
  'credit-card.expiryYear',
  'credit-card.cvc',
  'credit-card.pin',
  'credit-card.issuer',
  'credit-card.cardType',
  'credit-card.billingAddress',
  'credit-card.servicePhone',
  'credit-card.website',
  'identity.salutation',
  'identity.firstName',
  'identity.middleName',
  'identity.lastName',
  'identity.birthDate',
  'identity.idNumber',
  'identity.passportNumber',
  'identity.taxNumber',
  'wifi.ssid',
  'wifi.password',
  'wifi.security',
  'wifi.hidden',
  'wifi.routerAddress',
  'wifi.routerUsername',
  'software-license.product',
  'software-license.manufacturer',
  'software-license.version',
  'software-license.licenseKey',
  'software-license.licensedTo',
  'software-license.purchaseDate',
  'software-license.activationDate',
  'software-license.expiryDate',
  'software-license.orderNumber',
  'software-license.downloadUrl',
  'software-license.purchasePrice',
  'ssh-key.host',
  'ssh-key.port',
  'ssh-key.username',
  'ssh-key.keyType',
  'ssh-key.fingerprint',
  'ssh-key.publicKey',
  'ssh-key.privateKey',
  'ssh-key.passphrase',
  'file.description',
  'custom.description',
] as const;

export type DuplicateMergeScalarField = (typeof DUPLICATE_MERGE_SCALAR_FIELDS)[number];

export const DUPLICATE_MERGE_COLLECTION_FIELDS = [
  'tags',
  'note',
  'customFields',
  'attachments',
  'credential.websites',
  'credential.appNames',
  'secure-note.markdown',
  'identity.emails',
  'identity.phones',
  'identity.addresses',
] as const;

export type DuplicateMergeCollectionField = (typeof DUPLICATE_MERGE_COLLECTION_FIELDS)[number];
export type DuplicateMergeSource = 'survivor' | 'duplicate';
export type DuplicateMergeCollectionStrategy = DuplicateMergeSource | 'union';

export interface DuplicateMergeFieldChoice {
  field: DuplicateMergeScalarField;
  source: DuplicateMergeSource;
}

export interface DuplicateMergeCollectionChoice {
  field: DuplicateMergeCollectionField;
  strategy: DuplicateMergeCollectionStrategy;
}

export interface DuplicateMergeIdReplacement {
  sourceId: string;
  targetId: string;
}

export interface VerifiedAttachmentDuplicate {
  duplicateAttachmentId: string;
  survivorAttachmentId: string;
}

export interface DuplicateMergeInput {
  survivor: VaultEntry;
  duplicate: VaultEntry;
  now: string;
  fieldChoices?: readonly DuplicateMergeFieldChoice[];
  collectionChoices?: readonly DuplicateMergeCollectionChoice[];
  customFieldIdReplacements?: readonly DuplicateMergeIdReplacement[];
  identityAddressIdReplacements?: readonly DuplicateMergeIdReplacement[];
  attachmentIdReplacements?: readonly DuplicateMergeIdReplacement[];
  /** Every pair must already have passed authenticated content verification outside this service. */
  verifiedAttachmentDuplicates?: readonly VerifiedAttachmentDuplicate[];
}

export interface DuplicateMergeFieldDescription {
  field: DuplicateMergeScalarField;
  secret: boolean;
}

export interface DuplicateMergeCollectionDescription {
  field: DuplicateMergeCollectionField;
  supportsUnion: true;
}

export interface DuplicateMergeDescription {
  survivor: DuplicateEntryReference;
  duplicate: DuplicateEntryReference;
  type: EntryType;
  scalarFields: DuplicateMergeFieldDescription[];
  collectionFields: DuplicateMergeCollectionDescription[];
  idCollisions: {
    customFieldIds: string[];
    identityAddressIds: string[];
    attachmentIds: string[];
  };
  potentialAttachmentDuplicates: VerifiedAttachmentDuplicate[];
  duplicateDisposition: 'trash';
}

export interface DuplicateAttachmentCopy {
  sourceVaultId: string;
  sourceAttachmentId: string;
  targetVaultId: string;
  targetAttachmentId: string;
}

export interface DuplicateMergePlan {
  survivor: VaultEntry;
  duplicate: VaultEntry;
  duplicateDisposition: 'trash';
  changedSecretSemantics: boolean;
  attachmentCopies: DuplicateAttachmentCopy[];
  detachedSurvivorAttachmentIds: string[];
}

interface MatchFeature {
  reason: DuplicateReasonCode;
  key: string;
  weight: number;
}

interface IndexedEntry {
  entry: VaultEntry;
  reference: DuplicateEntryReference;
  features: MatchFeature[];
}

interface FeatureBucket {
  reason: DuplicateReasonCode;
  weight: number;
  entries: number[];
}

interface CollectionPlanState {
  customFieldReplacements: Map<string, string>;
  identityAddressReplacements: Map<string, string>;
  attachmentReplacements: Map<string, string>;
  consumedCustomFieldReplacements: Set<string>;
  consumedIdentityAddressReplacements: Set<string>;
  consumedAttachmentReplacements: Set<string>;
}

const DEFAULT_CANDIDATE_LIMIT = 500;
const MAX_CANDIDATE_LIMIT = 10_000;
const MIN_MATCH_SCORE = 3;
const LIKELY_MATCH_SCORE = 4;
const CHECKPOINT_INTERVAL = 128;
const COMMON_SCALAR_FIELDS = ['title', 'folderId', 'favorite'] as const;
const COMMON_COLLECTION_FIELDS = ['tags', 'note', 'customFields', 'attachments'] as const;
const SECRET_SCALAR_FIELDS = new Set<DuplicateMergeScalarField>([
  'credential.password',
  'credential.totp',
  'credit-card.number',
  'credit-card.cvc',
  'credit-card.pin',
  'identity.idNumber',
  'identity.passportNumber',
  'identity.taxNumber',
  'wifi.password',
  'software-license.licenseKey',
  'ssh-key.privateKey',
  'ssh-key.passphrase',
]);
const REASON_ORDER = new Map<DuplicateReasonCode, number>(
  DUPLICATE_REASON_CODES.map((reason, index) => [reason, index]),
);

const TYPE_SCALAR_FIELDS: Record<EntryType, readonly DuplicateMergeScalarField[]> = {
  credential: ['credential.username', 'credential.password', 'credential.totp'],
  'secure-note': [],
  'credit-card': [
    'credit-card.cardName',
    'credit-card.cardholder',
    'credit-card.number',
    'credit-card.expiryMonth',
    'credit-card.expiryYear',
    'credit-card.cvc',
    'credit-card.pin',
    'credit-card.issuer',
    'credit-card.cardType',
    'credit-card.billingAddress',
    'credit-card.servicePhone',
    'credit-card.website',
  ],
  identity: [
    'identity.salutation',
    'identity.firstName',
    'identity.middleName',
    'identity.lastName',
    'identity.birthDate',
    'identity.idNumber',
    'identity.passportNumber',
    'identity.taxNumber',
  ],
  wifi: [
    'wifi.ssid',
    'wifi.password',
    'wifi.security',
    'wifi.hidden',
    'wifi.routerAddress',
    'wifi.routerUsername',
  ],
  'software-license': [
    'software-license.product',
    'software-license.manufacturer',
    'software-license.version',
    'software-license.licenseKey',
    'software-license.licensedTo',
    'software-license.purchaseDate',
    'software-license.activationDate',
    'software-license.expiryDate',
    'software-license.orderNumber',
    'software-license.downloadUrl',
    'software-license.purchasePrice',
  ],
  'ssh-key': [
    'ssh-key.host',
    'ssh-key.port',
    'ssh-key.username',
    'ssh-key.keyType',
    'ssh-key.fingerprint',
    'ssh-key.publicKey',
    'ssh-key.privateKey',
    'ssh-key.passphrase',
  ],
  file: ['file.description'],
  custom: ['custom.description'],
};

const TYPE_COLLECTION_FIELDS: Record<EntryType, readonly DuplicateMergeCollectionField[]> = {
  credential: ['credential.websites', 'credential.appNames'],
  'secure-note': ['secure-note.markdown'],
  'credit-card': [],
  identity: ['identity.emails', 'identity.phones', 'identity.addresses'],
  wifi: [],
  'software-license': [],
  'ssh-key': [],
  file: [],
  custom: [],
};

export class DuplicateService {
  private readonly createHmacKey: () => Buffer;
  private readonly yieldControl: () => Promise<void>;

  public constructor(dependencies: Partial<DuplicateServiceDependencies> = {}) {
    this.createHmacKey = dependencies.createHmacKey ?? (() => randomBytes(32));
    this.yieldControl =
      dependencies.yieldControl ?? (() => new Promise((resolve) => setImmediate(resolve)));
  }

  /**
   * Runs a synchronous pipeline against the same type-specific matching core as {@link scan}.
   *
   * The matcher and its HMAC key are scoped to the callback. The key is erased before this method
   * returns or rethrows, so callers cannot accidentally retain a secret-comparison index.
   */
  public withMatcher<T>(operation: (matcher: DuplicateMatcher) => T): T {
    const hmacKey = this.acquireHmacKey();
    const matcher = new IncrementalDuplicateMatcher(hmacKey);
    try {
      return operation(matcher);
    } finally {
      matcher.dispose();
      hmacKey.fill(0);
    }
  }

  public async scan(
    entries: readonly VaultEntry[],
    options: DuplicateScanOptions = {},
  ): Promise<DuplicateScanResult> {
    const candidateLimit = validateCandidateLimit(options.candidateLimit);
    assertCanContinue(options);
    const activeEntries = [...entries]
      .filter((entry) => entry.deletedAt === null)
      .sort(compareEntries);
    assertUniqueEntryReferences(activeEntries);
    const hmacKey = this.acquireHmacKey();

    try {
      reportProgress(options, {
        phase: 'indexing',
        processed: 0,
        total: activeEntries.length,
        candidates: 0,
      });
      const indexed: IndexedEntry[] = [];
      for (let index = 0; index < activeEntries.length; index += 1) {
        assertCanContinue(options);
        const entry = activeEntries[index]!;
        indexed.push({
          entry,
          reference: entryReference(entry),
          features: featuresOf(entry, hmacKey),
        });
        if ((index + 1) % CHECKPOINT_INTERVAL === 0) {
          await this.checkpoint(options, {
            phase: 'indexing',
            processed: index + 1,
            total: activeEntries.length,
            candidates: 0,
          });
        }
      }
      reportProgress(options, {
        phase: 'indexing',
        processed: activeEntries.length,
        total: activeEntries.length,
        candidates: 0,
      });

      const buckets = buildFeatureBuckets(indexed);
      reportProgress(options, {
        phase: 'matching',
        processed: 0,
        total: buckets.length,
        candidates: 0,
      });
      const seenPairs = new Set<string>();
      const candidates: DuplicateCandidate[] = [];
      let work = 0;
      let truncated = false;
      let processedBuckets = 0;

      outer: for (let bucketIndex = 0; bucketIndex < buckets.length; bucketIndex += 1) {
        const bucket = buckets[bucketIndex]!;
        for (let leftIndex = 0; leftIndex < bucket.entries.length; leftIndex += 1) {
          for (
            let rightIndex = leftIndex + 1;
            rightIndex < bucket.entries.length;
            rightIndex += 1
          ) {
            assertCanContinue(options);
            work += 1;
            const left = indexed[bucket.entries[leftIndex]!]!;
            const right = indexed[bucket.entries[rightIndex]!]!;
            const pairKey = entryPairKey(left.entry, right.entry);
            if (!seenPairs.has(pairKey)) {
              seenPairs.add(pairKey);
              const candidate = matchCandidate(left, right);
              if (candidate !== null) {
                candidates.push(candidate);
                if (candidates.length >= candidateLimit) {
                  truncated = hasUnvisitedPair(buckets, bucketIndex, leftIndex, rightIndex);
                  processedBuckets = truncated ? bucketIndex : bucketIndex + 1;
                  break outer;
                }
              }
            }

            if (work % CHECKPOINT_INTERVAL === 0) {
              await this.checkpoint(options, {
                phase: 'matching',
                processed: bucketIndex,
                total: buckets.length,
                candidates: candidates.length,
              });
            }
          }
        }
        processedBuckets = bucketIndex + 1;
        if ((bucketIndex + 1) % CHECKPOINT_INTERVAL === 0) {
          await this.checkpoint(options, {
            phase: 'matching',
            processed: bucketIndex + 1,
            total: buckets.length,
            candidates: candidates.length,
          });
        }
      }

      assertCanContinue(options);
      candidates.sort(compareCandidates);
      reportProgress(options, {
        phase: 'matching',
        processed: processedBuckets,
        total: buckets.length,
        candidates: candidates.length,
      });
      assertCanContinue(options);
      return { candidates, activeEntryCount: activeEntries.length, truncated };
    } finally {
      hmacKey.fill(0);
    }
  }

  public describeMerge(survivor: VaultEntry, duplicate: VaultEntry): DuplicateMergeDescription {
    validateMergePair(survivor, duplicate);
    const type = survivor.data.type;
    return {
      survivor: entryReference(survivor),
      duplicate: entryReference(duplicate),
      type,
      scalarFields: applicableScalarFields(type).map((field) => ({
        field,
        secret: SECRET_SCALAR_FIELDS.has(field),
      })),
      collectionFields: applicableCollectionFields(type).map((field) => ({
        field,
        supportsUnion: true,
      })),
      idCollisions: {
        customFieldIds: collidingIds(survivor.customFields, duplicate.customFields),
        identityAddressIds:
          survivor.data.type === 'identity' && duplicate.data.type === 'identity'
            ? collidingIds(survivor.data.value.addresses, duplicate.data.value.addresses)
            : [],
        attachmentIds: collidingIds(survivor.attachments, duplicate.attachments),
      },
      potentialAttachmentDuplicates: potentialAttachmentDuplicates(survivor, duplicate),
      duplicateDisposition: 'trash',
    };
  }

  public planMerge(input: DuplicateMergeInput): DuplicateMergePlan {
    validateMergePair(input.survivor, input.duplicate);
    const now = validateTimestamp(input.now);
    const fieldChoices = validateFieldChoices(input.survivor.data.type, input.fieldChoices ?? []);
    const collectionChoices = validateCollectionChoices(
      input.survivor.data.type,
      input.collectionChoices ?? [],
    );
    const planState: CollectionPlanState = {
      customFieldReplacements: replacementMap(input.customFieldIdReplacements ?? []),
      identityAddressReplacements: replacementMap(input.identityAddressIdReplacements ?? []),
      attachmentReplacements: replacementMap(input.attachmentIdReplacements ?? []),
      consumedCustomFieldReplacements: new Set(),
      consumedIdentityAddressReplacements: new Set(),
      consumedAttachmentReplacements: new Set(),
    };
    const hmacKey = this.acquireHmacKey();

    try {
      const survivor = structuredClone(input.survivor);
      const duplicate = structuredClone(input.duplicate);
      applyScalarChoices(survivor, input.duplicate, fieldChoices);
      if (
        survivor.vaultId !== input.duplicate.vaultId &&
        fieldChoices.get('folderId') === 'duplicate' &&
        input.duplicate.folderId !== null
      ) {
        throw invalidMerge(
          'Ein Ordner aus einem anderen Tresor kann nicht direkt übernommen werden.',
        );
      }

      survivor.tags = selectTags(
        input.survivor.tags,
        input.duplicate.tags,
        collectionStrategy(collectionChoices, 'tags'),
      );
      survivor.note = selectNote(
        input.survivor.note,
        input.duplicate.note,
        collectionStrategy(collectionChoices, 'note'),
      );
      survivor.customFields = selectCustomFields(
        input.survivor.customFields,
        input.duplicate.customFields,
        collectionStrategy(collectionChoices, 'customFields'),
        planState,
        hmacKey,
      );

      applyTypeCollections(survivor, input.survivor, input.duplicate, collectionChoices, planState);

      const attachmentResult = selectAttachments(
        input.survivor,
        input.duplicate,
        collectionStrategy(collectionChoices, 'attachments'),
        planState,
        input.verifiedAttachmentDuplicates ?? [],
      );
      survivor.attachments = attachmentResult.attachments;
      assertAllReplacementsConsumed(planState);

      const changedSecretSemantics = secretSemanticsChanged(input.survivor, survivor, hmacKey);
      survivor.updatedAt = now;
      survivor.secretChangedAt = changedSecretSemantics ? now : input.survivor.secretChangedAt;
      survivor.deletedAt = null;
      duplicate.updatedAt = now;
      duplicate.deletedAt = now;

      return {
        survivor,
        duplicate,
        duplicateDisposition: 'trash',
        changedSecretSemantics,
        attachmentCopies: attachmentResult.copies,
        detachedSurvivorAttachmentIds: attachmentResult.detachedSurvivorAttachmentIds,
      };
    } finally {
      hmacKey.fill(0);
    }
  }

  private acquireHmacKey(): Buffer {
    const key = this.createHmacKey();
    if (!Buffer.isBuffer(key) || key.length < 32) {
      if (Buffer.isBuffer(key)) key.fill(0);
      throw new VaultaError('INTERNAL', 'Der geschützte Dublettenvergleich konnte nicht starten.');
    }
    return key;
  }

  private async checkpoint(
    options: DuplicateScanOptions,
    progress: DuplicateScanProgress,
  ): Promise<void> {
    assertCanContinue(options);
    reportProgress(options, progress);
    assertCanContinue(options);
    await this.yieldControl();
    assertCanContinue(options);
  }
}

function featuresOf(entry: VaultEntry, hmacKey: Buffer): MatchFeature[] {
  const features: MatchFeature[] = [];
  addTextFeature(features, 'title', entry.title, 1);
  addCustomFieldFeatures(features, entry.customFields, hmacKey);

  switch (entry.data.type) {
    case 'credential': {
      const value = entry.data.value;
      addTextFeature(features, 'credential-username', value.username, 2);
      for (const website of value.websites) {
        addHostFeature(features, 'credential-website-host', website, 2);
      }
      for (const appName of value.appNames) {
        addTextFeature(features, 'credential-app-name', appName, 1);
      }
      addSecretFeature(
        features,
        'credential-password',
        'credential.password',
        value.password,
        2,
        hmacKey,
      );
      if (value.totp !== undefined) {
        addSecretFeature(
          features,
          'credential-totp-secret',
          'credential.totp.secret',
          value.totp.secret,
          3,
          hmacKey,
        );
      }
      break;
    }
    case 'secure-note':
      addSecretFeature(
        features,
        'secure-note-content',
        'secure-note.markdown',
        entry.data.value.markdown,
        4,
        hmacKey,
      );
      break;
    case 'credit-card': {
      const value = entry.data.value;
      addSecretFeature(
        features,
        'credit-card-number',
        'credit-card.number',
        normalizeCardNumber(value.number),
        4,
        hmacKey,
      );
      addTextFeature(features, 'credit-card-cardholder', value.cardholder, 1);
      addTextFeature(features, 'credit-card-issuer', value.issuer, 1);
      if (value.expiryMonth > 0 && value.expiryYear > 0) {
        addRawFeature(
          features,
          'credit-card-expiry',
          `${String(value.expiryYear)}-${String(value.expiryMonth).padStart(2, '0')}`,
          1,
        );
      }
      addHostFeature(features, 'credit-card-website-host', value.website, 2);
      break;
    }
    case 'identity': {
      const value = entry.data.value;
      addTextFeature(
        features,
        'identity-name',
        [value.firstName, value.middleName, value.lastName].join(' '),
        2,
      );
      for (const email of value.emails) addTextFeature(features, 'identity-email', email, 4);
      for (const phone of value.phones) addTextFeature(features, 'identity-phone', phone, 3);
      for (const address of value.addresses) {
        addRawFeature(features, 'identity-address', normalizedAddress(address), 2);
      }
      for (const [domain, identifier] of [
        ['identity.id-number', value.idNumber],
        ['identity.passport-number', value.passportNumber],
        ['identity.tax-number', value.taxNumber],
      ] as const) {
        addSecretFeature(
          features,
          'identity-government-id',
          domain,
          normalizeText(identifier),
          4,
          hmacKey,
        );
      }
      break;
    }
    case 'wifi': {
      const value = entry.data.value;
      addTextFeature(features, 'wifi-ssid', value.ssid, 2);
      addHostFeature(features, 'wifi-router-host', value.routerAddress, 2);
      addTextFeature(features, 'wifi-router-username', value.routerUsername, 1);
      addSecretFeature(features, 'wifi-password', 'wifi.password', value.password, 2, hmacKey);
      break;
    }
    case 'software-license': {
      const value = entry.data.value;
      addTextFeature(
        features,
        'software-product',
        [value.manufacturer, value.product, value.version].join(' '),
        2,
      );
      addTextFeature(features, 'software-order-number', value.orderNumber, 4);
      addHostFeature(features, 'software-download-host', value.downloadUrl, 2);
      addSecretFeature(
        features,
        'software-license-key',
        'software-license.license-key',
        value.licenseKey,
        4,
        hmacKey,
      );
      break;
    }
    case 'ssh-key': {
      const value = entry.data.value;
      const host = normalizeHost(value.host);
      if (host !== null) {
        addRawFeature(features, 'ssh-host', `${host}:${String(value.port)}`, 2);
      }
      addTextFeature(features, 'ssh-username', value.username, 1);
      addTextFeature(features, 'ssh-fingerprint', value.fingerprint, 4);
      addSecretFeature(
        features,
        'ssh-public-key',
        'ssh.public-key',
        value.publicKey.trim().replace(/\s+/gu, ' '),
        4,
        hmacKey,
      );
      addSecretFeature(
        features,
        'ssh-private-key',
        'ssh.private-key',
        value.privateKey,
        4,
        hmacKey,
      );
      break;
    }
    case 'file':
      addTextFeature(features, 'file-description', entry.data.value.description, 2);
      for (const attachment of entry.attachments) {
        addRawFeature(
          features,
          'file-attachment',
          `${attachment.sha256.toLocaleLowerCase('en-US')}:${String(attachment.size)}`,
          4,
        );
      }
      break;
    case 'custom':
      addTextFeature(features, 'custom-description', entry.data.value.description, 2);
      break;
  }

  return deduplicateFeatures(features);
}

function addCustomFieldFeatures(
  features: MatchFeature[],
  fields: readonly CustomField[],
  hmacKey: Buffer,
): void {
  for (const field of fields) {
    const secret = field.secret || field.type === 'secret';
    if (secret) {
      if (isEmptyValue(field.value)) continue;
      addSecretFeature(
        features,
        'custom-secret-field',
        `custom-field:${normalizeText(field.label)}:${field.type}`,
        field.value,
        4,
        hmacKey,
      );
      continue;
    }
    const value = normalizedCustomFieldValue(field);
    if (value === null) continue;
    addRawFeature(
      features,
      'custom-field',
      `${normalizeText(field.label)}\u0000${field.type}\u0000${value}`,
      2,
    );
  }
}

function addTextFeature(
  features: MatchFeature[],
  reason: DuplicateReasonCode,
  value: string,
  weight: number,
): void {
  addRawFeature(features, reason, normalizeText(value), weight);
}

function addHostFeature(
  features: MatchFeature[],
  reason: DuplicateReasonCode,
  value: string,
  weight: number,
): void {
  const host = normalizeHost(value);
  if (host !== null) addRawFeature(features, reason, host, weight);
}

function addSecretFeature(
  features: MatchFeature[],
  reason: DuplicateReasonCode,
  domain: string,
  value: unknown,
  weight: number,
  hmacKey: Buffer,
): void {
  if (isEmptyValue(value)) return;
  const digest = digestValue(hmacKey, domain, value);
  try {
    addRawFeature(features, reason, digest.toString('hex'), weight);
  } finally {
    digest.fill(0);
  }
}

function addRawFeature(
  features: MatchFeature[],
  reason: DuplicateReasonCode,
  key: string,
  weight: number,
): void {
  if (key.length === 0) return;
  features.push({ reason, key, weight });
}

function deduplicateFeatures(features: readonly MatchFeature[]): MatchFeature[] {
  const seen = new Set<string>();
  const output: MatchFeature[] = [];
  for (const feature of features) {
    const key = JSON.stringify([feature.reason, feature.key]);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(feature);
  }
  return output;
}

function buildFeatureBuckets(entries: readonly IndexedEntry[]): FeatureBucket[] {
  const buckets = new Map<string, FeatureBucket>();
  for (let entryIndex = 0; entryIndex < entries.length; entryIndex += 1) {
    const indexed = entries[entryIndex]!;
    for (const feature of indexed.features) {
      const key = featureBucketKey(indexed.entry.data.type, feature);
      const bucket = buckets.get(key);
      if (bucket === undefined) {
        buckets.set(key, { reason: feature.reason, weight: feature.weight, entries: [entryIndex] });
      } else {
        bucket.entries.push(entryIndex);
      }
    }
  }
  return [...buckets.values()]
    .filter((bucket) => bucket.entries.length > 1)
    .sort((left, right) => {
      if (left.weight !== right.weight) return right.weight - left.weight;
      return (REASON_ORDER.get(left.reason) ?? 0) - (REASON_ORDER.get(right.reason) ?? 0);
    });
}

class IncrementalDuplicateMatcher implements DuplicateMatcher {
  private readonly entries: IndexedEntry[] = [];
  private readonly featureBuckets = new Map<string, number[]>();
  private readonly references = new Set<string>();
  private disposed = false;

  public constructor(private readonly hmacKey: Buffer) {}

  public add(entry: VaultEntry): DuplicateCandidate[] {
    if (this.disposed) {
      throw new VaultaError('INTERNAL', 'Der Dublettenvergleich ist nicht mehr aktiv.');
    }
    if (entry.deletedAt !== null) return [];

    const referenceKey = entryKey(entry);
    if (this.references.has(referenceKey)) {
      throw new VaultaError('INVALID_INPUT', 'Eine Eintragsreferenz wurde mehrfach übergeben.');
    }
    this.references.add(referenceKey);

    const indexed: IndexedEntry = {
      entry,
      reference: entryReference(entry),
      features: featuresOf(entry, this.hmacKey),
    };
    const possibleMatches = new Set<number>();
    for (const feature of indexed.features) {
      const bucket = this.featureBuckets.get(featureBucketKey(entry.data.type, feature));
      if (bucket !== undefined) {
        for (const entryIndex of bucket) possibleMatches.add(entryIndex);
      }
    }

    const candidates: DuplicateCandidate[] = [];
    for (const entryIndex of possibleMatches) {
      const existing = this.entries[entryIndex];
      if (existing === undefined) continue;
      const candidate = matchCandidate(existing, indexed);
      if (candidate !== null) candidates.push(candidate);
    }

    const newIndex = this.entries.length;
    this.entries.push(indexed);
    for (const feature of indexed.features) {
      const key = featureBucketKey(entry.data.type, feature);
      const bucket = this.featureBuckets.get(key);
      if (bucket === undefined) this.featureBuckets.set(key, [newIndex]);
      else bucket.push(newIndex);
    }
    candidates.sort(compareCandidates);
    return candidates;
  }

  public dispose(): void {
    this.disposed = true;
    this.entries.length = 0;
    this.featureBuckets.clear();
    this.references.clear();
  }
}

function featureBucketKey(type: EntryType, feature: MatchFeature): string {
  return JSON.stringify([type, feature.reason, feature.key]);
}

function matchCandidate(left: IndexedEntry, right: IndexedEntry): DuplicateCandidate | null {
  if (left.entry.data.type !== right.entry.data.type) return null;
  const rightFeatures = new Map<string, MatchFeature>();
  for (const feature of right.features) {
    rightFeatures.set(JSON.stringify([feature.reason, feature.key]), feature);
  }
  const matched = new Map<DuplicateReasonCode, number>();
  for (const feature of left.features) {
    if (!rightFeatures.has(JSON.stringify([feature.reason, feature.key]))) continue;
    matched.set(feature.reason, Math.max(matched.get(feature.reason) ?? 0, feature.weight));
  }
  const score = [...matched.values()].reduce((sum, weight) => sum + weight, 0);
  if (score < MIN_MATCH_SCORE) return null;
  const reasons = [...matched.keys()].sort(
    (a, b) => (REASON_ORDER.get(a) ?? 0) - (REASON_ORDER.get(b) ?? 0),
  );
  return {
    left: left.reference,
    right: right.reference,
    type: left.entry.data.type,
    confidence: score >= LIKELY_MATCH_SCORE ? 'likely' : 'possible',
    reasons,
  };
}

function hasUnvisitedPair(
  buckets: readonly FeatureBucket[],
  bucketIndex: number,
  leftIndex: number,
  rightIndex: number,
): boolean {
  const bucket = buckets[bucketIndex];
  if (bucket === undefined) return false;
  return (
    rightIndex + 1 < bucket.entries.length ||
    leftIndex + 1 < bucket.entries.length - 1 ||
    bucketIndex + 1 < buckets.length
  );
}

function applicableScalarFields(type: EntryType): DuplicateMergeScalarField[] {
  return [...COMMON_SCALAR_FIELDS, ...TYPE_SCALAR_FIELDS[type]];
}

function applicableCollectionFields(type: EntryType): DuplicateMergeCollectionField[] {
  return [...COMMON_COLLECTION_FIELDS, ...TYPE_COLLECTION_FIELDS[type]];
}

function validateFieldChoices(
  type: EntryType,
  choices: readonly DuplicateMergeFieldChoice[],
): Map<DuplicateMergeScalarField, DuplicateMergeSource> {
  const applicable = new Set(applicableScalarFields(type));
  const output = new Map<DuplicateMergeScalarField, DuplicateMergeSource>();
  for (const choice of choices) {
    if (
      !applicable.has(choice.field) ||
      (choice.source !== 'survivor' && choice.source !== 'duplicate')
    ) {
      throw invalidMerge('Eine Feldentscheidung ist für diesen Eintragstyp ungültig.');
    }
    if (output.has(choice.field))
      throw invalidMerge('Eine Feldentscheidung wurde mehrfach angegeben.');
    output.set(choice.field, choice.source);
  }
  return output;
}

function validateCollectionChoices(
  type: EntryType,
  choices: readonly DuplicateMergeCollectionChoice[],
): Map<DuplicateMergeCollectionField, DuplicateMergeCollectionStrategy> {
  const applicable = new Set(applicableCollectionFields(type));
  const output = new Map<DuplicateMergeCollectionField, DuplicateMergeCollectionStrategy>();
  for (const choice of choices) {
    if (
      !applicable.has(choice.field) ||
      !['survivor', 'duplicate', 'union'].includes(choice.strategy)
    ) {
      throw invalidMerge('Eine Sammlungsentscheidung ist für diesen Eintragstyp ungültig.');
    }
    if (output.has(choice.field)) {
      throw invalidMerge('Eine Sammlungsentscheidung wurde mehrfach angegeben.');
    }
    output.set(choice.field, choice.strategy);
  }
  return output;
}

function collectionStrategy(
  choices: ReadonlyMap<DuplicateMergeCollectionField, DuplicateMergeCollectionStrategy>,
  field: DuplicateMergeCollectionField,
): DuplicateMergeCollectionStrategy {
  return choices.get(field) ?? 'survivor';
}

function applyScalarChoices(
  target: VaultEntry,
  source: VaultEntry,
  choices: ReadonlyMap<DuplicateMergeScalarField, DuplicateMergeSource>,
): void {
  for (const [field, selectedSource] of choices) {
    if (selectedSource === 'survivor') continue;
    applyDuplicateScalar(target, source, field);
  }
}

function applyDuplicateScalar(
  target: VaultEntry,
  source: VaultEntry,
  field: DuplicateMergeScalarField,
): void {
  if (field === 'title') {
    target.title = source.title;
    return;
  }
  if (field === 'folderId') {
    target.folderId = source.folderId;
    return;
  }
  if (field === 'favorite') {
    target.favorite = source.favorite;
    return;
  }
  if (target.data.type !== source.data.type) {
    throw new VaultaError('INTERNAL', 'Eine Merge-Feldzuordnung passt nicht zum Eintragstyp.');
  }

  if (target.data.type === 'credential' && source.data.type === 'credential') {
    if (field === 'credential.username') target.data.value.username = source.data.value.username;
    else if (field === 'credential.password')
      target.data.value.password = source.data.value.password;
    else if (field === 'credential.totp') {
      if (source.data.value.totp === undefined) delete target.data.value.totp;
      else target.data.value.totp = structuredClone(source.data.value.totp);
    }
    return;
  }
  if (target.data.type === 'credit-card' && source.data.type === 'credit-card') {
    const targetValue = target.data.value;
    const sourceValue = source.data.value;
    switch (field) {
      case 'credit-card.cardName':
        targetValue.cardName = sourceValue.cardName;
        return;
      case 'credit-card.cardholder':
        targetValue.cardholder = sourceValue.cardholder;
        return;
      case 'credit-card.number':
        targetValue.number = sourceValue.number;
        return;
      case 'credit-card.expiryMonth':
        targetValue.expiryMonth = sourceValue.expiryMonth;
        return;
      case 'credit-card.expiryYear':
        targetValue.expiryYear = sourceValue.expiryYear;
        return;
      case 'credit-card.cvc':
        targetValue.cvc = sourceValue.cvc;
        return;
      case 'credit-card.pin':
        targetValue.pin = sourceValue.pin;
        return;
      case 'credit-card.issuer':
        targetValue.issuer = sourceValue.issuer;
        return;
      case 'credit-card.cardType':
        targetValue.cardType = sourceValue.cardType;
        return;
      case 'credit-card.billingAddress':
        targetValue.billingAddress = sourceValue.billingAddress;
        return;
      case 'credit-card.servicePhone':
        targetValue.servicePhone = sourceValue.servicePhone;
        return;
      case 'credit-card.website':
        targetValue.website = sourceValue.website;
        return;
      default:
        return;
    }
  }
  if (target.data.type === 'identity' && source.data.type === 'identity') {
    const targetValue = target.data.value;
    const sourceValue = source.data.value;
    switch (field) {
      case 'identity.salutation':
        targetValue.salutation = sourceValue.salutation;
        return;
      case 'identity.firstName':
        targetValue.firstName = sourceValue.firstName;
        return;
      case 'identity.middleName':
        targetValue.middleName = sourceValue.middleName;
        return;
      case 'identity.lastName':
        targetValue.lastName = sourceValue.lastName;
        return;
      case 'identity.birthDate':
        targetValue.birthDate = sourceValue.birthDate;
        return;
      case 'identity.idNumber':
        targetValue.idNumber = sourceValue.idNumber;
        return;
      case 'identity.passportNumber':
        targetValue.passportNumber = sourceValue.passportNumber;
        return;
      case 'identity.taxNumber':
        targetValue.taxNumber = sourceValue.taxNumber;
        return;
      default:
        return;
    }
  }
  if (target.data.type === 'wifi' && source.data.type === 'wifi') {
    const targetValue = target.data.value;
    const sourceValue = source.data.value;
    switch (field) {
      case 'wifi.ssid':
        targetValue.ssid = sourceValue.ssid;
        return;
      case 'wifi.password':
        targetValue.password = sourceValue.password;
        return;
      case 'wifi.security':
        targetValue.security = sourceValue.security;
        return;
      case 'wifi.hidden':
        targetValue.hidden = sourceValue.hidden;
        return;
      case 'wifi.routerAddress':
        targetValue.routerAddress = sourceValue.routerAddress;
        return;
      case 'wifi.routerUsername':
        targetValue.routerUsername = sourceValue.routerUsername;
        return;
      default:
        return;
    }
  }
  if (target.data.type === 'software-license' && source.data.type === 'software-license') {
    const targetValue = target.data.value;
    const sourceValue = source.data.value;
    switch (field) {
      case 'software-license.product':
        targetValue.product = sourceValue.product;
        return;
      case 'software-license.manufacturer':
        targetValue.manufacturer = sourceValue.manufacturer;
        return;
      case 'software-license.version':
        targetValue.version = sourceValue.version;
        return;
      case 'software-license.licenseKey':
        targetValue.licenseKey = sourceValue.licenseKey;
        return;
      case 'software-license.licensedTo':
        targetValue.licensedTo = sourceValue.licensedTo;
        return;
      case 'software-license.purchaseDate':
        targetValue.purchaseDate = sourceValue.purchaseDate;
        return;
      case 'software-license.activationDate':
        targetValue.activationDate = sourceValue.activationDate;
        return;
      case 'software-license.expiryDate':
        targetValue.expiryDate = sourceValue.expiryDate;
        return;
      case 'software-license.orderNumber':
        targetValue.orderNumber = sourceValue.orderNumber;
        return;
      case 'software-license.downloadUrl':
        targetValue.downloadUrl = sourceValue.downloadUrl;
        return;
      case 'software-license.purchasePrice':
        targetValue.purchasePrice = sourceValue.purchasePrice;
        return;
      default:
        return;
    }
  }
  if (target.data.type === 'ssh-key' && source.data.type === 'ssh-key') {
    const targetValue = target.data.value;
    const sourceValue = source.data.value;
    switch (field) {
      case 'ssh-key.host':
        targetValue.host = sourceValue.host;
        return;
      case 'ssh-key.port':
        targetValue.port = sourceValue.port;
        return;
      case 'ssh-key.username':
        targetValue.username = sourceValue.username;
        return;
      case 'ssh-key.keyType':
        targetValue.keyType = sourceValue.keyType;
        return;
      case 'ssh-key.fingerprint':
        targetValue.fingerprint = sourceValue.fingerprint;
        return;
      case 'ssh-key.publicKey':
        targetValue.publicKey = sourceValue.publicKey;
        return;
      case 'ssh-key.privateKey':
        targetValue.privateKey = sourceValue.privateKey;
        return;
      case 'ssh-key.passphrase':
        targetValue.passphrase = sourceValue.passphrase;
        return;
      default:
        return;
    }
  }
  if (target.data.type === 'file' && source.data.type === 'file') {
    if (field === 'file.description') target.data.value.description = source.data.value.description;
    return;
  }
  if (target.data.type === 'custom' && source.data.type === 'custom') {
    if (field === 'custom.description')
      target.data.value.description = source.data.value.description;
  }
}

function applyTypeCollections(
  target: VaultEntry,
  survivor: VaultEntry,
  duplicate: VaultEntry,
  choices: ReadonlyMap<DuplicateMergeCollectionField, DuplicateMergeCollectionStrategy>,
  state: CollectionPlanState,
): void {
  switch (target.data.type) {
    case 'credential': {
      assertEntryType(survivor, 'credential');
      assertEntryType(duplicate, 'credential');
      target.data.value.websites = selectTextArray(
        survivor.data.value.websites,
        duplicate.data.value.websites,
        collectionStrategy(choices, 'credential.websites'),
        normalizedUrlKey,
      );
      target.data.value.appNames = selectTextArray(
        survivor.data.value.appNames,
        duplicate.data.value.appNames,
        collectionStrategy(choices, 'credential.appNames'),
        normalizeText,
      );
      return;
    }
    case 'secure-note':
      assertEntryType(survivor, 'secure-note');
      assertEntryType(duplicate, 'secure-note');
      target.data.value.markdown = selectNote(
        survivor.data.value.markdown,
        duplicate.data.value.markdown,
        collectionStrategy(choices, 'secure-note.markdown'),
      );
      return;
    case 'identity':
      assertEntryType(survivor, 'identity');
      assertEntryType(duplicate, 'identity');
      target.data.value.emails = selectTextArray(
        survivor.data.value.emails,
        duplicate.data.value.emails,
        collectionStrategy(choices, 'identity.emails'),
        normalizeText,
      );
      target.data.value.phones = selectTextArray(
        survivor.data.value.phones,
        duplicate.data.value.phones,
        collectionStrategy(choices, 'identity.phones'),
        normalizeText,
      );
      target.data.value.addresses = selectAddresses(
        survivor.data.value.addresses,
        duplicate.data.value.addresses,
        collectionStrategy(choices, 'identity.addresses'),
        state,
      );
      return;
    case 'credit-card':
    case 'wifi':
    case 'software-license':
    case 'ssh-key':
    case 'file':
    case 'custom':
      return;
  }
}

function selectTags(
  survivor: readonly string[],
  duplicate: readonly string[],
  strategy: DuplicateMergeCollectionStrategy,
): string[] {
  if (strategy === 'survivor') return [...survivor];
  if (strategy === 'duplicate') return [...duplicate];
  return normalizeTags([...survivor, ...duplicate]);
}

function selectNote(
  survivor: string,
  duplicate: string,
  strategy: DuplicateMergeCollectionStrategy,
): string {
  if (strategy === 'survivor') return survivor;
  if (strategy === 'duplicate') return duplicate;
  const values: string[] = [];
  const keys = new Set<string>();
  for (const note of [survivor, duplicate]) {
    for (const value of noteFragments(note)) {
      const key = normalizeMergeText(value);
      if (key.length === 0 || keys.has(key)) continue;
      keys.add(key);
      values.push(value);
    }
  }
  return values.join('\n\n');
}

function noteFragments(value: string): string[] {
  return value.split(/(?:\r?\n){2,}/u).filter((fragment) => fragment.trim().length > 0);
}

function selectTextArray(
  survivor: readonly string[],
  duplicate: readonly string[],
  strategy: DuplicateMergeCollectionStrategy,
  keyOf: (value: string) => string,
): string[] {
  if (strategy === 'survivor') return [...survivor];
  if (strategy === 'duplicate') return [...duplicate];
  const output: string[] = [];
  const keys = new Set<string>();
  for (const value of [...survivor, ...duplicate]) {
    const key = keyOf(value);
    if (keys.has(key)) continue;
    keys.add(key);
    output.push(value);
  }
  return output;
}

function selectCustomFields(
  survivor: readonly CustomField[],
  duplicate: readonly CustomField[],
  strategy: DuplicateMergeCollectionStrategy,
  state: CollectionPlanState,
  hmacKey: Buffer,
): CustomField[] {
  assertUniqueIds(survivor, 'Eigene Felder');
  assertUniqueIds(duplicate, 'Eigene Felder');
  if (strategy === 'survivor') return structuredClone([...survivor]);
  const output: CustomField[] = strategy === 'union' ? structuredClone([...survivor]) : [];
  for (const source of duplicate) {
    if (strategy === 'union' && output.some((field) => sameCustomField(field, source, hmacKey))) {
      continue;
    }
    const copy = structuredClone(source);
    const replacement = state.customFieldReplacements.get(source.id);
    if (replacement !== undefined) {
      copy.id = replacement;
      state.consumedCustomFieldReplacements.add(source.id);
    } else if (output.some((field) => field.id === copy.id)) {
      throw invalidMerge('Eine ID-Kollision bei eigenen Feldern benötigt eine neue Ziel-ID.');
    }
    if (output.some((field) => field.id === copy.id)) {
      throw invalidMerge('Eine Ziel-ID für eigene Felder ist bereits belegt.');
    }
    output.push(copy);
  }
  return output;
}

function selectAddresses(
  survivor: readonly IdentityAddress[],
  duplicate: readonly IdentityAddress[],
  strategy: DuplicateMergeCollectionStrategy,
  state: CollectionPlanState,
): IdentityAddress[] {
  assertUniqueIds(survivor, 'Adressen');
  assertUniqueIds(duplicate, 'Adressen');
  if (strategy === 'survivor') return structuredClone([...survivor]);
  const output: IdentityAddress[] = strategy === 'union' ? structuredClone([...survivor]) : [];
  for (const source of duplicate) {
    if (strategy === 'union' && output.some((address) => sameAddress(address, source))) continue;
    const copy = structuredClone(source);
    const replacement = state.identityAddressReplacements.get(source.id);
    if (replacement !== undefined) {
      copy.id = replacement;
      state.consumedIdentityAddressReplacements.add(source.id);
    } else if (output.some((address) => address.id === copy.id)) {
      throw invalidMerge('Eine ID-Kollision bei Adressen benötigt eine neue Ziel-ID.');
    }
    if (output.some((address) => address.id === copy.id)) {
      throw invalidMerge('Eine Ziel-ID für Adressen ist bereits belegt.');
    }
    output.push(copy);
  }
  return output;
}

function selectAttachments(
  survivor: VaultEntry,
  duplicate: VaultEntry,
  strategy: DuplicateMergeCollectionStrategy,
  state: CollectionPlanState,
  verifiedDuplicates: readonly VerifiedAttachmentDuplicate[],
): {
  attachments: AttachmentMetadata[];
  copies: DuplicateAttachmentCopy[];
  detachedSurvivorAttachmentIds: string[];
} {
  assertUniqueIds(survivor.attachments, 'Anhänge');
  assertUniqueIds(duplicate.attachments, 'Anhänge');
  const verified = verifiedAttachmentMap(survivor, duplicate, verifiedDuplicates, strategy);
  if (strategy === 'survivor') {
    return {
      attachments: structuredClone(survivor.attachments),
      copies: [],
      detachedSurvivorAttachmentIds: [],
    };
  }

  const output = strategy === 'union' ? structuredClone(survivor.attachments) : [];
  const copies: DuplicateAttachmentCopy[] = [];
  const forbiddenIds = new Set([
    ...survivor.attachments.map((attachment) => attachment.id),
    ...duplicate.attachments.map((attachment) => attachment.id),
  ]);
  for (const source of duplicate.attachments) {
    if (strategy === 'union' && verified.has(source.id)) continue;
    const targetId = state.attachmentReplacements.get(source.id);
    if (targetId === undefined) {
      throw invalidMerge('Ein übernommener Anhang benötigt eine neue, zuvor reservierte Ziel-ID.');
    }
    state.consumedAttachmentReplacements.add(source.id);
    if (forbiddenIds.has(targetId) || output.some((attachment) => attachment.id === targetId)) {
      throw invalidMerge('Eine Ziel-ID für Anhänge ist bereits belegt.');
    }
    forbiddenIds.add(targetId);
    output.push({ ...structuredClone(source), id: targetId });
    copies.push({
      sourceVaultId: duplicate.vaultId,
      sourceAttachmentId: source.id,
      targetVaultId: survivor.vaultId,
      targetAttachmentId: targetId,
    });
  }
  return {
    attachments: output,
    copies,
    detachedSurvivorAttachmentIds:
      strategy === 'duplicate' ? survivor.attachments.map((attachment) => attachment.id) : [],
  };
}

function replacementMap(replacements: readonly DuplicateMergeIdReplacement[]): Map<string, string> {
  const output = new Map<string, string>();
  const targetIds = new Set<string>();
  for (const replacement of replacements) {
    validateLocalId(replacement.sourceId);
    validateLocalId(replacement.targetId);
    if (output.has(replacement.sourceId) || targetIds.has(replacement.targetId)) {
      throw invalidMerge('Eine ID-Ersetzung wurde mehrfach oder widersprüchlich angegeben.');
    }
    output.set(replacement.sourceId, replacement.targetId);
    targetIds.add(replacement.targetId);
  }
  return output;
}

function assertAllReplacementsConsumed(state: CollectionPlanState): void {
  if (
    state.customFieldReplacements.size !== state.consumedCustomFieldReplacements.size ||
    state.identityAddressReplacements.size !== state.consumedIdentityAddressReplacements.size ||
    state.attachmentReplacements.size !== state.consumedAttachmentReplacements.size
  ) {
    throw invalidMerge('Mindestens eine ID-Ersetzung gehört nicht zur gewählten Zusammenführung.');
  }
}

function verifiedAttachmentMap(
  survivor: VaultEntry,
  duplicate: VaultEntry,
  pairs: readonly VerifiedAttachmentDuplicate[],
  strategy: DuplicateMergeCollectionStrategy,
): Map<string, string> {
  if (pairs.length > 0 && strategy !== 'union') {
    throw invalidMerge('Verifizierte Anhang-Dubletten sind nur bei einer Vereinigung zulässig.');
  }
  const output = new Map<string, string>();
  const targets = new Set<string>();
  for (const pair of pairs) {
    if (output.has(pair.duplicateAttachmentId) || targets.has(pair.survivorAttachmentId)) {
      throw invalidMerge('Eine verifizierte Anhang-Dublette wurde mehrfach angegeben.');
    }
    const source = duplicate.attachments.find(
      (attachment) => attachment.id === pair.duplicateAttachmentId,
    );
    const target = survivor.attachments.find(
      (attachment) => attachment.id === pair.survivorAttachmentId,
    );
    if (
      source === undefined ||
      target === undefined ||
      source.size !== target.size ||
      source.sha256.toLocaleLowerCase('en-US') !== target.sha256.toLocaleLowerCase('en-US')
    ) {
      throw invalidMerge('Eine verifizierte Anhang-Dublette passt nicht zu den Metadaten.');
    }
    output.set(pair.duplicateAttachmentId, pair.survivorAttachmentId);
    targets.add(pair.survivorAttachmentId);
  }
  return output;
}

function sameCustomField(left: CustomField, right: CustomField, hmacKey: Buffer): boolean {
  if (
    normalizeText(left.label) !== normalizeText(right.label) ||
    left.type !== right.type ||
    left.secret !== right.secret ||
    left.searchable !== right.searchable
  ) {
    return false;
  }
  const secret = left.secret || left.type === 'secret';
  if (secret) return hmacValuesEqual(hmacKey, 'custom-field.value', left.value, right.value);
  return normalizedCustomFieldValue(left) === normalizedCustomFieldValue(right);
}

function normalizedCustomFieldValue(field: CustomField): string | null {
  if (typeof field.value === 'string') {
    const normalized =
      field.type === 'url' ? normalizedUrlKey(field.value) : normalizeMergeText(field.value);
    return normalized.length === 0 ? null : normalized;
  }
  if (typeof field.value === 'number')
    return Number.isFinite(field.value) ? String(field.value) : null;
  return field.value ? 'true' : 'false';
}

function sameAddress(left: IdentityAddress, right: IdentityAddress): boolean {
  return normalizedAddress(left) === normalizedAddress(right);
}

function normalizedAddress(address: IdentityAddress): string {
  return [
    address.label,
    address.street,
    address.postalCode,
    address.city,
    address.region,
    address.country,
  ]
    .map(normalizeText)
    .join('\u0000');
}

function secretSemanticsChanged(left: VaultEntry, right: VaultEntry, hmacKey: Buffer): boolean {
  const leftDigests = secretSemanticDigests(left, hmacKey);
  const rightDigests = secretSemanticDigests(right, hmacKey);
  try {
    if (leftDigests.length !== rightDigests.length) return true;
    leftDigests.sort((a, b) => Buffer.compare(a, b));
    rightDigests.sort((a, b) => Buffer.compare(a, b));
    return leftDigests.some((digest, index) => !timingSafeEqual(digest, rightDigests[index]!));
  } finally {
    for (const digest of leftDigests) digest.fill(0);
    for (const digest of rightDigests) digest.fill(0);
  }
}

function secretSemanticDigests(entry: VaultEntry, hmacKey: Buffer): Buffer[] {
  const values: Array<readonly [string, unknown]> = [];
  switch (entry.data.type) {
    case 'credential':
      values.push(['credential.password', entry.data.value.password]);
      values.push(['credential.totp.secret', entry.data.value.totp?.secret ?? null]);
      break;
    case 'secure-note':
      values.push(['secure-note.markdown', entry.data.value.markdown]);
      break;
    case 'credit-card':
      values.push(['credit-card.number', entry.data.value.number]);
      values.push(['credit-card.cvc', entry.data.value.cvc]);
      values.push(['credit-card.pin', entry.data.value.pin]);
      break;
    case 'identity':
      values.push(['identity.id-number', entry.data.value.idNumber]);
      values.push(['identity.passport-number', entry.data.value.passportNumber]);
      values.push(['identity.tax-number', entry.data.value.taxNumber]);
      break;
    case 'wifi':
      values.push(['wifi.password', entry.data.value.password]);
      break;
    case 'software-license':
      values.push(['software-license.license-key', entry.data.value.licenseKey]);
      break;
    case 'ssh-key':
      values.push(['ssh.private-key', entry.data.value.privateKey]);
      values.push(['ssh.passphrase', entry.data.value.passphrase]);
      break;
    case 'file':
    case 'custom':
      break;
  }
  for (const field of entry.customFields) {
    if (!field.secret && field.type !== 'secret') continue;
    values.push([`custom-field:${field.type}:${normalizeText(field.label)}`, field.value]);
  }
  return values.map(([domain, value]) => digestValue(hmacKey, domain, value));
}

function hmacValuesEqual(hmacKey: Buffer, domain: string, left: unknown, right: unknown): boolean {
  const leftDigest = digestValue(hmacKey, domain, left);
  const rightDigest = digestValue(hmacKey, domain, right);
  try {
    return timingSafeEqual(leftDigest, rightDigest);
  } finally {
    leftDigest.fill(0);
    rightDigest.fill(0);
  }
}

function digestValue(hmacKey: Buffer, domain: string, value: unknown): Buffer {
  const hmac = createHmac('sha256', hmacKey);
  updateLengthPrefixed(hmac, 'domain', domain);
  updateStructuredValue(hmac, value);
  return hmac.digest();
}

function updateStructuredValue(hmac: ReturnType<typeof createHmac>, value: unknown): void {
  if (value === null) {
    hmac.update('null;');
    return;
  }
  if (value === undefined) {
    hmac.update('undefined;');
    return;
  }
  if (typeof value === 'string') {
    updateLengthPrefixed(hmac, 'string', value);
    return;
  }
  if (typeof value === 'number') {
    updateLengthPrefixed(hmac, 'number', String(value));
    return;
  }
  if (typeof value === 'boolean') {
    hmac.update(value ? 'boolean:1;' : 'boolean:0;');
    return;
  }
  if (Array.isArray(value)) {
    hmac.update(`array:${String(value.length)};`);
    for (const item of value) updateStructuredValue(hmac, item);
    return;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    hmac.update(`object:${String(keys.length)};`);
    for (const key of keys) {
      updateLengthPrefixed(hmac, 'key', key);
      updateStructuredValue(hmac, record[key]);
    }
    return;
  }
  throw new VaultaError('INTERNAL', 'Ein geschützter Vergleichswert ist ungültig.');
}

function updateLengthPrefixed(
  hmac: ReturnType<typeof createHmac>,
  type: string,
  value: string,
): void {
  hmac.update(`${type}:${String(Buffer.byteLength(value, 'utf8'))}:`);
  hmac.update(value, 'utf8');
  hmac.update(';');
}

function validateMergePair(survivor: VaultEntry, duplicate: VaultEntry): void {
  if (survivor.id === duplicate.id && survivor.vaultId === duplicate.vaultId) {
    throw invalidMerge('Ein Eintrag kann nicht mit sich selbst zusammengeführt werden.');
  }
  if (survivor.data.type !== duplicate.data.type) {
    throw invalidMerge('Nur Einträge desselben Typs können zusammengeführt werden.');
  }
  if (survivor.deletedAt !== null || duplicate.deletedAt !== null) {
    throw invalidMerge('Einträge im Papierkorb können nicht zusammengeführt werden.');
  }
}

function assertEntryType<T extends EntryType>(
  entry: VaultEntry,
  type: T,
): asserts entry is VaultEntry & { data: Extract<VaultEntry['data'], { type: T }> } {
  if (entry.data.type !== type) {
    throw new VaultaError('INTERNAL', 'Eine Merge-Feldzuordnung passt nicht zum Eintragstyp.');
  }
}

function potentialAttachmentDuplicates(
  survivor: VaultEntry,
  duplicate: VaultEntry,
): VerifiedAttachmentDuplicate[] {
  const output: VerifiedAttachmentDuplicate[] = [];
  for (const source of duplicate.attachments) {
    for (const target of survivor.attachments) {
      if (
        source.size === target.size &&
        source.sha256.toLocaleLowerCase('en-US') === target.sha256.toLocaleLowerCase('en-US')
      ) {
        output.push({
          duplicateAttachmentId: source.id,
          survivorAttachmentId: target.id,
        });
      }
    }
  }
  return output.sort(
    (left, right) =>
      left.duplicateAttachmentId.localeCompare(right.duplicateAttachmentId, 'en') ||
      left.survivorAttachmentId.localeCompare(right.survivorAttachmentId, 'en'),
  );
}

function collidingIds<T extends { id: string }>(left: readonly T[], right: readonly T[]): string[] {
  const leftIds = new Set(left.map((value) => value.id));
  return [...new Set(right.map((value) => value.id).filter((id) => leftIds.has(id)))].sort((a, b) =>
    a.localeCompare(b, 'en'),
  );
}

function assertUniqueIds<T extends { id: string }>(values: readonly T[], label: string): void {
  const ids = new Set<string>();
  for (const value of values) {
    validateLocalId(value.id);
    if (ids.has(value.id)) throw invalidMerge(`${label} enthalten eine mehrdeutige ID.`);
    ids.add(value.id);
  }
}

function validateLocalId(value: string): void {
  if (value.trim().length === 0 || value.length > 512 || value.includes('\0')) {
    throw invalidMerge('Eine lokale ID ist ungültig.');
  }
}

function validateTimestamp(value: string): string {
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw invalidMerge('Der Merge-Zeitpunkt ist ungültig.');
  return parsed.toISOString();
}

function validateCandidateLimit(value: number | undefined): number {
  const candidateLimit = value ?? DEFAULT_CANDIDATE_LIMIT;
  if (
    !Number.isInteger(candidateLimit) ||
    candidateLimit < 1 ||
    candidateLimit > MAX_CANDIDATE_LIMIT
  ) {
    throw new VaultaError('INVALID_INPUT', 'Das Kandidatenlimit ist ungültig.');
  }
  return candidateLimit;
}

function assertUniqueEntryReferences(entries: readonly VaultEntry[]): void {
  const references = new Set<string>();
  for (const entry of entries) {
    const key = entryKey(entry);
    if (references.has(key)) {
      throw new VaultaError('INVALID_INPUT', 'Eine Eintragsreferenz wurde mehrfach übergeben.');
    }
    references.add(key);
  }
}

function assertCanContinue(options: DuplicateScanOptions): void {
  if (isAborted(options.signal)) {
    throw new VaultaError('CANCELLED', 'Der Dublettenscan wurde abgebrochen.');
  }
  options.assertAuthorized?.();
  if (isAborted(options.signal)) {
    throw new VaultaError('CANCELLED', 'Der Dublettenscan wurde abgebrochen.');
  }
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted ?? false;
}

function reportProgress(options: DuplicateScanOptions, progress: DuplicateScanProgress): void {
  options.onProgress?.({ ...progress });
}

function normalizeText(value: string): string {
  return value.normalize('NFKC').trim().replace(/\s+/gu, ' ').toLocaleLowerCase('de-DE');
}

function normalizeMergeText(value: string): string {
  return value.normalize('NFKC').trim().replace(/\s+/gu, ' ');
}

function normalizeCardNumber(value: string): string {
  return value
    .normalize('NFKC')
    .trim()
    .replace(/[\s-]+/gu, '');
}

function normalizedUrlKey(value: string): string {
  const parsed = parseHttpUrl(value);
  if (parsed === null) return `text:${normalizeText(value)}`;
  parsed.hash = '';
  return parsed.toString();
}

function normalizeHost(value: string): string | null {
  const parsed = parseHttpUrl(value);
  if (parsed === null) return null;
  return parsed.host.toLocaleLowerCase('en-US').replace(/\.$/u, '');
}

function parseHttpUrl(value: string): URL | null {
  const normalized = value.normalize('NFKC').trim();
  if (normalized.length === 0 || /\s/u.test(normalized)) return null;
  const hasScheme = /^[a-z][a-z0-9+.-]*:/iu.test(normalized);
  let parsed: URL;
  try {
    parsed = new URL(hasScheme ? normalized : `https://${normalized}`);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (parsed.username.length > 0 || parsed.password.length > 0 || parsed.hostname.length === 0) {
    return null;
  }
  parsed.hostname = parsed.hostname.toLocaleLowerCase('en-US').replace(/\.$/u, '');
  return parsed;
}

function isEmptyValue(value: unknown): boolean {
  return typeof value === 'string' ? value.length === 0 : value === null || value === undefined;
}

function entryReference(entry: VaultEntry): DuplicateEntryReference {
  return { vaultId: entry.vaultId, entryId: entry.id, updatedAt: entry.updatedAt };
}

function entryKey(entry: Pick<VaultEntry, 'vaultId' | 'id'>): string {
  return JSON.stringify([entry.vaultId, entry.id]);
}

function entryPairKey(left: VaultEntry, right: VaultEntry): string {
  return JSON.stringify([entryKey(left), entryKey(right)]);
}

function compareEntries(left: VaultEntry, right: VaultEntry): number {
  return (
    left.vaultId.localeCompare(right.vaultId, 'en') ||
    left.id.localeCompare(right.id, 'en') ||
    left.updatedAt.localeCompare(right.updatedAt, 'en')
  );
}

function compareReferences(left: DuplicateEntryReference, right: DuplicateEntryReference): number {
  return (
    left.vaultId.localeCompare(right.vaultId, 'en') ||
    left.entryId.localeCompare(right.entryId, 'en') ||
    left.updatedAt.localeCompare(right.updatedAt, 'en')
  );
}

function compareCandidates(left: DuplicateCandidate, right: DuplicateCandidate): number {
  return compareReferences(left.left, right.left) || compareReferences(left.right, right.right);
}

function invalidMerge(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
