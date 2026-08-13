import type {
  AttachmentMetadata,
  SavedViewRecord,
  VaultDocument,
  VaultEntry,
} from '../../shared/models';

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

export type DataQualityErrorCode =
  'INVALID_INPUT' | 'FINDING_NOT_FOUND' | 'FINDING_NOT_FIXABLE' | 'STALE_REFERENCE';

export class DataQualityError extends Error {
  public constructor(
    public readonly code: DataQualityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'DataQualityError';
  }
}

export type DataQualityReference =
  | {
      kind: 'entry';
      vaultId: string;
      entryId: string;
      updatedAt: string;
    }
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

export type DataQualityUrlField =
  'credential-website' | 'credit-card-website' | 'license-download-url' | 'custom-url-field';

export type DataQualityLocation =
  | { kind: 'url'; field: DataQualityUrlField; index: number | null; customFieldId: string | null }
  | { kind: 'website-pair'; firstIndex: number; secondIndex: number }
  | { kind: 'title' }
  | { kind: 'credit-card-expiry' }
  | { kind: 'license-expiry' }
  | {
      kind: 'totp-parameters';
      parameters: Array<'algorithm' | 'digits' | 'period'>;
    }
  | { kind: 'attachment' }
  | { kind: 'folder-reference' }
  | {
      kind: 'saved-view-references';
      orphanFolder: boolean;
      orphanTagIndexes: number[];
    };

export interface DataQualityFinding {
  id: string;
  code: DataQualityFindingCode;
  severity: 'info' | 'warning';
  reference: DataQualityReference;
  location: DataQualityLocation;
  fixCode: DataQualityFixCode | null;
}

export interface DataQualityReport {
  generatedAt: string;
  vaultId: string;
  scannedEntries: number;
  findings: DataQualityFinding[];
  networkUsed: false;
}

export interface AuthenticatedAttachmentMetadata {
  size: number;
  sha256: string;
}

interface EntryAttachmentTechnicalCheck {
  vaultId: string;
  entryId: string;
  attachmentId: string;
  entryUpdatedAt: string;
}

export type AttachmentTechnicalCheck =
  | (EntryAttachmentTechnicalCheck & {
      status: 'metadata-mismatch';
      verifiedMetadata: AuthenticatedAttachmentMetadata;
    })
  | (EntryAttachmentTechnicalCheck & {
      status: 'missing-file' | 'corrupt-file';
    })
  | {
      status: 'orphan-file';
      vaultId: string;
      attachmentId: string;
      vaultUpdatedAt: string;
    };

export interface DataQualityScanInput {
  document: VaultDocument;
  savedViews?: readonly SavedViewRecord[];
  attachmentChecks?: readonly AttachmentTechnicalCheck[];
}

export interface DataQualityProgress {
  phase: 'entries' | 'attachments' | 'saved-views';
  completed: number;
  total: number;
}

export interface DataQualityScanOptions {
  now?: Date;
  batchSize?: number;
  assertAuthorized?: () => void;
  onProgress?: (progress: DataQualityProgress) => void;
  yieldControl?: () => Promise<void>;
}

export interface DataQualityPreviewOptions {
  now?: Date;
  assertAuthorized?: () => void;
}

export type DataQualityFixMutation =
  | {
      kind: 'replace-entry-url';
      location: Extract<DataQualityLocation, { kind: 'url' }>;
      value: string;
    }
  | {
      kind: 'remove-entry-website';
      index: number;
    }
  | {
      kind: 'replace-entry-title';
      value: string;
    }
  | {
      kind: 'clear-entry-folder';
    }
  | {
      kind: 'remove-saved-view-references';
      clearFolder: boolean;
      removeTagIndexes: number[];
    }
  | {
      kind: 'update-attachment-metadata';
      attachmentId: string;
      metadata: AuthenticatedAttachmentMetadata;
    };

/**
 * Main-process-only preview. Unlike a report, this plan may contain a replacement URL or an
 * authenticated attachment hash because those values are required to apply the exact mutation.
 */
export interface DataQualityFixPlan {
  findingId: string;
  fixCode: DataQualityFixCode;
  reference: DataQualityReference;
  mutation: DataQualityFixMutation;
}

interface InternalFinding {
  finding: DataQualityFinding;
  plan: DataQualityFixPlan | null;
}

interface ParsedUrl {
  parsed: URL | null;
  replacement: string | null;
}

interface UrlCandidate {
  raw: string;
  location: Extract<DataQualityLocation, { kind: 'url' }>;
}

const IMPORT_PLACEHOLDER = /^Importierter Eintrag \d+$/iu;
const SHA256_HEX = /^[a-f\d]{64}$/iu;
const DEFAULT_BATCH_SIZE = 25;

export class DataQualityService {
  public async scan(
    input: DataQualityScanInput,
    options: DataQualityScanOptions = {},
  ): Promise<DataQualityReport> {
    const context = validateScanContext(input, options);
    const findings: InternalFinding[] = [];
    const assertAuthorized = options.assertAuthorized ?? noOp;
    const onProgress = options.onProgress ?? noOp;
    const yieldControl = options.yieldControl ?? yieldToEventLoop;
    const activeEntries = input.document.entries.filter((entry) => entry.deletedAt === null);
    const attachmentChecks = (input.attachmentChecks ?? []).filter(
      (check) => check.vaultId === input.document.id,
    );
    const savedViews = (input.savedViews ?? []).filter(
      (view) => view.vaultId === input.document.id,
    );
    let workSinceYield = 0;

    const processWorkItem = async (): Promise<void> => {
      assertAuthorized();
      workSinceYield += 1;
      if (workSinceYield < context.batchSize) return;
      workSinceYield = 0;
      await yieldControl();
      assertAuthorized();
    };

    assertAuthorized();
    onProgress({ phase: 'entries', completed: 0, total: activeEntries.length });
    for (let index = 0; index < activeEntries.length; index += 1) {
      const entry = activeEntries[index]!;
      findings.push(...inspectEntry(entry, input.document, context.now));
      onProgress({ phase: 'entries', completed: index + 1, total: activeEntries.length });
      await processWorkItem();
    }

    onProgress({ phase: 'attachments', completed: 0, total: attachmentChecks.length });
    for (let index = 0; index < attachmentChecks.length; index += 1) {
      findings.push(...inspectAttachmentCheck(attachmentChecks[index]!, input.document));
      onProgress({
        phase: 'attachments',
        completed: index + 1,
        total: attachmentChecks.length,
      });
      await processWorkItem();
    }

    const knownTags = collectKnownTags(input.document);
    onProgress({ phase: 'saved-views', completed: 0, total: savedViews.length });
    for (let index = 0; index < savedViews.length; index += 1) {
      findings.push(...inspectSavedView(savedViews[index]!, input.document, knownTags));
      onProgress({ phase: 'saved-views', completed: index + 1, total: savedViews.length });
      await processWorkItem();
    }

    assertAuthorized();
    const publicFindings = uniqueAndSorted(findings).map(({ finding }) => clone(finding));
    return {
      generatedAt: context.now.toISOString(),
      vaultId: input.document.id,
      scannedEntries: activeEntries.length,
      findings: publicFindings,
      networkUsed: false,
    };
  }

  public previewFix(
    input: DataQualityScanInput,
    finding: DataQualityFinding,
    options: DataQualityPreviewOptions = {},
  ): DataQualityFixPlan {
    const now = validateNow(options.now);
    const assertAuthorized = options.assertAuthorized ?? noOp;
    assertAuthorized();
    assertReferenceRevision(input, finding.reference);

    const current = collectAll(input, now).find((candidate) => candidate.finding.id === finding.id);
    if (!current) {
      throw new DataQualityError(
        'FINDING_NOT_FOUND',
        'Der Befund ist in der aktuellen Revision nicht mehr vorhanden.',
      );
    }
    if (!sameReference(current.finding.reference, finding.reference)) {
      throw new DataQualityError(
        'STALE_REFERENCE',
        'Der Befund verweist nicht auf die aktuelle Revision.',
      );
    }
    if (current.finding.fixCode !== finding.fixCode) {
      throw new DataQualityError('INVALID_INPUT', 'Der Fix-Code passt nicht zum aktuellen Befund.');
    }
    if (!current.plan) {
      throw new DataQualityError(
        'FINDING_NOT_FIXABLE',
        'Fuer diesen Befund ist keine sichere automatische Korrektur erlaubt.',
      );
    }

    assertAuthorized();
    return clone(current.plan);
  }
}

function validateScanContext(
  input: DataQualityScanInput,
  options: DataQualityScanOptions,
): { now: Date; batchSize: number } {
  if (!input.document || typeof input.document.id !== 'string') {
    throw new DataQualityError('INVALID_INPUT', 'Das Vault-Dokument ist ungueltig.');
  }
  const now = validateNow(options.now);
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > 10_000) {
    throw new DataQualityError('INVALID_INPUT', 'Die Batch-Groesse ist ungueltig.');
  }
  return { now, batchSize };
}

function validateNow(value: Date | undefined): Date {
  const now = value ?? new Date();
  if (Number.isNaN(now.getTime())) {
    throw new DataQualityError('INVALID_INPUT', 'Der Pruefzeitpunkt ist ungueltig.');
  }
  return new Date(now.getTime());
}

function collectAll(input: DataQualityScanInput, now: Date): InternalFinding[] {
  const findings = input.document.entries
    .filter((entry) => entry.deletedAt === null)
    .flatMap((entry) => inspectEntry(entry, input.document, now));
  for (const check of input.attachmentChecks ?? []) {
    if (check.vaultId === input.document.id) {
      findings.push(...inspectAttachmentCheck(check, input.document));
    }
  }
  const knownTags = collectKnownTags(input.document);
  for (const view of input.savedViews ?? []) {
    if (view.vaultId === input.document.id) {
      findings.push(...inspectSavedView(view, input.document, knownTags));
    }
  }
  return uniqueAndSorted(findings);
}

function inspectEntry(entry: VaultEntry, document: VaultDocument, now: Date): InternalFinding[] {
  const findings: InternalFinding[] = [];
  const reference = entryReference(entry);
  const title = entry.title.normalize('NFKC').trim();
  const titleCode =
    title.length === 0
      ? ('empty-title' as const)
      : IMPORT_PLACEHOLDER.test(title)
        ? ('import-placeholder-title' as const)
        : null;
  if (titleCode) {
    const replacement = deriveUnambiguousTitle(entry);
    findings.push(
      makeFinding({
        code: titleCode,
        severity: 'warning',
        reference,
        location: { kind: 'title' },
        fixCode: replacement ? 'replace-unambiguous-title' : null,
        suffix: 'title',
        mutation: replacement ? { kind: 'replace-entry-title', value: replacement } : null,
      }),
    );
  }

  for (const candidate of urlCandidates(entry)) {
    const inspection = parseUrl(candidate.raw);
    if (!inspection.parsed) {
      findings.push(
        makeFinding({
          code: 'invalid-url',
          severity: 'warning',
          reference,
          location: candidate.location,
          fixCode: null,
          suffix: urlLocationSuffix(candidate.location),
          mutation: null,
        }),
      );
    } else if (inspection.replacement !== null) {
      findings.push(
        makeFinding({
          code: 'url-needs-normalization',
          severity: 'info',
          reference,
          location: candidate.location,
          fixCode: 'normalize-url-https-whitespace',
          suffix: urlLocationSuffix(candidate.location),
          mutation: {
            kind: 'replace-entry-url',
            location: candidate.location,
            value: inspection.replacement,
          },
        }),
      );
    }
  }

  if (entry.data.type === 'credential') {
    findings.push(...inspectWebsiteDuplicates(entry));
  }

  if (!document.folders.some((folder) => folder.id === entry.folderId) && entry.folderId !== null) {
    findings.push(
      makeFinding({
        code: 'orphan-folder-reference',
        severity: 'warning',
        reference,
        location: { kind: 'folder-reference' },
        fixCode: 'clear-orphan-folder',
        suffix: 'folder',
        mutation: { kind: 'clear-entry-folder' },
      }),
    );
  }

  if (entry.data.type === 'credit-card' && isExpiredCreditCard(entry, now)) {
    findings.push(
      makeFinding({
        code: 'expired-credit-card',
        severity: 'warning',
        reference,
        location: { kind: 'credit-card-expiry' },
        fixCode: null,
        suffix: 'expiry',
        mutation: null,
      }),
    );
  }

  if (entry.data.type === 'software-license' && isExpiredLicense(entry, now)) {
    findings.push(
      makeFinding({
        code: 'expired-license',
        severity: 'warning',
        reference,
        location: { kind: 'license-expiry' },
        fixCode: null,
        suffix: 'expiry',
        mutation: null,
      }),
    );
  }

  if (entry.data.type === 'credential' && entry.data.value.totp) {
    const parameters: Array<'algorithm' | 'digits' | 'period'> = [];
    if (entry.data.value.totp.algorithm !== 'SHA1') parameters.push('algorithm');
    if (entry.data.value.totp.digits !== 6) parameters.push('digits');
    if (entry.data.value.totp.period !== 30) parameters.push('period');
    if (parameters.length > 0) {
      findings.push(
        makeFinding({
          code: 'unusual-totp-parameters',
          severity: 'info',
          reference,
          location: { kind: 'totp-parameters', parameters },
          fixCode: null,
          suffix: 'totp',
          mutation: null,
        }),
      );
    }
  }

  return findings;
}

function inspectWebsiteDuplicates(entry: VaultEntry): InternalFinding[] {
  if (entry.data.type !== 'credential') return [];
  const findings: InternalFinding[] = [];
  const parsed = entry.data.value.websites.map((raw) => parseUrl(raw).parsed);
  const firstByExactKey = new Map<string, number>();

  for (let index = 0; index < parsed.length; index += 1) {
    const url = parsed[index];
    if (!url) continue;
    const key = exactUrlKey(url);
    const firstIndex = firstByExactKey.get(key);
    if (firstIndex === undefined) {
      firstByExactKey.set(key, index);
      continue;
    }
    findings.push(
      makeFinding({
        code: 'duplicate-website',
        severity: 'warning',
        reference: entryReference(entry),
        location: { kind: 'website-pair', firstIndex, secondIndex: index },
        fixCode: 'remove-exact-duplicate-url',
        suffix: `${String(firstIndex)}:${String(index)}`,
        mutation: { kind: 'remove-entry-website', index },
      }),
    );
  }

  for (let left = 0; left < parsed.length; left += 1) {
    const leftUrl = parsed[left];
    if (!leftUrl) continue;
    for (let right = left + 1; right < parsed.length; right += 1) {
      const rightUrl = parsed[right];
      if (!rightUrl || exactUrlKey(leftUrl) === exactUrlKey(rightUrl)) continue;
      if (similarUrlKey(leftUrl) !== similarUrlKey(rightUrl)) continue;
      findings.push(
        makeFinding({
          code: 'similar-website',
          severity: 'info',
          reference: entryReference(entry),
          location: { kind: 'website-pair', firstIndex: left, secondIndex: right },
          fixCode: null,
          suffix: `${String(left)}:${String(right)}`,
          mutation: null,
        }),
      );
    }
  }
  return findings;
}

function inspectAttachmentCheck(
  check: AttachmentTechnicalCheck,
  document: VaultDocument,
): InternalFinding[] {
  if (check.status === 'orphan-file') {
    if (check.vaultUpdatedAt !== document.updatedAt) {
      throw staleTechnicalResult();
    }
    if (findAttachment(document, check.attachmentId)) {
      throw staleTechnicalResult();
    }
    const reference: DataQualityReference = {
      kind: 'attachment',
      vaultId: document.id,
      entryId: null,
      attachmentId: check.attachmentId,
      updatedAt: document.updatedAt,
    };
    return [
      makeFinding({
        code: 'attachment-file-orphan',
        severity: 'warning',
        reference,
        location: { kind: 'attachment' },
        fixCode: null,
        suffix: 'orphan',
        mutation: null,
      }),
    ];
  }

  const entry = document.entries.find((candidate) => candidate.id === check.entryId);
  if (!entry || entry.vaultId !== document.id || entry.updatedAt !== check.entryUpdatedAt) {
    throw staleTechnicalResult();
  }
  const attachment = entry.attachments.find((candidate) => candidate.id === check.attachmentId);
  if (!attachment) throw staleTechnicalResult();
  const reference: DataQualityReference = {
    kind: 'attachment',
    vaultId: document.id,
    entryId: entry.id,
    attachmentId: attachment.id,
    updatedAt: entry.updatedAt,
  };

  if (check.status === 'metadata-mismatch') {
    validateAuthenticatedMetadata(check.verifiedMetadata);
    return [
      makeFinding({
        code: 'attachment-metadata-mismatch',
        severity: 'warning',
        reference,
        location: { kind: 'attachment' },
        fixCode: 'update-authenticated-attachment-metadata',
        suffix: 'metadata',
        mutation: {
          kind: 'update-attachment-metadata',
          attachmentId: attachment.id,
          metadata: {
            ...check.verifiedMetadata,
            sha256: check.verifiedMetadata.sha256.toLowerCase(),
          },
        },
      }),
    ];
  }

  return [
    makeFinding({
      code: check.status === 'missing-file' ? 'attachment-file-missing' : 'attachment-file-corrupt',
      severity: 'warning',
      reference,
      location: { kind: 'attachment' },
      fixCode: null,
      suffix: check.status,
      mutation: null,
    }),
  ];
}

function inspectSavedView(
  view: SavedViewRecord,
  document: VaultDocument,
  knownTags: ReadonlySet<string>,
): InternalFinding[] {
  const orphanFolder =
    view.filters.folderId !== null &&
    !document.folders.some((folder) => folder.id === view.filters.folderId);
  const orphanTagIndexes = view.filters.tags.flatMap((tag, index) =>
    knownTags.has(normalizeKey(tag)) ? [] : [index],
  );
  if (!orphanFolder && orphanTagIndexes.length === 0) return [];

  return [
    makeFinding({
      code: 'saved-view-orphan-reference',
      severity: 'warning',
      reference: {
        kind: 'saved-view',
        vaultId: document.id,
        savedViewId: view.id,
        updatedAt: view.updatedAt,
      },
      location: { kind: 'saved-view-references', orphanFolder, orphanTagIndexes },
      fixCode: 'remove-saved-view-references',
      suffix: 'references',
      mutation: {
        kind: 'remove-saved-view-references',
        clearFolder: orphanFolder,
        removeTagIndexes: orphanTagIndexes,
      },
    }),
  ];
}

function makeFinding(input: {
  code: DataQualityFindingCode;
  severity: DataQualityFinding['severity'];
  reference: DataQualityReference;
  location: DataQualityLocation;
  fixCode: DataQualityFixCode | null;
  suffix: string;
  mutation: DataQualityFixMutation | null;
}): InternalFinding {
  const subjectId = referenceId(input.reference);
  const id = `${input.reference.kind}:${subjectId}:${input.code}:${input.suffix}`;
  const finding: DataQualityFinding = {
    id,
    code: input.code,
    severity: input.severity,
    reference: clone(input.reference),
    location: clone(input.location),
    fixCode: input.fixCode,
  };
  return {
    finding,
    plan:
      input.fixCode && input.mutation
        ? {
            findingId: id,
            fixCode: input.fixCode,
            reference: clone(input.reference),
            mutation: clone(input.mutation),
          }
        : null,
  };
}

function urlCandidates(entry: VaultEntry): UrlCandidate[] {
  const candidates: UrlCandidate[] = [];
  if (entry.data.type === 'credential') {
    entry.data.value.websites.forEach((raw, index) => {
      if (raw.trim().length > 0) {
        candidates.push({
          raw,
          location: {
            kind: 'url',
            field: 'credential-website',
            index,
            customFieldId: null,
          },
        });
      }
    });
  }
  if (entry.data.type === 'credit-card' && entry.data.value.website.trim().length > 0) {
    candidates.push({
      raw: entry.data.value.website,
      location: {
        kind: 'url',
        field: 'credit-card-website',
        index: null,
        customFieldId: null,
      },
    });
  }
  if (entry.data.type === 'software-license' && entry.data.value.downloadUrl.trim().length > 0) {
    candidates.push({
      raw: entry.data.value.downloadUrl,
      location: {
        kind: 'url',
        field: 'license-download-url',
        index: null,
        customFieldId: null,
      },
    });
  }
  entry.customFields.forEach((field, index) => {
    if (field.type === 'url' && typeof field.value === 'string' && field.value.trim().length > 0) {
      candidates.push({
        raw: field.value,
        location: {
          kind: 'url',
          field: 'custom-url-field',
          index,
          customFieldId: field.id,
        },
      });
    }
  });
  return candidates;
}

function parseUrl(raw: string): ParsedUrl {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || /\s/u.test(trimmed)) return { parsed: null, replacement: null };

  const hasWebScheme = /^https?:\/\//iu.test(trimmed);
  const looksLikeHostWithPort = /^[^/?#]+:\d+(?:[/?#]|$)/u.test(trimmed);
  const hasOtherOrMalformedScheme = /^[a-z][a-z\d+.-]*:/iu.test(trimmed) && !looksLikeHostWithPort;
  if (hasOtherOrMalformedScheme && !hasWebScheme) {
    return { parsed: null, replacement: null };
  }
  const candidate = hasWebScheme ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      parsed.hostname.length === 0 ||
      parsed.hostname.includes('..')
    ) {
      return { parsed: null, replacement: null };
    }
    if (!hasWebScheme && !isConfidentHost(parsed.hostname)) {
      return { parsed: null, replacement: null };
    }
    const replacement = !hasWebScheme ? parsed.href : raw === trimmed ? null : trimmed;
    return { parsed, replacement };
  } catch {
    return { parsed: null, replacement: null };
  }
}

function isConfidentHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.includes('.') ||
    (hostname.startsWith('[') && hostname.endsWith(']'))
  );
}

function exactUrlKey(url: URL): string {
  return url.href;
}

function similarUrlKey(url: URL): string {
  const hostname = url.hostname.replace(/^www\./iu, '');
  const pathname = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/u, '');
  return `${hostname}:${url.port}${pathname}${url.search}`;
}

function deriveUnambiguousTitle(entry: VaultEntry): string | null {
  if (entry.data.type === 'credential') {
    const nonEmpty = entry.data.value.websites.filter((website) => website.trim().length > 0);
    const parsed = nonEmpty.map((website) => parseUrl(website).parsed);
    if (nonEmpty.length === 0 || parsed.some((url) => !url)) return null;
    const hosts = new Set(
      parsed.map((url) =>
        url!.hostname
          .replace(/^www\./iu, '')
          .normalize('NFKC')
          .trim(),
      ),
    );
    return hosts.size === 1 ? [...hosts][0]! : null;
  }
  if (entry.data.type === 'software-license') return nonEmptyText(entry.data.value.product);
  if (entry.data.type === 'credit-card') return nonEmptyText(entry.data.value.cardName);
  if (entry.data.type === 'wifi') return nonEmptyText(entry.data.value.ssid);
  if (entry.data.type === 'ssh-key') return nonEmptyText(entry.data.value.host);
  return null;
}

function nonEmptyText(value: string): string | null {
  const normalized = value.normalize('NFKC').trim();
  return normalized.length > 0 ? normalized : null;
}

function isExpiredCreditCard(entry: VaultEntry, now: Date): boolean {
  if (entry.data.type !== 'credit-card') return false;
  const { expiryMonth, expiryYear } = entry.data.value;
  if (!Number.isInteger(expiryMonth) || expiryMonth < 1 || expiryMonth > 12) return false;
  if (!Number.isInteger(expiryYear) || expiryYear < 1) return false;
  const currentYear = now.getUTCFullYear();
  const currentMonth = now.getUTCMonth() + 1;
  return expiryYear < currentYear || (expiryYear === currentYear && expiryMonth < currentMonth);
}

function isExpiredLicense(entry: VaultEntry, now: Date): boolean {
  if (entry.data.type !== 'software-license') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(entry.data.value.expiryDate);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const expiry = Date.UTC(year, month - 1, day);
  const parsed = new Date(expiry);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return false;
  }
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return expiry < today;
}

function collectKnownTags(document: VaultDocument): Set<string> {
  return new Set(document.entries.flatMap((entry) => entry.tags.map(normalizeKey)));
}

function normalizeKey(value: string): string {
  return value.normalize('NFKC').trim().replace(/\s+/gu, ' ').toLocaleLowerCase('de');
}

function validateAuthenticatedMetadata(metadata: AuthenticatedAttachmentMetadata): void {
  if (
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < 0 ||
    !SHA256_HEX.test(metadata.sha256)
  ) {
    throw new DataQualityError(
      'INVALID_INPUT',
      'Das authentifizierte Attachment-Pruefergebnis ist ungueltig.',
    );
  }
}

function findAttachment(
  document: VaultDocument,
  attachmentId: string,
): { entry: VaultEntry; attachment: AttachmentMetadata } | null {
  for (const entry of document.entries) {
    const attachment = entry.attachments.find((candidate) => candidate.id === attachmentId);
    if (attachment) return { entry, attachment };
  }
  return null;
}

function assertReferenceRevision(
  input: DataQualityScanInput,
  reference: DataQualityReference,
): void {
  if (reference.vaultId !== input.document.id) throw staleReference();
  if (reference.kind === 'entry') {
    const entry = input.document.entries.find((candidate) => candidate.id === reference.entryId);
    if (!entry || entry.updatedAt !== reference.updatedAt) throw staleReference();
    return;
  }
  if (reference.kind === 'saved-view') {
    const view = (input.savedViews ?? []).find(
      (candidate) =>
        candidate.vaultId === input.document.id && candidate.id === reference.savedViewId,
    );
    if (!view || view.updatedAt !== reference.updatedAt) throw staleReference();
    return;
  }
  if (reference.entryId === null) {
    if (input.document.updatedAt !== reference.updatedAt) throw staleReference();
    return;
  }
  const entry = input.document.entries.find((candidate) => candidate.id === reference.entryId);
  const attachment = entry?.attachments.find(
    (candidate) => candidate.id === reference.attachmentId,
  );
  if (!entry || !attachment || entry.updatedAt !== reference.updatedAt) throw staleReference();
}

function entryReference(entry: VaultEntry): DataQualityReference {
  return {
    kind: 'entry',
    vaultId: entry.vaultId,
    entryId: entry.id,
    updatedAt: entry.updatedAt,
  };
}

function referenceId(reference: DataQualityReference): string {
  if (reference.kind === 'entry') return reference.entryId;
  if (reference.kind === 'saved-view') return reference.savedViewId;
  return reference.attachmentId;
}

function urlLocationSuffix(location: Extract<DataQualityLocation, { kind: 'url' }>): string {
  return `${location.field}:${location.index === null ? '-' : String(location.index)}:${location.customFieldId ?? '-'}`;
}

function uniqueAndSorted(findings: readonly InternalFinding[]): InternalFinding[] {
  const byId = new Map<string, InternalFinding>();
  for (const finding of findings) {
    if (!byId.has(finding.finding.id)) byId.set(finding.finding.id, finding);
  }
  return [...byId.values()].sort((left, right) =>
    left.finding.id < right.finding.id ? -1 : left.finding.id > right.finding.id ? 1 : 0,
  );
}

function sameReference(left: DataQualityReference, right: DataQualityReference): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function staleReference(): DataQualityError {
  return new DataQualityError(
    'STALE_REFERENCE',
    'Die referenzierte Revision ist nicht mehr aktuell.',
  );
}

function staleTechnicalResult(): DataQualityError {
  return new DataQualityError(
    'STALE_REFERENCE',
    'Ein technisches Attachment-Pruefergebnis ist nicht mehr aktuell.',
  );
}

function noOp(): void {}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
