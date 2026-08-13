import { VaultaError } from '../../shared/errors';
import type {
  AttachmentMetadata,
  IntegrityFindingCode,
  IntegrityFindingDto,
  IntegrityReportDto,
  SavedViewRecord,
  VaultDocument,
} from '../../shared/models';
import type {
  AttachmentIntegrityOptions,
  AuthenticatedAttachmentMetadata,
  StoredAttachmentInventory,
} from './attachment-service';
import type { StoredVaultInventory } from './vault-service';

export type IntegrityCoreReport = Omit<IntegrityReportDto, 'reportId'>;

type IntegrityFindingSeverity = IntegrityFindingDto['severity'];
type IntegrityFindingScope = IntegrityFindingDto['scope'];

export type IntegrityProgressPhase = 'profile' | 'vaults' | 'references' | 'attachments' | 'audit';

export interface IntegrityProgress {
  readonly phase: IntegrityProgressPhase;
  readonly completed: number;
  readonly total: number;
}

export interface IntegrityProfileReader {
  readPublicHeader(): Promise<unknown>;
  getProtectedMetadata<T>(namespace: string): Promise<T | null>;
  getPublicFactorData<T>(): Promise<T | null>;
}

export interface IntegrityVaultReader {
  inspectStoredVaultInventory(assertAuthorized?: () => void): Promise<StoredVaultInventory>;
  listRegisteredVaultIds(assertAuthorized?: () => void): Promise<string[]>;
  readVaultFresh(vaultId: string, assertAuthorized?: () => void): Promise<VaultDocument>;
}

export interface IntegrityAttachmentReader {
  inspectStoredAttachmentInventory(
    assertAuthorized?: () => void,
  ): Promise<StoredAttachmentInventory>;
  inspectIntegrity(
    vaultId: string,
    attachmentId: string,
    options?: AttachmentIntegrityOptions,
  ): Promise<AuthenticatedAttachmentMetadata>;
}

export interface IntegrityAuditReader {
  inspectStoredDocumentFormatVersion(): Promise<number>;
}

export interface IntegrityCheckServiceOptions {
  readonly profile: IntegrityProfileReader;
  readonly vaults: IntegrityVaultReader;
  readonly attachments: IntegrityAttachmentReader;
  readonly audit: IntegrityAuditReader;
  readonly now?: () => Date;
}

export interface IntegrityScanOptions {
  readonly savedViews?: readonly SavedViewRecord[];
  readonly assertAuthorized?: () => void;
  readonly onProgress?: (progress: IntegrityProgress) => void;
  readonly yieldControl?: () => Promise<void>;
  /**
   * Recovery-only verification cannot derive the master gate that authenticates
   * public factor data. The original payload is therefore left untouched and
   * this single check is explicitly omitted.
   */
  readonly skipPublicFactorVerification?: boolean;
}

interface InternalFinding extends IntegrityFindingDto {
  readonly sortKey: string;
}

interface ExpectedAttachment {
  readonly metadata: AttachmentMetadata;
  readonly sortKey: string;
}

const PROFILE_PROBE_NAMESPACE = 'integrity-probe';
const REFERENCE_CHECKPOINT_INTERVAL = 100;
const SCOPE_ORDER: Readonly<Record<IntegrityFindingScope, number>> = {
  profile: 0,
  vault: 1,
  reference: 2,
  attachment: 3,
  audit: 4,
};

/**
 * Performs a complete read-only integrity pass. Technical identifiers are used
 * only as transient sort keys and are removed before the report is returned.
 */
export class IntegrityCheckService {
  private readonly profile: IntegrityProfileReader;
  private readonly vaults: IntegrityVaultReader;
  private readonly attachments: IntegrityAttachmentReader;
  private readonly audit: IntegrityAuditReader;
  private readonly now: () => Date;

  public constructor(options: IntegrityCheckServiceOptions) {
    this.profile = options.profile;
    this.vaults = options.vaults;
    this.attachments = options.attachments;
    this.audit = options.audit;
    this.now = options.now ?? (() => new Date());
  }

  public async scan(options: IntegrityScanOptions = {}): Promise<IntegrityCoreReport> {
    const generatedAt = this.now();
    if (Number.isNaN(generatedAt.getTime())) {
      throw new VaultaError('INVALID_INPUT', 'Der Zeitpunkt der Integritätsprüfung ist ungültig.');
    }
    const assertAuthorized = options.assertAuthorized ?? (() => undefined);
    const yieldControl =
      options.yieldControl ?? (() => new Promise<void>((resolve) => setImmediate(resolve)));
    const findings: InternalFinding[] = [];
    const addFinding = (
      code: IntegrityFindingCode,
      scope: IntegrityFindingScope,
      severity: IntegrityFindingSeverity,
      sortKey: string,
    ): void => {
      findings.push({ id: '', code, scope, severity, sortKey });
    };

    assertAuthorized();
    const profileHeaderValid = await this.capture(
      () => this.profile.readPublicHeader(),
      assertAuthorized,
      () => addFinding('profile-invalid', 'profile', 'critical', 'header'),
    );
    if (profileHeaderValid !== null) {
      await this.capture(
        () => this.profile.getProtectedMetadata<unknown>(PROFILE_PROBE_NAMESPACE),
        assertAuthorized,
        () => addFinding('profile-metadata-invalid', 'profile', 'critical', 'protected-metadata'),
      );
      if (options.skipPublicFactorVerification !== true) {
        await this.capture(
          () => this.profile.getPublicFactorData<unknown>(),
          assertAuthorized,
          () => addFinding('profile-factor-invalid', 'profile', 'critical', 'factor-mac'),
        );
      }
    }

    const vaultInventory =
      (await this.capture(
        () => this.vaults.inspectStoredVaultInventory(assertAuthorized),
        assertAuthorized,
        () => addFinding('vault-registry-mismatch', 'vault', 'critical', 'inventory-unreadable'),
      )) ?? emptyVaultInventory();
    for (let index = 0; index < vaultInventory.invalidEntryCount; index += 1) {
      addFinding('vault-registry-mismatch', 'vault', 'critical', `invalid-entry:${String(index)}`);
    }

    const registeredVaultIds =
      (await this.capture(
        () => this.vaults.listRegisteredVaultIds(assertAuthorized),
        assertAuthorized,
        () => addFinding('vault-registry-mismatch', 'vault', 'critical', 'registry-invalid'),
      )) ?? [];

    const attachmentInventory =
      (await this.capture(
        () => this.attachments.inspectStoredAttachmentInventory(assertAuthorized),
        assertAuthorized,
        () => addFinding('attachment-container-invalid', 'attachment', 'critical', 'inventory'),
      )) ?? emptyAttachmentInventory();
    for (let index = 0; index < attachmentInventory.invalidEntryCount; index += 1) {
      addFinding(
        'attachment-container-invalid',
        'attachment',
        'critical',
        `invalid-entry:${String(index)}`,
      );
    }

    const storedVaultIds = new Set(vaultInventory.vaultIds);
    const registeredIds = new Set(registeredVaultIds);
    const allVaultIds = [...new Set([...storedVaultIds, ...registeredIds])].sort(compareStrings);
    const totalWork = 3 + allVaultIds.length + attachmentInventory.references.length;
    let completed = 0;
    const reportProgress = (phase: IntegrityProgressPhase): void => {
      options.onProgress?.({ phase, completed, total: totalWork });
    };
    const advance = async (phase: IntegrityProgressPhase): Promise<void> => {
      completed += 1;
      reportProgress(phase);
      await yieldControl();
      assertAuthorized();
    };

    reportProgress('profile');
    await advance('profile');

    const documents = new Map<string, VaultDocument>();
    for (const vaultId of allVaultIds) {
      assertAuthorized();
      if (!storedVaultIds.has(vaultId)) {
        addFinding('vault-registry-mismatch', 'vault', 'critical', `registered:${vaultId}`);
      } else if (!registeredIds.has(vaultId)) {
        addFinding('vault-registry-mismatch', 'vault', 'critical', `file:${vaultId}`);
      } else {
        const document = await this.capture(
          () => this.vaults.readVaultFresh(vaultId, assertAuthorized),
          assertAuthorized,
          () => addFinding('vault-container-invalid', 'vault', 'critical', vaultId),
        );
        if (document !== null) documents.set(vaultId, document);
      }
      await advance('vaults');
    }

    const expectedAttachments = new Map<string, ExpectedAttachment[]>();
    const scanned = await this.inspectReferences(
      documents,
      options.savedViews ?? [],
      expectedAttachments,
      addFinding,
      assertAuthorized,
      yieldControl,
    );
    const storedAttachmentKeys = new Set(attachmentInventory.references.map(attachmentStorageKey));
    for (const [storageKey, expected] of expectedAttachments) {
      if (!storedAttachmentKeys.has(storageKey)) {
        addFinding(
          'attachment-missing',
          'attachment',
          'critical',
          expected[0]?.sortKey ?? storageKey,
        );
      }
    }
    await advance('references');

    for (const reference of attachmentInventory.references) {
      assertAuthorized();
      const storageKey = attachmentStorageKey(reference);
      const expected = expectedAttachments.get(storageKey) ?? [];
      if (expected.length === 0) {
        addFinding('attachment-orphan', 'attachment', 'warning', storageKey);
      }
      const authenticated = await this.capture(
        () =>
          this.attachments.inspectIntegrity(reference.vaultId, reference.attachmentId, {
            assertAuthorized,
            yieldControl,
            yieldEveryChunks: 1,
          }),
        assertAuthorized,
        () => addFinding('attachment-container-invalid', 'attachment', 'critical', storageKey),
      );
      if (authenticated !== null) {
        for (const candidate of expected) {
          if (
            candidate.metadata.size !== authenticated.size ||
            candidate.metadata.sha256.toLowerCase() !== authenticated.sha256.toLowerCase()
          ) {
            addFinding('attachment-metadata-mismatch', 'attachment', 'critical', candidate.sortKey);
          }
        }
      }
      await advance('attachments');
    }

    await this.capture(
      () => this.audit.inspectStoredDocumentFormatVersion(),
      assertAuthorized,
      () => addFinding('audit-invalid', 'audit', 'critical', 'audit'),
    );
    await advance('audit');
    assertAuthorized();

    const publicFindings = redactAndSortFindings(findings);
    return {
      generatedAt: generatedAt.toISOString(),
      success: publicFindings.length === 0,
      scannedVaults: scanned.vaults,
      scannedEntries: scanned.entries,
      scannedAttachments: attachmentInventory.references.length,
      findings: publicFindings,
      networkUsed: false,
    };
  }

  private async inspectReferences(
    documents: ReadonlyMap<string, VaultDocument>,
    savedViews: readonly SavedViewRecord[],
    expectedAttachments: Map<string, ExpectedAttachment[]>,
    addFinding: (
      code: IntegrityFindingCode,
      scope: IntegrityFindingScope,
      severity: IntegrityFindingSeverity,
      sortKey: string,
    ) => void,
    assertAuthorized: () => void,
    yieldControl: () => Promise<void>,
  ): Promise<{
    vaults: number;
    entries: number;
  }> {
    let entries = 0;
    let inspectedReferences = 0;
    const checkpoint = async (): Promise<void> => {
      assertAuthorized();
      inspectedReferences += 1;
      if (inspectedReferences % REFERENCE_CHECKPOINT_INTERVAL !== 0) return;
      await yieldControl();
      assertAuthorized();
    };

    assertAuthorized();
    for (const [vaultId, document] of [...documents].sort(([left], [right]) =>
      compareStrings(left, right),
    )) {
      const folderIds = new Set<string>();
      for (let index = 0; index < document.folders.length; index += 1) {
        const folder = document.folders[index]!;
        if (folderIds.has(folder.id)) {
          addFinding(
            'duplicate-folder-id',
            'reference',
            'critical',
            `${vaultId}:folder:${folder.id}:${String(index)}`,
          );
        }
        folderIds.add(folder.id);
        await checkpoint();
      }

      const entryIds = new Set<string>();
      for (let entryIndex = 0; entryIndex < document.entries.length; entryIndex += 1) {
        const entry = document.entries[entryIndex]!;
        entries += 1;
        const entrySortKey = `${vaultId}:entry:${entry.id}:${String(entryIndex)}`;
        if (entryIds.has(entry.id)) {
          addFinding('duplicate-entry-id', 'reference', 'critical', entrySortKey);
        }
        entryIds.add(entry.id);
        if (entry.vaultId !== vaultId) {
          addFinding('entry-vault-mismatch', 'reference', 'critical', entrySortKey);
        }
        if (entry.folderId !== null && !folderIds.has(entry.folderId)) {
          addFinding('folder-reference-invalid', 'reference', 'warning', entrySortKey);
        }

        for (
          let attachmentIndex = 0;
          attachmentIndex < entry.attachments.length;
          attachmentIndex += 1
        ) {
          const metadata = entry.attachments[attachmentIndex]!;
          const storageKey = `${vaultId}/${metadata.id}`;
          const candidates = expectedAttachments.get(storageKey) ?? [];
          const sortKey = `${entrySortKey}:attachment:${metadata.id}:${String(attachmentIndex)}`;
          if (candidates.length > 0) {
            addFinding('attachment-reference-duplicate', 'reference', 'critical', sortKey);
          }
          candidates.push({ metadata, sortKey });
          expectedAttachments.set(storageKey, candidates);
          await checkpoint();
        }
        await checkpoint();
      }
      await checkpoint();
    }

    const savedViewIds = new Set<string>();
    const orderedSavedViews = [...savedViews].sort(
      (left, right) =>
        compareStrings(left.id, right.id) ||
        compareStrings(left.vaultId, right.vaultId) ||
        compareStrings(left.updatedAt, right.updatedAt),
    );
    for (let index = 0; index < orderedSavedViews.length; index += 1) {
      const view = orderedSavedViews[index]!;
      const sortKey = `${view.id}:${view.vaultId}:${String(index)}`;
      if (savedViewIds.has(view.id)) {
        addFinding('saved-view-reference-invalid', 'reference', 'warning', sortKey);
      }
      savedViewIds.add(view.id);
      const document = documents.get(view.vaultId);
      if (document === undefined) {
        addFinding('saved-view-reference-invalid', 'reference', 'warning', sortKey);
      } else if (
        view.filters.folderId !== null &&
        !document.folders.some((folder) => folder.id === view.filters.folderId)
      ) {
        addFinding('saved-view-reference-invalid', 'reference', 'warning', sortKey);
      }
      await checkpoint();
    }

    assertAuthorized();
    return {
      vaults: documents.size,
      entries,
    };
  }

  private async capture<T>(
    operation: () => Promise<T>,
    assertAuthorized: () => void,
    onFailure: () => void,
  ): Promise<T | null> {
    assertAuthorized();
    try {
      const value = await operation();
      assertAuthorized();
      return value;
    } catch (error) {
      rethrowAuthorizationLoss(error);
      assertAuthorized();
      onFailure();
      return null;
    }
  }
}

function redactAndSortFindings(findings: readonly InternalFinding[]): IntegrityFindingDto[] {
  const ordered = [...findings].sort(
    (left, right) =>
      SCOPE_ORDER[left.scope] - SCOPE_ORDER[right.scope] ||
      compareStrings(left.code, right.code) ||
      compareStrings(left.sortKey, right.sortKey),
  );
  return ordered.map(({ code, scope, severity }, index) => ({
    id: `integrity-finding-${String(index + 1).padStart(4, '0')}`,
    code,
    scope,
    severity,
  }));
}

function attachmentStorageKey(reference: {
  readonly vaultId: string;
  readonly attachmentId: string;
}): string {
  return `${reference.vaultId}/${reference.attachmentId}`;
}

function emptyVaultInventory(): StoredVaultInventory {
  return { vaultIds: [], invalidEntryCount: 0 };
}

function emptyAttachmentInventory(): StoredAttachmentInventory {
  return { references: [], invalidEntryCount: 0 };
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function rethrowAuthorizationLoss(error: unknown): void {
  if (
    error instanceof VaultaError &&
    ['LOCKED', 'CANCELLED', 'AUTH_FAILED', 'AUTH_FACTOR_REQUIRED', 'AUTH_RATE_LIMITED'].includes(
      error.code,
    )
  ) {
    throw error;
  }
}
