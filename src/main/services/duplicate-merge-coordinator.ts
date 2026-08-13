import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type {
  AttachmentMetadata,
  CustomField,
  IdentityAddress,
  VaultDocument,
  VaultEntry,
} from '../../shared/models';
import { resolveInside } from '../storage/path-safety';
import type {
  MultiFileChange,
  MultiFileTransactionService,
} from '../storage/multi-file-transaction';
import type { AttachmentService } from './attachment-service';
import type { AuditService } from './audit-service';
import {
  DuplicateService,
  type DuplicateEntryReference,
  type DuplicateMergeCollectionChoice,
  type DuplicateMergeFieldChoice,
  type DuplicateMergeIdReplacement,
  type VerifiedAttachmentDuplicate,
} from './duplicate-service';
import { EntryLifecycleService } from './entry-lifecycle-service';
import type { VaultService } from './vault-service';

const STAGING_DIRECTORY = '.vaulta-duplicate-merge-staging';
const ATTACHMENT_EXTENSION = '.vatt';

export interface DuplicateMergeRequest {
  survivor: DuplicateEntryReference;
  duplicate: DuplicateEntryReference;
  fieldChoices: readonly DuplicateMergeFieldChoice[];
  collectionChoices: readonly DuplicateMergeCollectionChoice[];
}

export interface DuplicateMergeResult {
  survivor: DuplicateEntryReference;
  duplicate: DuplicateEntryReference;
  copiedAttachments: number;
  deduplicatedAttachments: number;
}

export interface DuplicateMergeCoordinatorOptions {
  rootDir: string;
  vaultService: VaultService;
  attachmentService: AttachmentService;
  getAuditService: () => AuditService;
  transactions: MultiFileTransactionService;
  duplicates?: DuplicateService;
  lifecycle?: EntryLifecycleService;
  now?: () => Date;
}

/**
 * Commits both vault generations, encrypted attachment copies and the redacted
 * audit event as one recoverable transaction. Renderer-provided references are
 * treated as optimistic revisions and rechecked while all vault locks are held.
 */
export class DuplicateMergeCoordinator {
  private readonly rootDir: string;
  private readonly stagingRoot: string;
  private readonly vaults: VaultService;
  private readonly attachments: AttachmentService;
  private readonly getAudit: () => AuditService;
  private readonly transactions: MultiFileTransactionService;
  private readonly duplicates: DuplicateService;
  private readonly lifecycle: EntryLifecycleService;
  private readonly now: () => Date;

  public constructor(options: DuplicateMergeCoordinatorOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.stagingRoot = resolveInside(this.rootDir, STAGING_DIRECTORY);
    this.vaults = options.vaultService;
    this.attachments = options.attachmentService;
    this.getAudit = options.getAuditService;
    this.transactions = options.transactions;
    this.duplicates = options.duplicates ?? new DuplicateService();
    this.lifecycle = options.lifecycle ?? new EntryLifecycleService();
    this.now = options.now ?? (() => new Date());
  }

  public async recoverOrphanedStaging(): Promise<void> {
    await this.removeOrphanedStaging();
  }

  public async merge(
    input: DuplicateMergeRequest,
    assertAuthorized: () => void = () => undefined,
  ): Promise<DuplicateMergeResult> {
    this.assertReferences(input);
    const vaultIds = [input.survivor.vaultId, input.duplicate.vaultId];
    const audit = this.getAudit();
    return this.vaults.withExclusiveVaults(vaultIds, async () =>
      audit.withExclusiveWrite(async () => {
        assertAuthorized();
        const documents = await this.readDocuments(vaultIds);
        const survivorDocument = requireDocument(documents, input.survivor.vaultId);
        const duplicateDocument = requireDocument(documents, input.duplicate.vaultId);
        const survivor = requireRevision(survivorDocument, input.survivor);
        const duplicate = requireRevision(duplicateDocument, input.duplicate);
        this.assertUnambiguousAttachmentIds(survivor, duplicate);
        assertAuthorized();

        const attachmentStrategy = collectionStrategy(input.collectionChoices, 'attachments');
        const verifiedDuplicates =
          attachmentStrategy === 'union'
            ? await this.verifyPotentialAttachmentDuplicates(survivor, duplicate, assertAuthorized)
            : [];
        const replacements = this.createIdReplacements(
          survivor,
          duplicate,
          input.collectionChoices,
          verifiedDuplicates,
        );
        const timestamp = this.now().toISOString();
        const plan = this.duplicates.planMerge({
          survivor,
          duplicate,
          now: timestamp,
          fieldChoices: input.fieldChoices,
          collectionChoices: input.collectionChoices,
          customFieldIdReplacements: replacements.customFields,
          identityAddressIdReplacements: replacements.addresses,
          attachmentIdReplacements: replacements.attachments,
          verifiedAttachmentDuplicates: verifiedDuplicates,
        });
        plan.survivor.lifecycle = plan.changedSecretSemantics
          ? this.lifecycle.afterSecretChange(
              plan.survivor.data.type,
              plan.survivor.lifecycle,
              timestamp,
            )
          : this.lifecycle.normalizeForType(plan.survivor.data.type, plan.survivor.lifecycle);

        const stagingDirectory = await this.createStagingDirectory();
        const sensitiveBuffers: Buffer[] = [];
        try {
          const attachmentChanges = await this.prepareAttachmentChanges(
            plan,
            duplicate,
            stagingDirectory,
            assertAuthorized,
          );
          replaceEntry(survivorDocument, plan.survivor);
          replaceEntry(duplicateDocument, plan.duplicate);
          survivorDocument.updatedAt = timestamp;
          duplicateDocument.updatedAt = timestamp;
          const changedDocuments = uniqueDocuments([survivorDocument, duplicateDocument]);
          const preparedDocuments = await Promise.all(
            changedDocuments.map((document) => this.vaults.prepareDocumentWrite(document)),
          );
          sensitiveBuffers.push(...preparedDocuments.map((prepared) => prepared.contents));
          assertAuthorized();
          const preparedAudit = await audit.prepareRecord({
            type: 'entries-merged',
            vaultId: survivor.vaultId,
            entryId: survivor.id,
          });
          sensitiveBuffers.push(preparedAudit.contents);
          const changes: MultiFileChange[] = [
            ...preparedDocuments.map((prepared): MultiFileChange => ({
              type: 'write',
              relativePath: prepared.relativePath,
              contents: prepared.contents,
              expectedSha256: prepared.expectedSha256,
            })),
            ...attachmentChanges,
            {
              type: 'write',
              relativePath: preparedAudit.relativePath,
              contents: preparedAudit.contents,
              expectedSha256: preparedAudit.expectedSha256,
            },
          ];
          assertAuthorized();
          await this.transactions.execute(changes, { assertAuthorized });
          this.vaults.installCommittedDocuments(changedDocuments);
          return {
            survivor: referenceOf(plan.survivor),
            duplicate: referenceOf(plan.duplicate),
            copiedAttachments: plan.attachmentCopies.length,
            deduplicatedAttachments: verifiedDuplicates.length,
          };
        } finally {
          for (const buffer of sensitiveBuffers) buffer.fill(0);
          await this.removeStagingDirectory(stagingDirectory).catch(() => undefined);
        }
      }),
    );
  }

  private async prepareAttachmentChanges(
    plan: ReturnType<DuplicateService['planMerge']>,
    duplicate: VaultEntry,
    stagingDirectory: string,
    assertAuthorized: () => void,
  ): Promise<MultiFileChange[]> {
    const changes: MultiFileChange[] = [];
    for (const copy of plan.attachmentCopies) {
      assertAuthorized();
      const source = duplicate.attachments.find(
        (attachment) => attachment.id === copy.sourceAttachmentId,
      );
      if (source === undefined) {
        throw new VaultaError('CONFLICT', 'Der zu übernehmende Anhang ist nicht mehr vorhanden.');
      }
      await this.attachments.verifyMetadata(copy.sourceVaultId, source, assertAuthorized);
      const stagingPath = resolveInside(
        stagingDirectory,
        `${copy.targetAttachmentId}${ATTACHMENT_EXTENSION}`,
      );
      const metadata = await this.attachments.reencryptToStaging({
        sourceVaultId: copy.sourceVaultId,
        sourceAttachmentId: copy.sourceAttachmentId,
        targetVaultId: copy.targetVaultId,
        targetAttachmentId: copy.targetAttachmentId,
        stagingPath,
        name: source.name,
        mediaType: source.mediaType,
        assertAuthorized,
      });
      if (metadata.size !== source.size || metadata.sha256 !== source.sha256) {
        throw new VaultaError(
          'CORRUPT_DATA',
          'Der neu verschlüsselte Anhang stimmt nicht mit seinen Metadaten überein.',
        );
      }
      replaceAttachmentMetadata(plan.survivor, metadata);
      changes.push({
        type: 'write-file',
        relativePath: attachmentRelativePath(copy.targetVaultId, copy.targetAttachmentId),
        sourcePath: stagingPath,
        expectedSha256: null,
      });
    }
    for (const attachmentId of plan.detachedSurvivorAttachmentIds) {
      changes.push({
        type: 'delete',
        relativePath: attachmentRelativePath(plan.survivor.vaultId, attachmentId),
      });
    }
    return changes;
  }

  private async verifyPotentialAttachmentDuplicates(
    survivor: VaultEntry,
    duplicate: VaultEntry,
    assertAuthorized: () => void,
  ): Promise<VerifiedAttachmentDuplicate[]> {
    const description = this.duplicates.describeMerge(survivor, duplicate);
    const usedSources = new Set<string>();
    const usedTargets = new Set<string>();
    const verified: VerifiedAttachmentDuplicate[] = [];
    for (const pair of description.potentialAttachmentDuplicates) {
      if (
        usedSources.has(pair.duplicateAttachmentId) ||
        usedTargets.has(pair.survivorAttachmentId)
      ) {
        continue;
      }
      const source = requireAttachment(duplicate, pair.duplicateAttachmentId);
      const target = requireAttachment(survivor, pair.survivorAttachmentId);
      await this.attachments.verifyMetadata(duplicate.vaultId, source, assertAuthorized);
      await this.attachments.verifyMetadata(survivor.vaultId, target, assertAuthorized);
      assertAuthorized();
      usedSources.add(source.id);
      usedTargets.add(target.id);
      verified.push(pair);
    }
    return verified;
  }

  private createIdReplacements(
    survivor: VaultEntry,
    duplicate: VaultEntry,
    choices: readonly DuplicateMergeCollectionChoice[],
    verified: readonly VerifiedAttachmentDuplicate[],
  ): {
    customFields: DuplicateMergeIdReplacement[];
    addresses: DuplicateMergeIdReplacement[];
    attachments: DuplicateMergeIdReplacement[];
  } {
    const customStrategy = collectionStrategy(choices, 'customFields');
    const customFields =
      customStrategy === 'union'
        ? duplicate.customFields.flatMap((field) => {
            const collision = survivor.customFields.some((candidate) => candidate.id === field.id);
            const semanticallyPresent = survivor.customFields.some((candidate) =>
              sameCustomField(candidate, field),
            );
            return collision && !semanticallyPresent
              ? [{ sourceId: field.id, targetId: randomUUID() }]
              : [];
          })
        : [];
    const addressStrategy = collectionStrategy(choices, 'identity.addresses');
    let addresses: DuplicateMergeIdReplacement[] = [];
    if (
      addressStrategy === 'union' &&
      survivor.data.type === 'identity' &&
      duplicate.data.type === 'identity'
    ) {
      const survivorAddresses = survivor.data.value.addresses;
      addresses = duplicate.data.value.addresses.flatMap((address) => {
        const collision = survivorAddresses.some((candidate) => candidate.id === address.id);
        const semanticallyPresent = survivorAddresses.some((candidate) =>
          sameAddress(candidate, address),
        );
        return collision && !semanticallyPresent
          ? [{ sourceId: address.id, targetId: randomUUID() }]
          : [];
      });
    }
    const attachmentStrategy = collectionStrategy(choices, 'attachments');
    const verifiedSources = new Set(verified.map((pair) => pair.duplicateAttachmentId));
    const attachments =
      attachmentStrategy === 'survivor'
        ? []
        : duplicate.attachments.flatMap((attachment) =>
            attachmentStrategy === 'union' && verifiedSources.has(attachment.id)
              ? []
              : [{ sourceId: attachment.id, targetId: randomUUID() }],
          );
    return { customFields, addresses, attachments };
  }

  private async readDocuments(vaultIds: readonly string[]): Promise<Map<string, VaultDocument>> {
    const documents = new Map<string, VaultDocument>();
    for (const vaultId of [...new Set(vaultIds)].sort()) {
      documents.set(vaultId, await this.vaults.readVault(vaultId));
    }
    return documents;
  }

  private assertReferences(input: DuplicateMergeRequest): void {
    if (
      input.survivor.vaultId === input.duplicate.vaultId &&
      input.survivor.entryId === input.duplicate.entryId
    ) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Ein Eintrag kann nicht mit sich selbst verschmolzen werden.',
      );
    }
    for (const reference of [input.survivor, input.duplicate]) {
      if (
        !reference.vaultId ||
        !reference.entryId ||
        !Number.isFinite(Date.parse(reference.updatedAt))
      ) {
        throw new VaultaError('INVALID_INPUT', 'Eine Dublettenreferenz ist ungültig.');
      }
    }
  }

  private assertUnambiguousAttachmentIds(left: VaultEntry, right: VaultEntry): void {
    if (left.vaultId !== right.vaultId) return;
    const leftIds = new Set(left.attachments.map((attachment) => attachment.id));
    if (right.attachments.some((attachment) => leftIds.has(attachment.id))) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Ein Anhang wird im selben Tresor von mehreren Einträgen referenziert.',
      );
    }
  }

  private async createStagingDirectory(): Promise<string> {
    const current = await lstat(this.stagingRoot).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (current === null) await mkdir(this.stagingRoot, { mode: 0o700 });
    else if (current.isSymbolicLink() || !current.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Dubletten-Staging ist kein reguläres Verzeichnis.');
    }
    const directory = resolveInside(this.stagingRoot, randomUUID());
    await mkdir(directory, { mode: 0o700 });
    return directory;
  }

  private async removeStagingDirectory(directory: string): Promise<void> {
    const relative = path.relative(this.stagingRoot, path.resolve(directory));
    if (
      !relative ||
      relative.includes(path.sep) ||
      relative.startsWith('..') ||
      path.isAbsolute(relative)
    ) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das Dubletten-Staging liegt außerhalb des Datenordners.',
      );
    }
    await assertSafeStagingTree(directory);
    await rm(directory, { recursive: true, force: true });
    await rmdir(this.stagingRoot).catch((error) => {
      if (!['ENOENT', 'ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code ?? ''))
        throw error;
    });
  }

  private async removeOrphanedStaging(): Promise<void> {
    const info = await lstat(this.stagingRoot).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) return;
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Dubletten-Staging ist kein reguläres Verzeichnis.');
    }
    await assertSafeStagingTree(this.stagingRoot);
    await rm(this.stagingRoot, { recursive: true, force: true });
  }
}

function requireDocument(documents: Map<string, VaultDocument>, vaultId: string): VaultDocument {
  const document = documents.get(vaultId);
  if (document === undefined)
    throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
  return document;
}

function requireRevision(document: VaultDocument, reference: DuplicateEntryReference): VaultEntry {
  const entry = document.entries.find((candidate) => candidate.id === reference.entryId);
  if (entry === undefined) throw new VaultaError('NOT_FOUND', 'Der Eintrag wurde nicht gefunden.');
  if (entry.updatedAt !== reference.updatedAt || entry.deletedAt !== null) {
    throw new VaultaError('CONFLICT', 'Die Dublette wurde seit der Vorschau verändert.');
  }
  return entry;
}

function replaceEntry(document: VaultDocument, replacement: VaultEntry): void {
  const index = document.entries.findIndex((entry) => entry.id === replacement.id);
  if (index < 0) throw new VaultaError('CONFLICT', 'Ein Merge-Eintrag ist nicht mehr vorhanden.');
  document.entries[index] = replacement;
}

function replaceAttachmentMetadata(entry: VaultEntry, metadata: AttachmentMetadata): void {
  const index = entry.attachments.findIndex((attachment) => attachment.id === metadata.id);
  if (index < 0) throw new VaultaError('INTERNAL', 'Ein vorbereiteter Anhang fehlt im Merge-Plan.');
  entry.attachments[index] = metadata;
}

function requireAttachment(entry: VaultEntry, id: string): AttachmentMetadata {
  const attachment = entry.attachments.find((candidate) => candidate.id === id);
  if (attachment === undefined) throw new VaultaError('CONFLICT', 'Ein Merge-Anhang fehlt.');
  return attachment;
}

function referenceOf(entry: VaultEntry): DuplicateEntryReference {
  return { vaultId: entry.vaultId, entryId: entry.id, updatedAt: entry.updatedAt };
}

function uniqueDocuments(documents: readonly VaultDocument[]): VaultDocument[] {
  return [...new Map(documents.map((document) => [document.id, document])).values()];
}

function collectionStrategy(
  choices: readonly DuplicateMergeCollectionChoice[],
  field: DuplicateMergeCollectionChoice['field'],
): DuplicateMergeCollectionChoice['strategy'] {
  return choices.find((choice) => choice.field === field)?.strategy ?? 'survivor';
}

function attachmentRelativePath(vaultId: string, attachmentId: string): string {
  return `attachments/${vaultId}/${attachmentId}${ATTACHMENT_EXTENSION}`;
}

function sameCustomField(left: CustomField, right: CustomField): boolean {
  if (
    normalizeText(left.label) !== normalizeText(right.label) ||
    left.type !== right.type ||
    left.secret !== right.secret ||
    left.searchable !== right.searchable
  ) {
    return false;
  }
  if (left.secret || left.type === 'secret') return sameStructuredValue(left.value, right.value);
  return normalizedCustomValue(left) === normalizedCustomValue(right);
}

function normalizedCustomValue(field: CustomField): string {
  if (typeof field.value === 'string') {
    if (field.type === 'url') {
      try {
        return new URL(
          /^[a-z][a-z\d+.-]*:/iu.test(field.value) ? field.value : `https://${field.value}`,
        ).toString();
      } catch {
        return normalizeText(field.value);
      }
    }
    return normalizeText(field.value);
  }
  return String(field.value);
}

function sameAddress(left: IdentityAddress, right: IdentityAddress): boolean {
  return (
    [left.label, left.street, left.postalCode, left.city, left.region, left.country]
      .map(normalizeText)
      .join('\0') ===
    [right.label, right.street, right.postalCode, right.city, right.region, right.country]
      .map(normalizeText)
      .join('\0')
  );
}

function normalizeText(value: string): string {
  return value.normalize('NFKC').trim().replace(/\s+/gu, ' ').toLocaleLowerCase('de-DE');
}

function sameStructuredValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function assertSafeStagingTree(directory: string): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = resolveInside(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Dubletten-Staging enthält einen Link.');
    }
    if (entry.isDirectory()) {
      await assertSafeStagingTree(entryPath);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(ATTACHMENT_EXTENSION)) {
      throw new VaultaError('UNSAFE_PATH', 'Das Dubletten-Staging enthält eine unbekannte Datei.');
    }
  }
}
