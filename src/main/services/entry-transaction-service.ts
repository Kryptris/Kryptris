import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type {
  AuditEventType,
  BatchEntryInput,
  BatchEntryResult,
  AttachmentMetadata,
  VaultDocument,
  VaultEntry,
} from '../../shared/models';
import { resolveInside } from '../storage/path-safety';
import {
  MultiFileTransactionService,
  type MultiFileChange,
} from '../storage/multi-file-transaction';
import type { AttachmentService } from './attachment-service';
import type { AuditService } from './audit-service';
import type { BatchMutationResult } from './productivity-service';
import type { VaultService } from './vault-service';

const STAGING_DIRECTORY = '.vaulta-entry-transaction-staging';
const ATTACHMENT_FILE_EXTENSION = '.vatt';

type CrossVaultAction = Extract<
  BatchEntryInput['action'],
  { type: 'copy-to-vault' | 'move-to-vault' }
>;

export interface CrossVaultTransferInput {
  readonly vaultId: string;
  readonly entryIds: readonly string[];
  readonly action: CrossVaultAction;
}

export interface CrossVaultTransferResult extends BatchEntryResult {
  readonly sourceEntryIds: string[];
  readonly targetEntryIds: string[];
}

export interface EntryTransactionServiceOptions {
  readonly rootDir: string;
  readonly vaultService: VaultService;
  readonly attachmentService: AttachmentService;
  readonly transactions?: MultiFileTransactionService;
  readonly getAuditService?: () => AuditService;
  readonly now?: () => Date;
}

/**
 * Coordinates vault documents and encrypted attachment files in one crash-recoverable commit.
 * Decrypted entry data never leaves the Main process or enters a staging file/journal.
 */
export class EntryTransactionService {
  private readonly rootDir: string;
  private readonly stagingRoot: string;
  private readonly vaults: VaultService;
  private readonly attachments: AttachmentService;
  private readonly transactions: MultiFileTransactionService;
  private readonly getAudit: (() => AuditService) | null;
  private readonly now: () => Date;

  public constructor(options: EntryTransactionServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.stagingRoot = resolveInside(this.rootDir, STAGING_DIRECTORY);
    this.vaults = options.vaultService;
    this.attachments = options.attachmentService;
    this.transactions =
      options.transactions ?? new MultiFileTransactionService({ rootDir: this.rootDir });
    this.getAudit = options.getAuditService ?? null;
    this.now = options.now ?? (() => new Date());
  }

  public async recoverInterruptedTransaction(): Promise<void> {
    await this.transactions.recoverInterruptedTransaction();
    await this.removeOrphanedStaging();
  }

  public async transfer(
    input: CrossVaultTransferInput,
    assertAuthorized: () => void = () => undefined,
  ): Promise<CrossVaultTransferResult> {
    if (input.vaultId === input.action.targetVaultId) {
      throw new VaultaError('INVALID_INPUT', 'Quell- und Ziel-Tresor müssen verschieden sein.');
    }
    if (input.entryIds.length === 0 || new Set(input.entryIds).size !== input.entryIds.length) {
      throw new VaultaError('INVALID_INPUT', 'Die Eintragsauswahl ist ungültig.');
    }

    return this.vaults.withExclusiveVaults(
      [input.vaultId, input.action.targetVaultId],
      async () => {
        const operation = async (): Promise<CrossVaultTransferResult> => {
          assertAuthorized();
          const source = await this.vaults.readVault(input.vaultId);
          const target = await this.vaults.readVault(input.action.targetVaultId);
          assertAuthorized();
          const selected = this.requireSelectedEntries(source, input.entryIds);
          if (selected.some((entry) => entry.deletedAt !== null)) {
            throw new VaultaError(
              'CONFLICT',
              'Einträge im Papierkorb können nicht zwischen Tresoren übertragen werden.',
            );
          }
          const stagingDirectory = await this.createStagingDirectory();
          const sensitiveBuffers: Buffer[] = [];
          try {
            const result = await this.prepareTransfer(
              source,
              target,
              selected,
              input.action,
              stagingDirectory,
              assertAuthorized,
            );
            assertAuthorized();
            const preparedDocuments = await Promise.all(
              result.documents.map((document) => this.vaults.prepareDocumentWrite(document)),
            );
            sensitiveBuffers.push(...preparedDocuments.map((prepared) => prepared.contents));
            assertAuthorized();
            const changes: MultiFileChange[] = [
              ...preparedDocuments.map((prepared): MultiFileChange => ({
                type: 'write',
                relativePath: prepared.relativePath,
                contents: prepared.contents,
                expectedSha256: prepared.expectedSha256,
              })),
              ...result.attachmentChanges,
            ];
            if (this.getAudit !== null) {
              const preparedAudit = await this.getAudit().prepareRecords(
                result.targetEntryIds.map((entryId) => ({
                  type:
                    input.action.type === 'copy-to-vault'
                      ? ('entry-copied-to-vault' as const)
                      : ('entry-moved-to-vault' as const),
                  vaultId: input.action.targetVaultId,
                  entryId,
                })),
              );
              sensitiveBuffers.push(preparedAudit.contents);
              changes.push({
                type: 'write',
                relativePath: preparedAudit.relativePath,
                contents: preparedAudit.contents,
                expectedSha256: preparedAudit.expectedSha256,
              });
            }
            await this.transactions.execute(changes, { assertAuthorized });
            this.vaults.installCommittedDocuments(result.documents);
            return {
              affected: selected.length,
              entryIds: [...result.targetEntryIds],
              sourceEntryIds: selected.map((entry) => entry.id),
              targetEntryIds: [...result.targetEntryIds],
            };
          } finally {
            for (const buffer of sensitiveBuffers) buffer.fill(0);
            await this.removeStagingDirectory(stagingDirectory).catch(() => undefined);
          }
        };
        return this.getAudit === null ? operation() : this.getAudit().withExclusiveWrite(operation);
      },
    );
  }

  public async purge(
    vaultId: string,
    mutation: (document: VaultDocument) => BatchMutationResult,
    assertAuthorized: () => void = () => undefined,
    auditType: AuditEventType = 'entry-purged',
  ): Promise<BatchMutationResult> {
    return this.vaults.withExclusiveVaults([vaultId], async () => {
      const operation = async (): Promise<BatchMutationResult> => {
        assertAuthorized();
        const document = await this.vaults.readVault(vaultId);
        const result = mutation(document);
        assertAuthorized();
        const prepared = await this.vaults.prepareDocumentWrite(document);
        const sensitiveBuffers = [prepared.contents];
        try {
          const changes: MultiFileChange[] = [
            {
              type: 'write',
              relativePath: prepared.relativePath,
              contents: prepared.contents,
              expectedSha256: prepared.expectedSha256,
            },
            ...result.purgedAttachmentIds.map((attachmentId): MultiFileChange => ({
              type: 'delete',
              relativePath: this.attachmentRelativePath(vaultId, attachmentId),
            })),
          ];
          if (this.getAudit !== null) {
            const preparedAudit = await this.getAudit().prepareRecords(
              result.entryIds.map((entryId) => ({ type: auditType, vaultId, entryId })),
            );
            sensitiveBuffers.push(preparedAudit.contents);
            changes.push({
              type: 'write',
              relativePath: preparedAudit.relativePath,
              contents: preparedAudit.contents,
              expectedSha256: preparedAudit.expectedSha256,
            });
          }
          await this.transactions.execute(changes, { assertAuthorized });
          this.vaults.installCommittedDocuments([document]);
          return result;
        } finally {
          for (const buffer of sensitiveBuffers) buffer.fill(0);
        }
      };
      return this.getAudit === null ? operation() : this.getAudit().withExclusiveWrite(operation);
    });
  }

  private async prepareTransfer(
    source: VaultDocument,
    target: VaultDocument,
    selected: readonly VaultEntry[],
    action: CrossVaultAction,
    stagingDirectory: string,
    assertAuthorized: () => void,
  ): Promise<{
    documents: VaultDocument[];
    targetEntryIds: string[];
    attachmentChanges: MultiFileChange[];
  }> {
    const timestamp = this.now().toISOString();
    const targetFolderIds = new Set(target.folders.map((folder) => folder.id));
    const occupiedEntryIds = new Set(target.entries.map((entry) => entry.id));
    const attachmentChanges: MultiFileChange[] = [];
    const targetEntryIds: string[] = [];
    const sourceIds = new Set(selected.map((entry) => entry.id));

    for (const entry of selected) {
      assertAuthorized();
      const targetEntryId = this.freshIdentifier(occupiedEntryIds);
      targetEntryIds.push(targetEntryId);
      const targetAttachments: AttachmentMetadata[] = [];
      for (const attachment of entry.attachments) {
        assertAuthorized();
        const targetAttachmentId = randomUUID();
        const stagingPath = resolveInside(
          stagingDirectory,
          `${targetAttachmentId}${ATTACHMENT_FILE_EXTENSION}`,
        );
        const metadata = await this.attachments.reencryptToStaging({
          sourceVaultId: source.id,
          sourceAttachmentId: attachment.id,
          targetVaultId: target.id,
          targetAttachmentId,
          stagingPath,
          name: attachment.name,
          mediaType: attachment.mediaType,
          assertAuthorized,
        });
        if (
          metadata.size !== attachment.size ||
          metadata.sha256.toLowerCase() !== attachment.sha256.toLowerCase()
        ) {
          throw new VaultaError(
            'CORRUPT_DATA',
            'Anhangsmetadaten und authentifizierter Inhalt stimmen nicht überein.',
          );
        }
        targetAttachments.push(metadata);
        attachmentChanges.push({
          type: 'write-file',
          relativePath: this.attachmentRelativePath(target.id, targetAttachmentId),
          sourcePath: stagingPath,
          expectedSha256: null,
        });
        if (action.type === 'move-to-vault') {
          attachmentChanges.push({
            type: 'delete',
            relativePath: this.attachmentRelativePath(source.id, attachment.id),
          });
        }
      }

      const transferred = structuredClone(entry);
      transferred.id = targetEntryId;
      transferred.vaultId = target.id;
      transferred.folderId =
        transferred.folderId !== null && targetFolderIds.has(transferred.folderId)
          ? transferred.folderId
          : null;
      transferred.attachments = targetAttachments;
      transferred.updatedAt = timestamp;
      if (action.type === 'copy-to-vault') {
        transferred.createdAt = timestamp;
        transferred.lastUsedAt = null;
      }
      target.entries.push(transferred);
    }

    target.updatedAt = timestamp;
    const documents = [target];
    if (action.type === 'move-to-vault') {
      source.entries = source.entries.filter((entry) => !sourceIds.has(entry.id));
      source.updatedAt = timestamp;
      documents.unshift(source);
    }
    return { documents, targetEntryIds, attachmentChanges };
  }

  private requireSelectedEntries(
    document: VaultDocument,
    entryIds: readonly string[],
  ): VaultEntry[] {
    const entries = new Map(document.entries.map((entry) => [entry.id, entry]));
    return entryIds.map((entryId) => {
      const entry = entries.get(entryId);
      if (entry === undefined) {
        throw new VaultaError('NOT_FOUND', 'Ein ausgewählter Eintrag wurde nicht gefunden.');
      }
      return entry;
    });
  }

  private freshIdentifier(occupied: Set<string>): string {
    for (;;) {
      const candidate = randomUUID();
      if (occupied.has(candidate)) continue;
      occupied.add(candidate);
      return candidate;
    }
  }

  private attachmentRelativePath(vaultId: string, attachmentId: string): string {
    return `attachments/${vaultId}/${attachmentId}${ATTACHMENT_FILE_EXTENSION}`;
  }

  private async createStagingDirectory(): Promise<string> {
    const current = await lstat(this.stagingRoot).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (current === null) await mkdir(this.stagingRoot, { mode: 0o700 });
    else if (current.isSymbolicLink() || !current.isDirectory()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Transfer-Staging ist kein reguläres Verzeichnis.');
    }
    const runDirectory = resolveInside(this.stagingRoot, randomUUID());
    await mkdir(runDirectory, { mode: 0o700 });
    return runDirectory;
  }

  private async removeStagingDirectory(directory: string): Promise<void> {
    const relative = path.relative(this.stagingRoot, path.resolve(directory));
    if (
      relative.length === 0 ||
      relative === '..' ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative) ||
      relative.includes(path.sep)
    ) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das Transfer-Staging liegt außerhalb des Datenordners.',
      );
    }
    await this.assertSafeStagingTree(directory);
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
      throw new VaultaError('UNSAFE_PATH', 'Das Transfer-Staging ist kein reguläres Verzeichnis.');
    }
    await this.assertSafeStagingTree(this.stagingRoot);
    await rm(this.stagingRoot, { recursive: true, force: true });
  }

  private async assertSafeStagingTree(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = resolveInside(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new VaultaError('UNSAFE_PATH', 'Das Transfer-Staging enthält einen Link.');
      }
      if (entry.isDirectory()) {
        await this.assertSafeStagingTree(entryPath);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(ATTACHMENT_FILE_EXTENSION)) {
        throw new VaultaError('UNSAFE_PATH', 'Das Transfer-Staging enthält eine unbekannte Datei.');
      }
    }
  }
}
