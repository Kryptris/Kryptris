import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  type FileHandle,
} from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import {
  ForwardMigrationDispatcher,
  type ForwardMigrationStep,
} from '../migrations/forward-migration-dispatcher';
import { AtomicFileWriter } from '../storage/atomic-file';
import { ENCRYPTED_CONTAINER_VERSION } from '../storage/encrypted-container';
import { resolveInside } from '../storage/path-safety';
import { ATTACHMENT_FORMAT_VERSION } from './attachment-service';
import { AUDIT_DOCUMENT_FORMAT_VERSION } from './audit-service';
import {
  BackupService,
  type BackupRestoreResult,
  type MigrationSnapshotSourceExpectation,
} from './backup-service';
import {
  PROFILE_FORMAT_VERSION,
  type BackupCredential,
  type ProfileService,
  parseStoredProfileHeader,
} from './profile-service';
import { VAULT_DOCUMENT_FORMAT_VERSION } from './vault-service';

const MIGRATION_BACKUP_DIRECTORY = 'migration-backups';
const MIGRATION_SNAPSHOT_EXTENSION = '.vaulta-backup';
const MIGRATION_TRANSACTION_DIRECTORY = '.vaulta-migration-transaction';
const MIGRATION_TRANSACTION_FORMAT = 'vaulta-migration-transaction';
const MIGRATION_TRANSACTION_VERSION = 1;
const MIGRATION_JOURNAL_FILE = 'journal.json';
const MIGRATION_TERMINAL_FILE = 'terminal.json';
const ATTACHMENT_MAGIC = Buffer.from('VLTATT01', 'ascii');
const ATTACHMENT_HEADER_LIMIT = 64 * 1024;
const COPY_CHUNK_BYTES = 1024 * 1024;

export const PERSISTENT_FORMAT_BASELINE = Object.freeze({
  profileHeader: PROFILE_FORMAT_VERSION,
  encryptedContainer: ENCRYPTED_CONTAINER_VERSION,
  vaultDocument: VAULT_DOCUMENT_FORMAT_VERSION,
  auditDocument: AUDIT_DOCUMENT_FORMAT_VERSION,
  attachment: ATTACHMENT_FORMAT_VERSION,
});

export interface PersistentMigrationPayload {
  readonly relativePath: string;
  readonly version: number;
  readonly bytes: Buffer;
}

export interface PersistentFormatAdapter {
  readonly id: string;
  readonly formatName: string;
  readonly currentVersion: number;
  readonly matches: (relativePath: string) => boolean;
  readonly readVersion: (filePath: string) => Promise<number>;
  readonly readVersionFromBytes: (bytes: Buffer, relativePath: string) => Promise<number> | number;
  readonly validateAtRest: (filePath: string) => Promise<void>;
  readonly validateCurrent: (bytes: Buffer, relativePath: string) => Promise<void> | void;
  readonly migrations?: readonly ForwardMigrationStep<PersistentMigrationPayload>[];
}

export interface PersistentMigrationServiceOptions {
  readonly rootDir: string;
  readonly profileService: ProfileService;
  readonly backupService?: BackupService;
  readonly atomicWriter?: AtomicFileWriter;
  readonly now?: () => Date;
  readonly additionalAdapters?: readonly PersistentFormatAdapter[];
  readonly embeddedInspectors?: readonly EmbeddedFormatInspector[];
}

export interface EmbeddedFormatInspector {
  readonly id: string;
  readonly formatName: string;
  readonly currentVersion: number;
  readonly matches: (relativePath: string) => boolean;
  readonly readVersion: (
    filePath: string,
    relativePath: string,
    assertAuthorized: () => void,
  ) => Promise<number>;
}

export interface MigrationInspection {
  readonly inspectedFiles: number;
  readonly pendingFiles: number;
}

export interface MigrationRunResult extends MigrationInspection {
  readonly migratedFiles: number;
  readonly backupPath: string | null;
}

interface DiscoveredArtifact {
  readonly filePath: string;
  readonly relativePath: string;
  readonly adapter: PersistentFormatAdapter;
  readonly sourceVersion: number;
  readonly plan: readonly ForwardMigrationStep<PersistentMigrationPayload>[];
}

interface PreparedArtifact extends DiscoveredArtifact {
  readonly bytes: Buffer;
  readonly rollbackBytes: Buffer;
  readonly source: MigrationSnapshotSourceExpectation;
}

interface MigrationTransactionEntry {
  readonly relativePath: string;
  readonly rollbackFile: string;
  readonly sourceSize: number;
  readonly sourceSha256: string;
  readonly targetSize: number;
  readonly targetSha256: string;
}

interface MigrationTransactionJournal {
  readonly format: typeof MIGRATION_TRANSACTION_FORMAT;
  readonly version: typeof MIGRATION_TRANSACTION_VERSION;
  readonly transactionId: string;
  readonly snapshotPath: string;
  readonly files: readonly MigrationTransactionEntry[];
}

interface MigrationTerminalMarker {
  readonly format: 'vaulta-migration-terminal';
  readonly version: 1;
  readonly transactionId: string;
  readonly journalSha256: string;
  readonly outcome: 'committed' | 'rolled-back';
}

interface ActiveMigrationTransaction {
  readonly rootPath: string;
  readonly journal: MigrationTransactionJournal;
  readonly journalBytes: Buffer;
}

/**
 * Central migration boundary for every live persistent Vaulta format.
 *
 * The current product baseline is version 1. No v0 semantics are registered.
 * Consequently v1 is an idempotent no-op, an unknown future version is rejected,
 * and any future writer migration must pass through the snapshot-first commit path.
 */
export class PersistentMigrationService {
  private readonly rootDir: string;
  private readonly profileService: ProfileService;
  private readonly backups: BackupService;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly now: () => Date;
  private readonly adapters: readonly PersistentFormatAdapter[];
  private readonly embeddedInspectors: readonly EmbeddedFormatInspector[];

  public constructor(options: PersistentMigrationServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.profileService = options.profileService;
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.backups =
      options.backupService ??
      new BackupService({
        rootDir: this.rootDir,
        profileService: this.profileService,
        atomicWriter: this.atomicWriter,
      });
    this.now = options.now ?? (() => new Date());
    this.adapters = [...defaultAdapters(), ...(options.additionalAdapters ?? [])];
    this.embeddedInspectors = [...(options.embeddedInspectors ?? [])];
    this.assertAdapterRegistry();
  }

  public async inspect(): Promise<MigrationInspection> {
    await this.recoverInterruptedWrites();
    const artifacts = await this.inspectArtifacts();
    return {
      inspectedFiles: artifacts.length,
      pendingFiles: artifacts.filter((artifact) => artifact.plan.length > 0).length,
    };
  }

  public async migrate(
    assertAuthorized: () => void = () => undefined,
  ): Promise<MigrationRunResult> {
    await this.recoverInterruptedWrites();
    const artifacts = await this.inspectArtifacts();
    assertAuthorized();
    await this.inspectEmbeddedArtifacts(artifacts, assertAuthorized);
    assertAuthorized();
    const pending = artifacts.filter((artifact) => artifact.plan.length > 0);
    if (pending.length === 0) {
      return {
        inspectedFiles: artifacts.length,
        pendingFiles: 0,
        migratedFiles: 0,
        backupPath: null,
      };
    }

    const prepared = await Promise.all(pending.map((artifact) => this.prepare(artifact)));
    assertAuthorized();
    const backupPath = await this.createSnapshot(artifacts, prepared, assertAuthorized);
    assertAuthorized();
    const transaction = await this.beginMigrationTransaction(
      prepared,
      backupPath,
      assertAuthorized,
    );
    let migratedFiles = 0;
    for (const artifact of prepared) {
      assertAuthorized();
      await this.atomicWriter.writeFile(
        artifact.filePath,
        artifact.bytes,
        async (temporaryPath) => {
          assertAuthorized();
          const temporary = await readFile(temporaryPath);
          await artifact.adapter.validateCurrent(temporary, artifact.relativePath);
          assertAuthorized();
        },
        async () => {
          assertAuthorized();
          await this.assertArtifactUnchanged(artifact);
          assertAuthorized();
        },
      );
      assertAuthorized();
      migratedFiles += 1;
    }
    await this.assertTransactionStateInstalled(transaction, 'committed');
    await this.writeTerminalMarker(transaction, 'committed');
    await this.cleanupTerminalTransaction(transaction.rootPath);

    return {
      inspectedFiles: artifacts.length,
      pendingFiles: pending.length,
      migratedFiles,
      backupPath,
    };
  }

  public async recoverInterruptedWrites(): Promise<void> {
    await this.atomicWriter.recoverInterruptedWrites(this.rootDir);
    await this.recoverMigrationTransaction();
  }

  public async verifySnapshot(
    snapshotPath: string,
    assertAuthorized: () => void = () => undefined,
  ): Promise<void> {
    assertAuthorized();
    const resolvedSnapshot = await this.assertSnapshotPath(snapshotPath);
    await this.backups.inspectBackupWithActiveProfile(resolvedSnapshot);
    assertAuthorized();
  }

  public async restoreSnapshot(
    snapshotPath: string,
    credential: BackupCredential,
  ): Promise<BackupRestoreResult> {
    const resolvedSnapshot = await this.assertSnapshotPath(snapshotPath);
    return this.backups.restoreBackup({
      backupPath: resolvedSnapshot,
      credential,
      targetRoot: this.rootDir,
      replaceExisting: true,
    });
  }

  private async inspectArtifacts(): Promise<DiscoveredArtifact[]> {
    const relativePaths = await this.discoverRelativePaths();
    const artifacts: DiscoveredArtifact[] = [];
    for (const relativePath of relativePaths) {
      const matches = this.adapters.filter((adapter) => adapter.matches(relativePath));
      if (matches.length === 0) continue;
      if (matches.length > 1) {
        throw new VaultaError(
          'INTERNAL',
          `Für ${relativePath} sind mehrere Migrationsadapter registriert.`,
        );
      }
      const adapter = matches[0];
      if (adapter === undefined) continue;
      const filePath = resolveInside(this.rootDir, ...relativePath.split('/'));
      const sourceVersion = await adapter.readVersion(filePath);
      const dispatcher = dispatcherFor(adapter);
      const plan = dispatcher.plan(sourceVersion);
      if (plan.length === 0) await adapter.validateAtRest(filePath);
      artifacts.push({ filePath, relativePath, adapter, sourceVersion, plan });
    }
    return artifacts.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  }

  private async prepare(artifact: DiscoveredArtifact): Promise<PreparedArtifact> {
    const source = await readFile(artifact.filePath);
    if (
      (await artifact.adapter.readVersionFromBytes(source, artifact.relativePath)) !==
      artifact.sourceVersion
    ) {
      throw new VaultaError(
        'CONFLICT',
        'Persistente Daten wurden während der Migrationsvorbereitung verändert.',
      );
    }
    const result = await dispatcherFor(artifact.adapter).migrate({
      relativePath: artifact.relativePath,
      version: artifact.sourceVersion,
      bytes: source,
    });
    if (!result.migrated) {
      throw new VaultaError('INTERNAL', 'Eine geplante Migration hat keine Änderung erzeugt.');
    }
    return {
      ...artifact,
      bytes: result.value.bytes,
      rollbackBytes: source,
      source: { size: source.length, sha256: createHash('sha256').update(source).digest('hex') },
    };
  }

  private async createSnapshot(
    artifacts: readonly DiscoveredArtifact[],
    prepared: readonly PreparedArtifact[],
    assertAuthorized: () => void,
  ): Promise<string> {
    assertAuthorized();
    if (!this.profileService.isUnlocked()) {
      throw new VaultaError(
        'LOCKED',
        'Eine schreibende Datenmigration benötigt ein vollständig entsperrtes Profil.',
      );
    }
    const snapshotId = `${this.now().toISOString().replace(/[-:.]/gu, '')}-${randomUUID()}`;
    const snapshotPath = resolveInside(
      this.rootDir,
      MIGRATION_BACKUP_DIRECTORY,
      `${snapshotId}${MIGRATION_SNAPSHOT_EXTENSION}`,
    );
    const expectedSources = Object.fromEntries(
      prepared.map((artifact) => [artifact.relativePath, artifact.source]),
    );

    try {
      assertAuthorized();
      await this.backups.createMigrationSnapshot({
        destination: snapshotPath,
        sourcePaths: artifacts.map((artifact) => artifact.relativePath),
        expectedSources,
        assertAuthorized,
      });
      assertAuthorized();
      await this.verifySnapshot(snapshotPath, assertAuthorized);
      assertAuthorized();
      return snapshotPath;
    } catch (error) {
      await rm(snapshotPath, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }
  }

  private async beginMigrationTransaction(
    prepared: readonly PreparedArtifact[],
    snapshotPath: string,
    assertAuthorized: () => void,
  ): Promise<ActiveMigrationTransaction> {
    const rootPath = resolveInside(this.rootDir, MIGRATION_TRANSACTION_DIRECTORY);
    await mkdir(rootPath, { mode: 0o700 }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new VaultaError('CONFLICT', 'Es existiert bereits eine unvollstaendige Migration.');
      }
      throw error;
    });

    let journalInstalled = false;
    try {
      const files: MigrationTransactionEntry[] = [];
      for (const [index, artifact] of prepared.entries()) {
        assertAuthorized();
        await this.assertArtifactUnchanged(artifact);
        const rollbackFile = `rollback-${String(index).padStart(6, '0')}.bin`;
        const rollbackPath = resolveInside(rootPath, rollbackFile);
        await this.writeDurableExclusive(rollbackPath, artifact.rollbackBytes);
        const rollbackHash = await hashRegularFile(rollbackPath, assertAuthorized);
        if (
          rollbackHash.size !== artifact.source.size ||
          rollbackHash.sha256 !== artifact.source.sha256
        ) {
          throw new VaultaError(
            'CORRUPT_DATA',
            'Eine Migrations-Rollbackdatei wurde nicht bytegenau geschrieben.',
          );
        }
        files.push({
          relativePath: artifact.relativePath,
          rollbackFile,
          sourceSize: artifact.source.size,
          sourceSha256: artifact.source.sha256,
          targetSize: artifact.bytes.length,
          targetSha256: createHash('sha256').update(artifact.bytes).digest('hex'),
        });
      }

      for (const artifact of prepared) {
        assertAuthorized();
        await this.assertArtifactUnchanged(artifact);
      }

      const journal: MigrationTransactionJournal = {
        format: MIGRATION_TRANSACTION_FORMAT,
        version: MIGRATION_TRANSACTION_VERSION,
        transactionId: randomUUID(),
        snapshotPath: this.relativePathInsideRoot(snapshotPath),
        files,
      };
      const journalBytes = Buffer.from(JSON.stringify(journal), 'utf8');
      const temporaryJournal = resolveInside(rootPath, `.journal-${randomUUID()}.tmp`);
      await this.writeDurableExclusive(temporaryJournal, journalBytes);
      await rename(temporaryJournal, resolveInside(rootPath, MIGRATION_JOURNAL_FILE));
      journalInstalled = true;
      await this.syncDirectory(rootPath);
      await this.syncDirectory(this.rootDir);
      assertAuthorized();
      return { rootPath, journal, journalBytes };
    } catch (error) {
      if (!journalInstalled) {
        await rm(rootPath, { recursive: true, force: true }).catch(() => undefined);
        await this.syncDirectory(this.rootDir).catch(() => undefined);
      }
      throw error;
    }
  }

  private async recoverMigrationTransaction(): Promise<void> {
    const rootPath = resolveInside(this.rootDir, MIGRATION_TRANSACTION_DIRECTORY);
    const transactionInfo = await lstat(rootPath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (transactionInfo === null) return;
    if (transactionInfo.isSymbolicLink() || !transactionInfo.isDirectory()) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Das Migrations-Transaktionsverzeichnis ist kein regulaeres Verzeichnis.',
      );
    }

    const journalBytes = await this.readOptionalRegularFile(
      resolveInside(rootPath, MIGRATION_JOURNAL_FILE),
      'Das Migrationsjournal ist keine regulaere Datei.',
    );
    const terminalBytes = await this.readOptionalRegularFile(
      resolveInside(rootPath, MIGRATION_TERMINAL_FILE),
      'Der Migrationsabschluss ist keine regulaere Datei.',
    );

    if (journalBytes === null) {
      if (terminalBytes !== null) this.parseTerminalMarker(terminalBytes);
      await this.cleanupTerminalTransaction(rootPath);
      return;
    }

    const journal = this.parseMigrationJournal(journalBytes);
    const transaction = { rootPath, journal, journalBytes };
    if (terminalBytes !== null) {
      const terminal = this.parseTerminalMarker(terminalBytes);
      this.assertTerminalMatchesJournal(terminal, transaction);
      await this.assertTransactionStateInstalled(transaction, terminal.outcome);
      await this.cleanupTerminalTransaction(rootPath);
      return;
    }

    await this.rollbackMigrationTransaction(transaction);
  }

  private async rollbackMigrationTransaction(
    transaction: ActiveMigrationTransaction,
  ): Promise<void> {
    for (const entry of transaction.journal.files) {
      const rollbackPath = resolveInside(transaction.rootPath, entry.rollbackFile);
      const rollbackHash = await hashRegularFile(rollbackPath);
      if (rollbackHash.size !== entry.sourceSize || rollbackHash.sha256 !== entry.sourceSha256) {
        throw new VaultaError(
          'CORRUPT_DATA',
          `Die Rollbackdatei fuer ${entry.relativePath} ist unvollstaendig oder veraendert.`,
        );
      }
    }

    for (const entry of transaction.journal.files) {
      const rollbackPath = resolveInside(transaction.rootPath, entry.rollbackFile);
      const rollbackBytes = await readFile(rollbackPath);
      if (
        rollbackBytes.length !== entry.sourceSize ||
        createHash('sha256').update(rollbackBytes).digest('hex') !== entry.sourceSha256
      ) {
        throw new VaultaError(
          'CORRUPT_DATA',
          `Die Rollbackdatei fuer ${entry.relativePath} wurde waehrend der Recovery veraendert.`,
        );
      }
      const targetPath = this.resolveManagedTransactionPath(entry.relativePath);
      await this.atomicWriter.writeFile(targetPath, rollbackBytes, async (temporaryPath) => {
        const restored = await hashRegularFile(temporaryPath);
        if (restored.size !== entry.sourceSize || restored.sha256 !== entry.sourceSha256) {
          throw new VaultaError(
            'CORRUPT_DATA',
            `Die Recovery fuer ${entry.relativePath} ist nicht bytegenau.`,
          );
        }
      });
    }

    for (const entry of transaction.journal.files) {
      const restored = await hashRegularFile(
        this.resolveManagedTransactionPath(entry.relativePath),
      );
      if (restored.size !== entry.sourceSize || restored.sha256 !== entry.sourceSha256) {
        throw new VaultaError(
          'CORRUPT_DATA',
          `Die Recovery fuer ${entry.relativePath} konnte nicht bestaetigt werden.`,
        );
      }
    }

    await this.writeTerminalMarker(transaction, 'rolled-back');
    await this.cleanupTerminalTransaction(transaction.rootPath);
  }

  private async assertTransactionStateInstalled(
    transaction: ActiveMigrationTransaction,
    outcome: MigrationTerminalMarker['outcome'],
  ): Promise<void> {
    for (const entry of transaction.journal.files) {
      const expectedSize = outcome === 'committed' ? entry.targetSize : entry.sourceSize;
      const expectedHash = outcome === 'committed' ? entry.targetSha256 : entry.sourceSha256;
      const installed = await hashRegularFile(
        this.resolveManagedTransactionPath(entry.relativePath),
      );
      if (installed.size !== expectedSize || installed.sha256 !== expectedHash) {
        throw new VaultaError(
          'CORRUPT_DATA',
          `Der ${outcome === 'committed' ? 'Commit' : 'Rollback'} fuer ${entry.relativePath} ist unvollstaendig.`,
        );
      }
    }
  }

  private async writeTerminalMarker(
    transaction: ActiveMigrationTransaction,
    outcome: MigrationTerminalMarker['outcome'],
  ): Promise<void> {
    const marker: MigrationTerminalMarker = {
      format: 'vaulta-migration-terminal',
      version: 1,
      transactionId: transaction.journal.transactionId,
      journalSha256: createHash('sha256').update(transaction.journalBytes).digest('hex'),
      outcome,
    };
    const temporaryMarker = resolveInside(transaction.rootPath, `.terminal-${randomUUID()}.tmp`);
    await this.writeDurableExclusive(temporaryMarker, Buffer.from(JSON.stringify(marker), 'utf8'));
    await rename(temporaryMarker, resolveInside(transaction.rootPath, MIGRATION_TERMINAL_FILE));
    await this.syncDirectory(transaction.rootPath);
    await this.syncDirectory(this.rootDir);
  }

  private async cleanupTerminalTransaction(rootPath: string): Promise<void> {
    const entries = await readdir(rootPath, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    for (const entry of entries) {
      if (entry.name === MIGRATION_TERMINAL_FILE) continue;
      await rm(resolveInside(rootPath, entry.name), { recursive: true, force: true });
    }
    await this.syncDirectory(rootPath);
    await rm(resolveInside(rootPath, MIGRATION_TERMINAL_FILE), { force: true });
    await this.syncDirectory(rootPath);
    await rm(rootPath, { recursive: true, force: true });
    await this.syncDirectory(this.rootDir);
  }

  private parseMigrationJournal(bytes: Buffer): MigrationTransactionJournal {
    const value = this.parseTransactionRecord(bytes, 'Das Migrationsjournal ist beschaedigt.');
    if (
      value.format !== MIGRATION_TRANSACTION_FORMAT ||
      value.version !== MIGRATION_TRANSACTION_VERSION ||
      typeof value.transactionId !== 'string' ||
      !isUuid(value.transactionId) ||
      typeof value.snapshotPath !== 'string' ||
      !/^migration-backups\/[A-Za-z0-9_.-]+\.vaulta-backup$/u.test(value.snapshotPath) ||
      !Array.isArray(value.files) ||
      value.files.length === 0
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Das Migrationsjournal ist ungueltig.');
    }

    const relativePaths = new Set<string>();
    const rollbackFiles = new Set<string>();
    const files = value.files.map((candidate) => {
      if (
        !isRecord(candidate) ||
        typeof candidate.relativePath !== 'string' ||
        typeof candidate.rollbackFile !== 'string' ||
        !/^rollback-[0-9]{6}\.bin$/u.test(candidate.rollbackFile) ||
        !isSafeFileSize(candidate.sourceSize) ||
        !isSha256(candidate.sourceSha256) ||
        !isSafeFileSize(candidate.targetSize) ||
        !isSha256(candidate.targetSha256)
      ) {
        throw new VaultaError('CORRUPT_DATA', 'Ein Migrationsjournaleintrag ist ungueltig.');
      }
      this.resolveManagedTransactionPath(candidate.relativePath);
      if (relativePaths.has(candidate.relativePath) || rollbackFiles.has(candidate.rollbackFile)) {
        throw new VaultaError('CORRUPT_DATA', 'Das Migrationsjournal enthaelt doppelte Eintraege.');
      }
      relativePaths.add(candidate.relativePath);
      rollbackFiles.add(candidate.rollbackFile);
      return {
        relativePath: candidate.relativePath,
        rollbackFile: candidate.rollbackFile,
        sourceSize: candidate.sourceSize,
        sourceSha256: candidate.sourceSha256,
        targetSize: candidate.targetSize,
        targetSha256: candidate.targetSha256,
      };
    });

    return {
      format: MIGRATION_TRANSACTION_FORMAT,
      version: MIGRATION_TRANSACTION_VERSION,
      transactionId: value.transactionId,
      snapshotPath: value.snapshotPath,
      files,
    };
  }

  private parseTerminalMarker(bytes: Buffer): MigrationTerminalMarker {
    const value = this.parseTransactionRecord(bytes, 'Der Migrationsabschluss ist beschaedigt.');
    if (
      value.format !== 'vaulta-migration-terminal' ||
      value.version !== 1 ||
      typeof value.transactionId !== 'string' ||
      !isUuid(value.transactionId) ||
      typeof value.journalSha256 !== 'string' ||
      !isSha256(value.journalSha256) ||
      (value.outcome !== 'committed' && value.outcome !== 'rolled-back')
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Der Migrationsabschluss ist ungueltig.');
    }
    return {
      format: 'vaulta-migration-terminal',
      version: 1,
      transactionId: value.transactionId,
      journalSha256: value.journalSha256,
      outcome: value.outcome,
    };
  }

  private parseTransactionRecord(bytes: Buffer, message: string): Record<string, unknown> {
    try {
      const value = JSON.parse(bytes.toString('utf8')) as unknown;
      if (!isRecord(value)) throw new Error('not a record');
      return value;
    } catch (error) {
      throw new VaultaError('CORRUPT_DATA', message, null, { cause: error });
    }
  }

  private assertTerminalMatchesJournal(
    terminal: MigrationTerminalMarker,
    transaction: ActiveMigrationTransaction,
  ): void {
    const expectedHash = createHash('sha256').update(transaction.journalBytes).digest('hex');
    if (
      terminal.transactionId !== transaction.journal.transactionId ||
      terminal.journalSha256 !== expectedHash
    ) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Der Migrationsabschluss gehoert nicht zum vorhandenen Journal.',
      );
    }
  }

  private resolveManagedTransactionPath(relativePath: string): string {
    if (
      relativePath.length === 0 ||
      relativePath.includes('\\') ||
      relativePath.includes('\0') ||
      relativePath.startsWith('/') ||
      relativePath.endsWith('/') ||
      path.posix.normalize(relativePath) !== relativePath ||
      !(
        relativePath === 'profile.json' ||
        relativePath === 'audit.vaulta' ||
        relativePath.startsWith('vaults/') ||
        relativePath.startsWith('attachments/')
      )
    ) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Das Migrationsjournal enthaelt einen unsicheren Pfad.',
      );
    }
    return resolveInside(this.rootDir, ...relativePath.split('/'));
  }

  private relativePathInsideRoot(filePath: string): string {
    const relativePath = path.relative(this.rootDir, path.resolve(filePath));
    if (
      relativePath.length === 0 ||
      relativePath === '..' ||
      relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath)
    ) {
      throw new VaultaError('UNSAFE_PATH', 'Der Migrationspfad liegt ausserhalb des Datenordners.');
    }
    return relativePath.split(path.sep).join('/');
  }

  private async readOptionalRegularFile(filePath: string, message: string): Promise<Buffer | null> {
    const info = await lstat(filePath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) return null;
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new VaultaError('UNSAFE_PATH', message);
    }
    return readFile(filePath);
  }

  private async writeDurableExclusive(filePath: string, bytes: Buffer): Promise<void> {
    let handle: FileHandle | null = null;
    let complete = false;
    try {
      handle = await open(
        filePath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = null;
      complete = true;
    } finally {
      await handle?.close().catch(() => undefined);
      if (!complete) await rm(filePath, { force: true }).catch(() => undefined);
    }
  }

  private async syncDirectory(directory: string): Promise<void> {
    let handle: FileHandle | null = null;
    try {
      handle = await open(directory, constants.O_RDONLY);
      await handle.sync();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const expected =
        process.platform === 'win32' ? ['EINVAL', 'EPERM', 'EACCES'] : ['EINVAL', 'EPERM'];
      if (code === undefined || !expected.includes(code)) throw error;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  private async inspectEmbeddedArtifacts(
    artifacts: readonly DiscoveredArtifact[],
    assertAuthorized: () => void,
  ): Promise<void> {
    for (const artifact of artifacts) {
      for (const inspector of this.embeddedInspectors) {
        if (!inspector.matches(artifact.relativePath)) continue;
        assertAuthorized();
        const version = await inspector.readVersion(
          artifact.filePath,
          artifact.relativePath,
          assertAuthorized,
        );
        new ForwardMigrationDispatcher<number>({
          formatName: inspector.formatName,
          currentVersion: inspector.currentVersion,
          readVersion: (value) => value,
          validateCurrent: () => undefined,
        }).plan(version);
        assertAuthorized();
      }
    }
  }

  private async assertArtifactUnchanged(artifact: PreparedArtifact): Promise<void> {
    const actual = await hashRegularFile(artifact.filePath);
    if (actual.size !== artifact.source.size || actual.sha256 !== artifact.source.sha256) {
      throw new VaultaError(
        'CONFLICT',
        `Die Migrationsquelle ${artifact.relativePath} wurde vor dem Commit verändert.`,
      );
    }
  }

  private async assertSnapshotPath(snapshotPath: string): Promise<string> {
    const resolvedSnapshot = path.resolve(snapshotPath);
    const snapshotsRoot = resolveInside(this.rootDir, MIGRATION_BACKUP_DIRECTORY);
    const relativeSnapshot = path.relative(snapshotsRoot, resolvedSnapshot);
    if (
      relativeSnapshot.length === 0 ||
      relativeSnapshot === '..' ||
      relativeSnapshot.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativeSnapshot) ||
      relativeSnapshot.includes(path.sep) ||
      !relativeSnapshot.endsWith(MIGRATION_SNAPSHOT_EXTENSION)
    ) {
      throw new VaultaError(
        'UNSAFE_PATH',
        'Der Migrations-Snapshot liegt außerhalb des Datenordners.',
      );
    }
    const info = await lstat(resolvedSnapshot).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Der Migrations-Snapshot wurde nicht gefunden.');
      }
      throw error;
    });
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Der Migrations-Snapshot ist keine reguläre Datei.');
    }
    return resolvedSnapshot;
  }

  private async discoverRelativePaths(): Promise<string[]> {
    const results = new Set<string>();
    await this.addExactFile('profile.json', results);
    await this.addExactFile('audit.vaulta', results);
    await this.walkManagedDirectory('vaults', results);
    await this.walkManagedDirectory('attachments', results);
    return [...results].sort((left, right) => left.localeCompare(right));
  }

  private async addExactFile(relativePath: string, results: Set<string>): Promise<void> {
    const filePath = resolveInside(this.rootDir, ...relativePath.split('/'));
    const info = await lstat(filePath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) return;
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new VaultaError('UNSAFE_PATH', `${relativePath} ist keine reguläre Vaulta-Datei.`);
    }
    results.add(relativePath);
  }

  private async walkManagedDirectory(
    relativeDirectory: string,
    results: Set<string>,
  ): Promise<void> {
    const root = resolveInside(this.rootDir, relativeDirectory);
    const walk = async (directory: string, relative: string): Promise<void> => {
      const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
        throw error;
      });
      for (const entry of entries) {
        const entryRelative = `${relative}/${entry.name}`.replace(/^\//u, '');
        if (entry.isSymbolicLink()) {
          throw new VaultaError(
            'UNSAFE_PATH',
            `${entryRelative} ist eine unzulässige symbolische Verknüpfung.`,
          );
        }
        const entryPath = resolveInside(
          root,
          ...entryRelative.slice(relativeDirectory.length + 1).split('/'),
        );
        if (entry.isDirectory()) await walk(entryPath, entryRelative);
        else if (entry.isFile()) results.add(entryRelative);
      }
    };
    await walk(root, relativeDirectory);
  }

  private assertAdapterRegistry(): void {
    const identifiers = new Set<string>();
    for (const adapter of this.adapters) {
      if (adapter.id.length === 0 || identifiers.has(adapter.id)) {
        throw new VaultaError('INTERNAL', 'Migrationsadapter benötigen eindeutige IDs.');
      }
      identifiers.add(adapter.id);
      dispatcherFor(adapter);
    }
    for (const inspector of this.embeddedInspectors) {
      if (inspector.id.length === 0 || identifiers.has(inspector.id)) {
        throw new VaultaError('INTERNAL', 'Migrationsadapter benötigen eindeutige IDs.');
      }
      identifiers.add(inspector.id);
      new ForwardMigrationDispatcher<number>({
        formatName: inspector.formatName,
        currentVersion: inspector.currentVersion,
        readVersion: (value) => value,
        validateCurrent: () => undefined,
      });
    }
  }
}

function dispatcherFor(
  adapter: PersistentFormatAdapter,
): ForwardMigrationDispatcher<PersistentMigrationPayload> {
  return new ForwardMigrationDispatcher({
    formatName: adapter.formatName,
    currentVersion: adapter.currentVersion,
    readVersion: (value) => value.version,
    validateCurrent: (value) => adapter.validateCurrent(value.bytes, value.relativePath),
    ...(adapter.migrations === undefined ? {} : { steps: adapter.migrations }),
  });
}

function defaultAdapters(): readonly PersistentFormatAdapter[] {
  return [profileAdapter(), encryptedContainerAdapter(), attachmentAdapter()];
}

function profileAdapter(): PersistentFormatAdapter {
  const readVersionFromBytes = (bytes: Buffer): number => {
    const value = parseJsonRecord(bytes, 'Das lokale Profil ist beschädigt.');
    if (value.format !== 'vaulta-profile') {
      throw new VaultaError('CORRUPT_DATA', 'Das lokale Profilformat ist ungültig.');
    }
    return readFormatVersion(value.version, 'Profil');
  };
  return {
    id: 'profile-header',
    formatName: 'Vaulta-Profil',
    currentVersion: PROFILE_FORMAT_VERSION,
    matches: (relativePath) => relativePath === 'profile.json',
    readVersion: async (filePath) => readVersionFromBytes(await readFile(filePath)),
    readVersionFromBytes,
    validateAtRest: async (filePath) => {
      parseStoredProfileHeader(
        parseJsonRecord(await readFile(filePath), 'Das lokale Profil ist beschädigt.'),
      );
    },
    validateCurrent: (bytes) => {
      parseStoredProfileHeader(parseJsonRecord(bytes, 'Das lokale Profil ist beschädigt.'));
    },
  };
}

function encryptedContainerAdapter(): PersistentFormatAdapter {
  const readVersionFromBytes = (bytes: Buffer): number => {
    const value = parseJsonRecord(bytes, 'Der verschlüsselte Container ist beschädigt.');
    if (!isRecord(value.header) || value.header.magic !== 'VAULTA-CONTAINER') {
      throw new VaultaError('CORRUPT_DATA', 'Das verschlüsselte Containerformat ist ungültig.');
    }
    return readFormatVersion(value.header.version, 'Container');
  };
  return {
    id: 'encrypted-container',
    formatName: 'Vaulta-Container',
    currentVersion: ENCRYPTED_CONTAINER_VERSION,
    matches: (relativePath) =>
      relativePath === 'audit.vaulta' || /^vaults\/[A-Za-z0-9_-]+\.vaulta$/u.test(relativePath),
    readVersion: async (filePath) => readVersionFromBytes(await readFile(filePath)),
    readVersionFromBytes,
    validateAtRest: async (filePath) => {
      validateEncryptedContainer(await readFile(filePath));
    },
    validateCurrent: (bytes) => {
      validateEncryptedContainer(bytes);
    },
  };
}

function attachmentAdapter(): PersistentFormatAdapter {
  const readVersionFromBytes = (bytes: Buffer): number =>
    readFormatVersion(parseAttachmentHeader(bytes).version, 'Anhang');
  return {
    id: 'attachment',
    formatName: 'Vaulta-Anhang',
    currentVersion: ATTACHMENT_FORMAT_VERSION,
    matches: (relativePath) =>
      /^attachments\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\.vatt$/u.test(relativePath),
    readVersion: readAttachmentVersion,
    readVersionFromBytes,
    validateAtRest: async (filePath) => {
      validateAttachmentHeader(await readAttachmentHeader(filePath));
    },
    validateCurrent: (bytes) => {
      validateAttachmentHeader(parseAttachmentHeader(bytes));
    },
  };
}

async function readAttachmentVersion(filePath: string): Promise<number> {
  const header = await readAttachmentHeader(filePath);
  return readFormatVersion(header.version, 'Anhang');
}

async function readAttachmentHeader(filePath: string): Promise<Record<string, unknown>> {
  const handle = await open(filePath, constants.O_RDONLY);
  try {
    const prefix = await readExact(handle, 12, 0);
    if (!prefix.subarray(0, ATTACHMENT_MAGIC.length).equals(ATTACHMENT_MAGIC)) {
      throw new VaultaError('CORRUPT_DATA', 'Das Anhangsformat ist ungültig.');
    }
    const headerLength = prefix.readUInt32BE(ATTACHMENT_MAGIC.length);
    if (headerLength <= 0 || headerLength > ATTACHMENT_HEADER_LIMIT) {
      throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
    }
    const headerBytes = await readExact(handle, headerLength, 12);
    return parseJsonRecord(headerBytes, 'Der Anhangsheader ist ungültig.');
  } finally {
    await handle.close();
  }
}

function validateEncryptedContainer(bytes: Buffer): void {
  const value = parseJsonRecord(bytes, 'Der verschlüsselte Container ist beschädigt.');
  if (
    !isRecord(value.header) ||
    value.header.magic !== 'VAULTA-CONTAINER' ||
    value.header.version !== ENCRYPTED_CONTAINER_VERSION ||
    typeof value.header.kind !== 'string' ||
    value.header.kind.length === 0 ||
    value.header.cipher !== 'AES-256-GCM' ||
    typeof value.header.contextHash !== 'string' ||
    !isEnvelope(value.payload)
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der verschlüsselte Container ist beschädigt.');
  }
}

function validateAttachmentHeader(header: Record<string, unknown>): void {
  if (
    header.version !== ATTACHMENT_FORMAT_VERSION ||
    header.format !== 'vaulta-attachment' ||
    header.cipher !== 'AES-256-GCM-CHUNKED' ||
    typeof header.chunkSize !== 'number' ||
    !Number.isSafeInteger(header.chunkSize) ||
    header.chunkSize < 4096 ||
    header.chunkSize > 16 * 1024 * 1024 ||
    typeof header.noncePrefix !== 'string' ||
    Buffer.from(header.noncePrefix, 'base64').length !== 8 ||
    !isEnvelope(header.wrappedFileKey)
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
  }
}

function parseAttachmentHeader(bytes: Buffer): Record<string, unknown> {
  if (bytes.length < 12 || !bytes.subarray(0, 8).equals(ATTACHMENT_MAGIC)) {
    throw new VaultaError('CORRUPT_DATA', 'Das Anhangsformat ist ungültig.');
  }
  const headerLength = bytes.readUInt32BE(8);
  if (
    headerLength <= 0 ||
    headerLength > ATTACHMENT_HEADER_LIMIT ||
    bytes.length < 12 + headerLength
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Anhangsheader ist ungültig.');
  }
  return parseJsonRecord(bytes.subarray(12, 12 + headerLength), 'Der Anhangsheader ist ungültig.');
}

function parseJsonRecord(bytes: Buffer, message: string): Record<string, unknown> {
  try {
    const value = JSON.parse(bytes.toString('utf8')) as unknown;
    if (!isRecord(value)) throw new Error('not a record');
    return value;
  } catch (error) {
    throw new VaultaError('CORRUPT_DATA', message, null, { cause: error });
  }
}

function readFormatVersion(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new VaultaError('CORRUPT_DATA', `Die ${label}-Formatversion ist ungültig.`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
}

function isSafeFileSize(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isEnvelope(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.algorithm === 'AES-256-GCM' &&
    typeof value.nonce === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.tag === 'string'
  );
}

async function hashRegularFile(
  filePath: string,
  assertAuthorized: () => void = () => undefined,
): Promise<{ size: number; sha256: string }> {
  assertAuthorized();
  const info = await lstat(filePath);
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new VaultaError('UNSAFE_PATH', 'Der Snapshot enthält keine reguläre Datei.');
  }
  const handle = await open(filePath, constants.O_RDONLY);
  const hash = createHash('sha256');
  let position = 0;
  try {
    while (true) {
      assertAuthorized();
      const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
      const result = await handle.read(buffer, 0, buffer.length, position);
      if (result.bytesRead === 0) break;
      hash.update(buffer.subarray(0, result.bytesRead));
      position += result.bytesRead;
    }
  } finally {
    await handle.close();
  }
  if (position !== info.size) {
    throw new VaultaError('CONFLICT', 'Eine Snapshot-Datei änderte sich während der Prüfung.');
  }
  return { size: position, sha256: hash.digest('hex') };
}

async function readExact(handle: FileHandle, length: number, position: number): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(length);
  let read = 0;
  while (read < length) {
    const result = await handle.read(buffer, read, length - read, position + read);
    if (result.bytesRead === 0) {
      throw new VaultaError('CORRUPT_DATA', 'Die persistente Datei ist unvollständig.');
    }
    read += result.bytesRead;
  }
  return buffer;
}
