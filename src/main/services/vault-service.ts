import { createHash, randomUUID } from 'node:crypto';
import { readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import {
  createDefaultEntryLifecycleMetadata,
  type EntryInput,
  type VaultDocument,
  type VaultDocumentV1,
  type VaultEntry,
  type VaultSummary,
} from '../../shared/models';
import {
  entryInputSchema,
  vaultDocumentV1Schema,
  vaultDocumentV2Schema,
} from '../../shared/schemas';
import { normalizeTags } from '../../shared/tags';
import { CryptoService } from '../security/crypto-service';
import { AtomicFileWriter } from '../storage/atomic-file';
import { EncryptedContainerCodec } from '../storage/encrypted-container';
import { assertSafeIdentifier, resolveInside } from '../storage/path-safety';
import { SerialExecutor } from '../storage/serial-executor';
import { EntryLifecycleService } from './entry-lifecycle-service';
import type {
  PreparedProtectedMetadataWrite,
  ProfileService,
  ProtectedMetadataValue,
} from './profile-service';

const VAULT_KEYS_NAMESPACE = 'vault-keys';
const VAULT_EXTENSION = '.vaulta';
export const VAULT_DOCUMENT_FORMAT_VERSION = 2 as const;
export const LEGACY_VAULT_DOCUMENT_FORMAT_VERSION = 1 as const;

type VaultKeyRegistry = Record<string, string>;

export interface VaultServiceOptions {
  rootDir: string;
  profileService: ProfileService;
  crypto?: CryptoService;
  containers?: EncryptedContainerCodec;
  atomicWriter?: AtomicFileWriter;
  lifecycle?: EntryLifecycleService;
  now?: () => Date;
}

export interface PreparedVaultDocumentWrite {
  readonly document: VaultDocument;
  readonly relativePath: string;
  readonly contents: Buffer;
  readonly expectedSha256: string;
}

/**
 * An encrypted new-vault generation plus the matching protected key-registry
 * generation. The caller owns both buffers and commits them in one wider
 * transaction while the profile writer is held.
 */
export interface PreparedNewVaultWrite {
  readonly document: VaultDocument;
  readonly relativePath: string;
  readonly contents: Buffer;
  readonly expectedSha256: null;
  readonly profileWrite: PreparedProtectedMetadataWrite;
  /**
   * Main-process-only target key for writing already verified attachment bytes
   * into encrypted staging files before the surrounding transaction commits.
   * The caller must overwrite it after staging or on every error path.
   */
  readonly vaultKey: Buffer;
}

export interface StoredVaultInventory {
  readonly vaultIds: string[];
  readonly invalidEntryCount: number;
}

export function readVaultDocumentFormatVersion(value: unknown): number {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VaultaError('CORRUPT_DATA', 'Der Tresorcontainer ist beschädigt.');
  }
  const version = 'formatVersion' in value ? value.formatVersion : undefined;
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) {
    throw new VaultaError('CORRUPT_DATA', 'Die Vaulta-Tresorinhalt-Formatversion ist ungültig.');
  }
  if (version > VAULT_DOCUMENT_FORMAT_VERSION) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      `Vaulta-Tresorinhalt verwendet die neuere Formatversion ${version}; unterstützt wird Version ${VAULT_DOCUMENT_FORMAT_VERSION}.`,
      'Öffne diese Daten mit einer neueren Vaulta-Version. Die Datei wurde nicht verändert.',
    );
  }
  return version;
}

export function parseVaultDocumentV1(value: unknown, expectedId: string): VaultDocumentV1 {
  const version = readVaultDocumentFormatVersion(value);
  if (version !== LEGACY_VAULT_DOCUMENT_FORMAT_VERSION) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      `Der V1-Leser akzeptiert keine Tresorinhalte der Formatversion ${version}.`,
      'Die Datei wurde nicht verändert.',
    );
  }
  const result = vaultDocumentV1Schema.safeParse(value);
  if (!result.success || result.data.id !== expectedId) {
    throw new VaultaError('CORRUPT_DATA', 'Der V1-Tresorinhalt ist ungültig.', null, {
      ...(result.success ? {} : { cause: result.error }),
    });
  }
  return value as VaultDocumentV1;
}

export function parseVaultDocumentV2(value: unknown, expectedId: string): VaultDocument {
  const version = readVaultDocumentFormatVersion(value);
  if (version !== VAULT_DOCUMENT_FORMAT_VERSION) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      `Der Tresorinhalt verwendet Formatversion ${version} und muss vor der normalen Verwendung auf Version ${VAULT_DOCUMENT_FORMAT_VERSION} migriert werden.`,
      'Die Datei wurde nicht verändert.',
    );
  }
  const result = vaultDocumentV2Schema.safeParse(value);
  if (!result.success || result.data.id !== expectedId) {
    throw new VaultaError('CORRUPT_DATA', 'Der V2-Tresorinhalt ist ungültig.', null, {
      ...(result.success ? {} : { cause: result.error }),
    });
  }
  return value as VaultDocument;
}

function parseVaultKeyRegistry(value: ProtectedMetadataValue | null): VaultKeyRegistry {
  if (value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new VaultaError('CORRUPT_DATA', 'Das Tresorschlüsselverzeichnis ist beschädigt.');
  }
  const registry: VaultKeyRegistry = {};
  for (const [id, encodedKey] of Object.entries(value)) {
    assertSafeIdentifier(id, 'Tresor-ID');
    if (typeof encodedKey !== 'string' || Buffer.from(encodedKey, 'base64').length !== 32) {
      throw new VaultaError('CORRUPT_DATA', 'Ein gespeicherter Tresorschlüssel ist beschädigt.');
    }
    registry[id] = encodedKey;
  }
  return registry;
}

function requireEntry(document: VaultDocument, entryId: string): VaultEntry {
  const entry = document.entries.find((candidate) => candidate.id === entryId);
  if (entry === undefined) throw new VaultaError('NOT_FOUND', 'Der Eintrag wurde nicht gefunden.');
  return entry;
}

function assertValidEntryInput(input: EntryInput): void {
  const result = entryInputSchema.safeParse(input);
  if (!result.success) {
    throw new VaultaError('INVALID_INPUT', 'Der Eintrag enthält ungültige Werte.', null, {
      cause: result.error,
    });
  }
}

function secretState(entry: VaultEntry | EntryInput): string {
  const data = (() => {
    switch (entry.data.type) {
      case 'credential':
        return {
          password: entry.data.value.password,
          totpSecret: entry.data.value.totp?.secret ?? null,
        };
      case 'wifi':
        return { wifiPassword: entry.data.value.password };
      case 'credit-card':
        return {
          cardNumber: entry.data.value.number,
          cardCvc: entry.data.value.cvc,
          cardPin: entry.data.value.pin,
        };
      case 'software-license':
        return { licenseKey: entry.data.value.licenseKey };
      case 'ssh-key':
        return {
          sshPrivateKey: entry.data.value.privateKey,
          sshPassphrase: entry.data.value.passphrase,
        };
      default:
        return null;
    }
  })();
  return JSON.stringify({
    data,
    secretFields: entry.customFields
      .filter((field) => field.secret)
      .map((field) => [field.id, field.value] as const)
      .sort(([left], [right]) => left.localeCompare(right)),
  });
}

export class VaultService {
  private readonly vaultsDir: string;
  private readonly profileService: ProfileService;
  private readonly crypto: CryptoService;
  private readonly containers: EncryptedContainerCodec;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly lifecycle: EntryLifecycleService;
  private readonly now: () => Date;
  private readonly registryWrites = new SerialExecutor();
  private readonly vaultWrites = new Map<string, SerialExecutor>();
  /**
   * Decrypted documents are retained only while the controller keeps the vault unlocked.
   * This avoids re-reading and decrypting an entire vault for every list, folder, and detail IPC call.
   */
  private readonly documentCache = new Map<string, VaultDocument>();
  private readonly pendingReads = new Map<string, Promise<VaultDocument>>();
  private cacheGeneration = 0;

  public constructor(options: VaultServiceOptions) {
    this.vaultsDir = path.resolve(options.rootDir, 'vaults');
    this.profileService = options.profileService;
    this.crypto = options.crypto ?? new CryptoService();
    this.containers = options.containers ?? new EncryptedContainerCodec(this.crypto);
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.lifecycle = options.lifecycle ?? new EntryLifecycleService();
    this.now = options.now ?? (() => new Date());
  }

  public async listVaults(): Promise<VaultSummary[]> {
    const entries = await readdir(this.vaultsDir, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    const ids = entries
      .filter((entry) => entry.isFile() && entry.name.endsWith(VAULT_EXTENSION))
      .map((entry) => entry.name.slice(0, -VAULT_EXTENSION.length));
    const documents = await Promise.all(ids.map((id) => this.readVault(id)));
    return documents
      .map((document) => this.toSummary(document))
      .sort((left, right) => left.name.localeCompare(right.name, 'de'));
  }

  public async validateStorageConsistency(
    assertAuthorized: () => void = () => undefined,
  ): Promise<VaultDocument[]> {
    assertAuthorized();
    const entries = await readdir(this.vaultsDir, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    const fileIds = entries
      .map((entry) => {
        assertAuthorized();
        if (!entry.isFile() || !entry.name.endsWith(VAULT_EXTENSION)) {
          throw new VaultaError(
            'CONFLICT',
            'Der Tresorspeicher enthaelt einen nicht bestaetigten Dateistand.',
          );
        }
        const id = entry.name.slice(0, -VAULT_EXTENSION.length);
        assertSafeIdentifier(id, 'Tresor-ID');
        return id;
      })
      .sort();
    assertAuthorized();
    const registryIds = Object.keys(await this.readKeyRegistry()).sort();
    assertAuthorized();
    if (JSON.stringify(fileIds) !== JSON.stringify(registryIds)) {
      throw new VaultaError(
        'CONFLICT',
        'Tresordateien und Schluesselverzeichnis bilden keinen bestaetigten gemeinsamen Stand.',
      );
    }
    const documents: VaultDocument[] = [];
    for (const id of fileIds) {
      assertAuthorized();
      documents.push(await this.readVault(id));
    }
    assertAuthorized();
    return documents;
  }

  /**
   * Enumerates only technical vault identifiers from the on-disk directory.
   * Invalid directory entries are counted without returning their names.
   */
  public async inspectStoredVaultInventory(
    assertAuthorized: () => void = () => undefined,
  ): Promise<StoredVaultInventory> {
    assertAuthorized();
    const entries = await readdir(this.vaultsDir, { withFileTypes: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    });
    const vaultIds = new Set<string>();
    let invalidEntryCount = 0;
    for (const entry of entries) {
      assertAuthorized();
      if (!entry.isFile() || !entry.name.endsWith(VAULT_EXTENSION)) {
        invalidEntryCount += 1;
        continue;
      }
      const vaultId = entry.name.slice(0, -VAULT_EXTENSION.length);
      try {
        assertSafeIdentifier(vaultId, 'Tresor-ID');
      } catch {
        invalidEntryCount += 1;
        continue;
      }
      if (vaultIds.has(vaultId)) {
        invalidEntryCount += 1;
        continue;
      }
      vaultIds.add(vaultId);
    }
    assertAuthorized();
    return { vaultIds: [...vaultIds].sort(), invalidEntryCount };
  }

  /** Returns the authenticated technical vault-key registry without exposing key material. */
  public async listRegisteredVaultIds(
    assertAuthorized: () => void = () => undefined,
  ): Promise<string[]> {
    assertAuthorized();
    const vaultIds = Object.keys(await this.readKeyRegistry()).sort();
    assertAuthorized();
    return vaultIds;
  }

  /**
   * Reads and authenticates the current on-disk container without consulting or
   * populating the decrypted document cache.
   */
  public async readVaultFresh(
    vaultId: string,
    assertAuthorized: () => void = () => undefined,
  ): Promise<VaultDocument> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertAuthorized();
    const document = await this.readVaultFromStorage(vaultId, assertAuthorized);
    assertAuthorized();
    return structuredClone(document);
  }

  public async withVaultKey<T>(
    vaultId: string,
    operation: (vaultKey: Buffer) => Promise<T> | T,
  ): Promise<T> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    const key = await this.getVaultKey(vaultId);
    try {
      return await operation(key);
    } finally {
      this.crypto.erase(key);
    }
  }

  public async createVault(name: string, color: string): Promise<VaultDocument> {
    this.validateVaultAppearance(name, color);
    return this.registryWrites.run(async () => {
      const id = randomUUID();
      const now = this.now().toISOString();
      const document: VaultDocument = {
        formatVersion: VAULT_DOCUMENT_FORMAT_VERSION,
        id,
        name: name.trim(),
        color,
        createdAt: now,
        updatedAt: now,
        folders: [],
        entries: [],
      };
      const registry = await this.readKeyRegistry();
      const seed = this.crypto.randomBytes(32);
      const key = this.crypto.deriveKey(seed, `vault-data:${id}`, Buffer.from(id, 'utf8'));
      registry[id] = seed.toString('base64');
      await this.writeKeyRegistry(registry);
      try {
        await this.writeVaultWithKey(document, key);
      } catch (error) {
        delete registry[id];
        await this.writeKeyRegistry(registry).catch(() => undefined);
        throw error;
      } finally {
        this.crypto.erase(seed);
        this.crypto.erase(key);
      }
      this.documentCache.set(id, structuredClone(document));
      return document;
    });
  }

  public async readVault(vaultId: string): Promise<VaultDocument> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    const cached = this.documentCache.get(vaultId);
    if (cached !== undefined) return structuredClone(cached);

    const pending = this.pendingReads.get(vaultId);
    if (pending !== undefined) return structuredClone(await pending);

    const generation = this.cacheGeneration;
    const read = this.readVaultFromStorage(vaultId);
    this.pendingReads.set(vaultId, read);
    try {
      const document = await read;
      if (generation === this.cacheGeneration) this.documentCache.set(vaultId, document);
      return structuredClone(document);
    } finally {
      if (this.pendingReads.get(vaultId) === read) this.pendingReads.delete(vaultId);
    }
  }

  /** Clears all decrypted documents when the application locks or is disposed. */
  public clearCachedDocuments(): void {
    this.cacheGeneration += 1;
    this.documentCache.clear();
    this.pendingReads.clear();
  }

  /**
   * Serializes one operation against every writer for the supplied vaults.
   * Callers must acquire all vaults in this single sorted call to avoid lock inversion.
   */
  public async withExclusiveVaults<T>(
    vaultIds: readonly string[],
    operation: () => Promise<T>,
  ): Promise<T> {
    const unique = [...new Set(vaultIds)].sort();
    if (unique.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Mindestens ein Tresor muss gesperrt werden.');
    }
    unique.forEach((vaultId) => assertSafeIdentifier(vaultId, 'Tresor-ID'));

    const acquire = async (index: number): Promise<T> => {
      const vaultId = unique[index];
      if (vaultId === undefined) return operation();
      return this.executorFor(vaultId).run(async () => acquire(index + 1));
    };
    return acquire(0);
  }

  /**
   * Serializes a wider transaction with vault creation and deletion. Callers
   * that prepare a replacement key registry must retain this lock until their
   * profile generation is committed, otherwise a concurrent create/delete
   * could publish a stale registry snapshot afterwards.
   */
  public async withExclusiveRegistryWrite<T>(operation: () => Promise<T>): Promise<T> {
    return this.registryWrites.run(operation);
  }

  /**
   * Creates and verifies the encrypted bytes for a wider file transaction without
   * changing the live file or decrypted cache.
   */
  public async prepareDocumentWrite(document: VaultDocument): Promise<PreparedVaultDocumentWrite> {
    assertSafeIdentifier(document.id, 'Tresor-ID');
    parseVaultDocumentV2(document, document.id);
    const target = this.vaultPath(document.id);
    await this.atomicWriter.recoverPreviousIfTargetMissing(target);
    const sourceBytes = await readFile(target).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
      }
      throw error;
    });
    const expectedSha256 = createHash('sha256').update(sourceBytes).digest('hex');
    const key = await this.getVaultKey(document.id);
    try {
      const contents = this.containers.encodeJson(document, key, 'vault', document.id);
      parseVaultDocumentV2(
        this.containers.decodeJson<unknown>(contents, key, 'vault', document.id),
        document.id,
      );
      return {
        document: structuredClone(document),
        relativePath: `vaults/${document.id}${VAULT_EXTENSION}`,
        contents,
        expectedSha256,
      };
    } finally {
      this.crypto.erase(key);
      this.crypto.erase(sourceBytes);
    }
  }

  /**
   * Prepares a completely new local vault and its fresh random key seed without
   * publishing either file. Package import uses this so the vault container,
   * protected key registry, attachments and audit entry can share one atomic
   * commit. Callers must hold `withExclusiveRegistryWrite` and
   * `ProfileService.withExclusiveWrite` until that commit has completed.
   */
  public async prepareNewVaultWrite(document: VaultDocument): Promise<PreparedNewVaultWrite> {
    assertSafeIdentifier(document.id, 'Tresor-ID');
    this.validateVaultAppearance(document.name, document.color);
    parseVaultDocumentV2(document, document.id);

    const target = this.vaultPath(document.id);
    await readFile(target).then(
      () => {
        throw new VaultaError(
          'CONFLICT',
          'Ein Tresor mit dieser technischen ID existiert bereits.',
        );
      },
      (error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error;
      },
    );

    const registry = await this.readKeyRegistry();
    if (registry[document.id] !== undefined) {
      throw new VaultaError('CONFLICT', 'Ein Tresor mit dieser technischen ID existiert bereits.');
    }

    const seed = this.crypto.randomBytes(32);
    const key = this.crypto.deriveKey(
      seed,
      `vault-data:${document.id}`,
      Buffer.from(document.id, 'utf8'),
    );
    let retainedKey = false;
    try {
      const contents = this.containers.encodeJson(document, key, 'vault', document.id);
      parseVaultDocumentV2(
        this.containers.decodeJson<unknown>(contents, key, 'vault', document.id),
        document.id,
      );
      registry[document.id] = seed.toString('base64');
      const profileWrite = await this.profileService.prepareProtectedMetadataUpdates({
        [VAULT_KEYS_NAMESPACE]: registry,
      });
      retainedKey = true;
      return {
        document: structuredClone(document),
        relativePath: `vaults/${document.id}${VAULT_EXTENSION}`,
        contents,
        expectedSha256: null,
        profileWrite,
        vaultKey: key,
      };
    } finally {
      this.crypto.erase(seed);
      if (!retainedKey) this.crypto.erase(key);
    }
  }

  /** Publishes decrypted cache generations only after the wider file commit succeeded. */
  public installCommittedDocuments(documents: readonly VaultDocument[]): void {
    for (const document of documents) {
      parseVaultDocumentV2(document, document.id);
      this.documentCache.set(document.id, structuredClone(document));
      this.pendingReads.delete(document.id);
    }
  }

  private async readVaultFromStorage(
    vaultId: string,
    assertAuthorized: () => void = () => undefined,
  ): Promise<VaultDocument> {
    assertAuthorized();
    const key = await this.getVaultKey(vaultId);
    try {
      assertAuthorized();
      await this.atomicWriter.recoverPreviousIfTargetMissing(this.vaultPath(vaultId));
      assertAuthorized();
      const bytes = await readFile(this.vaultPath(vaultId)).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
        }
        throw error;
      });
      assertAuthorized();
      const value = this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId);
      const document = parseVaultDocumentV2(value, vaultId);
      assertAuthorized();
      return document;
    } finally {
      this.crypto.erase(key);
    }
  }

  public async inspectStoredDocumentFormatVersion(vaultId: string): Promise<number> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.vaultPath(vaultId));
    return this.inspectDocumentBytes(vaultId, await readFile(this.vaultPath(vaultId)));
  }

  /** Reads and strictly validates a V1 or V2 document inside encrypted vault bytes. */
  public async inspectDocumentBytes(
    vaultId: string,
    bytes: Buffer,
    assertAuthorized: () => void = () => undefined,
  ): Promise<number> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertAuthorized();
    const key = await this.getVaultKey(vaultId);
    try {
      assertAuthorized();
      const value = this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId);
      const version = readVaultDocumentFormatVersion(value);
      if (version === LEGACY_VAULT_DOCUMENT_FORMAT_VERSION) parseVaultDocumentV1(value, vaultId);
      else parseVaultDocumentV2(value, vaultId);
      assertAuthorized();
      return version;
    } finally {
      this.crypto.erase(key);
    }
  }

  /** Accepts only a fully encrypted vault target containing the current V2 document. */
  public async validateCurrentDocumentBytes(
    vaultId: string,
    bytes: Buffer,
    assertAuthorized: () => void = () => undefined,
  ): Promise<void> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertAuthorized();
    const key = await this.getVaultKey(vaultId);
    try {
      assertAuthorized();
      parseVaultDocumentV2(
        this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId),
        vaultId,
      );
      assertAuthorized();
    } finally {
      this.crypto.erase(key);
    }
  }

  /** Produces a complete encrypted V2 target while retaining the original V1 ciphertext. */
  public async migrateDocumentBytesV1ToV2(
    vaultId: string,
    bytes: Buffer,
    assertAuthorized: () => void = () => undefined,
  ): Promise<Buffer> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    assertAuthorized();
    const key = await this.getVaultKey(vaultId);
    try {
      assertAuthorized();
      const legacy = parseVaultDocumentV1(
        this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId),
        vaultId,
      );
      const migrated: VaultDocument = {
        ...legacy,
        formatVersion: VAULT_DOCUMENT_FORMAT_VERSION,
        entries: legacy.entries.map((entry) => ({
          ...entry,
          lifecycle: createDefaultEntryLifecycleMetadata(),
        })),
      };
      assertAuthorized();
      const target = this.containers.encodeJson(migrated, key, 'vault', vaultId);
      parseVaultDocumentV2(
        this.containers.decodeJson<unknown>(target, key, 'vault', vaultId),
        vaultId,
      );
      assertAuthorized();
      return target;
    } finally {
      this.crypto.erase(key);
    }
  }

  public async updateVault(
    vaultId: string,
    changes: { name: string; color: string },
  ): Promise<VaultDocument> {
    this.validateVaultAppearance(changes.name, changes.color);
    return this.mutateVault(vaultId, (document) => {
      document.name = changes.name.trim();
      document.color = changes.color;
      return document;
    });
  }

  public async replaceVault(document: VaultDocument): Promise<void> {
    assertSafeIdentifier(document.id, 'Tresor-ID');
    parseVaultDocumentV2(document, document.id);
    await this.executorFor(document.id).run(async () => {
      const replacement: VaultDocument = {
        ...document,
        updatedAt: this.now().toISOString(),
      };
      const key = await this.getVaultKey(document.id);
      try {
        await this.writeVaultWithKey(replacement, key);
        this.documentCache.set(document.id, structuredClone(replacement));
      } finally {
        this.crypto.erase(key);
      }
    });
  }

  public async deleteVault(vaultId: string): Promise<void> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    await this.registryWrites.run(async () => {
      const registry = await this.readKeyRegistry();
      if (registry[vaultId] === undefined) {
        throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
      }
      delete registry[vaultId];
      await this.writeKeyRegistry(registry);
      await rm(this.vaultPath(vaultId), { force: true });
      this.documentCache.delete(vaultId);
      this.pendingReads.delete(vaultId);
    });
  }

  public async createEntry(vaultId: string, input: EntryInput): Promise<VaultEntry> {
    assertValidEntryInput(input);
    return this.mutateVault(vaultId, (document) => {
      const id = input.id ?? randomUUID();
      assertSafeIdentifier(id, 'Eintrags-ID');
      if (document.entries.some((entry) => entry.id === id)) {
        throw new VaultaError('CONFLICT', 'Ein Eintrag mit dieser ID existiert bereits.');
      }
      const now = this.now().toISOString();
      const entry: VaultEntry = {
        ...input,
        tags: normalizeTags(input.tags),
        id,
        vaultId,
        attachments: [],
        lifecycle: this.lifecycle.afterSecretChange(
          input.data.type,
          input.lifecycle ?? createDefaultEntryLifecycleMetadata(),
          now,
        ),
        createdAt: now,
        updatedAt: now,
        secretChangedAt: now,
        lastUsedAt: null,
        deletedAt: null,
      };
      document.entries.push(entry);
      return entry;
    });
  }

  public async updateEntry(
    vaultId: string,
    entryId: string,
    input: EntryInput,
  ): Promise<VaultEntry> {
    assertSafeIdentifier(entryId, 'Eintrags-ID');
    assertValidEntryInput(input);
    return this.mutateVault(vaultId, (document) => {
      const existing = requireEntry(document, entryId);
      const changedSecret = secretState(existing) !== secretState(input);
      const updatedAt = this.now().toISOString();
      const lifecycleSource = input.lifecycle ?? existing.lifecycle;
      const replacement: VaultEntry = {
        ...input,
        tags: normalizeTags(input.tags),
        id: existing.id,
        vaultId,
        attachments: existing.attachments,
        lifecycle: changedSecret
          ? this.lifecycle.afterSecretChange(input.data.type, lifecycleSource, updatedAt)
          : this.lifecycle.normalizeForType(input.data.type, lifecycleSource),
        createdAt: existing.createdAt,
        updatedAt,
        secretChangedAt: changedSecret ? updatedAt : existing.secretChangedAt,
        lastUsedAt: existing.lastUsedAt,
        deletedAt: existing.deletedAt,
      };
      document.entries[document.entries.indexOf(existing)] = replacement;
      return replacement;
    });
  }

  public async moveEntryToTrash(vaultId: string, entryId: string): Promise<void> {
    await this.mutateVault(vaultId, (document) => {
      const entry = requireEntry(document, entryId);
      entry.deletedAt = this.now().toISOString();
      entry.updatedAt = this.now().toISOString();
    });
  }

  public async restoreEntry(vaultId: string, entryId: string): Promise<void> {
    await this.mutateVault(vaultId, (document) => {
      const entry = requireEntry(document, entryId);
      entry.deletedAt = null;
      entry.updatedAt = this.now().toISOString();
    });
  }

  public async purgeEntry(vaultId: string, entryId: string): Promise<void> {
    await this.mutateVault(vaultId, (document) => {
      const index = document.entries.findIndex((entry) => entry.id === entryId);
      if (index < 0) throw new VaultaError('NOT_FOUND', 'Der Eintrag wurde nicht gefunden.');
      document.entries.splice(index, 1);
    });
  }

  public async toggleFavorite(vaultId: string, entryId: string): Promise<boolean> {
    return this.mutateVault(vaultId, (document) => {
      const entry = requireEntry(document, entryId);
      entry.favorite = !entry.favorite;
      entry.updatedAt = this.now().toISOString();
      return entry.favorite;
    });
  }

  public async mutateVault<T>(
    vaultId: string,
    mutation: (document: VaultDocument) => T | Promise<T>,
  ): Promise<T> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    return this.executorFor(vaultId).run(async () => {
      const document = await this.readVault(vaultId);
      const result = await mutation(document);
      document.updatedAt = this.now().toISOString();
      const key = await this.getVaultKey(vaultId);
      try {
        await this.writeVaultWithKey(document, key);
        this.documentCache.set(vaultId, structuredClone(document));
      } finally {
        this.crypto.erase(key);
      }
      return result;
    });
  }

  private async readKeyRegistry(): Promise<VaultKeyRegistry> {
    const value =
      await this.profileService.getProtectedMetadata<ProtectedMetadataValue>(VAULT_KEYS_NAMESPACE);
    return parseVaultKeyRegistry(value);
  }

  private async writeKeyRegistry(registry: VaultKeyRegistry): Promise<void> {
    await this.profileService.setProtectedMetadata(VAULT_KEYS_NAMESPACE, registry);
  }

  private async getVaultKey(vaultId: string): Promise<Buffer> {
    const registry = await this.readKeyRegistry();
    const encoded = registry[vaultId];
    if (encoded === undefined) {
      throw new VaultaError(
        'NOT_FOUND',
        'Der Tresor wurde nicht gefunden oder kryptografisch gelöscht.',
      );
    }
    const seed = Buffer.from(encoded, 'base64');
    const key = this.crypto.deriveKey(seed, `vault-data:${vaultId}`, Buffer.from(vaultId, 'utf8'));
    this.crypto.erase(seed);
    return key;
  }

  private async writeVaultWithKey(document: VaultDocument, key: Buffer): Promise<void> {
    const bytes = this.containers.encodeJson(document, key, 'vault', document.id);
    const target = this.vaultPath(document.id);
    await this.atomicWriter.writeFile(target, bytes, async (temporaryPath) => {
      const temporary = await readFile(temporaryPath);
      parseVaultDocumentV2(
        this.containers.decodeJson<unknown>(temporary, key, 'vault', document.id),
        document.id,
      );
    });
  }

  private vaultPath(vaultId: string): string {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    return resolveInside(this.vaultsDir, `${vaultId}${VAULT_EXTENSION}`);
  }

  private executorFor(vaultId: string): SerialExecutor {
    let executor = this.vaultWrites.get(vaultId);
    if (executor === undefined) {
      executor = new SerialExecutor();
      this.vaultWrites.set(vaultId, executor);
    }
    return executor;
  }

  private validateVaultAppearance(name: string, color: string): void {
    if (name.trim().length === 0 || name.trim().length > 100) {
      throw new VaultaError('INVALID_INPUT', 'Der Tresorname muss 1 bis 100 Zeichen lang sein.');
    }
    if (!/^#[0-9A-Fa-f]{6}$/.test(color)) {
      throw new VaultaError('INVALID_INPUT', 'Die Tresorfarbe muss eine gültige Hex-Farbe sein.');
    }
  }

  private toSummary(document: VaultDocument): VaultSummary {
    return {
      id: document.id,
      name: document.name,
      color: document.color,
      entryCount: document.entries.filter((entry) => entry.deletedAt === null).length,
      deletedCount: document.entries.filter((entry) => entry.deletedAt !== null).length,
      updatedAt: document.updatedAt,
    };
  }
}
