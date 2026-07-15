import { randomUUID } from 'node:crypto';
import { readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type { EntryInput, VaultDocument, VaultEntry, VaultSummary } from '../../shared/models';
import { requireCurrentFormatVersion } from '../migrations/format-version';
import { CryptoService } from '../security/crypto-service';
import { AtomicFileWriter } from '../storage/atomic-file';
import { EncryptedContainerCodec } from '../storage/encrypted-container';
import { assertSafeIdentifier, resolveInside } from '../storage/path-safety';
import { SerialExecutor } from '../storage/serial-executor';
import type { ProfileService, ProtectedMetadataValue } from './profile-service';

const VAULT_KEYS_NAMESPACE = 'vault-keys';
const VAULT_EXTENSION = '.vaulta';
export const VAULT_DOCUMENT_FORMAT_VERSION = 1 as const;

type VaultKeyRegistry = Record<string, string>;

export interface VaultServiceOptions {
  rootDir: string;
  profileService: ProfileService;
  crypto?: CryptoService;
  containers?: EncryptedContainerCodec;
  atomicWriter?: AtomicFileWriter;
  now?: () => Date;
}

export function readVaultDocumentFormatVersion(value: unknown): number {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VaultaError('CORRUPT_DATA', 'Der Tresorcontainer ist beschädigt.');
  }
  return requireCurrentFormatVersion(
    'formatVersion' in value ? value.formatVersion : undefined,
    VAULT_DOCUMENT_FORMAT_VERSION,
    'Vaulta-Tresorinhalt',
  );
}

function parseVaultDocument(value: unknown, expectedId: string): VaultDocument {
  readVaultDocumentFormatVersion(value);
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !('id' in value) ||
    value.id !== expectedId ||
    !('name' in value) ||
    typeof value.name !== 'string' ||
    !('color' in value) ||
    typeof value.color !== 'string' ||
    !('createdAt' in value) ||
    typeof value.createdAt !== 'string' ||
    !('updatedAt' in value) ||
    typeof value.updatedAt !== 'string' ||
    !('folders' in value) ||
    !Array.isArray(value.folders) ||
    !('entries' in value) ||
    !Array.isArray(value.entries)
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der Tresorinhalt ist ungültig.');
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

function secretState(entry: VaultEntry | EntryInput): string {
  return JSON.stringify({
    data: entry.data,
    secretFields: entry.customFields
      .filter((field) => field.secret)
      .map((field) => [field.id, field.value]),
  });
}

export class VaultService {
  private readonly vaultsDir: string;
  private readonly profileService: ProfileService;
  private readonly crypto: CryptoService;
  private readonly containers: EncryptedContainerCodec;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly now: () => Date;
  private readonly registryWrites = new SerialExecutor();
  private readonly vaultWrites = new Map<string, SerialExecutor>();

  public constructor(options: VaultServiceOptions) {
    this.vaultsDir = path.resolve(options.rootDir, 'vaults');
    this.profileService = options.profileService;
    this.crypto = options.crypto ?? new CryptoService();
    this.containers = options.containers ?? new EncryptedContainerCodec(this.crypto);
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
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
      return document;
    });
  }

  public async readVault(vaultId: string): Promise<VaultDocument> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    const key = await this.getVaultKey(vaultId);
    try {
      await this.atomicWriter.recoverPreviousIfTargetMissing(this.vaultPath(vaultId));
      const bytes = await readFile(this.vaultPath(vaultId)).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new VaultaError('NOT_FOUND', 'Der Tresor wurde nicht gefunden.');
        }
        throw error;
      });
      const value = this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId);
      return parseVaultDocument(value, vaultId);
    } finally {
      this.crypto.erase(key);
    }
  }

  public async inspectStoredDocumentFormatVersion(vaultId: string): Promise<number> {
    assertSafeIdentifier(vaultId, 'Tresor-ID');
    const key = await this.getVaultKey(vaultId);
    try {
      await this.atomicWriter.recoverPreviousIfTargetMissing(this.vaultPath(vaultId));
      const bytes = await readFile(this.vaultPath(vaultId));
      const value = this.containers.decodeJson<unknown>(bytes, key, 'vault', vaultId);
      const version = readVaultDocumentFormatVersion(value);
      parseVaultDocument(value, vaultId);
      return version;
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
    parseVaultDocument(document, document.id);
    await this.executorFor(document.id).run(async () => {
      const replacement: VaultDocument = {
        ...document,
        updatedAt: this.now().toISOString(),
      };
      const key = await this.getVaultKey(document.id);
      try {
        await this.writeVaultWithKey(replacement, key);
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
    });
  }

  public async createEntry(vaultId: string, input: EntryInput): Promise<VaultEntry> {
    return this.mutateVault(vaultId, (document) => {
      const id = input.id ?? randomUUID();
      assertSafeIdentifier(id, 'Eintrags-ID');
      if (document.entries.some((entry) => entry.id === id)) {
        throw new VaultaError('CONFLICT', 'Ein Eintrag mit dieser ID existiert bereits.');
      }
      const now = this.now().toISOString();
      const entry: VaultEntry = {
        ...input,
        id,
        vaultId,
        attachments: [],
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
    return this.mutateVault(vaultId, (document) => {
      const existing = requireEntry(document, entryId);
      const changedSecret = secretState(existing) !== secretState(input);
      const replacement: VaultEntry = {
        ...input,
        id: existing.id,
        vaultId,
        attachments: existing.attachments,
        createdAt: existing.createdAt,
        updatedAt: this.now().toISOString(),
        secretChangedAt: changedSecret ? this.now().toISOString() : existing.secretChangedAt,
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
      parseVaultDocument(
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
