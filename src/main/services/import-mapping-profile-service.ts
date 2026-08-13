import { randomUUID } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type { ImportMapping, ImportMappingProfile } from '../../shared/models';
import { validateImportMapping } from './import-mapping-utils';

export type { ImportMappingProfile } from '../../shared/models';

const SNAPSHOT_VERSION = 1;
const MAX_PROFILES = 100;
const MAX_PROFILE_NAME_LENGTH = 80;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

/**
 * Serializable, non-secret profile payload for the existing protected-metadata
 * path. This service deliberately owns no file path or persistence mechanism.
 */
export interface ImportMappingProfileSnapshot {
  version: typeof SNAPSHOT_VERSION;
  profiles: ImportMappingProfile[];
}

export interface ImportMappingProfileServiceDependencies {
  createId(): string;
  now(): Date;
}

export class ImportMappingProfileService {
  private readonly profiles = new Map<string, ImportMappingProfile>();
  private readonly createId: () => string;
  private readonly now: () => Date;

  public constructor(dependencies: Partial<ImportMappingProfileServiceDependencies> = {}) {
    this.createId = dependencies.createId ?? randomUUID;
    this.now = dependencies.now ?? (() => new Date());
  }

  public list(): ImportMappingProfile[] {
    return [...this.profiles.values()]
      .sort(
        (left, right) =>
          left.name.localeCompare(right.name, 'de') || left.id.localeCompare(right.id),
      )
      .map((profile) => structuredClone(profile));
  }

  public save(input: { id?: string; name: string; mapping: ImportMapping }): ImportMappingProfile {
    const id = assertProfileId(input.id ?? this.createId());
    const existing = this.profiles.get(id);
    if (existing === undefined && this.profiles.size >= MAX_PROFILES) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Es koennen hoechstens 100 Importprofile gespeichert werden.',
      );
    }
    const profile: ImportMappingProfile = {
      id,
      name: normalizeProfileName(input.name),
      mapping: validateImportMapping(input.mapping),
      updatedAt: this.now().toISOString(),
    };
    this.profiles.set(id, profile);
    return structuredClone(profile);
  }

  public remove(id: string): boolean {
    return this.profiles.delete(assertProfileId(id));
  }

  public clear(): void {
    this.profiles.clear();
  }

  public exportSnapshot(): ImportMappingProfileSnapshot {
    return { version: SNAPSHOT_VERSION, profiles: this.list() };
  }

  /**
   * Replaces the in-memory view only after the complete external snapshot has
   * passed validation. Callers can atomically persist this snapshot through the
   * existing encrypted profile-metadata transaction.
   */
  public restoreSnapshot(snapshot: unknown): void {
    const restored = parseSnapshot(snapshot);
    this.profiles.clear();
    for (const profile of restored) this.profiles.set(profile.id, profile);
  }
}

function parseSnapshot(snapshot: unknown): ImportMappingProfile[] {
  if (
    !isRecord(snapshot) ||
    snapshot.version !== SNAPSHOT_VERSION ||
    !Array.isArray(snapshot.profiles)
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Das Importprofil-Snapshot hat ein unbekanntes Format.');
  }
  if (snapshot.profiles.length > MAX_PROFILES) {
    throw new VaultaError('CORRUPT_DATA', 'Das Importprofil-Snapshot enthaelt zu viele Profile.');
  }

  const seen = new Set<string>();
  return snapshot.profiles.map((value) => {
    if (
      !isRecord(value) ||
      !isRecord(value.mapping) ||
      typeof value.name !== 'string' ||
      typeof value.updatedAt !== 'string'
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Ein Importprofil ist ungueltig.');
    }
    const id = assertProfileId(value.id);
    if (seen.has(id) || !Number.isFinite(Date.parse(value.updatedAt))) {
      throw new VaultaError('CORRUPT_DATA', 'Ein Importprofil ist ungueltig.');
    }
    seen.add(id);
    return {
      id,
      name: normalizeProfileName(value.name),
      mapping: validateImportMapping(value.mapping as unknown as ImportMapping),
      updatedAt: value.updatedAt,
    };
  });
}

function assertProfileId(value: unknown): string {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new VaultaError('INVALID_INPUT', 'Die Importprofil-ID ist ungueltig.');
  }
  return value.toLowerCase();
}

function normalizeProfileName(value: string): string {
  const normalized = value.trim().replace(/\s+/gu, ' ');
  if (
    normalized.length === 0 ||
    normalized.length > MAX_PROFILE_NAME_LENGTH ||
    /[\0\r\n]/u.test(normalized)
  ) {
    throw new VaultaError('INVALID_INPUT', 'Der Name des Importprofils ist ungueltig.');
  }
  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
