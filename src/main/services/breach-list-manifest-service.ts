import { z } from 'zod';

import { VaultaError } from '../../shared/errors';
import type { BreachListStatusDto } from '../../shared/models';
import type { OfflineBreachIndexBuildResult } from './offline-breach-service';

export const BREACH_LIST_NAMESPACE = 'offline-breach-list';
export const BREACH_LIST_INDEX_RELATIVE_PATH = 'security/offline-breach-v1.kbi';

const manifestSchema = z
  .object({
    format: z.literal('kryptris-offline-breach-manifest'),
    version: z.literal(1),
    listFormat: z.literal('sha1-count-v1'),
    sourceLabel: z.string().min(1).max(120),
    sourceDate: z.iso.date(),
    importedAt: z.iso.datetime(),
    sourceSha256: z.string().regex(/^[0-9a-f]{64}$/u),
    indexSha256: z.string().regex(/^[0-9a-f]{64}$/u),
    recordCount: z.number().int().min(1).max(1_000_000_000),
    indexBytes: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

export type BreachListManifest = z.infer<typeof manifestSchema>;

export class BreachListManifestService {
  public parse(value: unknown): BreachListManifest | null {
    if (value === null || value === undefined) return null;
    const parsed = manifestSchema.safeParse(value);
    if (!parsed.success) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Die geschützten Metadaten der lokalen Datenleckliste sind beschädigt.',
      );
    }
    return parsed.data;
  }

  public create(
    build: OfflineBreachIndexBuildResult,
    input: { sourceLabel: string; sourceDate: string },
    now: Date = new Date(),
  ): BreachListManifest {
    const value = {
      format: 'kryptris-offline-breach-manifest',
      version: 1,
      listFormat: build.format,
      sourceLabel: input.sourceLabel.trim(),
      sourceDate: input.sourceDate,
      importedAt: now.toISOString(),
      sourceSha256: build.sourceSha256,
      indexSha256: build.indexSha256,
      recordCount: build.recordCount,
      indexBytes: build.indexBytes,
    };
    const parsed = manifestSchema.safeParse(value);
    if (!parsed.success) {
      throw new VaultaError('INVALID_INPUT', 'Die Metadaten der Datenleckliste sind ungültig.');
    }
    return parsed.data;
  }

  public status(
    manifest: BreachListManifest | null,
    state: 'ready' | 'missing' | 'corrupt' = 'ready',
  ): BreachListStatusDto {
    if (manifest === null) {
      return {
        state: 'not-configured',
        sourceLabel: null,
        sourceDate: null,
        importedAt: null,
        recordCount: 0,
        corpusSha256: null,
        networkUsed: false,
      };
    }
    return {
      state,
      sourceLabel: manifest.sourceLabel,
      sourceDate: manifest.sourceDate,
      importedAt: manifest.importedAt,
      recordCount: manifest.recordCount,
      corpusSha256: manifest.sourceSha256,
      networkUsed: false,
    };
  }
}
