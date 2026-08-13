import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { OfflineBreachService } from '../../src/main/services/offline-breach-service';

const syntheticText = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'),
  minLength: 1,
  maxLength: 32,
});

describe('OfflineBreachService Properties', () => {
  it('liefert fuer beliebige sortierte Quellen dieselbe Membership wie die Referenzmenge', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(syntheticText, { minLength: 1, maxLength: 24 }),
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        fc.integer({ min: 1, max: 79 }),
        async (passwords, useCrLf, useBom, finalNewline, readChunkBytes) => {
          const root = await mkdtemp(path.join(tmpdir(), 'kryptris-breach-property-'));
          try {
            const sourcePath = path.join(root, 'source.txt');
            const indexPath = path.join(root, 'index.kbi');
            const hashes = passwords.map((password) => sha1(password));
            const uniqueHashes = [...new Set(hashes)].sort();
            const newline = useCrLf ? '\r\n' : '\n';
            const records = uniqueHashes.map(
              (hash, index) => `${hash}:${String((index % 97) + 1)}`,
            );
            const source = `${useBom ? '\uFEFF' : ''}${records.join(newline)}${
              finalNewline ? newline : ''
            }`;
            await writeFile(sourcePath, source, 'utf8');

            const service = new OfflineBreachService({
              readChunkBytes,
              candidateYieldInterval: 3,
            });
            const built = await service.buildIndex({ sourcePath, stagingPath: indexPath });
            expect(built.recordCount).toBe(uniqueHashes.length);

            let missingPassword = 'synthetic-property-miss';
            while (uniqueHashes.includes(sha1(missingPassword))) missingPassword += '-next';
            const candidates = [
              ...passwords.map((password, index) => ({
                reference: {
                  vaultId: 'vault-property',
                  entryId: `entry-${String(index)}`,
                  updatedAt: '2026-07-26T10:00:00.000Z',
                },
                password,
                deletedAt: null,
              })),
              {
                reference: {
                  vaultId: 'vault-property',
                  entryId: 'missing',
                  updatedAt: '2026-07-26T10:00:00.000Z',
                },
                password: missingPassword,
                deletedAt: null,
              },
              {
                reference: {
                  vaultId: 'vault-property',
                  entryId: 'deleted',
                  updatedAt: '2026-07-26T10:00:00.000Z',
                },
                password: passwords[0]!,
                deletedAt: '2026-07-26T11:00:00.000Z',
              },
              {
                reference: {
                  vaultId: 'vault-property',
                  entryId: 'empty',
                  updatedAt: '2026-07-26T10:00:00.000Z',
                },
                password: '',
                deletedAt: null,
              },
            ];

            const result = await service.scan({
              indexPath,
              expectedIndexSha256: built.indexSha256,
              candidates,
            });

            expect(result.checkedCandidates).toBe(passwords.length + 1);
            expect(result.matches.map((reference) => reference.entryId)).toEqual(
              passwords.map((_password, index) => `entry-${String(index)}`),
            );
            expect(result.networkUsed).toBe(false);
          } finally {
            await rm(root, { recursive: true, force: true });
          }
        },
      ),
      { numRuns: 30 },
    );
  });
});

function sha1(value: string): string {
  return createHash('sha1').update(value, 'utf8').digest('hex').toUpperCase();
}
