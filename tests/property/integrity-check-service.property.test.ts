import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { IntegrityCheckService } from '../../src/main/services/integrity-check-service';
import type { VaultDocument, VaultEntry } from '../../src/shared/models';
import { credentialEntry } from '../unit/service-fixtures';

const NOW = new Date('2026-07-26T15:00:00.000Z');

describe('Property-basierte Integritätsprüfung', () => {
  it('ist unabhängig von Eingabereihenfolgen und gibt beliebige fachliche Werte nie aus', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(fc.integer({ min: 1, max: 10_000 }), {
          minLength: 1,
          maxLength: 30,
        }),
        fc.string({
          unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'),
          minLength: 8,
          maxLength: 30,
        }),
        async (indexes, randomPart) => {
          const canary = `CANARY-${randomPart}-END`;
          const entries = indexes.map((index) =>
            brokenEntry(`entry-${String(index)}`, canary, index % 2 === 0),
          );
          const forward = await serviceFor(document(entries)).scan({
            yieldControl: () => Promise.resolve(),
          });
          const reverse = await serviceFor(document([...entries].reverse())).scan({
            yieldControl: () => Promise.resolve(),
          });

          expect(reverse).toEqual(forward);
          expect(forward.success).toBe(false);
          expect(forward.findings.every((finding) => finding.scope === 'reference')).toBe(true);
          expect(JSON.stringify(forward)).not.toContain(canary);
          for (const index of indexes) {
            expect(JSON.stringify(forward)).not.toContain(`entry-${String(index)}`);
          }
          expect(forward.findings.map((finding) => finding.id)).toEqual(
            forward.findings.map(
              (_, index) => `integrity-finding-${String(index + 1).padStart(4, '0')}`,
            ),
          );
        },
      ),
      { numRuns: 100 },
    );
  });
});

function serviceFor(value: VaultDocument): IntegrityCheckService {
  return new IntegrityCheckService({
    profile: {
      readPublicHeader: () => Promise.resolve({ format: 'vaulta-profile' }),
      getProtectedMetadata: () => Promise.resolve(null),
      getPublicFactorData: () => Promise.resolve(null),
    },
    vaults: {
      inspectStoredVaultInventory: () =>
        Promise.resolve({ vaultIds: [value.id], invalidEntryCount: 0 }),
      listRegisteredVaultIds: () => Promise.resolve([value.id]),
      readVaultFresh: () => Promise.resolve(structuredClone(value)),
    },
    attachments: {
      inspectStoredAttachmentInventory: () =>
        Promise.resolve({ references: [], invalidEntryCount: 0 }),
      inspectIntegrity: () => Promise.reject(new Error('unexpected attachment')),
    },
    audit: { inspectStoredDocumentFormatVersion: () => Promise.resolve(1) },
    now: () => NOW,
  });
}

function document(entries: VaultEntry[]): VaultDocument {
  return {
    formatVersion: 2,
    id: 'vault-a',
    name: 'CANARY-Vault',
    color: '#112233',
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
    folders: [],
    entries,
  };
}

function brokenEntry(id: string, canary: string, wrongVault: boolean): VaultEntry {
  return {
    ...credentialEntry({
      id,
      vaultId: wrongVault ? 'wrong-vault' : 'vault-a',
      title: canary,
      username: canary,
      password: canary,
    }),
    folderId: 'missing-folder',
    note: `C:\\private\\${canary}\\secret.txt`,
  };
}
