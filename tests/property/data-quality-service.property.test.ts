import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  DataQualityService,
  type AttachmentTechnicalCheck,
  type DataQualityScanInput,
} from '../../src/main/services/data-quality-service';
import type { AttachmentMetadata, VaultDocument, VaultEntry } from '../../src/shared/models';

const NOW = new Date('2026-07-21T12:00:00.000Z');
const REVISION = '2026-07-20T10:00:00.000Z';
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const letters = [...'abcdefghijklmnopqrstuvwxyz'];
const label = fc.string({ unit: fc.constantFrom(...letters), minLength: 1, maxLength: 20 });
const pathSegment = fc.string({ unit: fc.constantFrom(...letters), maxLength: 20 });

describe('Property-basierte Datenqualitaet', () => {
  it('entfernt bei sicher normalisierten exakten URL-Duplikaten immer nur die spaetere Website', async () => {
    await fc.assert(
      fc.asyncProperty(label, pathSegment, async (hostLabel, path) => {
        const suffix = path.length > 0 ? `/${path}` : '';
        const first = `https://${hostLabel}.test${suffix}`;
        const second = `  https://${hostLabel.toUpperCase()}.test${suffix}  `;
        const input = scanInput([entry('entry-1', [first, second])]);
        const snapshot = structuredClone(input);
        const service = new DataQualityService();

        const report = await service.scan(input, { now: NOW });
        const duplicate = report.findings.find((item) => item.code === 'duplicate-website');

        expect(duplicate).toBeDefined();
        expect(duplicate?.location).toEqual({
          kind: 'website-pair',
          firstIndex: 0,
          secondIndex: 1,
        });
        expect(service.previewFix(input, duplicate!, { now: NOW }).mutation).toEqual({
          kind: 'remove-entry-website',
          index: 1,
        });
        expect(input).toEqual(snapshot);
      }),
      { numRuns: 150 },
    );
  });

  it('liefert unabhaengig von der Eingabereihenfolge denselben sortierten Report', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(fc.integer({ min: 0, max: 50 }), { minLength: 1, maxLength: 20 }),
        async (indexes) => {
          const entries = indexes.map((index) => ({
            ...entry(`entry-${String(index).padStart(2, '0')}`, [
              `  site-${String(index)}.example.test  `,
            ]),
            folderId: index % 2 === 0 ? 'missing-folder' : null,
            title:
              index % 3 === 0 ? `Importierter Eintrag ${String(index)}` : `Titel ${String(index)}`,
          }));
          const service = new DataQualityService();

          const forward = await service.scan(scanInput(entries), { now: NOW });
          const reverse = await service.scan(scanInput([...entries].reverse()), { now: NOW });

          expect(reverse).toEqual(forward);
          expect(forward.findings.map((item) => item.id)).toEqual(
            [...forward.findings.map((item) => item.id)].sort((left, right) =>
              left.localeCompare(right, 'en'),
            ),
          );
        },
      ),
      { numRuns: 100 },
    );
  });

  it('gibt zufaellige Geheimnisse, Hashes und technische Pfade nie im Report aus', async () => {
    const canaryPart = fc.string({
      unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'),
      minLength: 6,
      maxLength: 32,
    });
    await fc.assert(
      fc.asyncProperty(canaryPart, async (part) => {
        const secret = `CANARY-SECRET-${part}-END`;
        const sourcePath = `C:\\private\\CANARY-PATH-${part}\\attachment.bin`;
        const attachment = metadata('attachment-1');
        const sourceEntry = {
          ...entry('entry-1', ['javascript:invalid']),
          note: secret,
          customFields: [
            {
              id: 'secret-field',
              label: 'Token',
              type: 'secret' as const,
              value: secret,
              secret: true,
              searchable: false,
              order: 0,
            },
          ],
          attachments: [attachment],
        };
        if (sourceEntry.data.type !== 'credential') throw new Error('Test-Fixture ist ungueltig.');
        sourceEntry.data.value.password = secret;
        sourceEntry.data.value.totp = {
          secret,
          issuer: 'Kryptris',
          account: 'test@example.test',
          algorithm: 'SHA512',
          digits: 8,
          period: 45,
        };
        const check = {
          status: 'metadata-mismatch',
          vaultId: 'vault-1',
          entryId: sourceEntry.id,
          attachmentId: attachment.id,
          entryUpdatedAt: sourceEntry.updatedAt,
          verifiedMetadata: { size: 42, sha256: HASH_B },
          sourcePath,
        } as AttachmentTechnicalCheck & { sourcePath: string };

        const report = await new DataQualityService().scan(scanInput([sourceEntry], [check]), {
          now: NOW,
        });
        const serialized = JSON.stringify(report);

        expect(serialized).not.toContain(secret);
        expect(serialized).not.toContain(HASH_A);
        expect(serialized).not.toContain(HASH_B);
        expect(serialized).not.toContain(sourcePath);
      }),
      { numRuns: 100 },
    );
  });
});

function entry(id: string, websites: string[]): VaultEntry {
  return {
    id,
    vaultId: 'vault-1',
    title: 'Beispiel',
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    attachments: [],
    data: {
      type: 'credential',
      value: {
        username: 'user@example.test',
        password: 'Strong!Password-12345',
        websites,
        appNames: [],
      },
    },
    lifecycle: {
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    },
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: REVISION,
    secretChangedAt: '2026-01-01T00:00:00.000Z',
    lastUsedAt: null,
    deletedAt: null,
  };
}

function scanInput(
  entries: VaultEntry[],
  attachmentChecks: AttachmentTechnicalCheck[] = [],
): DataQualityScanInput {
  const document: VaultDocument = {
    formatVersion: 2,
    id: 'vault-1',
    name: 'Privat',
    color: '#22d3c5',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: REVISION,
    folders: [],
    entries,
  };
  return { document, attachmentChecks, savedViews: [] };
}

function metadata(id: string): AttachmentMetadata {
  return {
    id,
    name: 'attachment.bin',
    mediaType: 'application/octet-stream',
    size: 12,
    sha256: HASH_A,
    createdAt: '2026-01-01T00:00:00.000Z',
    previewable: false,
  };
}
