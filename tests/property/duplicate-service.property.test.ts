import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { DuplicateService } from '../../src/main/services/duplicate-service';
import { emptyEntryData } from '../../src/main/services/entry-utils';
import {
  createDefaultEntryLifecycleMetadata,
  type CustomField,
  type EntryType,
  type VaultEntry,
} from '../../src/shared/models';
import { normalizeTagKey, normalizeTags } from '../../src/shared/tags';

const CREATED_AT = '2026-01-01T00:00:00.000Z';
const UPDATED_AT = '2026-02-01T00:00:00.000Z';
const MERGED_AT = '2026-03-01T00:00:00.000Z';
const shortText = fc.string({
  unit: fc.constantFrom(
    ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 äöüＡＢＣ',
  ),
  maxLength: 24,
});

describe('DuplicateService Properties', () => {
  it('ist unabhängig von der Eingabereihenfolge und liefert symmetrische, eindeutige Paare', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            title: shortText,
            username: shortText,
            host: fc.integer({ min: 0, max: 6 }),
            password: shortText,
            deleted: fc.boolean(),
          }),
          { maxLength: 18 },
        ),
        async (records) => {
          const entries = records.map((record, index) => {
            const entry = baseEntry('credential', `entry-${String(index).padStart(2, '0')}`);
            entry.title = record.title;
            entry.deletedAt = record.deleted ? UPDATED_AT : null;
            if (entry.data.type !== 'credential') throw new Error();
            entry.data.value.username = record.username;
            entry.data.value.websites = [`https://host-${String(record.host)}.example/login`];
            entry.data.value.password = record.password;
            return entry;
          });
          const service = new DuplicateService();

          const forward = await service.scan(entries, { candidateLimit: 10_000 });
          const backward = await service.scan([...entries].reverse(), { candidateLimit: 10_000 });

          expect(forward).toEqual(backward);
          const keys = forward.candidates.map((candidate) => {
            expect(
              candidate.left.entryId.localeCompare(candidate.right.entryId, 'en'),
            ).toBeLessThan(0);
            return JSON.stringify([
              candidate.left.vaultId,
              candidate.left.entryId,
              candidate.right.vaultId,
              candidate.right.entryId,
            ]);
          });
          expect(new Set(keys).size).toBe(keys.length);
        },
      ),
      { numRuns: 120 },
    );
  });

  it('vereinigt Tags, Notizen und Websites stabil und idempotent ohne Eingabemutation', () => {
    fc.assert(
      fc.property(
        fc.array(shortText, { maxLength: 12 }),
        fc.array(shortText, { maxLength: 12 }),
        fc.array(fc.integer({ min: 0, max: 8 }), { maxLength: 12 }),
        fc.array(fc.integer({ min: 0, max: 8 }), { maxLength: 12 }),
        shortText,
        shortText,
        (leftTags, rightTags, leftHosts, rightHosts, leftNote, rightNote) => {
          const survivor = baseEntry('credential', 'survivor');
          const duplicate = baseEntry('credential', 'duplicate');
          survivor.tags = leftTags;
          duplicate.tags = rightTags;
          survivor.note = leftNote;
          duplicate.note = rightNote;
          if (survivor.data.type !== 'credential' || duplicate.data.type !== 'credential') {
            throw new Error();
          }
          survivor.data.value.websites = leftHosts.map(
            (host) => `https://HOST-${String(host)}.example/login`,
          );
          duplicate.data.value.websites = rightHosts.map(
            (host) => `https://host-${String(host)}.example/login`,
          );
          const survivorBefore = structuredClone(survivor);
          const duplicateBefore = structuredClone(duplicate);

          const plan = new DuplicateService().planMerge({
            survivor,
            duplicate,
            now: MERGED_AT,
            collectionChoices: [
              { field: 'tags', strategy: 'union' },
              { field: 'note', strategy: 'union' },
              { field: 'credential.websites', strategy: 'union' },
            ],
          });

          expect(survivor).toEqual(survivorBefore);
          expect(duplicate).toEqual(duplicateBefore);
          expect(plan.survivor.tags).toEqual(normalizeTags([...leftTags, ...rightTags]));
          expect(new Set(plan.survivor.tags.map(normalizeTagKey)).size).toBe(
            plan.survivor.tags.length,
          );
          if (plan.survivor.data.type !== 'credential') throw new Error();
          const websiteKeys = plan.survivor.data.value.websites.map((value) =>
            new URL(value).toString(),
          );
          expect(new Set(websiteKeys).size).toBe(websiteKeys.length);

          const secondPlan = new DuplicateService().planMerge({
            survivor: plan.survivor,
            duplicate,
            now: MERGED_AT,
            collectionChoices: [
              { field: 'tags', strategy: 'union' },
              { field: 'note', strategy: 'union' },
              { field: 'credential.websites', strategy: 'union' },
            ],
          });
          expect(secondPlan.survivor.tags).toEqual(plan.survivor.tags);
          expect(secondPlan.survivor.note).toBe(plan.survivor.note);
          if (secondPlan.survivor.data.type !== 'credential') throw new Error();
          expect(secondPlan.survivor.data.value.websites).toEqual(
            plan.survivor.data.value.websites,
          );
        },
      ),
      { numRuns: 180 },
    );
  });

  it('setzt secretChangedAt genau dann neu, wenn die ausgewählte Passwortsemantik wechselt', () => {
    fc.assert(
      fc.property(shortText, shortText, (leftSecret, rightSecret) => {
        const survivor = baseEntry('credential', 'survivor');
        const duplicate = baseEntry('credential', 'duplicate');
        if (survivor.data.type !== 'credential' || duplicate.data.type !== 'credential') {
          throw new Error();
        }
        survivor.data.value.password = leftSecret;
        duplicate.data.value.password = rightSecret;

        const plan = new DuplicateService().planMerge({
          survivor,
          duplicate,
          now: MERGED_AT,
          fieldChoices: [{ field: 'credential.password', source: 'duplicate' }],
        });

        expect(plan.changedSecretSemantics).toBe(leftSecret !== rightSecret);
        expect(plan.survivor.secretChangedAt).toBe(
          leftSecret === rightSecret ? UPDATED_AT : MERGED_AT,
        );
      }),
      { numRuns: 250 },
    );
  });

  it('erzeugt bei beliebigen eigenen Feldwerten niemals kollidierende Ziel-IDs', () => {
    fc.assert(
      fc.property(
        shortText,
        shortText,
        fc.integer({ min: 0, max: 1_000_000 }),
        (leftValue, rightValue, replacementNumber) => {
          fc.pre(leftValue !== rightValue);
          const survivor = baseEntry('custom', 'survivor');
          const duplicate = baseEntry('custom', 'duplicate');
          survivor.customFields = [customField('collision', 'Links', leftValue)];
          duplicate.customFields = [customField('collision', 'Rechts', rightValue)];
          const targetId = `replacement-${String(replacementNumber)}`;

          const plan = new DuplicateService().planMerge({
            survivor,
            duplicate,
            now: MERGED_AT,
            collectionChoices: [{ field: 'customFields', strategy: 'union' }],
            customFieldIdReplacements: [{ sourceId: 'collision', targetId }],
          });

          const ids = plan.survivor.customFields.map((field) => field.id);
          expect(ids).toEqual(['collision', targetId]);
          expect(new Set(ids).size).toBe(ids.length);
        },
      ),
      { numRuns: 180 },
    );
  });
});

function baseEntry(type: EntryType, id: string): VaultEntry {
  return {
    id,
    vaultId: 'vault-main',
    title: `Titel ${id}`,
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    attachments: [],
    data: emptyEntryData(type),
    lifecycle: createDefaultEntryLifecycleMetadata(),
    createdAt: CREATED_AT,
    updatedAt: UPDATED_AT,
    secretChangedAt: UPDATED_AT,
    lastUsedAt: null,
    deletedAt: null,
  };
}

function customField(id: string, label: string, value: string): CustomField {
  return {
    id,
    label,
    type: 'text',
    value,
    secret: false,
    searchable: true,
    order: 0,
  };
}
