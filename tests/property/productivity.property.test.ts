import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { ProductivityService } from '../../src/main/services/productivity-service';
import { normalizeTagKey, normalizeTags } from '../../src/shared/tags';
import { credentialEntry, vaultDocument } from '../unit/service-fixtures';

const tagText = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZäöüÄÖÜß 　-＿'),
  maxLength: 40,
});

describe('Property-basierte Produktivitätsfunktionen', () => {
  it('normalisiert Tags idempotent und entfernt kanonische Duplikate', () => {
    fc.assert(
      fc.property(fc.array(tagText, { maxLength: 30 }), (values) => {
        const normalized = normalizeTags(values);
        const keys = normalized.map(normalizeTagKey);

        expect(normalizeTags(normalized)).toEqual(normalized);
        expect(new Set(keys).size).toBe(keys.length);
        expect(normalized.every((tag) => tag === tag.normalize('NFKC').trim())).toBe(true);
        expect(normalized.every((tag) => !/\s{2,}/u.test(tag))).toBe(true);
      }),
      { numRuns: 300 },
    );
  });

  it('fasst Whitespace-, NFKC- und Groß-/Kleinschreibungsvarianten zu einem Tag zusammen', () => {
    fc.assert(
      fc.property(
        fc.string({
          unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzäöü'),
          minLength: 1,
          maxLength: 24,
        }),
        (value) => {
          const fullWidth = value.replace(/[a-z]/gu, (character) =>
            String.fromCodePoint(character.codePointAt(0)! + 0xfee0),
          );
          expect(
            normalizeTags([`  ${value}  `, value.toLocaleUpperCase('de'), fullWidth]),
          ).toHaveLength(1);
        },
      ),
      { numRuns: 200 },
    );
    expect(normalizeTags(['Straße', ' STRASSE '])).toEqual(['Straße']);
  });

  it('verändert bei Batch-Aktionen nie Einträge außerhalb der Auswahl', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.integer({ min: 0, max: 15 }), { minLength: 1, maxLength: 16 }),
        (selectedIndexes) => {
          const service = new ProductivityService();
          const document = vaultDocument(
            Array.from({ length: 16 }, (_, index) =>
              credentialEntry({ id: `entry-${String(index)}` }),
            ),
          );
          const selected = new Set(selectedIndexes.map((index) => `entry-${String(index)}`));

          service.applyBatch(document, {
            vaultId: document.id,
            entryIds: [...selected],
            action: { type: 'favorite', value: true },
          });

          for (const entry of document.entries) {
            expect(entry.favorite).toBe(selected.has(entry.id));
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it('führt beliebige Tagmengen ohne Duplikate und ohne verbleibenden Quell-Tag zusammen', () => {
    const simpleTag = fc.string({
      unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzäöü'),
      minLength: 1,
      maxLength: 16,
    });
    fc.assert(
      fc.property(
        fc.uniqueArray(simpleTag, { minLength: 2, maxLength: 8, selector: normalizeTagKey }),
        fc.array(fc.array(fc.nat(20), { maxLength: 8 }), { minLength: 1, maxLength: 12 }),
        (tagNames, assignments) => {
          const source = tagNames[0]!;
          const target = tagNames[1]!;
          const entries = assignments.map((indices, entryIndex) => ({
            ...credentialEntry({ id: `entry-${String(entryIndex)}` }),
            tags: normalizeTags(indices.map((index) => tagNames[index % tagNames.length]!)),
          }));
          if (
            !entries.some((entry) =>
              entry.tags.some((tag) => normalizeTagKey(tag) === normalizeTagKey(source)),
            )
          ) {
            entries[0]!.tags.push(source);
          }
          const document = vaultDocument(entries);
          const affectedBefore = new Set(
            entries
              .filter((entry) =>
                entry.tags.some((tag) => normalizeTagKey(tag) === normalizeTagKey(source)),
              )
              .map((entry) => entry.id),
          );

          new ProductivityService().mergeTags(
            document,
            [` ${source.toLocaleUpperCase('de')} `],
            target,
          );

          for (const entry of document.entries) {
            const keys = entry.tags.map(normalizeTagKey);
            expect(keys).not.toContain(normalizeTagKey(source));
            expect(new Set(keys).size).toBe(keys.length);
            if (affectedBefore.has(entry.id)) expect(keys).toContain(normalizeTagKey(target));
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
