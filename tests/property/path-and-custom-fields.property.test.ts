import path from 'node:path';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { TemplateService } from '../../src/main/services/template-service';
import {
  assertSafeIdentifier,
  normalizeBackupPath,
  resolveInside,
} from '../../src/main/storage/path-safety';
import { DEFAULT_SETTINGS, ENTRY_TYPES, type CustomFieldType } from '../../src/shared/models';
import { entryInputSchema, vaultaSettingsSchema } from '../../src/shared/schemas';

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const identifierCharacter = fc.constantFrom(
  ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-',
);
const pathCharacter = fc.constantFrom(
  ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-',
);
const labelCharacter = fc.constantFrom(
  ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 äöüÄÖÜß._-',
);
const safeIdentifier = fc
  .tuple(
    fc.constantFrom(...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
    fc.string({ unit: identifierCharacter, maxLength: 127 }),
  )
  .map(([first, rest]) => `${first}${rest}`);
const backupSegment = fc
  .string({ unit: pathCharacter, minLength: 1, maxLength: 40 })
  .filter((segment) => segment !== '.' && segment !== '..');
const label = fc
  .string({ unit: labelCharacter, minLength: 1, maxLength: 60 })
  .filter((value) => value.trim().length > 0);
const stringDefault = fc.string({ maxLength: 200 });
const templateField = fc.oneof(
  fc.record({
    label,
    type: fc.constantFrom<CustomFieldType>('text', 'secret', 'url', 'date'),
    secret: fc.boolean(),
    defaultValue: stringDefault,
  }),
  fc.record({
    label,
    type: fc.constant<CustomFieldType>('number'),
    secret: fc.boolean(),
    defaultValue: fc.double({ min: -1_000_000, max: 1_000_000, noNaN: true }),
  }),
  fc.record({
    label,
    type: fc.constant<CustomFieldType>('boolean'),
    secret: fc.boolean(),
    defaultValue: fc.boolean(),
  }),
);

describe('Property-basierte Pfadregeln', () => {
  it('akzeptiert genau die definierte Identifier-Sprache', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 160 }), (candidate) => {
        if (identifierPattern.test(candidate)) {
          expect(() => assertSafeIdentifier(candidate)).not.toThrow();
        } else {
          expect(() => assertSafeIdentifier(candidate)).toThrowError(
            expect.objectContaining({ code: 'UNSAFE_PATH' }),
          );
        }
      }),
    );
    fc.assert(
      fc.property(safeIdentifier, (candidate) => {
        expect(() => assertSafeIdentifier(candidate)).not.toThrow();
      }),
    );
  });

  it('normalisiert valide relative Backup-Pfade ohne Bedeutungsänderung', () => {
    fc.assert(
      fc.property(fc.array(backupSegment, { minLength: 1, maxLength: 8 }), (segments) => {
        const backupPath = segments.join('/');
        expect(normalizeBackupPath(backupPath)).toBe(backupPath);
      }),
    );
  });

  it('weist Traversal und nicht-kanonische Backup-Pfade für jede Segmentfolge zurück', () => {
    fc.assert(
      fc.property(
        fc.array(backupSegment, { minLength: 1, maxLength: 6 }),
        fc.constantFrom(
          (value: string) => `../${value}`,
          (value: string) => `${value}/../secret`,
          (value: string) => `${value}/./file`,
          (value: string) => `${value}//file`,
          (value: string) => `/${value}`,
          (value: string) => `${value}\\file`,
        ),
        (segments, makeUnsafe) => {
          const unsafePath = makeUnsafe(segments.join('/'));
          expect(() => normalizeBackupPath(unsafePath)).toThrowError(
            expect.objectContaining({ code: 'CORRUPT_DATA' }),
          );
        },
      ),
    );
  });

  it('löst valide Segmente stets innerhalb des Datenordners auf und blockiert Traversal', () => {
    const root = path.resolve('C:\\vaulta-property-root');
    fc.assert(
      fc.property(fc.array(safeIdentifier, { minLength: 1, maxLength: 8 }), (segments) => {
        const resolved = resolveInside(root, ...segments);
        const relative = path.relative(root, resolved);
        expect(path.isAbsolute(relative)).toBe(false);
        expect(relative).not.toBe('..');
        expect(relative.startsWith(`..${path.sep}`)).toBe(false);
        expect(() => resolveInside(root, '..', 'outside')).toThrowError(
          expect.objectContaining({ code: 'UNSAFE_PATH' }),
        );
      }),
    );
  });

  it('akzeptiert für automatische Backups nur lokale absolute Windows-Pfade', () => {
    for (const backupFolder of [
      'Vaulta-Backups',
      '.\\Vaulta-Backups',
      '..\\Vaulta-Backups',
      '\\\\server\\freigabe',
      '\\\\?\\UNC\\server\\freigabe',
      'file://server/freigabe',
      '/mnt/network/vaulta',
    ]) {
      expect(
        vaultaSettingsSchema.safeParse({ ...DEFAULT_SETTINGS, backupFolder }).success,
        backupFolder,
      ).toBe(false);
    }
    expect(
      vaultaSettingsSchema.safeParse({
        ...DEFAULT_SETTINGS,
        backupFolder: 'C:\\Users\\Lauri\\Vaulta-Backups',
      }).success,
    ).toBe(true);
    expect(
      vaultaSettingsSchema.safeParse({ ...DEFAULT_SETTINGS, backupFolder: null }).success,
    ).toBe(true);
  });
});

describe('Property-basierte eigene Felder und Vorlagen', () => {
  it('erzeugt aus jeder gültigen Vorlage schema-konforme, geordnete eigene Felder', () => {
    fc.assert(
      fc.property(
        label,
        fc.constantFrom(...ENTRY_TYPES),
        fc.uniqueArray(templateField, {
          maxLength: 30,
          selector: (field) => field.label.trim().toLocaleLowerCase('de'),
        }),
        (name, entryType, fields) => {
          const service = new TemplateService();
          const saved = service.save({ name: ` ${name} `, entryType, fields });
          const applied = service.apply(saved.id);

          expect(entryInputSchema.safeParse(applied).success).toBe(true);
          expect(saved.name).toBe(name.trim());
          expect(applied.data.type).toBe(entryType);
          expect(applied.customFields).toHaveLength(fields.length);
          expect(new Set(applied.customFields.map((field) => field.id)).size).toBe(fields.length);
          expect(applied.customFields.map((field) => field.order)).toEqual(
            fields.map((_, index) => index),
          );

          applied.customFields.forEach((field, index) => {
            const source = fields[index]!;
            const secret = source.secret || source.type === 'secret';
            expect(field).toMatchObject({
              label: source.label.trim(),
              type: source.type,
              value: source.defaultValue,
              secret,
              searchable: !secret,
            });
          });
        },
      ),
    );
  });

  it('hält angewendete Vorlagen und Snapshots unabhängig vom internen Zustand', () => {
    fc.assert(
      fc.property(
        label,
        fc.uniqueArray(templateField, {
          maxLength: 15,
          selector: (field) => field.label.trim().toLocaleLowerCase('de'),
        }),
        (name, fields) => {
          const service = new TemplateService();
          const saved = service.save({ name, entryType: 'custom', fields });
          const first = service.apply(saved.id);
          const snapshot = service.snapshot();

          first.title = 'Extern verändert';
          first.customFields.splice(0);
          snapshot[0]!.name = 'Extern verändert';
          snapshot[0]!.fields.splice(0);

          const second = service.apply(saved.id);
          expect(second.title).toBe(name.trim());
          expect(second.customFields).toHaveLength(fields.length);
          expect(service.list()[0]?.name).toBe(name.trim());
          expect(service.list()[0]?.fields).toHaveLength(fields.length);
        },
      ),
    );
  });

  it('weist Feldnamen unabhängig von Groß-/Kleinschreibung als Dublette zurück', () => {
    fc.assert(
      fc.property(
        fc.string({
          unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'),
          minLength: 1,
          maxLength: 40,
        }),
        (fieldName) => {
          const service = new TemplateService();
          expect(() =>
            service.save({
              name: 'Dublettentest',
              entryType: 'custom',
              fields: [
                { label: fieldName, type: 'text', secret: false, defaultValue: '' },
                {
                  label: fieldName.toUpperCase(),
                  type: 'secret',
                  secret: true,
                  defaultValue: '',
                },
              ],
            }),
          ).toThrow(/eindeutig/u);
        },
      ),
    );
  });
});
