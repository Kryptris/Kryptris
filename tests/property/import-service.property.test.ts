import fc from 'fast-check';
import Papa from 'papaparse';
import { describe, expect, it } from 'vitest';

import { ImportService } from '../../src/main/services/import-service';
import type { ImportFormat } from '../../src/shared/models';
import { entryInputSchema } from '../../src/shared/schemas';

interface CsvValues {
  title: string;
  username: string;
  password: string;
  website: string;
  note: string;
  folder: string;
  tags: string[];
}

interface CsvVendorCase {
  format: ImportFormat;
  sourceName: string;
  record(values: CsvValues): Record<string, string>;
  title(values: CsvValues): string;
  note(values: CsvValues): string;
  folder(values: CsvValues): string;
  tags(values: CsvValues): string[];
}

const richCharacter = fc.constantFrom(
  ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 äöüÄÖÜß,;"\n-_.:@/',
);
const richText = fc.string({ unit: richCharacter, maxLength: 100 });
const requiredRichText = fc
  .string({ unit: richCharacter, minLength: 1, maxLength: 80 })
  .filter((value) => value.trim().length > 0);
const tag = fc.string({
  unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-_'),
  minLength: 1,
  maxLength: 20,
});
const csvValues = fc.record({
  title: requiredRichText,
  username: requiredRichText,
  password: requiredRichText,
  website: fc
    .string({
      unit: fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-_'),
      minLength: 1,
      maxLength: 50,
    })
    .map((segment) => `https://example.test/${segment}`),
  note: richText,
  folder: requiredRichText,
  tags: fc.uniqueArray(tag, { maxLength: 8 }),
});

const normalTitle = (values: CsvValues): string => values.title.trim();
const normalNote = (values: CsvValues): string => values.note;
const normalFolder = (values: CsvValues): string => values.folder.trim();
const noFolder = (): string => '';
const normalTags = (values: CsvValues): string[] => values.tags;
const noTags = (): string[] => [];

const csvVendors: CsvVendorCase[] = [
  {
    format: 'onepassword-csv',
    sourceName: '1password.csv',
    record: (value) => ({
      Title: value.title,
      Url: value.website,
      Username: value.username,
      Password: value.password,
      OTPAuth: '',
      Favorite: 'false',
      Archived: 'false',
      Tags: value.tags.join(','),
      Notes: value.note,
    }),
    title: normalTitle,
    note: normalNote,
    folder: noFolder,
    tags: normalTags,
  },
  {
    format: 'lastpass-csv',
    sourceName: 'lastpass.csv',
    record: (value) => ({
      url: value.website,
      username: value.username,
      password: value.password,
      extra: value.note,
      name: value.title,
      grouping: value.folder,
      fav: '0',
    }),
    title: normalTitle,
    note: normalNote,
    folder: normalFolder,
    tags: noTags,
  },
  {
    format: 'keepass-csv',
    sourceName: 'keepass.csv',
    record: (value) => ({
      Group: value.folder,
      Title: value.title,
      Username: value.username,
      Password: value.password,
      URL: value.website,
      Notes: value.note,
    }),
    title: normalTitle,
    note: normalNote,
    folder: normalFolder,
    tags: noTags,
  },
  {
    format: 'chrome-csv',
    sourceName: 'chrome.csv',
    record: (value) => ({
      name: value.title,
      url: value.website,
      username: value.username,
      password: value.password,
      note: value.note,
    }),
    title: normalTitle,
    note: normalNote,
    folder: noFolder,
    tags: noTags,
  },
  {
    format: 'edge-csv',
    sourceName: 'edge.csv',
    record: (value) => ({
      name: value.title,
      url: value.website,
      username: value.username,
      password: value.password,
    }),
    title: normalTitle,
    note: () => '',
    folder: noFolder,
    tags: noTags,
  },
  {
    format: 'firefox-csv',
    sourceName: 'firefox.csv',
    record: (value) => ({
      url: value.website,
      username: value.username,
      password: value.password,
      httpRealm: '',
      formActionOrigin: value.website,
      guid: '00000000-0000-4000-8000-000000000001',
      timeCreated: '1710000000000',
      timeLastUsed: '1710000001000',
      timePasswordChanged: '1710000002000',
    }),
    title: () => 'Importierter Eintrag 1',
    note: () => '',
    folder: noFolder,
    tags: noTags,
  },
];

describe('Property-basierte Hersteller-Importer', () => {
  it('erhält CSV-Werte auch mit Trennzeichen, Anführungszeichen und Zeilenumbrüchen', () => {
    fc.assert(
      fc.property(fc.constantFrom(...csvVendors), csvValues, (vendor, values) => {
        const service = new ImportService();
        const preview = service.preview({
          format: vendor.format,
          sourceName: vendor.sourceName,
          content: Papa.unparse([vendor.record(values)]),
        });
        const imported = service.materialize(preview.token, [0]);
        const entry = imported[0]?.entry;

        expect(preview.errors).toEqual([]);
        expect(imported).toHaveLength(1);
        expect(entryInputSchema.safeParse(entry).success).toBe(true);
        expect(entry).toMatchObject({
          title: vendor.title(values),
          note: vendor.note(values),
          tags: vendor.tags(values),
        });
        expect(imported[0]?.folderName).toBe(vendor.folder(values));
        expect(entry?.data).toEqual({
          type: 'credential',
          value: {
            username: values.username.trim(),
            password: values.password,
            websites: [values.website],
            appNames: [],
          },
        });
      }),
      { numRuns: 250 },
    );
  });

  it('erhält Bitwarden-Felder und ihre Schutzsemantik für beliebige Inhalte', () => {
    fc.assert(
      fc.property(csvValues, richText, richText, fc.boolean(), (values, text, secret, flag) => {
        const service = new ImportService();
        const preview = service.preview({
          format: 'bitwarden-json',
          sourceName: 'bitwarden.json',
          content: JSON.stringify({
            encrypted: false,
            folders: [{ id: 'folder-1', name: values.folder }],
            items: [
              {
                type: 1,
                name: values.title,
                folderId: 'folder-1',
                notes: values.note,
                favorite: flag,
                fields: [
                  { name: 'Text', value: text, type: 0 },
                  { name: 'Geheimnis', value: secret, type: 1 },
                  { name: 'Schalter', value: String(flag), type: 2 },
                ],
                login: {
                  username: values.username,
                  password: values.password,
                  uris: [{ uri: values.website }],
                },
              },
            ],
          }),
        });
        const imported = service.materialize(preview.token, [0])[0]!;

        expect(preview.errors).toEqual([]);
        expect(imported.folderName).toBe(values.folder);
        expect(entryInputSchema.safeParse(imported.entry).success).toBe(true);
        expect(imported.entry.favorite).toBe(flag);
        expect(imported.entry.customFields).toEqual([
          expect.objectContaining({
            label: 'Text',
            value: text,
            type: 'text',
            secret: false,
            searchable: true,
            order: 0,
          }),
          expect.objectContaining({
            label: 'Geheimnis',
            value: secret,
            type: 'secret',
            secret: true,
            searchable: false,
            order: 1,
          }),
          expect.objectContaining({
            label: 'Schalter',
            value: flag,
            type: 'boolean',
            secret: false,
            searchable: true,
            order: 2,
          }),
        ]);
      }),
      { numRuns: 150 },
    );
  });

  it('erhält Proton-Pass-Zusatzfelder und Tresorzuordnung für beliebige Inhalte', () => {
    fc.assert(
      fc.property(csvValues, richText, richText, (values, text, secret) => {
        const service = new ImportService();
        const preview = service.preview({
          format: 'protonpass-json',
          sourceName: 'proton-pass.json',
          content: JSON.stringify({
            version: '1.0.0',
            vaults: {
              work: {
                name: values.folder,
                items: [
                  {
                    data: {
                      metadata: { name: values.title, note: values.note },
                      content: {
                        itemType: 'login',
                        itemUsername: values.username,
                        itemPassword: values.password,
                        urls: [values.website],
                      },
                      extraFields: [
                        { fieldName: 'Text', type: 'text', data: text },
                        { fieldName: 'Geheimnis', type: 'hidden', data: secret },
                      ],
                    },
                  },
                ],
              },
            },
          }),
        });
        const imported = service.materialize(preview.token, [0])[0]!;

        expect(preview.errors).toEqual([]);
        expect(imported.folderName).toBe(values.folder);
        expect(entryInputSchema.safeParse(imported.entry).success).toBe(true);
        expect(imported.entry.customFields).toEqual([
          expect.objectContaining({
            label: 'Text',
            value: text,
            type: 'text',
            secret: false,
            searchable: true,
            order: 0,
          }),
          expect.objectContaining({
            label: 'Geheimnis',
            value: secret,
            type: 'secret',
            secret: true,
            searchable: false,
            order: 1,
          }),
        ]);
      }),
      { numRuns: 150 },
    );
  });
});
