import { describe, expect, it } from 'vitest';

import { IPC_CHANNELS } from '../../src/shared/ipc';
import {
  entryListQuerySchema,
  IPC_REQUEST_SCHEMAS,
  savedViewRecordSchema,
} from '../../src/shared/schemas';

const vaultId = '00000000-0000-4000-8000-000000000001';
const entryId = '00000000-0000-4000-8000-000000000002';

describe('Productivity-Schemas', () => {
  it('normalisiert und dedupliziert Tags in Listenabfragen', () => {
    expect(
      entryListQuerySchema.parse({
        vaultId,
        search: '',
        view: 'all',
        types: [],
        tags: [' Arbeit ', 'Ａｒｂｅｉｔ', 'PRIVAT'],
        folderId: null,
        security: [],
        smartView: 'without-folder',
      }),
    ).toMatchObject({ tags: ['Arbeit', 'PRIVAT'], smartView: 'without-folder' });
  });

  it('weist leere oder doppelte Batch-Auswahlen an der IPC-Grenze ab', () => {
    const schema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.productivityBatch]!;
    const base = { vaultId, action: { type: 'favorite', value: true } };

    expect(schema.safeParse({ ...base, entryIds: [] }).success).toBe(false);
    expect(schema.safeParse({ ...base, entryIds: [entryId, entryId] }).success).toBe(false);
    expect(schema.safeParse({ ...base, entryIds: [entryId] }).success).toBe(true);
  });

  it('validiert gespeicherte Ansichten einschließlich Zeitstempeln und Smart View', () => {
    const record = {
      id: entryId,
      vaultId,
      name: 'Meine Ansicht',
      filters: {
        search: '',
        view: 'all',
        types: [],
        tags: [],
        folderId: null,
        security: [],
        smartView: 'rotation-due',
      },
      order: 0,
      createdAt: '2026-07-21T12:00:00.000Z',
      updatedAt: '2026-07-21T12:00:00.000Z',
    };

    expect(savedViewRecordSchema.safeParse(record).success).toBe(true);
    expect(savedViewRecordSchema.safeParse({ ...record, updatedAt: 'gestern' }).success).toBe(
      false,
    );
  });

  it('weist leere Tagnamen nach NFKC- und Whitespace-Normalisierung ab', () => {
    const schema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.productivityTagRename]!;
    expect(schema.safeParse({ vaultId, tag: 'Arbeit', name: '　 ' }).success).toBe(false);
    expect(schema.safeParse({ vaultId, tag: 'Arbeit', name: ' Beruf ' }).success).toBe(true);
  });
});
