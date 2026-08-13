import { describe, expect, it } from 'vitest';

import { ProductivityService } from '../../src/main/services/productivity-service';
import type { SavedViewFilters } from '../../src/shared/models';
import { credentialEntry, vaultDocument } from './service-fixtures';

const filters = (overrides: Partial<SavedViewFilters> = {}): SavedViewFilters => ({
  search: '',
  view: 'all',
  types: [],
  tags: [],
  folderId: null,
  security: [],
  smartView: null,
  ...overrides,
});

describe('ProductivityService', () => {
  it('verwaltet gespeicherte Ansichten in stabiler Reihenfolge und markiert veraltete Referenzen', () => {
    const service = new ProductivityService([], () => new Date('2026-07-21T12:00:00.000Z'));
    const document = vaultDocument([
      { ...credentialEntry({ id: 'one' }), folderId: 'folder-1', tags: ['Arbeit'] },
    ]);
    document.folders.push({
      id: 'folder-1',
      name: 'Arbeit',
      color: '#25d2c8',
      createdAt: '2026-07-21T12:00:00.000Z',
    });

    const first = service.saveSavedView({
      vaultId: document.id,
      name: ' Arbeit ',
      filters: filters({ folderId: 'folder-1', tags: ['arbeit'] }),
    });
    const second = service.saveSavedView({
      vaultId: document.id,
      name: 'Ohne Tags',
      filters: filters({ smartView: 'without-tags' }),
    });

    expect(service.listSavedViews(document.id, document)).toMatchObject([
      { id: first.id, name: 'Arbeit', order: 0, invalidReferences: { folder: false, tags: [] } },
      { id: second.id, order: 1 },
    ]);

    service.reorderSavedViews(document.id, [second.id, first.id]);
    document.folders = [];
    document.entries[0]!.tags = [];
    expect(service.listSavedViews(document.id, document)).toMatchObject([
      { id: second.id, order: 0 },
      {
        id: first.id,
        order: 1,
        invalidReferences: { folder: true, tags: ['arbeit'] },
      },
    ]);

    service.deleteSavedView(document.id, second.id);
    expect(service.snapshot()).toMatchObject([{ id: first.id, order: 0 }]);
  });

  it('normalisiert Tags zentral und kann sie umbenennen, zusammenführen und löschen', () => {
    const service = new ProductivityService([], () => new Date('2026-07-21T13:00:00.000Z'));
    const document = vaultDocument([
      { ...credentialEntry({ id: 'one' }), tags: [' Arbeit ', 'PRIVAT'] },
      { ...credentialEntry({ id: 'two' }), tags: ['Ａｒｂｅｉｔ', 'Privat'] },
    ]);

    expect(service.listTags(document)).toEqual([
      { name: 'Arbeit', normalizedName: 'arbeit', usageCount: 2 },
      { name: 'PRIVAT', normalizedName: 'privat', usageCount: 2 },
    ]);

    expect(service.renameTag(document, 'arbeit', ' Beruf ')).toEqual(['one', 'two']);
    expect(service.mergeTags(document, ['beruf'], 'Privat')).toEqual(['one', 'two']);
    expect(document.entries.map((entry) => entry.tags)).toEqual([['Privat'], ['Privat']]);
    expect(service.deleteTag(document, ' privat ')).toEqual(['one', 'two']);
    expect(document.entries.every((entry) => entry.tags.length === 0)).toBe(true);
  });

  it('validiert eine Batch-Auswahl vollständig, bevor der Tresor verändert wird', () => {
    const service = new ProductivityService();
    const document = vaultDocument([
      credentialEntry({ id: 'one' }),
      credentialEntry({ id: 'two' }),
    ]);
    const before = structuredClone(document);

    expect(() =>
      service.applyBatch(document, {
        vaultId: document.id,
        entryIds: ['one', 'missing'],
        action: { type: 'favorite', value: true },
      }),
    ).toThrow(/nicht gefunden/i);
    expect(document).toEqual(before);
  });

  it('ändert ausschließlich ausgewählte Einträge und liefert exakt die betroffenen IDs', () => {
    const service = new ProductivityService([], () => new Date('2026-07-21T14:00:00.000Z'));
    const document = vaultDocument([
      credentialEntry({ id: 'one' }),
      credentialEntry({ id: 'two' }),
      credentialEntry({ id: 'three' }),
    ]);

    const result = service.applyBatch(document, {
      vaultId: document.id,
      entryIds: ['one', 'three'],
      action: { type: 'tags-add', tags: [' Neu ', 'Ｎｅｕ'] },
    });

    expect(result).toEqual({
      affected: 2,
      entryIds: ['one', 'three'],
      purgedAttachmentIds: [],
    });
    expect(document.entries.map((entry) => entry.tags)).toEqual([['Neu'], [], ['Neu']]);
  });

  it('delegiert Cross-Vault-Aktionen und liefert Attachment-IDs für den atomaren Purge', () => {
    const service = new ProductivityService();
    const document = vaultDocument([
      credentialEntry({
        id: 'deleted',
        deletedAt: '2026-07-20T12:00:00.000Z',
        attachments: [
          {
            id: 'attachment-1',
            name: 'beleg.pdf',
            mediaType: 'application/pdf',
            size: 42,
            sha256: 'a'.repeat(64),
            createdAt: '2026-07-20T12:00:00.000Z',
            previewable: true,
          },
        ],
      }),
    ]);

    expect(() =>
      service.applyBatch(document, {
        vaultId: document.id,
        entryIds: ['deleted'],
        action: { type: 'copy-to-vault', targetVaultId: 'vault-2' },
      }),
    ).toThrow(/Transfer-Service/i);
    expect(
      service.applyBatch(document, {
        vaultId: document.id,
        entryIds: ['deleted'],
        action: { type: 'purge', masterPassword: 'korrekt', confirmationCount: 1 },
      }),
    ).toEqual({ affected: 1, entryIds: ['deleted'], purgedAttachmentIds: ['attachment-1'] });
    expect(document.entries).toHaveLength(0);
  });
});
