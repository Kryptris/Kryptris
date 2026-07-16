import { describe, expect, it, vi } from 'vitest';

import type { EntryListQuery, VaultEntry } from '../../src/shared/models';
import { EntryViewService } from '../../src/main/services/entry-view-service';
import { credentialEntry } from './service-fixtures';

const query = (view: EntryListQuery['view']): EntryListQuery => ({
  vaultId: 'vault-1',
  search: '',
  view,
  types: [],
  tags: [],
  folderId: null,
  security: [],
});

describe('EntryViewService', () => {
  it('serialisiert boolesche Felder eindeutig und respektiert Reihenfolge sowie Maskierung', () => {
    const entry = credentialEntry({
      customFields: [
        {
          id: 'second',
          label: 'Geheim',
          type: 'text',
          value: 'verborgen',
          secret: true,
          searchable: false,
          order: 2,
        },
        {
          id: 'first',
          label: 'Aktiv',
          type: 'boolean',
          value: true,
          secret: false,
          searchable: true,
          order: 1,
        },
      ],
    });

    const fields = new EntryViewService().detail(entry).fields;
    const firstIndex = fields.findIndex((field) => field.path === 'custom.first');
    const secondIndex = fields.findIndex((field) => field.path === 'custom.second');
    expect(fields[firstIndex]).toMatchObject({ kind: 'boolean', value: 'true', secret: false });
    expect(fields[secondIndex]).toMatchObject({ secret: true });
    expect(fields[secondIndex]).not.toHaveProperty('value');
    expect(firstIndex).toBeLessThan(secondIndex);
  });

  it('kennzeichnet den Inhalt sicherer Notizen als Markdown', () => {
    const note: VaultEntry = {
      ...credentialEntry({ id: 'note-1' }),
      data: { type: 'secure-note', value: { markdown: '# Überschrift' } },
    };
    expect(new EntryViewService().detail(note).fields[0]).toMatchObject({
      path: 'data.markdown',
      kind: 'markdown',
      value: '# Überschrift',
    });
  });

  it('sortiert Zuletzt-verwendet nach Nutzung statt Bearbeitungsdatum', () => {
    const olderUse = {
      ...credentialEntry({ id: 'older', title: 'A', updatedAt: '2026-07-14T12:00:00.000Z' }),
      lastUsedAt: '2026-07-13T12:00:00.000Z',
    };
    const newerUse = {
      ...credentialEntry({ id: 'newer', title: 'Z', updatedAt: '2026-07-12T12:00:00.000Z' }),
      lastUsedAt: '2026-07-14T12:00:00.000Z',
    };
    expect(
      new EntryViewService().list([olderUse, newerUse], query('recent')).map(({ id }) => id),
    ).toEqual(['newer', 'older']);
  });

  it('berechnet den Sicherheitsstatus bei unveraenderten Eintraegen nur einmal', () => {
    const scan = vi.fn(() => ({ findings: [] }));
    const service = new EntryViewService({ scan } as never);
    const entries = [credentialEntry({ id: 'cached-entry' })];

    service.list(entries, query('all'));
    service.list(entries, { ...query('favorites'), search: 'cached' });

    expect(scan).toHaveBeenCalledTimes(1);
  });

  it('aktualisiert den Sicherheitsstatus nach einer Eintragsaenderung', () => {
    const scan = vi.fn(() => ({ findings: [] }));
    const service = new EntryViewService({ scan } as never);
    const entry = credentialEntry({ id: 'changed-entry' }) as VaultEntry;

    service.list([entry], query('all'));
    service.list([{ ...entry, updatedAt: '2026-07-16T12:00:00.000Z' }], query('all'));

    expect(scan).toHaveBeenCalledTimes(2);
  });
});
