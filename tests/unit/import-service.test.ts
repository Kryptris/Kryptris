import { describe, expect, it } from 'vitest';

import { ImportService } from '../../src/main/services/import-service';
import { credentialEntry } from './service-fixtures';

describe('ImportService', () => {
  it('unterstützt generisches CSV mit expliziter Feldzuordnung', () => {
    const service = new ImportService();
    const preview = service.preview({
      format: 'generic-csv',
      sourceName: 'eigene-spalten.csv',
      content: [
        'Bezeichnung,Zugang,Geheimnis,Ziel,Kommentar,Ablage,Schlagworte',
        'Portal,lauri,secret123,https://example.de,Lokale Notiz,Arbeit,"wichtig,intern"',
      ].join('\n'),
      mapping: {
        title: 'Bezeichnung',
        username: 'Zugang',
        password: 'Geheimnis',
        url: 'Ziel',
        note: 'Kommentar',
        folder: 'Ablage',
        tags: 'Schlagworte',
      },
    });
    const result = service.materialize(preview.token, [0]);

    expect(preview.errors).toEqual([]);
    expect(result[0]?.folderName).toBe('Arbeit');
    expect(result[0]?.entry).toMatchObject({
      title: 'Portal',
      note: 'Lokale Notiz',
      tags: ['wichtig', 'intern'],
      data: {
        type: 'credential',
        value: {
          username: 'lauri',
          password: 'secret123',
          websites: ['https://example.de'],
        },
      },
    });
  });

  it('importiert Bitwarden-Typen und erkennt vorhandene Dubletten', () => {
    const service = new ImportService();
    const content = JSON.stringify({
      encrypted: false,
      folders: [{ id: 'folder-1', name: 'Privat' }],
      items: [
        {
          type: 1,
          name: 'Beispiel',
          folderId: 'folder-1',
          login: {
            username: 'user@example.de',
            password: 'secret123',
            uris: [{ uri: 'https://example.de' }],
          },
        },
        { type: 2, name: 'Notiz', notes: '# Lokal' },
      ],
    });
    const preview = service.preview({
      format: 'bitwarden-json',
      content,
      sourceName: 'C:\\Users\\person\\Desktop\\bitwarden.json',
      existingEntries: [credentialEntry()],
    });

    expect(preview.sourceName).toBe('bitwarden.json');
    expect(preview.candidates.map((item) => item.type)).toEqual(['credential', 'secure-note']);
    expect(preview.candidates[0]?.duplicateOf).toBe('entry-1');
    expect(preview.candidates[0]?.selected).toBe(false);
    expect(JSON.stringify(preview)).not.toContain('Users');
  });

  it('importiert Proton Pass und behaelt den Tresornamen als Ordnerhinweis', () => {
    const service = new ImportService();
    const preview = service.preview({
      format: 'protonpass-json',
      sourceName: '/home/person/proton.json',
      content: JSON.stringify({
        vaults: {
          a: {
            name: 'Arbeit',
            items: [
              {
                data: {
                  metadata: { name: 'Proton Portal', note: 'lokal' },
                  content: {
                    itemType: 'login',
                    itemUsername: 'user',
                    itemPassword: 'secret',
                    urls: ['https://proton.example'],
                  },
                },
              },
            ],
          },
        },
      }),
    });
    const result = service.materialize(preview.token, [0]);
    expect(result[0]?.folderName).toBe('Arbeit');
    expect(result[0]?.entry.title).toBe('Proton Portal');
    expect(preview.sourceName).toBe('proton.json');
  });

  it('unterstuetzt generisches JSON mit expliziter Feldzuordnung', () => {
    const service = new ImportService();
    const preview = service.preview({
      format: 'generic-json',
      sourceName: 'generic.json',
      content: JSON.stringify([{ bez: 'Portal', konto: 'lauri', geheim: 'pw' }]),
      mapping: {
        title: 'bez',
        username: 'konto',
        password: 'geheim',
        url: '',
        note: '',
        folder: '',
        tags: '',
      },
    });
    expect(service.materialize(preview.token, [0])[0]?.entry.data).toMatchObject({
      type: 'credential',
      value: { username: 'lauri', password: 'pw' },
    });
  });
});
