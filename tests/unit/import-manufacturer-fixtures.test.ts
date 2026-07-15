import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ImportService } from '../../src/main/services/import-service';
import type { ImportFormat } from '../../src/shared/models';

interface FixtureExpectation {
  format: ImportFormat;
  file: string;
  title: string;
  username: string;
  password: string;
  website: string;
  folderName: string;
  note: string;
  detectedAs?: ImportFormat;
}

const fixtures: FixtureExpectation[] = [
  {
    format: 'onepassword-csv',
    file: '1password.csv',
    title: '1Password Portal',
    username: 'op-user',
    password: 'op-secret',
    website: 'https://onepassword.example',
    folderName: '',
    note: 'Aus 1Password exportiert',
    detectedAs: 'onepassword-csv',
  },
  {
    format: 'lastpass-csv',
    file: 'lastpass.csv',
    title: 'LastPass Portal',
    username: 'lp-user',
    password: 'lp-secret',
    website: 'https://lastpass.example',
    folderName: 'Arbeit',
    note: 'Notiz, mit Komma',
    detectedAs: 'lastpass-csv',
  },
  {
    format: 'keepass-csv',
    file: 'keepass.csv',
    title: 'KeePass Portal',
    username: 'kp-user',
    password: 'kp-secret',
    website: 'https://keepass.example',
    folderName: 'Privat',
    note: 'Aus KeePass exportiert',
    detectedAs: 'keepass-csv',
  },
  {
    format: 'chrome-csv',
    file: 'chrome.csv',
    title: 'Chrome Portal',
    username: 'chrome-user',
    password: 'chrome-secret',
    website: 'https://chrome.example',
    folderName: '',
    note: 'Aus Chrome exportiert',
    detectedAs: 'chrome-csv',
  },
  {
    format: 'edge-csv',
    file: 'edge.csv',
    title: 'Edge Portal',
    username: 'edge-user',
    password: 'edge-secret',
    website: 'https://edge.example',
    folderName: '',
    note: '',
  },
  {
    format: 'firefox-csv',
    file: 'firefox.csv',
    title: 'Importierter Eintrag 1',
    username: 'firefox-user',
    password: 'firefox-secret',
    website: 'https://firefox.example',
    folderName: '',
    note: '',
    detectedAs: 'firefox-csv',
  },
  {
    format: 'bitwarden-json',
    file: 'bitwarden.json',
    title: 'Bitwarden Portal',
    username: 'bw-user',
    password: 'bw-secret',
    website: 'https://bitwarden.example',
    folderName: 'Arbeit',
    note: 'Aus Bitwarden exportiert',
    detectedAs: 'bitwarden-json',
  },
  {
    format: 'protonpass-json',
    file: 'proton-pass.json',
    title: 'Proton Portal',
    username: 'proton-user',
    password: 'proton-secret',
    website: 'https://proton.example',
    folderName: 'Arbeit',
    note: 'Aus Proton Pass exportiert',
    detectedAs: 'protonpass-json',
  },
];

function fixture(file: string): string {
  return readFileSync(path.join(process.cwd(), 'tests', 'fixtures', 'import', file), 'utf8');
}

describe('Repräsentative Hersteller-Import-Fixtures', () => {
  it.each(fixtures)('liest $format mit den nativen Exportspalten', (expected) => {
    const service = new ImportService();
    const content = fixture(expected.file);
    const preview = service.preview({
      format: expected.format,
      content,
      sourceName: expected.file,
    });
    const result = service.materialize(preview.token, [0]);

    expect(preview.errors).toEqual([]);
    expect(preview.candidates).toHaveLength(1);
    expect(result).toHaveLength(1);
    expect(result[0]?.folderName).toBe(expected.folderName);
    expect(result[0]?.entry).toMatchObject({ title: expected.title, note: expected.note });
    const data = result[0]?.entry.data;
    expect(data?.type).toBe('credential');
    if (data?.type !== 'credential') throw new Error('Zugangsdaten erwartet.');
    expect(data.value).toMatchObject({
      username: expected.username,
      password: expected.password,
      websites: [expected.website],
    });
    if (expected.detectedAs !== undefined) {
      expect(service.detectFormat(expected.file, content)).toBe(expected.detectedAs);
    }
  });

  it('übernimmt herstellerspezifische Zusatzfelder und Flags', () => {
    const service = new ImportService();
    const bitwarden = service.preview({
      format: 'bitwarden-json',
      content: fixture('bitwarden.json'),
      sourceName: 'bitwarden.json',
    });
    const bitwardenEntry = service.materialize(bitwarden.token, [0])[0]?.entry;
    expect(bitwardenEntry).toMatchObject({ favorite: true });
    expect(bitwardenEntry?.customFields).toEqual([
      expect.objectContaining({
        label: 'Kundennummer',
        type: 'text',
        value: '4711',
        secret: false,
        searchable: true,
        order: 0,
      }),
      expect.objectContaining({
        label: 'Support-PIN',
        type: 'secret',
        value: '0815',
        secret: true,
        searchable: false,
        order: 1,
      }),
    ]);

    const proton = service.preview({
      format: 'protonpass-json',
      content: fixture('proton-pass.json'),
      sourceName: 'proton-pass.json',
    });
    const protonEntry = service.materialize(proton.token, [0])[0]?.entry;
    expect(protonEntry?.customFields).toEqual([
      expect.objectContaining({
        label: 'Mandant',
        type: 'text',
        value: 'Nord',
        secret: false,
        searchable: true,
        order: 0,
      }),
      expect.objectContaining({
        label: 'Support-PIN',
        type: 'secret',
        value: '1234',
        secret: true,
        searchable: false,
        order: 1,
      }),
    ]);
  });
});
