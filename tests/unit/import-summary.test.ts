import { describe, expect, it } from 'vitest';

import { summarizeImportPreview } from '../../src/main/services/import-summary';

describe('summarizeImportPreview', () => {
  it('liefert ausschliesslich redigierte Zaehler fuer Auswahl, Dubletten und Fehler', () => {
    const sourceOnlyCanary = 'CANARY_IMPORTED_VALUE_MUST_NOT_BE_SUMMARIZED';
    const preview = {
      candidates: [
        {
          sourceIndex: 0,
          title: sourceOnlyCanary,
          username: 'anonymous-user',
          website: 'https://example.test',
          type: 'credential' as const,
          duplicateOf: null,
          warnings: ['Passwort fehlt.'],
          selected: true,
        },
        {
          sourceIndex: 1,
          title: 'Doppelter Eintrag',
          username: 'anonymous-user',
          website: 'https://example.test',
          type: 'credential' as const,
          duplicateOf: 'import:0',
          warnings: ['Moegliche Dublette erkannt.', 'Benutzername fehlt.'],
          selected: false,
        },
      ],
      errors: [{ row: 3, message: 'Dieser Datensatz konnte nicht gelesen werden.' }],
    };

    expect(summarizeImportPreview(preview)).toEqual({
      newEntries: 1,
      skippedEntries: 1,
      duplicates: 1,
      warnings: 3,
      invalidRows: 1,
    });
    expect(summarizeImportPreview(preview, [1])).toMatchObject({
      newEntries: 1,
      skippedEntries: 1,
      duplicates: 1,
    });
    expect(JSON.stringify(summarizeImportPreview(preview))).not.toContain(sourceOnlyCanary);
  });
});
