import { describe, expect, it } from 'vitest';

import { ImportMappingProfileService } from '../../src/main/services/import-mapping-profile-service';
import type { ImportMapping } from '../../src/shared/models';

const FIRST_ID = '00000000-0000-4000-8000-000000000101';
const SECOND_ID = '00000000-0000-4000-8000-000000000102';

const mapping: ImportMapping = {
  title: 'Titel',
  username: 'Benutzer',
  password: 'Passwort',
  url: 'Adresse',
  note: 'Notiz',
  folder: 'Ordner',
  tags: 'Tags',
};

describe('ImportMappingProfileService', () => {
  it('serialisiert nur Namen und Spaltenzuordnungen, niemals Importwerte', () => {
    const service = new ImportMappingProfileService({
      createId: () => FIRST_ID,
      now: () => new Date('2026-07-27T10:00:00.000Z'),
    });
    const sourceOnlyCanary = 'CANARY_IMPORTED_VALUE_MUST_NOT_BE_PROFILED';
    const profile = service.save({ name: '  Meine CSV  ', mapping });
    const snapshot = service.exportSnapshot();

    expect(profile).toMatchObject({ id: FIRST_ID, name: 'Meine CSV', mapping });
    expect(snapshot).toEqual({
      version: 1,
      profiles: [
        {
          id: FIRST_ID,
          name: 'Meine CSV',
          mapping,
          updatedAt: '2026-07-27T10:00:00.000Z',
        },
      ],
    });
    expect(JSON.stringify(snapshot)).not.toContain(sourceOnlyCanary);
  });

  it('validiert ein Snapshot vollstaendig vor dem atomaren Ersetzen', () => {
    const service = new ImportMappingProfileService({
      createId: () => FIRST_ID,
      now: () => new Date('2026-07-27T10:00:00.000Z'),
    });
    const existing = service.save({ name: 'Bestehend', mapping });

    expect(() =>
      service.restoreSnapshot({
        version: 1,
        profiles: [
          { ...existing },
          {
            id: SECOND_ID,
            name: 'Defekt',
            mapping: { ...mapping, password: 'Nicht\nErlaubt' },
            updatedAt: '2026-07-27T10:00:00.000Z',
          },
        ],
      }),
    ).toThrow(/Importzuordnung/u);
    expect(service.list()).toEqual([existing]);
  });

  it('lehnt unbekannte Snapshot-Versionen und ungueltige IDs ab', () => {
    const service = new ImportMappingProfileService();

    expect(() => service.restoreSnapshot({ version: 2, profiles: [] })).toThrow(
      /unbekanntes Format/u,
    );
    expect(() => service.save({ id: 'not-a-uuid', name: 'Profil', mapping })).toThrow(
      /Importprofil-ID/u,
    );
  });
});
