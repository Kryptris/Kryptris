import { describe, expect, it } from 'vitest';

import {
  RevisionTokenService,
  type RevisionTokenDocument,
} from '../../src/main/services/revision-token-service';

describe('RevisionTokenService', () => {
  const service = new RevisionTokenService();

  it('liefert auch für 10.000 Einträge einen kurzen SHA-256-Token', () => {
    const document: RevisionTokenDocument = {
      id: 'vault-large',
      updatedAt: '2026-07-26T10:00:00.000Z',
      entries: Array.from({ length: 10_000 }, (_, index) => ({
        id: `entry-${String(index).padStart(5, '0')}`,
        updatedAt: `2026-07-26T10:${String(index % 60).padStart(2, '0')}:00.000Z`,
        deletedAt: index % 11 === 0 ? '2026-07-26T11:00:00.000Z' : null,
      })),
    };

    const token = service.create([document], ['duplicate-scan', 'active-and-deleted']);

    expect(token).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(token.length).toBeLessThanOrEqual(128);
    expect(service.create([document], ['duplicate-scan', 'active-and-deleted'])).toBe(token);
  });

  it('ist unabhängig von der Reihenfolge der Dokumente, Einträge und Zusatzwerte', () => {
    const first: RevisionTokenDocument = {
      id: 'vault-a',
      updatedAt: '2026-07-26T10:00:00.000Z',
      entries: [
        {
          id: 'entry-b',
          updatedAt: '2026-07-26T10:02:00.000Z',
          deletedAt: null,
        },
        {
          id: 'entry-a',
          updatedAt: '2026-07-26T10:01:00.000Z',
          deletedAt: '2026-07-26T10:03:00.000Z',
        },
      ],
    };
    const second: RevisionTokenDocument = {
      id: 'vault-b',
      updatedAt: '2026-07-26T11:00:00.000Z',
      entries: [
        {
          id: 'entry-c',
          updatedAt: '2026-07-26T11:01:00.000Z',
        },
      ],
    };

    expect(service.create([first, second], ['scope:all', 'include:trash'])).toBe(
      service.create(
        [
          second,
          {
            ...first,
            entries: [...first.entries].reverse(),
          },
        ],
        ['include:trash', 'scope:all'],
      ),
    );
  });

  it('ändert den Token bei Vault-ID, Dokument-, Eintrags-, Lösch- oder Kontextrevisionen', () => {
    const document: RevisionTokenDocument = {
      id: 'vault-a',
      updatedAt: '2026-07-26T10:00:00.000Z',
      entries: [
        {
          id: 'entry-a',
          updatedAt: '2026-07-26T10:01:00.000Z',
          deletedAt: null,
        },
      ],
    };
    const baseline = service.create([document]);

    expect(service.create([{ ...document, id: 'vault-b' }])).not.toBe(baseline);
    expect(
      service.create([
        {
          ...document,
          updatedAt: '2026-07-26T10:02:00.000Z',
        },
      ]),
    ).not.toBe(baseline);
    expect(
      service.create([
        {
          ...document,
          entries: [{ ...document.entries[0]!, updatedAt: '2026-07-26T10:02:00.000Z' }],
        },
      ]),
    ).not.toBe(baseline);
    expect(
      service.create([
        {
          ...document,
          entries: [{ ...document.entries[0]!, deletedAt: '2026-07-26T10:03:00.000Z' }],
        },
      ]),
    ).not.toBe(baseline);
    expect(service.create([document], ['refresh:requested'])).not.toBe(baseline);
  });

  it('nimmt keine Fachwerte oder Secrets in den Token auf', () => {
    const first = {
      id: 'vault-a',
      updatedAt: '2026-07-26T10:00:00.000Z',
      name: 'Privater Tresor',
      entries: [
        {
          id: 'entry-a',
          updatedAt: '2026-07-26T10:01:00.000Z',
          deletedAt: null,
          title: 'Produktivkonto',
          data: { username: 'person@example.invalid', password: 'test-secret-one' },
        },
      ],
    };
    const changedSecrets = {
      ...first,
      name: 'Anderer Fachwert',
      entries: [
        {
          ...first.entries[0]!,
          title: 'Geänderter Fachwert',
          data: { username: 'changed@example.invalid', password: 'test-secret-two' },
        },
      ],
    };

    expect(service.create([changedSecrets])).toBe(service.create([first]));
  });
});
