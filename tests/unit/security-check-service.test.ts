import { describe, expect, it } from 'vitest';

import { SecurityCheckService } from '../../src/main/services/security-check-service';
import { credentialEntry, sshEntry } from './service-fixtures';

describe('SecurityCheckService', () => {
  const service = new SecurityCheckService();

  it('findet schwache, wiederverwendete, alte und unvollstaendige Zugaenge', () => {
    const entries = [
      credentialEntry({
        id: 'one',
        title: 'Erster Zugang',
        username: '',
        password: 'password',
        websites: [],
        secretChangedAt: '2020-01-01T00:00:00.000Z',
      }),
      credentialEntry({ id: 'two', title: 'Zweiter Zugang', password: 'password' }),
      sshEntry(),
    ];
    const report = service.scan(entries, { now: new Date('2026-07-14T00:00:00.000Z') });
    const kinds = report.findings.map((finding) => finding.kind);

    expect(kinds).toContain('weak');
    expect(kinds).toContain('reused');
    expect(kinds).toContain('old');
    expect(kinds).toContain('incomplete');
    expect(kinds).toContain('unprotected-key');
    expect(report.networkUsed).toBe(false);
    expect(report.counts.critical).toBeGreaterThan(0);
  });

  it('ueberspringt Eintraege im Papierkorb', () => {
    const report = service.scan([
      credentialEntry({ password: 'password', deletedAt: '2026-01-01T00:00:00.000Z' }),
    ]);
    expect(report.findings).toEqual([]);
    expect(report.counts.good).toBe(0);
  });

  it('erkennt sichtbar gespeicherte sensible eigene Felder', () => {
    const report = service.scan([
      credentialEntry({
        customFields: [
          {
            id: 'token',
            label: 'API Token',
            type: 'text',
            value: 'canary',
            secret: false,
            searchable: true,
            order: 0,
          },
        ],
      }),
    ]);
    expect(report.findings.some((finding) => finding.kind === 'sensitive-field')).toBe(true);
  });

  it('liefert asynchron dasselbe Ergebnis und gibt zwischen Arbeitsabschnitten frei', async () => {
    const entries = Array.from({ length: 26 }, (_, index) =>
      credentialEntry({ id: `entry-${index}`, password: `password-${index}` }),
    );
    const options = { now: new Date('2026-07-14T00:00:00.000Z') };

    await expect(service.scanAsync(entries, options)).resolves.toEqual(
      service.scan(entries, options),
    );
  });
});
