import { describe, expect, it } from 'vitest';

import { ReportService } from '../../src/main/services/report-service';
import { credentialEntry, vaultDocument } from './service-fixtures';

describe('ReportService', () => {
  it('aggregiert ausschliesslich lokal und trennt aktive Eintraege vom Papierkorb', () => {
    const active = credentialEntry({
      id: 'active',
      favorite: true,
      password: 'password',
      createdAt: '2020-01-01T00:00:00.000Z',
      attachments: [
        {
          id: 'a',
          name: 'datei.txt',
          mediaType: 'text/plain',
          size: 128,
          sha256: 'hash',
          createdAt: '2025-01-01T00:00:00.000Z',
          previewable: true,
        },
      ],
    });
    const deleted = credentialEntry({
      id: 'deleted',
      deletedAt: '2026-01-01T00:00:00.000Z',
    });
    const report = new ReportService().generate([vaultDocument([active, deleted])], {
      now: new Date('2026-07-14T00:00:00.000Z'),
    });

    expect(report).toMatchObject({
      vaultCount: 1,
      entryCount: 1,
      favoriteCount: 1,
      trashCount: 1,
      attachmentCount: 1,
      attachmentBytes: 128,
      networkUsed: false,
    });
    expect(report.typeCounts.credential).toBe(1);
    expect(report.oldestEntries[0]?.id).toBe('active');
    expect(report.security.networkUsed).toBe(false);
  });
});
