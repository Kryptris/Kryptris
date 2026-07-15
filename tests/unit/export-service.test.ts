import { describe, expect, it } from 'vitest';

import { ExportService } from '../../src/main/services/export-service';
import { credentialEntry, vaultDocument } from './service-fixtures';

describe('ExportService', () => {
  const service = new ExportService();

  it('bereitet einen verlustfreien Klartext-JSON-Export ohne Anhangsnamen vor', () => {
    const entry = credentialEntry({
      password: 'canary-secret',
      attachments: [
        {
          id: 'attachment',
          name: 'vertraulich.pdf',
          mediaType: 'application/pdf',
          size: 42,
          sha256: 'abc',
          createdAt: '2025-01-01T00:00:00.000Z',
          previewable: true,
        },
      ],
    });
    const result = service.prepare('json', [vaultDocument([entry])]);

    expect(result.content).toContain('canary-secret');
    expect(result.content).not.toContain('vertraulich.pdf');
    expect(result.entryCount).toBe(1);
    expect(JSON.parse(result.content)).toMatchObject({
      format: 'vaulta-cleartext-json',
      formatVersion: 1,
    });
  });

  it('nimmt Anhangsmetadaten nur nach gesonderter Auswahl auf', () => {
    const entry = credentialEntry({
      attachments: [
        {
          id: 'attachment',
          name: 'beleg.pdf',
          mediaType: 'application/pdf',
          size: 42,
          sha256: 'abc',
          createdAt: '2025-01-01T00:00:00.000Z',
          previewable: true,
        },
      ],
    });
    const result = service.prepare('json', [vaultDocument([entry])], {
      includeAttachmentMetadata: true,
    });
    expect(result.content).toContain('beleg.pdf');
  });

  it('neutralisiert Tabellenformeln und laesst den Papierkorb standardmaessig aus', () => {
    const active = credentialEntry({ id: 'active', title: '=WEBSERVICE("bad")' });
    const deleted = credentialEntry({ id: 'deleted', deletedAt: '2026-01-01T00:00:00.000Z' });
    const result = service.prepare('csv', [vaultDocument([active, deleted])]);
    expect(result.entryCount).toBe(1);
    expect(result.content).toContain("'=WEBSERVICE");
    expect(result.content).not.toContain('"deleted","credential"');
  });
});
