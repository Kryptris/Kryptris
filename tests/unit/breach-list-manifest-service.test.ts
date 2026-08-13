import { describe, expect, it } from 'vitest';

import { BreachListManifestService } from '../../src/main/services/breach-list-manifest-service';

const build = {
  format: 'sha1-count-v1' as const,
  version: 1 as const,
  recordCount: 2,
  sourceSha256: 'a'.repeat(64),
  indexSha256: 'b'.repeat(64),
  indexBytes: 524_400,
  sourceBytes: 86,
  stagingPath: 'C:\\Temp\\offline-breach.kbi',
};

describe('BreachListManifestService', () => {
  it('erzeugt ausschließlich technische, geschützte Metadaten', () => {
    const service = new BreachListManifestService();
    const manifest = service.create(
      build,
      { sourceLabel: ' Lokaler Testbestand ', sourceDate: '2026-07-25' },
      new Date('2026-07-26T12:00:00.000Z'),
    );

    expect(manifest).toMatchObject({
      format: 'kryptris-offline-breach-manifest',
      version: 1,
      sourceLabel: 'Lokaler Testbestand',
      sourceDate: '2026-07-25',
      importedAt: '2026-07-26T12:00:00.000Z',
      recordCount: 2,
    });
    expect(JSON.stringify(manifest)).not.toContain(build.stagingPath);
  });

  it('unterscheidet absent, fehlend und beschädigt ohne einen Passwort-Hash auszugeben', () => {
    const service = new BreachListManifestService();
    const manifest = service.create(
      build,
      { sourceLabel: 'Test', sourceDate: '2026-07-25' },
      new Date('2026-07-26T12:00:00.000Z'),
    );

    expect(service.status(null).state).toBe('not-configured');
    expect(service.status(manifest, 'missing').state).toBe('missing');
    expect(service.status(manifest, 'corrupt').state).toBe('corrupt');
    expect(service.status(manifest, 'ready').corpusSha256).toBe(build.sourceSha256);
  });

  it('lehnt unbekannte Felder und manipulierte Prüfsummen fail-closed ab', () => {
    const service = new BreachListManifestService();
    const manifest = service.create(
      build,
      { sourceLabel: 'Test', sourceDate: '2026-07-25' },
      new Date('2026-07-26T12:00:00.000Z'),
    );

    expect(() => service.parse({ ...manifest, path: 'C:\\nicht-erlaubt' })).toThrow(
      'geschützten Metadaten',
    );
    expect(() => service.parse({ ...manifest, indexSha256: 'zu-kurz' })).toThrow(
      'geschützten Metadaten',
    );
  });
});
