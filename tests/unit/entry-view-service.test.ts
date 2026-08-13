import { describe, expect, it, vi } from 'vitest';

import { VaultaError } from '../../src/shared/errors';
import type { EntryListQuery, VaultEntry } from '../../src/shared/models';
import type { SecurityScanOptions } from '../../src/main/services/security-check-service';
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
    const entry = credentialEntry({ id: 'changed-entry' });

    service.list([entry], query('all'));
    service.list([{ ...entry, updatedAt: '2026-07-16T12:00:00.000Z' }], query('all'));

    expect(scan).toHaveBeenCalledTimes(2);
  });

  it('wendet intelligente Ansichten deterministisch und kombinierbar an', () => {
    const current = new Date('2026-07-21T12:00:00.000Z');
    const service = new EntryViewService(undefined, () => current);
    const recent = credentialEntry({
      id: 'recent',
      title: 'Recent',
      updatedAt: '2026-07-20T12:00:00.000Z',
      secretChangedAt: '2026-07-20T12:00:00.000Z',
    });
    const old = {
      ...credentialEntry({
        id: 'old',
        title: 'A',
        updatedAt: '2026-05-01T12:00:00.000Z',
        secretChangedAt: '2025-01-01T00:00:00.000Z',
      }),
      folderId: 'folder-1',
      tags: ['Arbeit'],
      lifecycle: {
        rotationIntervalDays: 90,
        nextRotationDate: '2025-04-01',
        rotationExcluded: false,
        twoFactorStatus: 'unknown' as const,
        expiryReminderDate: null,
      },
    };
    const future = credentialEntry({
      id: 'future',
      updatedAt: '2026-08-01T12:00:00.000Z',
    });

    expect(
      service
        .list([old, recent, future], { ...query('all'), smartView: 'recently-changed' })
        .map(({ id }) => id),
    ).toEqual(['recent']);
    expect(
      service
        .list([old, recent], { ...query('all'), smartView: 'without-folder' })
        .map(({ id }) => id),
    ).toEqual(['recent']);
    expect(
      service
        .list([old, recent], { ...query('all'), smartView: 'without-tags' })
        .map(({ id }) => id),
    ).toEqual(['recent']);
    expect(
      service
        .list([old, recent], { ...query('all'), smartView: 'rotation-due' })
        .map(({ id }) => id),
    ).toEqual(['old']);
    expect(
      service
        .list([old, recent], {
          ...query('all'),
          smartView: 'without-folder',
          search: 'recent',
        })
        .map(({ id }) => id),
    ).toEqual(['recent']);
  });

  it('findet fehlende Zwei-Faktor-Konfigurationen, Anhänge und Tags normalisiert', () => {
    const service = new EntryViewService();
    const withoutTotp = {
      ...credentialEntry({ id: 'without-totp' }),
      tags: ['Ａｒｂｅｉｔ'],
      attachments: [
        {
          id: 'attachment-1',
          name: 'beleg.pdf',
          mediaType: 'application/pdf',
          size: 42,
          sha256: 'a'.repeat(64),
          createdAt: '2026-07-20T12:00:00.000Z',
          previewable: true,
        },
      ],
    };
    const withTotp = credentialEntry({ id: 'with-totp' });
    if (withTotp.data.type !== 'credential') throw new Error('Test-Fixture hat den falschen Typ.');
    withTotp.data.value.totp = {
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'Kryptris',
      account: 'test@example.test',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    };

    expect(
      service
        .list([withTotp, withoutTotp], { ...query('all'), smartView: 'without-two-factor' })
        .map(({ id }) => id),
    ).toEqual(['without-totp']);
    expect(
      service
        .list([withTotp, withoutTotp], { ...query('all'), smartView: 'with-attachments' })
        .map(({ id }) => id),
    ).toEqual(['without-totp']);
    expect(
      service
        .list([withTotp, withoutTotp], { ...query('all'), tags: [' arbeit '] })
        .map(({ id }) => id),
    ).toEqual(['without-totp']);
  });

  it('arbeitet bei großen Listen in 10er-Batches und verwendet den warmen Sicherheitscache', async () => {
    const scanAsync = vi.fn(
      async (activeEntries: readonly VaultEntry[], options: SecurityScanOptions) => {
        expect(options.batchSize).toBe(10);
        for (let index = 0; index < activeEntries.length; index += 1) {
          options.assertAuthorized?.();
          if ((index + 1) % 10 === 0) {
            await options.yieldControl?.();
            options.assertAuthorized?.();
          }
        }
        return {
          generatedAt: '2026-07-21T12:00:00.000Z',
          score: 100,
          counts: { good: activeEntries.length, info: 0, warning: 0, critical: 0 },
          findings: [],
          networkUsed: false,
        };
      },
    );
    const service = new EntryViewService({ scanAsync } as never);
    const entries = Array.from({ length: 20 }, (_value, index) =>
      credentialEntry({ id: `entry-${index}`, title: `Titel ${index}` }),
    );
    const yieldControl = vi.fn(() => Promise.resolve());

    const first = await service.listAsync(entries, query('all'), { yieldControl });
    const cached = await service.listAsync(
      entries,
      { ...query('all'), search: 'titel' },
      {
        yieldControl,
      },
    );

    expect(first).toHaveLength(20);
    expect(cached).toHaveLength(20);
    expect(scanAsync).toHaveBeenCalledTimes(1);
    expect(yieldControl).toHaveBeenCalledTimes(10);
  });

  it('koalesziert parallele asynchrone Listen derselben Revision zu einem Sicherheits-Scan', async () => {
    let announceScanStarted: () => void = () => undefined;
    const scanStarted = new Promise<void>((resolve) => {
      announceScanStarted = resolve;
    });
    let releaseScan: () => void = () => undefined;
    const waitForRelease = new Promise<void>((resolve) => {
      releaseScan = resolve;
    });
    const scanAsync = vi.fn(
      async (activeEntries: readonly VaultEntry[], options: SecurityScanOptions) => {
        options.assertAuthorized?.();
        announceScanStarted();
        await waitForRelease;
        return {
          generatedAt: '2026-07-21T12:00:00.000Z',
          score: 100,
          counts: { good: activeEntries.length, info: 0, warning: 0, critical: 0 },
          findings: [],
          networkUsed: false,
        };
      },
    );
    const service = new EntryViewService({ scanAsync } as never);
    const entries = [credentialEntry({ id: 'shared-entry' })];
    const first = service.listAsync(entries, query('all'), {
      yieldControl: () => Promise.resolve(),
    });
    await scanStarted;
    const second = service.listAsync(entries, query('all'), {
      yieldControl: () => Promise.resolve(),
    });
    releaseScan();

    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.arrayContaining([expect.objectContaining({ id: 'shared-entry' })]),
      expect.arrayContaining([expect.objectContaining({ id: 'shared-entry' })]),
    ]);
    expect(scanAsync).toHaveBeenCalledTimes(1);
    expect(privatePendingSecurityReports(service).size).toBe(0);
  });

  it('bricht nach einem Yield ohne Sicherheitscache ab, wenn die Authentisierung endet', async () => {
    const service = new EntryViewService();
    const entries = Array.from({ length: 11 }, (_value, index) =>
      credentialEntry({ id: `entry-${index}`, title: `Titel ${index}` }),
    );
    let authorized = true;
    const assertAuthorized = vi.fn(() => {
      if (!authorized) throw new VaultaError('LOCKED', 'Der Tresor wurde gesperrt.');
    });
    const yieldControl = vi.fn(() => {
      authorized = false;
      return Promise.resolve();
    });

    await expect(
      service.listAsync(entries, query('all'), { assertAuthorized, batchSize: 10, yieldControl }),
    ).rejects.toMatchObject({ code: 'LOCKED' });

    expect(yieldControl).toHaveBeenCalledTimes(1);
    expect(assertAuthorized.mock.calls.length).toBeGreaterThan(10);
    expect(privateSecurityReports(service).size).toBe(0);
    expect(privatePendingSecurityReports(service).size).toBe(0);
  });
});

function privateSecurityReports(service: EntryViewService): Map<string, unknown> {
  return Reflect.get(service, 'securityReports') as Map<string, unknown>;
}

function privatePendingSecurityReports(service: EntryViewService): Map<string, unknown> {
  return Reflect.get(service, 'pendingSecurityReports') as Map<string, unknown>;
}
