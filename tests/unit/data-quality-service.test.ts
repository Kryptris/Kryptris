import { describe, expect, it, vi } from 'vitest';

import {
  DataQualityService,
  type AttachmentTechnicalCheck,
  type DataQualityFinding,
  type DataQualityScanInput,
} from '../../src/main/services/data-quality-service';
import type {
  AttachmentMetadata,
  SavedViewRecord,
  VaultDocument,
  VaultEntry,
} from '../../src/shared/models';

const NOW = new Date('2026-07-21T12:00:00.000Z');
const ENTRY_REVISION = '2026-07-20T10:00:00.000Z';
const VAULT_REVISION = '2026-07-20T09:00:00.000Z';
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

describe('DataQualityService', () => {
  it('meldet fehlerhafte URLs und plant nur HTTPS-/Whitespace-Normalisierungen', async () => {
    const fixable = credentialEntry({
      id: 'fixable',
      websites: ['  example.test/login  '],
    });
    const invalid = credentialEntry({
      id: 'invalid',
      websites: ['javascript:alert(1)', 'https:example.test'],
    });
    const input = scanInput([fixable, invalid]);
    const service = new DataQualityService();

    const report = await service.scan(input, { now: NOW });
    const normalization = finding(report.findings, 'url-needs-normalization');
    const invalidUrls = report.findings.filter((item) => item.code === 'invalid-url');
    const invalidUrl = invalidUrls[0]!;

    expect(normalization.fixCode).toBe('normalize-url-https-whitespace');
    expect(service.previewFix(input, normalization, { now: NOW })).toMatchObject({
      fixCode: 'normalize-url-https-whitespace',
      mutation: {
        kind: 'replace-entry-url',
        value: 'https://example.test/login',
      },
    });
    expect(invalidUrl.fixCode).toBeNull();
    expect(invalidUrls).toHaveLength(2);
    expect(() => service.previewFix(input, invalidUrl, { now: NOW })).toThrowError(
      expect.objectContaining({ code: 'FINDING_NOT_FIXABLE' }),
    );
  });

  it('trennt exakt doppelte von nur aehnlichen Websites', async () => {
    const duplicate = credentialEntry({
      id: 'duplicate',
      websites: ['https://EXAMPLE.test', 'https://example.test/'],
    });
    const similar = credentialEntry({
      id: 'similar',
      websites: ['http://www.example.test/login', 'https://example.test/login/'],
    });
    const input = scanInput([duplicate, similar]);
    const service = new DataQualityService();

    const report = await service.scan(input, { now: NOW });
    const exactFinding = finding(report.findings, 'duplicate-website');
    const nearFinding = finding(report.findings, 'similar-website');

    expect(exactFinding.location).toEqual({
      kind: 'website-pair',
      firstIndex: 0,
      secondIndex: 1,
    });
    expect(service.previewFix(input, exactFinding, { now: NOW }).mutation).toEqual({
      kind: 'remove-entry-website',
      index: 1,
    });
    expect(nearFinding.fixCode).toBeNull();
  });

  it('leitet leere und Import-Platzhaltertitel nur aus eindeutigen Daten ab', async () => {
    const placeholder = credentialEntry({
      id: 'placeholder',
      title: 'Importierter Eintrag 17',
      websites: ['https://www.example.test/login', 'https://example.test/account'],
    });
    const empty = credentialEntry({ id: 'empty', title: '', websites: ['one.test'] });
    const ambiguous = credentialEntry({
      id: 'ambiguous',
      title: '',
      websites: ['one.test', 'two.test'],
    });
    const input = scanInput([placeholder, empty, ambiguous]);
    const service = new DataQualityService();

    const report = await service.scan(input, { now: NOW });
    const placeholderFinding = report.findings.find(
      (item) => item.code === 'import-placeholder-title',
    )!;
    const emptyFindings = report.findings.filter((item) => item.code === 'empty-title');

    expect(service.previewFix(input, placeholderFinding, { now: NOW }).mutation).toEqual({
      kind: 'replace-entry-title',
      value: 'example.test',
    });
    const fixableEmpty = emptyFindings.find(
      (item) => item.reference.kind === 'entry' && item.reference.entryId === 'empty',
    )!;
    expect(service.previewFix(input, fixableEmpty, { now: NOW }).mutation).toEqual({
      kind: 'replace-entry-title',
      value: 'one.test',
    });
    expect(
      emptyFindings.find(
        (item) => item.reference.kind === 'entry' && item.reference.entryId === 'ambiguous',
      )?.fixCode,
    ).toBeNull();
  });

  it('meldet abgelaufene Kreditkarten und Lizenzen ohne fachlichen Auto-Fix', async () => {
    const expiredCard = asCreditCard(credentialEntry({ id: 'card' }), 6, 2026);
    const currentCard = asCreditCard(credentialEntry({ id: 'current-card' }), 7, 2026);
    const expiredLicense = asLicense(credentialEntry({ id: 'license' }), '2026-07-20', 'Kryptris');
    const report = await new DataQualityService().scan(
      scanInput([expiredCard, currentCard, expiredLicense]),
      { now: NOW },
    );

    expect(report.findings.filter((item) => item.code === 'expired-credit-card')).toHaveLength(1);
    expect(report.findings.filter((item) => item.code === 'expired-license')).toHaveLength(1);
    expect(
      report.findings
        .filter((item) => ['expired-credit-card', 'expired-license'].includes(item.code))
        .every((item) => item.fixCode === null),
    ).toBe(true);
  });

  it('meldet ungewoehnliche TOTP-Parameter, ohne das Geheimnis offenzulegen', async () => {
    const totpSecret = 'CANARY-TOTP-SECRET';
    const entry = credentialEntry({ id: 'totp' });
    if (entry.data.type !== 'credential') throw new Error('Test-Fixture ist ungueltig.');
    entry.data.value.totp = {
      secret: totpSecret,
      issuer: 'Kryptris',
      account: 'test@example.test',
      algorithm: 'SHA512',
      digits: 8,
      period: 45,
    };

    const report = await new DataQualityService().scan(scanInput([entry]), { now: NOW });
    const totpFinding = finding(report.findings, 'unusual-totp-parameters');

    expect(totpFinding.location).toEqual({
      kind: 'totp-parameters',
      parameters: ['algorithm', 'digits', 'period'],
    });
    expect(totpFinding.fixCode).toBeNull();
    expect(JSON.stringify(report)).not.toContain(totpSecret);
  });

  it('uebernimmt Attachment-Befunde nur aus revisionsgebundenen technischen Ergebnissen', async () => {
    const canaryPath = 'C:\\private\\CANARY-PATH\\secret.bin';
    const entry = credentialEntry({
      id: 'attachment-entry',
      password: 'CANARY-PASSWORD',
      attachments: [attachment('mismatch'), attachment('missing'), attachment('corrupt')],
    });
    const checks: AttachmentTechnicalCheck[] = [
      {
        status: 'metadata-mismatch',
        vaultId: 'vault-1',
        entryId: entry.id,
        attachmentId: 'mismatch',
        entryUpdatedAt: entry.updatedAt,
        verifiedMetadata: { size: 99, sha256: HASH_B },
      },
      {
        status: 'missing-file',
        vaultId: 'vault-1',
        entryId: entry.id,
        attachmentId: 'missing',
        entryUpdatedAt: entry.updatedAt,
      },
      {
        status: 'corrupt-file',
        vaultId: 'vault-1',
        entryId: entry.id,
        attachmentId: 'corrupt',
        entryUpdatedAt: entry.updatedAt,
      },
      {
        status: 'orphan-file',
        vaultId: 'vault-1',
        attachmentId: 'orphan',
        vaultUpdatedAt: VAULT_REVISION,
        sourcePath: canaryPath,
      } as AttachmentTechnicalCheck & { sourcePath: string },
    ];
    const input = scanInput([entry], { attachmentChecks: checks });
    const service = new DataQualityService();

    const report = await service.scan(input, { now: NOW });
    expect(
      report.findings
        .filter((item) => item.code.startsWith('attachment-'))
        .map((item) => item.code),
    ).toEqual([
      'attachment-file-corrupt',
      'attachment-metadata-mismatch',
      'attachment-file-missing',
      'attachment-file-orphan',
    ]);
    const mismatch = finding(report.findings, 'attachment-metadata-mismatch');
    expect(service.previewFix(input, mismatch, { now: NOW }).mutation).toEqual({
      kind: 'update-attachment-metadata',
      attachmentId: 'mismatch',
      metadata: { size: 99, sha256: HASH_B },
    });

    const serializedReport = JSON.stringify(report);
    expect(serializedReport).not.toContain('CANARY-PASSWORD');
    expect(serializedReport).not.toContain(HASH_A);
    expect(serializedReport).not.toContain(HASH_B);
    expect(serializedReport).not.toContain(canaryPath);
    expect(report.networkUsed).toBe(false);
  });

  it('plant nur das Leeren verwaister Ordner und Entfernen verwaister Saved-View-Referenzen', async () => {
    const entry = {
      ...credentialEntry({ id: 'orphan-folder' }),
      folderId: 'missing-folder',
      tags: ['Known'],
    };
    const view = savedView({ folderId: 'missing-folder', tags: [' known ', 'Missing'] });
    const input = scanInput([entry], { savedViews: [view] });
    const service = new DataQualityService();
    const report = await service.scan(input, { now: NOW });

    const folderFinding = finding(report.findings, 'orphan-folder-reference');
    const viewFinding = finding(report.findings, 'saved-view-orphan-reference');
    expect(service.previewFix(input, folderFinding, { now: NOW }).mutation).toEqual({
      kind: 'clear-entry-folder',
    });
    expect(viewFinding.location).toEqual({
      kind: 'saved-view-references',
      orphanFolder: true,
      orphanTagIndexes: [1],
    });
    expect(service.previewFix(input, viewFinding, { now: NOW }).mutation).toEqual({
      kind: 'remove-saved-view-references',
      clearFolder: true,
      removeTagIndexes: [1],
    });
  });

  it('bindet Preview-Plaene an updatedAt und lehnt stale Referenzen ab', async () => {
    const entry = { ...credentialEntry({ id: 'stale' }), folderId: 'missing' };
    const input = scanInput([entry]);
    const service = new DataQualityService();
    const report = await service.scan(input, { now: NOW });
    const staleFinding = finding(report.findings, 'orphan-folder-reference');
    const changedInput = structuredClone(input);
    changedInput.document.entries[0]!.updatedAt = '2026-07-21T13:00:00.000Z';

    expect(() => service.previewFix(changedInput, staleFinding, { now: NOW })).toThrowError(
      expect.objectContaining({ code: 'STALE_REFERENCE' }),
    );
  });

  it('bricht den asynchronen Scan nach einem Autorisierungsverlust ohne Teilreport ab', async () => {
    const abort = new Error('AUTH_EPOCH_CHANGED');
    let authorizationChecks = 0;
    const yieldControl = vi.fn(async () => Promise.resolve());
    const service = new DataQualityService();

    await expect(
      service.scan(scanInput([credentialEntry({ id: 'one' }), credentialEntry({ id: 'two' })]), {
        now: NOW,
        batchSize: 1,
        yieldControl,
        assertAuthorized: () => {
          authorizationChecks += 1;
          if (authorizationChecks === 3) throw abort;
        },
      }),
    ).rejects.toBe(abort);
    expect(yieldControl).toHaveBeenCalledTimes(1);
  });

  it('liefert deterministische Fortschritte und Ergebnisse, ohne Inputs zu veraendern', async () => {
    const entry = {
      ...credentialEntry({
        id: 'deterministic',
        title: 'Importierter Eintrag 3',
        websites: [' example.test ', 'https://example.test/'],
      }),
      folderId: 'missing',
    };
    const input = scanInput([entry], { savedViews: [savedView({ tags: ['Missing'] })] });
    const snapshot = structuredClone(input);
    const progress: string[] = [];
    const options = {
      now: NOW,
      batchSize: 1,
      yieldControl: async () => Promise.resolve(),
      onProgress: (state: { phase: string; completed: number; total: number }) => {
        progress.push(`${state.phase}:${String(state.completed)}/${String(state.total)}`);
      },
    };
    const service = new DataQualityService();

    const first = await service.scan(input, options);
    const firstProgress = [...progress];
    progress.length = 0;
    const second = await service.scan(input, options);

    expect(second).toEqual(first);
    expect(progress).toEqual(firstProgress);
    expect(progress).toContain('entries:0/1');
    expect(progress).toContain('entries:1/1');
    expect(progress).toContain('attachments:0/0');
    expect(progress).toContain('saved-views:0/1');
    expect(progress).toContain('saved-views:1/1');
    expect(input).toEqual(snapshot);
    expect(first.findings.map((item) => item.id)).toEqual(
      [...first.findings.map((item) => item.id)].sort((left, right) =>
        left.localeCompare(right, 'en'),
      ),
    );
    const fixable = first.findings.find((item) => item.fixCode !== null)!;
    service.previewFix(input, fixable, { now: NOW });
    expect(input).toEqual(snapshot);
  });
});

function finding(
  findings: readonly DataQualityFinding[],
  code: DataQualityFinding['code'],
): DataQualityFinding {
  const result = findings.find((item) => item.code === code);
  if (!result) throw new Error(`Befund ${code} fehlt.`);
  return result;
}

function credentialEntry(
  options: {
    id?: string;
    title?: string;
    password?: string;
    websites?: string[];
    attachments?: AttachmentMetadata[];
  } = {},
): VaultEntry {
  return {
    id: options.id ?? 'entry-1',
    vaultId: 'vault-1',
    title: options.title ?? 'Beispiel',
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    attachments: options.attachments ?? [],
    data: {
      type: 'credential',
      value: {
        username: 'user@example.test',
        password: options.password ?? 'Strong!Password-12345',
        websites: options.websites ?? ['https://example.test'],
        appNames: [],
      },
    },
    lifecycle: {
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    },
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: ENTRY_REVISION,
    secretChangedAt: '2026-01-01T00:00:00.000Z',
    lastUsedAt: null,
    deletedAt: null,
  };
}

function scanInput(
  entries: VaultEntry[],
  options: {
    savedViews?: SavedViewRecord[];
    attachmentChecks?: AttachmentTechnicalCheck[];
  } = {},
): DataQualityScanInput {
  const document: VaultDocument = {
    formatVersion: 2,
    id: 'vault-1',
    name: 'Privat',
    color: '#22d3c5',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: VAULT_REVISION,
    folders: [],
    entries,
  };
  return {
    document,
    savedViews: options.savedViews ?? [],
    attachmentChecks: options.attachmentChecks ?? [],
  };
}

function attachment(id: string): AttachmentMetadata {
  return {
    id,
    name: `${id}.bin`,
    mediaType: 'application/octet-stream',
    size: 12,
    sha256: HASH_A,
    createdAt: '2026-01-01T00:00:00.000Z',
    previewable: false,
  };
}

function savedView(options: { folderId?: string | null; tags?: string[] } = {}): SavedViewRecord {
  return {
    id: 'view-1',
    vaultId: 'vault-1',
    name: 'Ansicht',
    filters: {
      search: '',
      view: 'all',
      types: [],
      tags: options.tags ?? [],
      folderId: options.folderId ?? null,
      security: [],
      smartView: null,
    },
    order: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: ENTRY_REVISION,
  };
}

function asCreditCard(entry: VaultEntry, expiryMonth: number, expiryYear: number): VaultEntry {
  return {
    ...entry,
    data: {
      type: 'credit-card',
      value: {
        cardName: 'Privatkarte',
        cardholder: '',
        number: '',
        expiryMonth,
        expiryYear,
        cvc: '',
        pin: '',
        issuer: '',
        cardType: '',
        billingAddress: '',
        servicePhone: '',
        website: '',
      },
    },
  };
}

function asLicense(entry: VaultEntry, expiryDate: string, product: string): VaultEntry {
  return {
    ...entry,
    data: {
      type: 'software-license',
      value: {
        product,
        manufacturer: '',
        version: '',
        licenseKey: '',
        licensedTo: '',
        purchaseDate: '',
        activationDate: '',
        expiryDate,
        orderNumber: '',
        downloadUrl: '',
        purchasePrice: '',
      },
    },
  };
}
