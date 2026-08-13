import { describe, expect, it, vi } from 'vitest';

import {
  DataQualityFixService,
  type DataQualityFixSnapshot,
} from '../../src/main/services/data-quality-fix-service';
import {
  DataQualityError,
  type DataQualityFixCode,
  type DataQualityFixMutation,
  type DataQualityFixPlan,
  type DataQualityFindingCode,
  type DataQualityReference,
} from '../../src/main/services/data-quality-service';
import type {
  AttachmentMetadata,
  SavedViewRecord,
  VaultDocument,
  VaultEntry,
} from '../../src/shared/models';

const ENTRY_REVISION = '2026-07-20T10:00:00.000Z';
const VIEW_REVISION = '2026-07-20T11:00:00.000Z';
const DOCUMENT_REVISION = '2026-07-20T12:00:00.000Z';
const APPLIED_AT = new Date('2026-07-21T09:30:00.000Z');
const APPLIED_TIMESTAMP = APPLIED_AT.toISOString();
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

describe('DataQualityFixService', () => {
  it('wendet URL-Ersetzungen fuer alle vier festen URL-Ziele an', () => {
    const credential = credentialEntry({ websites: [' example.test '] });
    const card = creditCardEntry();
    const license = licenseEntry();
    const custom = {
      ...credentialEntry({ id: 'custom-entry' }),
      customFields: [
        {
          id: 'field-1',
          label: 'URL',
          type: 'url' as const,
          value: ' custom.example.test ',
          secret: false,
          searchable: true,
          order: 0,
        },
      ],
    };

    const cases: Array<{
      input: DataQualityFixSnapshot;
      plan: DataQualityFixPlan;
      read: (result: VaultDocument) => string;
    }> = [
      {
        input: snapshot([credential]),
        plan: entryPlan(
          credential,
          'normalize-url-https-whitespace',
          {
            kind: 'replace-entry-url',
            location: {
              kind: 'url',
              field: 'credential-website',
              index: 0,
              customFieldId: null,
            },
            value: 'https://example.test/',
          },
          'url-needs-normalization',
        ),
        read: (document) => credentialWebsites(document.entries[0]!)[0]!,
      },
      {
        input: snapshot([card]),
        plan: entryPlan(
          card,
          'normalize-url-https-whitespace',
          {
            kind: 'replace-entry-url',
            location: {
              kind: 'url',
              field: 'credit-card-website',
              index: null,
              customFieldId: null,
            },
            value: 'https://card.example.test/',
          },
          'url-needs-normalization',
        ),
        read: (document) => {
          const entry = document.entries[0]!;
          if (entry.data.type !== 'credit-card') throw new Error('Unerwarteter Typ.');
          return entry.data.value.website;
        },
      },
      {
        input: snapshot([license]),
        plan: entryPlan(
          license,
          'normalize-url-https-whitespace',
          {
            kind: 'replace-entry-url',
            location: {
              kind: 'url',
              field: 'license-download-url',
              index: null,
              customFieldId: null,
            },
            value: 'https://download.example.test/',
          },
          'url-needs-normalization',
        ),
        read: (document) => {
          const entry = document.entries[0]!;
          if (entry.data.type !== 'software-license') throw new Error('Unerwarteter Typ.');
          return entry.data.value.downloadUrl;
        },
      },
      {
        input: snapshot([custom]),
        plan: entryPlan(
          custom,
          'normalize-url-https-whitespace',
          {
            kind: 'replace-entry-url',
            location: {
              kind: 'url',
              field: 'custom-url-field',
              index: 0,
              customFieldId: 'field-1',
            },
            value: 'https://custom.example.test/',
          },
          'url-needs-normalization',
        ),
        read: (document) => String(document.entries[0]!.customFields[0]!.value),
      },
    ];

    for (const testCase of cases) {
      const before = structuredClone(testCase.input);
      const planBefore = structuredClone(testCase.plan);
      const result = new DataQualityFixService().apply(testCase.input, testCase.plan, {
        now: APPLIED_AT,
      });

      expect(testCase.read(result.document)).toMatch(/^https:\/\//u);
      expect(result.document.entries[0]!.updatedAt).toBe(APPLIED_TIMESTAMP);
      expect(result.document.updatedAt).toBe(APPLIED_TIMESTAMP);
      expect(testCase.input).toEqual(before);
      expect(testCase.plan).toEqual(planBefore);
    }
  });

  it('entfernt exakt den geplanten Website-Index ohne Duplikat-Heuristik', () => {
    const entry = credentialEntry({ websites: ['one.test', 'two.test', 'three.test'] });
    const input = snapshot([entry]);
    const plan = entryPlan(
      entry,
      'remove-exact-duplicate-url',
      { kind: 'remove-entry-website', index: 1 },
      'duplicate-website',
    );

    const result = new DataQualityFixService().apply(input, plan, { now: APPLIED_AT });

    expect(credentialWebsites(result.document.entries[0]!)).toEqual(['one.test', 'three.test']);
    expect(credentialWebsites(input.document.entries[0]!)).toEqual([
      'one.test',
      'two.test',
      'three.test',
    ]);
  });

  it('setzt ausschliesslich den im Plan enthaltenen eindeutigen Titel', () => {
    const entry = credentialEntry({ title: 'Importierter Eintrag 9' });
    const input = snapshot([entry]);
    const plan = entryPlan(
      entry,
      'replace-unambiguous-title',
      { kind: 'replace-entry-title', value: 'example.test' },
      'import-placeholder-title',
    );

    const result = new DataQualityFixService().apply(input, plan, { now: APPLIED_AT });

    expect(result.document.entries[0]!.title).toBe('example.test');
    expect(input.document.entries[0]!.title).toBe('Importierter Eintrag 9');
  });

  it('leert den geplanten Ordner ohne die Fachheuristik erneut auszufuehren', () => {
    const entry = { ...credentialEntry(), folderId: 'existing-folder' };
    const input = snapshot([entry]);
    input.document.folders.push({
      id: 'existing-folder',
      name: 'Noch vorhanden',
      color: '#22d3c5',
      createdAt: ENTRY_REVISION,
    });
    const plan = entryPlan(
      entry,
      'clear-orphan-folder',
      { kind: 'clear-entry-folder' },
      'orphan-folder-reference',
    );

    const result = new DataQualityFixService().apply(input, plan, { now: APPLIED_AT });

    expect(result.document.entries[0]!.folderId).toBeNull();
    expect(input.document.entries[0]!.folderId).toBe('existing-folder');
  });

  it('entfernt nur geplante Saved-View-Referenzen und aktualisiert View und Dokument', () => {
    const view = savedView({ folderId: 'folder-1', tags: ['Keep', 'Remove A', 'Remove B'] });
    const input = snapshot([credentialEntry()], [view]);
    input.document.folders.push({
      id: 'folder-1',
      name: 'Vorhanden',
      color: '#22d3c5',
      createdAt: ENTRY_REVISION,
    });
    const plan = savedViewPlan(view, {
      kind: 'remove-saved-view-references',
      clearFolder: true,
      removeTagIndexes: [1, 2],
    });

    const result = new DataQualityFixService().apply(input, plan, { now: APPLIED_AT });

    expect(result.savedViews[0]!.filters).toMatchObject({ folderId: null, tags: ['Keep'] });
    expect(result.savedViews[0]!.updatedAt).toBe(APPLIED_TIMESTAMP);
    expect(result.document.updatedAt).toBe(APPLIED_TIMESTAMP);
    expect(result.document.entries[0]!.updatedAt).toBe(ENTRY_REVISION);
    expect(input.savedViews[0]!.filters).toMatchObject({
      folderId: 'folder-1',
      tags: ['Keep', 'Remove A', 'Remove B'],
    });
  });

  it('aktualisiert nur authentifizierte Attachment-Metadaten und die Revisionen', () => {
    const entry = credentialEntry({ attachments: [attachment()] });
    const input = snapshot([entry]);
    const plan = attachmentPlan(entry, {
      kind: 'update-attachment-metadata',
      attachmentId: 'attachment-1',
      metadata: { size: 99, sha256: HASH_B },
    });

    const result = new DataQualityFixService().apply(input, plan, { now: APPLIED_AT });
    const changed = result.document.entries[0]!.attachments[0]!;

    expect(changed).toMatchObject({ size: 99, sha256: HASH_B });
    expect(changed.name).toBe('original.bin');
    expect(result.document.entries[0]!.updatedAt).toBe(APPLIED_TIMESTAMP);
    expect(result.document.updatedAt).toBe(APPLIED_TIMESTAMP);
    expect(input.document.entries[0]!.attachments[0]).toMatchObject({ size: 12, sha256: HASH_A });
  });

  it('lehnt stale Entry-, Saved-View- und Attachment-Referenzen vor jeder Mutation ab', () => {
    const entry = credentialEntry({ attachments: [attachment()] });
    const view = savedView();
    const input = snapshot([entry], [view]);
    const plans = [
      {
        ...entryPlan(
          entry,
          'replace-unambiguous-title',
          { kind: 'replace-entry-title', value: 'Neuer Titel' },
          'empty-title',
        ),
        reference: { ...entryReference(entry), updatedAt: '2026-07-19T00:00:00.000Z' },
      },
      {
        ...savedViewPlan(view, {
          kind: 'remove-saved-view-references',
          clearFolder: true,
          removeTagIndexes: [],
        }),
        reference: { ...savedViewReference(view), updatedAt: '2026-07-19T00:00:00.000Z' },
      },
      {
        ...attachmentPlan(entry, {
          kind: 'update-attachment-metadata',
          attachmentId: 'attachment-1',
          metadata: { size: 99, sha256: HASH_B },
        }),
        reference: { ...attachmentReference(entry), updatedAt: '2026-07-19T00:00:00.000Z' },
      },
    ] satisfies DataQualityFixPlan[];

    for (const plan of plans) {
      const before = structuredClone(input);
      expectDataQualityError(
        () => new DataQualityFixService().apply(input, plan, { now: APPLIED_AT }),
        'STALE_REFERENCE',
      );
      expect(input).toEqual(before);
    }
  });

  it('lehnt inkonsistente Codes, Ziele, Indizes und Metadaten vollstaendig ab', () => {
    const entry = credentialEntry({ attachments: [attachment()] });
    const view = savedView({ tags: ['One', 'Two'] });
    const input = snapshot([entry], [view]);
    const validTitlePlan = entryPlan(
      entry,
      'replace-unambiguous-title',
      { kind: 'replace-entry-title', value: 'Titel' },
      'empty-title',
    );
    const invalidPlans = [
      {
        ...validTitlePlan,
        fixCode: 'clear-orphan-folder',
      },
      entryPlan(
        entry,
        'remove-exact-duplicate-url',
        { kind: 'remove-entry-website', index: 99 },
        'duplicate-website',
      ),
      savedViewPlan(view, {
        kind: 'remove-saved-view-references',
        clearFolder: false,
        removeTagIndexes: [1, 0],
      }),
      attachmentPlan(entry, {
        kind: 'update-attachment-metadata',
        attachmentId: 'different-attachment',
        metadata: { size: 99, sha256: HASH_B },
      }),
      {
        ...attachmentPlan(entry, {
          kind: 'update-attachment-metadata',
          attachmentId: 'attachment-1',
          metadata: { size: 99, sha256: HASH_B },
        }),
        mutation: {
          kind: 'update-attachment-metadata',
          attachmentId: 'attachment-1',
          metadata: null,
        },
      } as unknown as DataQualityFixPlan,
    ] as DataQualityFixPlan[];

    for (const plan of invalidPlans) {
      const before = structuredClone(input);
      expectDataQualityError(
        () => new DataQualityFixService().apply(input, plan, { now: APPLIED_AT }),
        'INVALID_INPUT',
      );
      expect(input).toEqual(before);
    }
  });

  it('bricht bei fehlender Autorisierung ohne Mutation ab', () => {
    const entry = credentialEntry();
    const input = snapshot([entry]);
    const plan = entryPlan(
      entry,
      'replace-unambiguous-title',
      { kind: 'replace-entry-title', value: 'Titel' },
      'empty-title',
    );
    const before = structuredClone(input);
    const abort = new Error('AUTH_EPOCH_CHANGED');
    const assertAuthorized = vi.fn(() => {
      throw abort;
    });

    expect(() =>
      new DataQualityFixService().apply(input, plan, { now: APPLIED_AT, assertAuthorized }),
    ).toThrow(abort);
    expect(assertAuthorized).toHaveBeenCalledTimes(1);
    expect(input).toEqual(before);
  });

  it('liefert fuer denselben Snapshot, Plan und Zeitpunkt deterministisch dasselbe Ergebnis', () => {
    const entry = credentialEntry({ title: '' });
    const input = deepFreeze(snapshot([entry]));
    const plan = deepFreeze(
      entryPlan(
        entry,
        'replace-unambiguous-title',
        { kind: 'replace-entry-title', value: 'example.test' },
        'empty-title',
      ),
    );
    const inputBefore = structuredClone(input);
    const planBefore = structuredClone(plan);
    const service = new DataQualityFixService();

    const first = service.apply(input, plan, { now: APPLIED_AT });
    const second = service.apply(input, plan, { now: APPLIED_AT });

    expect(second).toEqual(first);
    expect(first.updatedAt).toBe(APPLIED_TIMESTAMP);
    expect(first.appliedFindingId).toBe(plan.findingId);
    expect(input).toEqual(inputBefore);
    expect(plan).toEqual(planBefore);
  });
});

function entryPlan(
  entry: VaultEntry,
  fixCode: DataQualityFixCode,
  mutation: DataQualityFixMutation,
  findingCode: DataQualityFindingCode,
): DataQualityFixPlan {
  return {
    findingId: `entry:${entry.id}:${findingCode}:test`,
    fixCode,
    reference: entryReference(entry),
    mutation,
  };
}

function savedViewPlan(
  view: SavedViewRecord,
  mutation: Extract<DataQualityFixMutation, { kind: 'remove-saved-view-references' }>,
): DataQualityFixPlan {
  return {
    findingId: `saved-view:${view.id}:saved-view-orphan-reference:references`,
    fixCode: 'remove-saved-view-references',
    reference: savedViewReference(view),
    mutation,
  };
}

function attachmentPlan(
  entry: VaultEntry,
  mutation: Extract<DataQualityFixMutation, { kind: 'update-attachment-metadata' }>,
): DataQualityFixPlan {
  return {
    findingId: `attachment:attachment-1:attachment-metadata-mismatch:metadata`,
    fixCode: 'update-authenticated-attachment-metadata',
    reference: attachmentReference(entry),
    mutation,
  };
}

function entryReference(entry: VaultEntry): DataQualityReference {
  return {
    kind: 'entry',
    vaultId: entry.vaultId,
    entryId: entry.id,
    updatedAt: entry.updatedAt,
  };
}

function savedViewReference(view: SavedViewRecord): DataQualityReference {
  return {
    kind: 'saved-view',
    vaultId: view.vaultId,
    savedViewId: view.id,
    updatedAt: view.updatedAt,
  };
}

function attachmentReference(entry: VaultEntry): DataQualityReference {
  return {
    kind: 'attachment',
    vaultId: entry.vaultId,
    entryId: entry.id,
    attachmentId: 'attachment-1',
    updatedAt: entry.updatedAt,
  };
}

function snapshot(
  entries: VaultEntry[],
  savedViews: SavedViewRecord[] = [],
): DataQualityFixSnapshot {
  return {
    document: document(entries),
    savedViews,
  };
}

function document(entries: VaultEntry[]): VaultDocument {
  return {
    formatVersion: 2,
    id: 'vault-1',
    name: 'Privat',
    color: '#22d3c5',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: DOCUMENT_REVISION,
    folders: [],
    entries,
  };
}

function credentialEntry(
  options: {
    id?: string;
    title?: string;
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
        password: 'Strong!Password-12345',
        websites: options.websites ?? ['example.test'],
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

function creditCardEntry(): VaultEntry {
  return {
    ...credentialEntry({ id: 'card-entry' }),
    data: {
      type: 'credit-card',
      value: {
        cardName: 'Privatkarte',
        cardholder: '',
        number: '',
        expiryMonth: 12,
        expiryYear: 2030,
        cvc: '',
        pin: '',
        issuer: '',
        cardType: '',
        billingAddress: '',
        servicePhone: '',
        website: ' card.example.test ',
      },
    },
  };
}

function licenseEntry(): VaultEntry {
  return {
    ...credentialEntry({ id: 'license-entry' }),
    data: {
      type: 'software-license',
      value: {
        product: 'Kryptris',
        manufacturer: '',
        version: '',
        licenseKey: '',
        licensedTo: '',
        purchaseDate: '',
        activationDate: '',
        expiryDate: '',
        orderNumber: '',
        downloadUrl: ' download.example.test ',
        purchasePrice: '',
      },
    },
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
      tags: options.tags ?? ['Keep'],
      folderId: options.folderId ?? null,
      security: [],
      smartView: null,
    },
    order: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: VIEW_REVISION,
  };
}

function attachment(): AttachmentMetadata {
  return {
    id: 'attachment-1',
    name: 'original.bin',
    mediaType: 'application/octet-stream',
    size: 12,
    sha256: HASH_A,
    createdAt: '2026-01-01T00:00:00.000Z',
    previewable: false,
  };
}

function credentialWebsites(entry: VaultEntry): string[] {
  if (entry.data.type !== 'credential') throw new Error('Unerwarteter Typ.');
  return entry.data.value.websites;
}

function expectDataQualityError(action: () => unknown, code: DataQualityError['code']): void {
  try {
    action();
    throw new Error('Erwarteter DataQualityError wurde nicht ausgeloest.');
  } catch (error) {
    expect(error).toBeInstanceOf(DataQualityError);
    expect((error as DataQualityError).code).toBe(code);
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  return Object.freeze(value);
}
