import { describe, expect, it } from 'vitest';

import {
  DUPLICATE_REASON_CODES,
  DuplicateService,
  type DuplicateMatcher,
  type DuplicateReasonCode,
} from '../../src/main/services/duplicate-service';
import { emptyEntryData } from '../../src/main/services/entry-utils';
import { VaultaError } from '../../src/shared/errors';
import {
  createDefaultEntryLifecycleMetadata,
  ENTRY_TYPES,
  type AttachmentMetadata,
  type CustomField,
  type EntryType,
  type VaultEntry,
} from '../../src/shared/models';

const CREATED_AT = '2026-01-01T00:00:00.000Z';
const UPDATED_AT = '2026-02-01T00:00:00.000Z';
const MERGED_AT = '2026-03-01T00:00:00.000Z';

describe('DuplicateService scan', () => {
  it('findet typspezifische Dubletten für alle neun Eintragstypen', async () => {
    const entries: VaultEntry[] = [];
    const expectedReasons = new Map<EntryType, DuplicateReasonCode>([
      ['credential', 'credential-username'],
      ['secure-note', 'secure-note-content'],
      ['credit-card', 'credit-card-number'],
      ['identity', 'identity-email'],
      ['wifi', 'wifi-ssid'],
      ['software-license', 'software-license-key'],
      ['ssh-key', 'ssh-fingerprint'],
      ['file', 'file-attachment'],
      ['custom', 'custom-secret-field'],
    ]);

    for (const type of ENTRY_TYPES) entries.push(...matchingPair(type));
    const result = await new DuplicateService().scan(entries);

    expect(result.candidates).toHaveLength(ENTRY_TYPES.length);
    expect(result.truncated).toBe(false);
    for (const type of ENTRY_TYPES) {
      const candidate = result.candidates.find((value) => value.type === type);
      expect(candidate?.reasons).toContain(expectedReasons.get(type));
      expect(candidate?.left.entryId.localeCompare(candidate.right.entryId, 'en')).toBeLessThan(0);
    }
  });

  it('schließt Papierkorb-Einträge sowie reine Titelgleichheit aus und mischt keine Typen', async () => {
    const active = baseEntry('credential', 'active', 'Nur Titel');
    const sameTitle = baseEntry('credential', 'same-title', 'nur   titel');
    const trashed = matchingPair('credential')[1];
    trashed.id = 'trashed';
    trashed.deletedAt = UPDATED_AT;
    const otherType = baseEntry('custom', 'custom', 'Nur Titel');

    const result = await new DuplicateService().scan([active, sameTitle, trashed, otherType]);

    expect(result.activeEntryCount).toBe(3);
    expect(result.candidates).toEqual([]);
  });

  it('normalisiert NFKC, Whitespace, Groß-/Kleinschreibung und alle Website-Hosts konservativ', async () => {
    const left = baseEntry('credential', 'left', 'Ｐｏｒｔａｌ   Ａｃｍｅ');
    const right = baseEntry('credential', 'right', ' portal acme ');
    if (left.data.type !== 'credential' || right.data.type !== 'credential') throw new Error();
    left.data.value.websites = ['https://irrelevant.test/login', 'https://EXAMPLE.com:443/a'];
    right.data.value.websites = ['example.com/b'];

    const result = await new DuplicateService().scan([right, left]);

    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.left.entryId).toBe('left');
    expect(result.candidates[0]?.right.entryId).toBe('right');
    expect(result.candidates[0]?.reasons).toEqual(['title', 'credential-website-host']);
  });

  it('redigiert Geheimnis-Canaries und löscht den scanlokalen HMAC-Schlüssel', async () => {
    const canary = 'CANARY-SECRET-do-not-return';
    const key = Buffer.alloc(32, 0xa5);
    const progress: unknown[] = [];
    const left = baseEntry('credential', 'left', 'Links');
    const right = baseEntry('credential', 'right', 'Rechts');
    if (left.data.type !== 'credential' || right.data.type !== 'credential') throw new Error();
    left.data.value.username = right.data.value.username = 'matching-user';
    left.data.value.password = right.data.value.password = canary;

    const result = await new DuplicateService({ createHmacKey: () => key }).scan([left, right], {
      onProgress: (value) => progress.push(value),
    });

    expect(result.candidates[0]?.reasons).toEqual(['credential-username', 'credential-password']);
    expect(JSON.stringify({ result, progress })).not.toContain(canary);
    expect([...key]).toEqual(Array.from({ length: 32 }, () => 0));
    expect(
      result.candidates[0]?.reasons.every((reason) => DUPLICATE_REASON_CODES.includes(reason)),
    ).toBe(true);
  });

  it('invalidiert einen synchronen Matcher samt HMAC-Schlüssel nach dem Callback', () => {
    const canary = 'CANARY-MATCHER-SECRET';
    const key = Buffer.alloc(32, 0x37);
    const left = baseEntry('credential', 'left', 'Links');
    const right = baseEntry('credential', 'right', 'Rechts');
    if (left.data.type !== 'credential' || right.data.type !== 'credential') throw new Error();
    left.data.value.username = right.data.value.username = 'matching-user';
    left.data.value.password = right.data.value.password = canary;
    const service = new DuplicateService({ createHmacKey: () => key });
    let retained: DuplicateMatcher | undefined;

    const result = service.withMatcher((matcher) => {
      retained = matcher;
      expect(matcher.add(left)).toEqual([]);
      return matcher.add(right);
    });

    expect(result[0]?.reasons).toEqual(['credential-username', 'credential-password']);
    expect(JSON.stringify(result)).not.toContain(canary);
    expect(key.every((value) => value === 0)).toBe(true);
    if (retained === undefined) throw new Error('Matcher wurde nicht bereitgestellt.');
    const invalidatedMatcher = retained;
    expect(() => invalidatedMatcher.add(right)).toThrowError(/nicht mehr aktiv/u);
  });

  it('priorisiert Abbruch nach einem Yield und löscht auch dann den HMAC-Schlüssel', async () => {
    const controller = new AbortController();
    const key = Buffer.alloc(32, 0x7c);
    let yields = 0;
    let authorizationChecks = 0;
    const entries = Array.from({ length: 129 }, (_, index) =>
      baseEntry('custom', `entry-${String(index).padStart(3, '0')}`, `Titel ${String(index)}`),
    );
    const service = new DuplicateService({
      createHmacKey: () => key,
      yieldControl: () => {
        yields += 1;
        controller.abort();
        return Promise.resolve();
      },
    });

    await expect(
      service.scan(entries, {
        signal: controller.signal,
        assertAuthorized: () => {
          authorizationChecks += 1;
        },
      }),
    ).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(yields).toBe(1);
    expect(authorizationChecks).toBeGreaterThan(1);
    expect(key.every((value) => value === 0)).toBe(true);
  });

  it('liefert bei einem Limit deterministische, eindeutige Paare und markiert die Kürzung', async () => {
    const entries = Array.from({ length: 6 }, (_, index) => {
      const entry = baseEntry('credential', `entry-${String(index)}`, 'Gemeinsam');
      if (entry.data.type !== 'credential') throw new Error();
      entry.data.value.username = 'same-user';
      entry.data.value.password = 'same-secret';
      return entry;
    });
    const service = new DuplicateService();

    const forward = await service.scan(entries, { candidateLimit: 4 });
    const backward = await service.scan([...entries].reverse(), { candidateLimit: 4 });

    expect(forward).toEqual(backward);
    expect(forward.candidates).toHaveLength(4);
    expect(forward.truncated).toBe(true);
    const pairKeys = forward.candidates.map((candidate) =>
      JSON.stringify([candidate.left, candidate.right]),
    );
    expect(new Set(pairKeys).size).toBe(pairKeys.length);
  });

  it('löscht den HMAC-Schlüssel auch bei einem Sperrfehler', async () => {
    const key = Buffer.alloc(32, 0x44);
    const service = new DuplicateService({ createHmacKey: () => key });
    let checks = 0;

    await expect(
      service.scan(matchingPair('wifi'), {
        assertAuthorized: () => {
          checks += 1;
          if (checks > 1) throw new VaultaError('LOCKED', 'Gesperrt.');
        },
      }),
    ).rejects.toMatchObject({ code: 'LOCKED' });
    expect(key.every((value) => value === 0)).toBe(true);
  });
});

describe('DuplicateService merge', () => {
  it('beschreibt nur feste Felder, Kollisionen und verifizierungsbedürftige Anhangspaare', () => {
    const canary = 'CANARY-MERGE-SECRET';
    const survivor = baseEntry('credential', 'survivor', 'Links');
    const duplicate = baseEntry('credential', 'duplicate', 'Rechts');
    survivor.customFields = [customField('collision', 'A', 'links')];
    duplicate.customFields = [customField('collision', 'B', canary, true)];
    survivor.attachments = [attachment('attachment-left', 'same-hash')];
    duplicate.attachments = [
      attachment('attachment-left', 'different-hash'),
      attachment('attachment-same', 'same-hash'),
    ];

    const description = new DuplicateService().describeMerge(survivor, duplicate);

    expect(description.scalarFields).toContainEqual({ field: 'credential.password', secret: true });
    expect(description.collectionFields.map((field) => field.field)).toContain(
      'credential.websites',
    );
    expect(description.idCollisions).toEqual({
      customFieldIds: ['collision'],
      identityAddressIds: [],
      attachmentIds: ['attachment-left'],
    });
    expect(description.potentialAttachmentDuplicates).toEqual([
      {
        duplicateAttachmentId: 'attachment-same',
        survivorAttachmentId: 'attachment-left',
      },
    ]);
    expect(description.duplicateDisposition).toBe('trash');
    expect(JSON.stringify(description)).not.toContain(canary);
  });

  it('plant stabile Unions ohne Eingaben zu verändern und bildet Anhangkopien explizit ab', () => {
    const survivor = baseEntry('credential', 'survivor', 'Links');
    const duplicate = baseEntry('credential', 'duplicate', 'Rechts');
    survivor.tags = ['Arbeit', 'Privat'];
    duplicate.tags = [' arbeit ', 'Team'];
    survivor.note = 'Erster Hinweis';
    duplicate.note = 'Zweiter Hinweis';
    survivor.customFields = [
      customField('field-equivalent-left', 'Account', 'alpha'),
      customField('field-collision', 'Alt', 'links'),
    ];
    duplicate.customFields = [
      customField('field-equivalent-right', ' account ', 'alpha'),
      customField('field-collision', 'Neu', 'rechts'),
      customField('field-extra', 'Region', 'EU'),
    ];
    survivor.attachments = [attachment('attachment-left', 'same-hash')];
    duplicate.attachments = [
      attachment('attachment-equivalent', 'same-hash'),
      attachment('attachment-new', 'new-hash'),
    ];
    if (survivor.data.type !== 'credential' || duplicate.data.type !== 'credential') {
      throw new Error();
    }
    survivor.data.value.password = duplicate.data.value.password = 'unchanged-secret';
    survivor.data.value.websites = ['https://EXAMPLE.test/'];
    duplicate.data.value.websites = ['https://example.test', 'https://other.test/login'];
    const survivorBefore = structuredClone(survivor);
    const duplicateBefore = structuredClone(duplicate);

    const plan = new DuplicateService().planMerge({
      survivor,
      duplicate,
      now: MERGED_AT,
      fieldChoices: [{ field: 'credential.username', source: 'duplicate' }],
      collectionChoices: [
        { field: 'tags', strategy: 'union' },
        { field: 'note', strategy: 'union' },
        { field: 'customFields', strategy: 'union' },
        { field: 'attachments', strategy: 'union' },
        { field: 'credential.websites', strategy: 'union' },
      ],
      customFieldIdReplacements: [
        { sourceId: 'field-collision', targetId: 'field-collision-copy' },
      ],
      attachmentIdReplacements: [{ sourceId: 'attachment-new', targetId: 'attachment-new-copy' }],
      verifiedAttachmentDuplicates: [
        {
          duplicateAttachmentId: 'attachment-equivalent',
          survivorAttachmentId: 'attachment-left',
        },
      ],
    });

    expect(survivor).toEqual(survivorBefore);
    expect(duplicate).toEqual(duplicateBefore);
    expect(plan.survivor.tags).toEqual(['Arbeit', 'Privat', 'Team']);
    expect(plan.survivor.note).toBe('Erster Hinweis\n\nZweiter Hinweis');
    expect(plan.survivor.customFields.map((field) => field.id)).toEqual([
      'field-equivalent-left',
      'field-collision',
      'field-collision-copy',
      'field-extra',
    ]);
    expect(plan.survivor.attachments.map((value) => value.id)).toEqual([
      'attachment-left',
      'attachment-new-copy',
    ]);
    expect(plan.survivor.data.type).toBe('credential');
    if (plan.survivor.data.type !== 'credential') throw new Error();
    expect(plan.survivor.data.value.websites).toEqual([
      'https://EXAMPLE.test/',
      'https://other.test/login',
    ]);
    expect(plan.attachmentCopies).toEqual([
      {
        sourceVaultId: duplicate.vaultId,
        sourceAttachmentId: 'attachment-new',
        targetVaultId: survivor.vaultId,
        targetAttachmentId: 'attachment-new-copy',
      },
    ]);
    expect(plan.changedSecretSemantics).toBe(false);
    expect(plan.survivor.secretChangedAt).toBe(UPDATED_AT);
    expect(plan.duplicate.deletedAt).toBe(MERGED_AT);
    expect(plan.duplicateDisposition).toBe('trash');
  });

  it('aktualisiert secretChangedAt ausschließlich bei geänderter Geheimnis-Semantik', () => {
    const survivor = baseEntry('credential', 'survivor', 'Links');
    const duplicate = baseEntry('credential', 'duplicate', 'Rechts');
    if (survivor.data.type !== 'credential' || duplicate.data.type !== 'credential') {
      throw new Error();
    }
    survivor.data.value.password = 'secret-left';
    duplicate.data.value.password = 'secret-left';
    const service = new DuplicateService();

    const equalSecret = service.planMerge({
      survivor,
      duplicate,
      now: MERGED_AT,
      fieldChoices: [{ field: 'credential.password', source: 'duplicate' }],
    });
    duplicate.data.value.password = 'secret-right';
    const changedSecret = service.planMerge({
      survivor,
      duplicate,
      now: MERGED_AT,
      fieldChoices: [{ field: 'credential.password', source: 'duplicate' }],
    });

    expect(equalSecret.changedSecretSemantics).toBe(false);
    expect(equalSecret.survivor.secretChangedAt).toBe(UPDATED_AT);
    expect(changedSecret.changedSecretSemantics).toBe(true);
    expect(changedSecret.survivor.secretChangedAt).toBe(MERGED_AT);
  });

  it('verlangt für mehrdeutige IDs explizite Auflösungen und lässt Quellen unverändert', () => {
    const survivor = baseEntry('custom', 'survivor', 'Links');
    const duplicate = baseEntry('custom', 'duplicate', 'Rechts');
    survivor.customFields = [customField('collision', 'A', 'links')];
    duplicate.customFields = [customField('collision', 'B', 'rechts')];
    survivor.attachments = [attachment('left-attachment', 'left-hash')];
    duplicate.attachments = [attachment('source-attachment', 'right-hash')];
    const survivorBefore = structuredClone(survivor);
    const duplicateBefore = structuredClone(duplicate);
    const service = new DuplicateService();

    expect(() =>
      service.planMerge({
        survivor,
        duplicate,
        now: MERGED_AT,
        collectionChoices: [{ field: 'customFields', strategy: 'union' }],
      }),
    ).toThrowError(VaultaError);
    expect(() =>
      service.planMerge({
        survivor,
        duplicate,
        now: MERGED_AT,
        collectionChoices: [{ field: 'attachments', strategy: 'union' }],
      }),
    ).toThrowError(/reservierte Ziel-ID/u);
    expect(survivor).toEqual(survivorBefore);
    expect(duplicate).toEqual(duplicateBefore);
  });

  it('weist Typmischung, Papierkorb und fremde Ordner bei Cross-Vault-Merge ab', () => {
    const survivor = baseEntry('credential', 'survivor', 'Links');
    const differentType = baseEntry('wifi', 'wifi', 'WLAN');
    const duplicate = baseEntry('credential', 'duplicate', 'Rechts');
    duplicate.vaultId = 'other-vault';
    duplicate.folderId = 'foreign-folder';
    const service = new DuplicateService();

    expect(() => service.describeMerge(survivor, differentType)).toThrowError(/desselben Typs/u);
    expect(() =>
      service.planMerge({
        survivor,
        duplicate,
        now: MERGED_AT,
        fieldChoices: [{ field: 'folderId', source: 'duplicate' }],
      }),
    ).toThrowError(/anderen Tresor/u);
    duplicate.deletedAt = UPDATED_AT;
    expect(() => service.describeMerge(survivor, duplicate)).toThrowError(/Papierkorb/u);
  });
});

function matchingPair(type: EntryType): [VaultEntry, VaultEntry] {
  const left = baseEntry(type, `${type}-left`, `${type} links`);
  const right = baseEntry(type, `${type}-right`, `${type} rechts`);
  if (left.data.type !== type || right.data.type !== type) throw new Error();

  switch (type) {
    case 'credential':
      if (left.data.type !== 'credential' || right.data.type !== 'credential') throw new Error();
      left.data.value.username = right.data.value.username = 'user@example.test';
      left.data.value.websites = ['https://first.test', 'https://shared.test/login'];
      right.data.value.websites = ['https://shared.test/account'];
      break;
    case 'secure-note':
      if (left.data.type !== 'secure-note' || right.data.type !== 'secure-note') throw new Error();
      left.data.value.markdown = right.data.value.markdown = 'Gleicher geschützter Inhalt';
      break;
    case 'credit-card':
      if (left.data.type !== 'credit-card' || right.data.type !== 'credit-card') throw new Error();
      left.data.value.number = '4111 1111 1111 1111';
      right.data.value.number = '4111-1111-1111-1111';
      break;
    case 'identity':
      if (left.data.type !== 'identity' || right.data.type !== 'identity') throw new Error();
      left.data.value.emails = ['person@example.test'];
      right.data.value.emails = [' PERSON@example.test '];
      break;
    case 'wifi':
      if (left.data.type !== 'wifi' || right.data.type !== 'wifi') throw new Error();
      left.data.value.ssid = 'Office WLAN';
      right.data.value.ssid = ' office   wlan ';
      left.data.value.password = right.data.value.password = 'wifi-secret';
      break;
    case 'software-license':
      if (left.data.type !== 'software-license' || right.data.type !== 'software-license') {
        throw new Error();
      }
      left.data.value.licenseKey = right.data.value.licenseKey = 'LICENSE-SECRET';
      break;
    case 'ssh-key':
      if (left.data.type !== 'ssh-key' || right.data.type !== 'ssh-key') throw new Error();
      left.data.value.fingerprint = 'SHA256:shared';
      right.data.value.fingerprint = ' sha256:SHARED ';
      break;
    case 'file':
      left.attachments = [attachment('file-left', 'shared-hash')];
      right.attachments = [attachment('file-right', 'shared-hash')];
      break;
    case 'custom':
      left.customFields = [customField('custom-left', 'API Token', 'token-value', true)];
      right.customFields = [customField('custom-right', 'api token', 'token-value', true)];
      break;
  }
  return [left, right];
}

function baseEntry(type: EntryType, id: string, title: string): VaultEntry {
  return {
    id,
    vaultId: 'vault-main',
    title,
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    attachments: [],
    data: emptyEntryData(type),
    lifecycle: createDefaultEntryLifecycleMetadata(),
    createdAt: CREATED_AT,
    updatedAt: UPDATED_AT,
    secretChangedAt: UPDATED_AT,
    lastUsedAt: null,
    deletedAt: null,
  };
}

function customField(id: string, label: string, value: string, secret = false): CustomField {
  return {
    id,
    label,
    type: secret ? 'secret' : 'text',
    value,
    secret,
    searchable: !secret,
    order: 0,
  };
}

function attachment(id: string, sha256: string): AttachmentMetadata {
  return {
    id,
    name: `${id}.bin`,
    mediaType: 'application/octet-stream',
    size: 42,
    sha256,
    createdAt: CREATED_AT,
    previewable: false,
  };
}
