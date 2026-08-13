import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { entryInputSchema, vaultDocumentV2Schema } from '../../src/shared/schemas';
import {
  parseVaultDocumentV1,
  parseVaultDocumentV2,
  readVaultDocumentFormatVersion,
} from '../../src/main/services/vault-service';
import { parseAuthenticatedVaultPackageDocument } from '../../src/main/services/vault-package-service';

const fixtures = path.resolve('tests', 'fixtures', 'migrations');
const vaultId = '10000000-0000-4000-8000-000000000001';

describe('VaultDocument V1/V2', () => {
  it('verwendet getrennte, strikte Leser ohne Werte zu normalisieren', async () => {
    const v1 = await readFixture('vault-document-v1.json');
    const v2 = await readFixture('vault-document-v2.json');

    expect(parseVaultDocumentV1(v1, vaultId)).toBe(v1);
    expect(parseVaultDocumentV2(v2, vaultId)).toBe(v2);
    expect(() => parseVaultDocumentV2(v1, vaultId)).toThrowError(
      expect.objectContaining({ code: 'UNSUPPORTED_FORMAT' }),
    );
    expect(() => parseVaultDocumentV1(v2, vaultId)).toThrowError(
      expect.objectContaining({ code: 'UNSUPPORTED_FORMAT' }),
    );
  });

  it('verlangt in V2 Lifecycle-Metadaten und lehnt unbekannte Felder ab', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const missingLifecycle = structuredClone(v2);
    const entries = missingLifecycle.entries as Array<Record<string, unknown>>;
    delete entries[0]?.lifecycle;
    const extraField = { ...v2, unrecognized: true };

    expect(() => parseVaultDocumentV2(missingLifecycle, vaultId)).toThrowError(
      expect.objectContaining({ code: 'CORRUPT_DATA' }),
    );
    expect(() => parseVaultDocumentV2(extraField, vaultId)).toThrowError(
      expect.objectContaining({ code: 'CORRUPT_DATA' }),
    );
  });

  it('ergänzt nur im bereits authentifizierten Paketdecoder fehlende historische V2-Lebenszyklen', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const missingLifecycle = structuredClone(v2);
    const entries = missingLifecycle.entries as Array<Record<string, unknown>>;
    delete entries[0]?.lifecycle;

    const parsed = parseAuthenticatedVaultPackageDocument(missingLifecycle);

    expect(parsed.entries[0]?.lifecycle).toEqual({
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    });
    expect(() => parseVaultDocumentV2(missingLifecycle, vaultId)).toThrowError(
      expect.objectContaining({ code: 'CORRUPT_DATA' }),
    );
  });

  it('lehnt im Paketdecoder partielle oder sonst ungültige V2-Lebenszyklen weiter ab', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const partialLifecycle = structuredClone(v2);
    const partialEntry = (partialLifecycle.entries as Array<Record<string, unknown>>)[0];
    if (partialEntry === undefined) throw new Error('Fixture-Eintrag fehlt');
    partialEntry.lifecycle = { rotationIntervalDays: null };

    const extraStoredField = structuredClone(v2);
    const entries = extraStoredField.entries as Array<Record<string, unknown>>;
    delete entries[0]?.lifecycle;
    entries[0]!.unrecognized = true;

    for (const invalid of [partialLifecycle, extraStoredField]) {
      expect(() => parseAuthenticatedVaultPackageDocument(invalid)).toThrowError(
        expect.objectContaining({ code: 'CORRUPT_DATA' }),
      );
    }
  });

  it('lehnt Zukunftsversionen fail-closed ab', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const future = { ...v2, formatVersion: 3 };

    expect(() => readVaultDocumentFormatVersion(future)).toThrowError(
      expect.objectContaining({ code: 'UNSUPPORTED_FORMAT' }),
    );
    expect(() => parseVaultDocumentV2(future, vaultId)).toThrowError(
      expect.objectContaining({ code: 'UNSUPPORTED_FORMAT' }),
    );
  });

  it('erzwingt typgebundene Lifecycle-Semantik im gespeicherten V2-Format', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const entry = (v2.entries as Array<Record<string, unknown>>)[0];
    if (entry === undefined) throw new Error('Fixture-Eintrag fehlt');

    const excludedWithSchedule = withLifecycle(v2, {
      rotationIntervalDays: 30,
      nextRotationDate: '2026-08-20',
      rotationExcluded: true,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    });
    const nextWithoutInterval = withLifecycle(v2, {
      rotationIntervalDays: null,
      nextRotationDate: '2026-08-20',
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    });
    const nonCredentialRotation = structuredClone(v2);
    const nonCredentialEntry = (nonCredentialRotation.entries as Array<Record<string, unknown>>)[0];
    if (nonCredentialEntry === undefined) throw new Error('Fixture-Eintrag fehlt');
    nonCredentialEntry.data = { type: 'file', value: { description: 'Datei' } };
    nonCredentialEntry.lifecycle = {
      rotationIntervalDays: 30,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'inactive',
      expiryReminderDate: null,
    };
    const credentialExpiry = withLifecycle(v2, {
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: '2026-08-20',
    });

    for (const invalid of [
      excludedWithSchedule,
      nextWithoutInterval,
      nonCredentialRotation,
      credentialExpiry,
    ]) {
      expect(vaultDocumentV2Schema.safeParse(invalid).success).toBe(false);
    }
  });

  it('lehnt dieselben ungültigen Kombinationen am normalen Eingaberand ab', async () => {
    const v2 = await readFixture('vault-document-v2.json');
    const stored = (v2.entries as Array<Record<string, unknown>>)[0];
    if (stored === undefined) throw new Error('Fixture-Eintrag fehlt');
    const {
      vaultId: ignoredVaultId,
      attachments: ignoredAttachments,
      createdAt: ignoredCreatedAt,
      updatedAt: ignoredUpdatedAt,
      secretChangedAt: ignoredSecretChangedAt,
      lastUsedAt: ignoredLastUsedAt,
      deletedAt: ignoredDeletedAt,
      ...input
    } = stored;
    void ignoredVaultId;
    void ignoredAttachments;
    void ignoredCreatedAt;
    void ignoredUpdatedAt;
    void ignoredSecretChangedAt;
    void ignoredLastUsedAt;
    void ignoredDeletedAt;
    input.lifecycle = {
      rotationIntervalDays: null,
      nextRotationDate: '2026-08-20',
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: null,
    };

    expect(entryInputSchema.safeParse(input).success).toBe(false);
  });
});

async function readFixture(fileName: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path.join(fixtures, fileName), 'utf8')) as Record<
    string,
    unknown
  >;
}

function withLifecycle(
  document: Record<string, unknown>,
  lifecycle: Record<string, unknown>,
): Record<string, unknown> {
  const result = structuredClone(document);
  const entry = (result.entries as Array<Record<string, unknown>>)[0];
  if (entry === undefined) throw new Error('Fixture-Eintrag fehlt');
  entry.lifecycle = lifecycle;
  return result;
}
