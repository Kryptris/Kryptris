import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { EntryInput, VaultEntry } from '../../src/shared/models';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';

const roots: string[] = [];

describe('VaultService Secret-Lifecycle', () => {
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });

  it('terminiert nur echte Secret-Änderungen neu und ignoriert Username, URL und TOTP-Anzeige', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-secret-lifecycle-'));
    roots.push(root);
    const profile = new ProfileService({
      rootDir: root,
      keyDerivation: new KeyDerivationService({
        parameters: {
          algorithm: 'argon2id',
          memorySizeKiB: 64,
          iterations: 1,
          parallelism: 1,
          hashLength: 32,
        },
        allowUnsafeParametersForTests: true,
      }),
    });
    const pending = await profile.beginSetup('Sehr langes Lifecycle-Master-Passwort!', false);
    await profile.completeSetup(pending.pendingId, {});
    let now = new Date('2026-01-01T12:00:00.000Z');
    const vaults = new VaultService({ rootDir: root, profileService: profile, now: () => now });
    const vault = await vaults.createVault('Lifecycle', '#14b8a6');
    const created = await vaults.createEntry(vault.id, {
      title: 'Zugang',
      folderId: null,
      tags: [],
      favorite: false,
      note: '',
      customFields: [],
      data: {
        type: 'credential',
        value: {
          username: 'first@example.invalid',
          password: 'Initial-Secret!123',
          websites: ['https://first.example.invalid'],
          appNames: [],
          totp: {
            secret: 'JBSWY3DPEHPK3PXP',
            issuer: 'Erster Anzeigename',
            account: 'first@example.invalid',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
          },
        },
      },
      lifecycle: {
        rotationIntervalDays: 30,
        nextRotationDate: null,
        rotationExcluded: false,
        twoFactorStatus: 'active',
        expiryReminderDate: null,
      },
    });
    if (created.data.type !== 'credential') throw new Error('Credential-Fixture erwartet');
    expect(created.secretChangedAt).toBe('2026-01-01T12:00:00.000Z');
    expect(created.lifecycle.nextRotationDate).toBe('2026-01-31');

    now = new Date('2026-02-01T12:00:00.000Z');
    const displayOnly = await vaults.updateEntry(vault.id, created.id, {
      ...toInput(created),
      title: 'Umbenannt',
      data: {
        type: 'credential',
        value: {
          ...created.data.value,
          username: 'second@example.invalid',
          websites: ['https://second.example.invalid'],
          totp: {
            ...created.data.value.totp!,
            issuer: 'Zweiter Anzeigename',
            account: 'second@example.invalid',
          },
        },
      },
    });
    if (displayOnly.data.type !== 'credential') throw new Error('Credential-Fixture erwartet');
    expect(displayOnly.secretChangedAt).toBe(created.secretChangedAt);
    expect(displayOnly.lifecycle.nextRotationDate).toBe('2026-01-31');

    now = new Date('2026-03-01T12:00:00.000Z');
    const secretChanged = await vaults.updateEntry(vault.id, created.id, {
      ...toInput(displayOnly),
      data: {
        type: 'credential',
        value: { ...displayOnly.data.value, password: 'Changed-Secret!456' },
      },
    });
    expect(secretChanged.secretChangedAt).toBe('2026-03-01T12:00:00.000Z');
    expect(secretChanged.lifecycle.nextRotationDate).toBe('2026-03-31');
  });
});

function toInput(entry: VaultEntry): EntryInput {
  return {
    title: entry.title,
    folderId: entry.folderId,
    tags: [...entry.tags],
    favorite: entry.favorite,
    note: entry.note,
    customFields: structuredClone(entry.customFields),
    data: structuredClone(entry.data),
    lifecycle: structuredClone(entry.lifecycle),
  };
}
