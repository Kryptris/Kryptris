import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { VaultaError } from '../../src/shared/errors';
import { ENTRY_TYPES, type EntryInput } from '../../src/shared/models';
import { entryInputSchema } from '../../src/shared/schemas';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AuditService } from '../../src/main/services/audit-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const roots: string[] = [];

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

async function setupProfile(root: string): Promise<{
  profile: ProfileService;
  recoveryKey: string;
}> {
  const profile = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
  const pending = await profile.beginSetup('Richtig langes Master-Passwort!', true);
  if (pending.recovery === null) throw new Error('Recovery setup missing');
  const confirmation = Object.fromEntries(
    pending.recovery.confirmationIndexes.map((index) => [
      String(index),
      pending.recovery?.groups[index],
    ]),
  ) as Record<string, string>;
  await profile.completeSetup(pending.pendingId, confirmation);
  return { profile, recoveryKey: pending.recovery.displayKey };
}

function allEntryInputs(): EntryInput[] {
  const common = (index: number, title: string) => ({
    id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    title,
    folderId: null,
    tags: ['Roundtrip', `Typ-${String(index)}`],
    favorite: index % 2 === 0,
    note: `Verschluesselte Notiz ${String(index)}`,
    customFields: [],
  });
  return [
    {
      ...common(1, 'Zugang Roundtrip'),
      data: {
        type: 'credential',
        value: {
          username: 'roundtrip@example.invalid',
          password: 'Roundtrip-Credential-Secret!1',
          websites: ['https://example.invalid/login'],
          appNames: ['Vaulta Test'],
          totp: {
            secret: 'JBSWY3DPEHPK3PXP',
            issuer: 'Vaulta',
            account: 'roundtrip@example.invalid',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
          },
        },
      },
    },
    {
      ...common(2, 'Sichere Notiz Roundtrip'),
      data: {
        type: 'secure-note',
        value: { markdown: '# Sicher\n\n**Nur lokal** und <script>niemals HTML</script>.' },
      },
    },
    {
      ...common(3, 'Kreditkarte Roundtrip'),
      data: {
        type: 'credit-card',
        value: {
          cardName: 'Reisekarte',
          cardholder: 'Erika Mustermann',
          number: '4111111111111111',
          expiryMonth: 12,
          expiryYear: 2032,
          cvc: '123',
          pin: '9876',
          issuer: 'Vaulta Bank',
          cardType: 'Visa',
          billingAddress: 'Teststrasse 1, 10115 Berlin',
          servicePhone: '+49 30 123456',
          website: 'https://bank.example.invalid',
        },
      },
    },
    {
      ...common(4, 'Identitaet Roundtrip'),
      data: {
        type: 'identity',
        value: {
          salutation: 'Frau',
          firstName: 'Erika',
          middleName: 'Maria',
          lastName: 'Mustermann',
          birthDate: '1990-02-03',
          emails: ['erika@example.invalid'],
          phones: ['+49 170 1234567'],
          addresses: [
            {
              id: '10000000-0000-4000-8000-000000000004',
              label: 'Privat',
              street: 'Teststrasse 1',
              postalCode: '10115',
              city: 'Berlin',
              region: 'Berlin',
              country: 'Deutschland',
            },
          ],
          idNumber: 'ID-ROUNDTRIP',
          passportNumber: 'PASS-ROUNDTRIP',
          taxNumber: 'TAX-ROUNDTRIP',
        },
      },
    },
    {
      ...common(5, 'WLAN Roundtrip'),
      data: {
        type: 'wifi',
        value: {
          ssid: 'Vaulta-Roundtrip',
          password: 'WLAN-Roundtrip-Secret!5',
          security: 'WPA3',
          hidden: true,
          routerAddress: '192.0.2.1',
          routerUsername: 'router-admin',
        },
      },
    },
    {
      ...common(6, 'Softwarelizenz Roundtrip'),
      data: {
        type: 'software-license',
        value: {
          product: 'Vaulta IDE',
          manufacturer: 'Vaulta Labs',
          version: '6.0',
          licenseKey: 'LICENSE-ROUNDTRIP-SECRET-6',
          licensedTo: 'Erika Mustermann',
          purchaseDate: '2026-01-02',
          activationDate: '2026-01-03',
          expiryDate: '2027-01-02',
          orderNumber: 'ORDER-6000',
          downloadUrl: 'https://download.example.invalid/vaulta',
          purchasePrice: '99,00 EUR',
        },
      },
    },
    {
      ...common(7, 'SSH Roundtrip'),
      data: {
        type: 'ssh-key',
        value: {
          host: 'ssh.example.invalid',
          port: 2222,
          username: 'deploy',
          keyType: 'ed25519',
          fingerprint: 'SHA256:ROUNDTRIP',
          publicKey: 'ssh-ed25519 AAAA-ROUNDTRIP-PUBLIC',
          privateKey:
            '-----BEGIN OPENSSH PRIVATE KEY-----\nROUNDTRIP-SECRET\n-----END OPENSSH PRIVATE KEY-----',
          passphrase: 'SSH-Roundtrip-Passphrase!7',
        },
      },
    },
    {
      ...common(8, 'Datei Roundtrip'),
      data: { type: 'file', value: { description: 'Dokumentcontainer fuer mehrere Anhaenge' } },
    },
    {
      ...common(9, 'Sonstiger Roundtrip'),
      customFields: [
        {
          id: '20000000-0000-4000-8000-000000000001',
          label: 'Suchbarer Text',
          type: 'text',
          value: 'Frei definierter Text',
          secret: false,
          searchable: true,
          order: 0,
        },
        {
          id: '20000000-0000-4000-8000-000000000002',
          label: 'Maskiertes Geheimnis',
          type: 'secret',
          value: 'CUSTOM-FIELD-ROUNDTRIP-SECRET',
          secret: true,
          searchable: false,
          order: 1,
        },
        {
          id: '20000000-0000-4000-8000-000000000003',
          label: 'URL',
          type: 'url',
          value: 'https://custom.example.invalid',
          secret: false,
          searchable: true,
          order: 2,
        },
        {
          id: '20000000-0000-4000-8000-000000000004',
          label: 'Zahl',
          type: 'number',
          value: 4711,
          secret: false,
          searchable: false,
          order: 3,
        },
        {
          id: '20000000-0000-4000-8000-000000000005',
          label: 'Datum',
          type: 'date',
          value: '2026-07-14',
          secret: false,
          searchable: false,
          order: 4,
        },
        {
          id: '20000000-0000-4000-8000-000000000006',
          label: 'Ein/Aus',
          type: 'boolean',
          value: true,
          secret: false,
          searchable: false,
          order: 5,
        },
      ],
      data: { type: 'custom', value: { description: 'Freier Basistyp' } },
    },
  ];
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Profil- und Tresorpersistenz', () => {
  it('gated den Profil-Key kryptografisch, übersteht Masterwechsel und setzt Faktoren bei Recovery zurück', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-profile-'));
    roots.push(root);
    const { profile, recoveryKey } = await setupProfile(root);
    const prfSecret = Buffer.alloc(32, 42);
    await profile.setProtectedMetadata('factors', {
      totpSecret: 'JBSWY3DPEHPK3PXP',
    });
    await profile.setPublicFactorData({ credentials: [{ keyId: 'key-1', mode: 'prf' }] });
    await profile.addAdditionalKeyWrap({
      keyId: 'key-1',
      secret: prfSecret,
      requireForUnlock: true,
    });
    await profile.changeMasterPassword(
      'Richtig langes Master-Passwort!',
      'Noch längeres neues Master-Passwort!',
    );
    profile.lock();

    expect(await profile.verifyMasterPassword('Richtig langes Master-Passwort!')).toBe(false);
    expect(await profile.verifyMasterPassword('Noch längeres neues Master-Passwort!')).toBe(true);
    expect(
      await profile.getPublicFactorDataWithMasterPassword<unknown>(
        'Noch längeres neues Master-Passwort!',
      ),
    ).not.toBeNull();
    await expect(profile.getPublicFactorData()).rejects.toMatchObject({ code: 'LOCKED' });
    await expect(profile.unlock('Noch längeres neues Master-Passwort!')).rejects.toMatchObject({
      code: 'AUTH_FACTOR_REQUIRED',
    });
    await profile.unlock('Noch längeres neues Master-Passwort!', {
      keyId: 'key-1',
      secret: prfSecret,
    });
    expect(await profile.getProtectedMetadata('factors')).not.toBeNull();

    profile.lock();
    await profile.recover(recoveryKey, 'Master nach Wiederherstellung!');
    expect(await profile.getProtectedMetadata('factors')).toBeNull();
    expect(await profile.getPublicFactorData()).toBeNull();
    expect(await profile.getAccessPolicy()).toEqual({
      recoveryEnabled: true,
      masterOnlyAccess: true,
      additionalKeyIds: [],
    });
  });

  it('speichert Tresorinhalte ausschließlich verschlüsselt und behält den letzten bestätigten Stand bei Schreibfehler', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-vault-'));
    roots.push(root);
    const { profile } = await setupProfile(root);
    const vaults = new VaultService({ rootDir: root, profileService: profile });
    const vault = await vaults.createVault('Privat', '#2DD4BF');
    const entry: EntryInput = {
      title: 'Sehr geheimer Dienst',
      folderId: null,
      tags: ['privat'],
      favorite: true,
      note: 'Darf nicht auf der Festplatte stehen',
      customFields: [],
      data: {
        type: 'credential',
        value: {
          username: 'alice@example.test',
          password: 'SuperGeheim!123',
          websites: ['https://example.test'],
          appNames: [],
        },
      },
    };
    await vaults.createEntry(vault.id, entry);
    const diskBytes = await readFile(path.join(root, 'vaults', `${vault.id}.vaulta`), 'utf8');
    expect(diskBytes).not.toContain('SuperGeheim!123');
    expect(diskBytes).not.toContain('Sehr geheimer Dienst');

    const failingVaults = new VaultService({
      rootDir: root,
      profileService: profile,
      atomicWriter: new AtomicFileWriter({
        beforeReplace: () => {
          throw new Error('simulierter Stromausfall');
        },
      }),
    });
    await expect(
      failingVaults.updateVault(vault.id, { name: 'Nicht bestätigt', color: '#8B5CF6' }),
    ).rejects.toThrow('simulierter Stromausfall');
    expect((await vaults.readVault(vault.id)).name).toBe('Privat');
    const directoryEntries = await readdir(path.join(root, 'vaults'));
    expect(directoryEntries.some((name) => name.includes('.vaulta-tmp-'))).toBe(false);
  });

  it('verwirft einen nicht gemeinsam bestaetigten Tresor-/Schluesselstand', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-vault-consistency-'));
    roots.push(root);
    const { profile } = await setupProfile(root);
    const vaults = new VaultService({ rootDir: root, profileService: profile });
    await vaults.createVault('Privat', '#2DD4BF');
    const registry = await profile.getProtectedMetadata<Record<string, string>>('vault-keys');
    expect(registry).not.toBeNull();
    await profile.setProtectedMetadata('vault-keys', {
      ...(registry ?? {}),
      'ghost-vault': Buffer.alloc(32, 7).toString('base64'),
    });

    await expect(vaults.validateStorageConsistency()).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('erhaelt alle neun Eintragstypen und freien Felder containergenau ueber Sperren und Neustart', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-all-entry-types-'));
    roots.push(root);
    const { profile } = await setupProfile(root);
    const vaults = new VaultService({ rootDir: root, profileService: profile });
    const vault = await vaults.createVault('Alle Typen', '#2DD4BF');
    const inputs = allEntryInputs();
    for (const input of inputs) expect(entryInputSchema.safeParse(input).success).toBe(true);

    for (const input of inputs) await vaults.createEntry(vault.id, input);
    const beforeLock = await vaults.readVault(vault.id);
    expect(beforeLock.entries.map((entry) => entry.data.type)).toEqual(ENTRY_TYPES);

    profile.lock();
    const reopenedProfile = new ProfileService({
      rootDir: root,
      keyDerivation: testDerivation(),
    });
    await reopenedProfile.unlock('Richtig langes Master-Passwort!');
    const reopenedVaults = new VaultService({ rootDir: root, profileService: reopenedProfile });
    const restored = await reopenedVaults.readVault(vault.id);

    expect(
      restored.entries.map(({ id, title, folderId, tags, favorite, note, customFields, data }) => ({
        id,
        title,
        folderId,
        tags,
        favorite,
        note,
        customFields,
        data,
      })),
    ).toEqual(inputs);
    expect(restored.entries[8]?.customFields.map((field) => field.type)).toEqual([
      'text',
      'secret',
      'url',
      'number',
      'date',
      'boolean',
    ]);

    const encryptedBytes = await readFile(path.join(root, 'vaults', `${vault.id}.vaulta`), 'utf8');
    for (const canary of [
      'Roundtrip-Credential-Secret!1',
      '4111111111111111',
      'WLAN-Roundtrip-Secret!5',
      'LICENSE-ROUNDTRIP-SECRET-6',
      'ROUNDTRIP-SECRET',
      'CUSTOM-FIELD-ROUNDTRIP-SECRET',
    ]) {
      expect(encryptedBytes).not.toContain(canary);
    }
  });

  it('erkennt manipulierte öffentliche Faktordaten vor ihrer Verwendung', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-factor-mac-'));
    roots.push(root);
    const { profile } = await setupProfile(root);
    await profile.setPublicFactorData({ credentialId: 'original' });
    profile.lock();
    const profilePath = path.join(root, 'profile.json');
    const stored = JSON.parse(await readFile(profilePath, 'utf8')) as {
      publicFactorData: { payload: string };
    };
    stored.publicFactorData.payload = Buffer.from(
      JSON.stringify({ credentialId: 'angreifer' }),
    ).toString('base64');
    await import('node:fs/promises').then(({ writeFile }) =>
      writeFile(profilePath, JSON.stringify(stored)),
    );
    expect(await profile.verifyMasterPassword('Richtig langes Master-Passwort!')).toBe(false);
    await expect(profile.getPublicFactorData()).rejects.toBeInstanceOf(VaultaError);
  });

  it('aktiviert einen rotierten Recovery-Key erst nach Gruppenbestätigung', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-recovery-rotation-'));
    roots.push(root);
    const { profile, recoveryKey: previousRecoveryKey } = await setupProfile(root);
    const rotation = await profile.beginRecoveryRotation('Richtig langes Master-Passwort!');
    await expect(profile.completeRecoveryRotation(rotation.pendingId, {})).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    const confirmation = Object.fromEntries(
      rotation.recovery.confirmationIndexes.map((index) => [
        String(index),
        rotation.recovery.groups[index],
      ]),
    ) as Record<string, string>;
    const completions = await Promise.allSettled([
      profile.completeRecoveryRotation(rotation.pendingId, confirmation),
      profile.completeRecoveryRotation(rotation.pendingId, confirmation),
    ]);
    expect(completions.filter(({ status }) => status === 'fulfilled')).toHaveLength(1);
    expect(completions.filter(({ status }) => status === 'rejected')).toHaveLength(1);
    profile.lock();
    await expect(
      profile.recover(previousRecoveryKey, 'Darf nicht funktionieren!'),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    await profile.recover(rotation.recovery.displayKey, 'Neues Recovery-Master!');
    expect(profile.isUnlocked()).toBe(true);
  });

  it('verschlüsselt das sicherheitsrelevante Aktivitätsprotokoll und begrenzt dessen Umfang', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-audit-'));
    roots.push(root);
    const { profile } = await setupProfile(root);
    const audit = new AuditService({
      rootDir: root,
      profileService: profile,
      maxEvents: 2,
      retentionDays: 180,
    });
    await audit.record({ type: 'unlocked' });
    await audit.record({ type: 'vault-created', vaultId: 'vault-technical-id' });
    await audit.record({ type: 'locked' });
    const listed = await audit.list();
    expect(listed).toHaveLength(2);
    expect(listed.map((event) => event.type)).toEqual(['locked', 'vault-created']);
    const stored = await readFile(path.join(root, 'audit.vaulta'), 'utf8');
    expect(stored).not.toContain('Vaulta gesperrt');
    expect(stored).not.toContain('vault-technical-id');
  });
});
