import { Buffer } from 'node:buffer';

import { beforeEach, describe, expect, it, vi } from 'vitest';

const webauthn = vi.hoisted(() => ({
  generateAuthenticationOptions: vi.fn(),
  generateRegistrationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => webauthn);

import { FactorService, type FactorProfileAdapter } from '../../src/main/services/factor-service';
import type { ProfileFactorStateUpdate } from '../../src/main/services/profile-service';
import { TotpService } from '../../src/main/services/totp-service';

class MemoryFactorProfile implements FactorProfileAdapter {
  public unlocked = true;
  public publicData: unknown = null;
  public protectedData: unknown = null;
  public lockCount = 0;
  public factorCommitCount = 0;
  public readonly addedWraps: Array<{
    keyId: string;
    secret: Buffer;
    requireForUnlock: boolean;
  }> = [];
  public readonly removedWraps: Array<{
    keyId: string;
    restoreMasterOnlyAccess: boolean;
  }> = [];
  public policy = {
    recoveryEnabled: true,
    masterOnlyAccess: true,
    additionalKeyIds: [] as string[],
  };

  public isUnlocked(): boolean {
    return this.unlocked;
  }

  public verifyMasterPassword(masterPassword: string): Promise<boolean> {
    return Promise.resolve(masterPassword === 'master-passwort');
  }

  public getPublicFactorDataWithMasterPassword<T>(masterPassword: string): Promise<T | null> {
    if (masterPassword !== 'master-passwort') {
      return Promise.reject(new Error('ungueltiges Passwort'));
    }
    return Promise.resolve(this.publicData as T | null);
  }

  public unlock(
    masterPassword: string,
    additional?: { keyId: string; secret: Buffer },
  ): Promise<void> {
    if (masterPassword !== 'master-passwort') throw new Error('ungueltiges Passwort');
    if (additional !== undefined && additional.secret.length !== 32) {
      throw new Error('ungueltiges Zusatzgeheimnis');
    }
    this.unlocked = true;
    return Promise.resolve();
  }

  public lock(): void {
    this.unlocked = false;
    this.lockCount += 1;
  }

  public getAccessPolicy(): Promise<{
    recoveryEnabled: boolean;
    masterOnlyAccess: boolean;
    additionalKeyIds: string[];
  }> {
    return Promise.resolve(structuredClone(this.policy));
  }

  public getProtectedMetadata<T>(namespace: string): Promise<T | null> {
    void namespace;
    return Promise.resolve(this.protectedData as T | null);
  }

  public setProtectedMetadata(namespace: string, value: unknown): Promise<void> {
    void namespace;
    this.protectedData = structuredClone(value);
    return Promise.resolve();
  }

  public deleteProtectedMetadata(namespace: string): Promise<void> {
    void namespace;
    this.protectedData = null;
    return Promise.resolve();
  }

  public getPublicFactorData<T>(): Promise<T | null> {
    return Promise.resolve(this.publicData as T | null);
  }

  public setPublicFactorData(value: unknown): Promise<void> {
    this.publicData = structuredClone(value);
    return Promise.resolve();
  }

  public addAdditionalKeyWrap(input: {
    keyId: string;
    secret: Buffer;
    requireForUnlock: boolean;
  }): Promise<void> {
    this.addedWraps.push(input);
    return Promise.resolve();
  }

  public removeAdditionalKeyWrap(
    keyId: string,
    options: { restoreMasterOnlyAccess: boolean },
  ): Promise<void> {
    this.removedWraps.push({ keyId, ...options });
    return Promise.resolve();
  }

  public commitFactorState(input: ProfileFactorStateUpdate): Promise<void> {
    if (JSON.stringify(this.publicData) !== JSON.stringify(input.expectedPublicFactorData)) {
      return Promise.reject(new Error('Faktor-Konflikt'));
    }
    this.factorCommitCount += 1;
    if (input.keyMutation?.type === 'add') {
      this.addedWraps.push({
        keyId: input.keyMutation.keyId,
        secret: input.keyMutation.secret,
        requireForUnlock: input.keyMutation.requireForUnlock,
      });
    } else if (input.keyMutation?.type === 'remove') {
      this.removedWraps.push({
        keyId: input.keyMutation.keyId,
        restoreMasterOnlyAccess: input.keyMutation.restoreMasterOnlyAccess,
      });
    }
    this.publicData = structuredClone(input.publicFactorData);
    this.protectedData = structuredClone(input.protectedMetadata);
    return Promise.resolve();
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  webauthn.generateRegistrationOptions.mockResolvedValue({ challenge: 'registration-challenge' });
  webauthn.generateAuthenticationOptions.mockResolvedValue({
    challenge: 'authentication-challenge',
  });
  webauthn.verifyRegistrationResponse.mockResolvedValue({
    verified: true,
    registrationInfo: {
      credential: {
        id: 'credential-identifier-1234',
        publicKey: Uint8Array.from({ length: 32 }, (_, index) => index),
        counter: 0,
        transports: ['usb'],
      },
    },
  });
  webauthn.verifyAuthenticationResponse.mockResolvedValue({
    verified: true,
    authenticationInfo: { newCounter: 1 },
  });
});

describe('FactorService ohne reale Hardware', () => {
  it('richtet TOTP lokal ein und erzwingt den Code beim Entsperren', async () => {
    const profile = new MemoryFactorProfile();
    const service = createService(profile);
    const setup = await service.beginTotpSetup('master-passwort');

    expect(setup.secret).toMatch(/^[A-Z2-7]+$/u);
    expect(setup.uri).toMatch(/^otpauth:\/\/totp\//u);
    expect(setup.qrDataUrl).toMatch(/^data:image\/png;base64,/u);
    expect(setup.explanation).toContain('vollständige Kopie');

    const totp = new TotpService();
    const config = totp.parseOtpAuthUri(setup.uri);
    const code = totp.getCode(config).code;
    await service.completeTotpSetup(setup.setupId, code);
    expect(profile.factorCommitCount).toBe(1);
    expect(profile.publicData).toMatchObject({ totpEnabled: true });
    expect(profile.protectedData).toMatchObject({ totp: { secret: setup.secret } });

    profile.unlocked = false;
    await expect(service.beginUnlock('master-passwort')).resolves.toEqual({
      status: 'totp-required',
    });
    await expect(service.beginUnlock('master-passwort', '000000')).rejects.toMatchObject({
      code: 'AUTH_FACTOR_REQUIRED',
    });
    expect(profile.unlocked).toBe(false);
    await expect(service.beginUnlock('master-passwort', code)).resolves.toEqual({
      status: 'unlocked',
    });
  });

  it('entfernt TOTP-Secret und Public-Flag in einem Faktorcommit', async () => {
    const profile = new MemoryFactorProfile();
    profile.publicData = publicFactors([], true);
    profile.protectedData = protectedFactors();
    const service = createService(profile);

    await service.removeTotp('master-passwort');

    expect(profile.factorCommitCount).toBe(1);
    expect(profile.publicData).toMatchObject({ totpEnabled: false });
    expect(profile.protectedData).toMatchObject({ totp: null });
  });

  it('legt initiale Public-Faktordaten an und gibt gesperrt keine lokalen Namen preis', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.policy.additionalKeyIds = ['11111111-1111-4111-8111-111111111111'];
    const status = await createService(profile).getStatus();

    expect(status).toMatchObject({
      totpEnabled: false,
      recoveryEnabled: true,
      securityKeys: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          name: 'Kryptografischer Sicherheitsschlüssel 1',
          mode: 'prf',
        },
      ],
    });
    expect(profile.publicData).toBeNull();
  });

  it('gibt waehrend der Faktorauthentifizierung trotz geladenem Profilschluessel keine Namen preis', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = true;
    profile.policy.additionalKeyIds = [prfKey.keyId];
    profile.publicData = publicFactors([prfKey]);
    profile.protectedData = {
      ...protectedFactors(),
      keyNames: { [prfKey.keyId]: 'Geheimer Schluesselname' },
    };

    const status = await createService(profile).getStatus(false);

    expect(status.securityKeys).toEqual([
      expect.objectContaining({
        id: prfKey.keyId,
        name: 'Kryptografischer Sicherheitsschlüssel 1',
      }),
    ]);
    expect(JSON.stringify(status)).not.toContain('Geheimer Schluesselname');
  });

  it('verweigert manipulierte Public-Faktordaten', async () => {
    const profile = new MemoryFactorProfile();
    profile.publicData = {
      version: 1,
      totpEnabled: false,
      prfSalt: 'zu-kurz',
      securityKeys: [],
    };
    await expect(createService(profile).getStatus()).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });
  });

  it('validiert das PRF-Ergebnis vor jeder Schluesselmutation', async () => {
    const profile = new MemoryFactorProfile();
    const service = createService(profile);
    const pending = await service.beginSecurityKeyRegistration({
      name: 'YubiKey',
      masterPassword: 'master-passwort',
    });

    await expect(
      service.completeSecurityKeyRegistration({
        challengeId: pending.challengeId,
        response: {},
        prfResult: 'ungueltig',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(profile.addedWraps).toEqual([]);
  });

  it('registriert ein gueltiges PRF als kryptografischen Faktor und nullt den Puffer', async () => {
    const profile = new MemoryFactorProfile();
    const service = createService(profile);
    const pending = await service.beginSecurityKeyRegistration({
      name: 'Backup-Key',
      masterPassword: 'master-passwort',
    });
    const prfResult = Buffer.alloc(32, 7).toString('base64url');

    await expect(
      service.completeSecurityKeyRegistration({
        challengeId: pending.challengeId,
        response: {},
        prfResult,
      }),
    ).resolves.toEqual({ verified: true, mode: 'prf', warning: null });
    expect(profile.factorCommitCount).toBe(1);
    expect(profile.addedWraps).toHaveLength(1);
    expect(profile.addedWraps[0]).toMatchObject({ requireForUnlock: true });
    expect(profile.addedWraps[0]?.secret.every((byte) => byte === 0)).toBe(true);
    expect(profile.publicData).toMatchObject({
      securityKeys: [{ mode: 'prf', credentialId: 'credential-identifier-1234' }],
    });
  });

  it('entfernt PRF-Wrap und beide Metadatenansichten in einem Faktorcommit', async () => {
    const profile = new MemoryFactorProfile();
    profile.publicData = publicFactors([prfKey]);
    profile.protectedData = {
      ...protectedFactors(),
      keyNames: { [prfKey.keyId]: 'Backup-Key' },
    };
    const service = createService(profile);

    await service.removeSecurityKey(prfKey.keyId, 'master-passwort');

    expect(profile.factorCommitCount).toBe(1);
    expect(profile.removedWraps).toEqual([{ keyId: prfKey.keyId, restoreMasterOnlyAccess: true }]);
    expect(profile.publicData).toMatchObject({ securityKeys: [] });
    expect(profile.protectedData).toMatchObject({ keyNames: {} });
  });

  it('entsperrt bei einem Presence-Schluessel erst nach der WebAuthn-Bestaetigung', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.publicData = publicFactors([presenceKey]);
    const service = createService(profile);

    const pending = await service.beginUnlock('master-passwort');

    expect(pending.status).toBe('security-key-required');
    expect(profile.unlocked).toBe(false);
    await expect(
      service.completeUnlock({
        challengeId: requiredChallengeId(pending),
        response: { id: presenceKey.credentialId },
      }),
    ).resolves.toEqual({ verified: true, unlocked: true });
    expect(profile.unlocked).toBe(true);
  });

  it('bleibt bei einem ungueltigen TOTP ohne Sicherheitsschluessel gesperrt', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.publicData = publicFactors([], true);
    profile.protectedData = protectedFactors();
    const service = createService(profile, rejectingTotp());

    await expect(service.beginUnlock('master-passwort', '123456')).rejects.toMatchObject({
      code: 'AUTH_FACTOR_REQUIRED',
    });
    expect(profile.unlocked).toBe(false);
  });

  it('sperrt nach einem ungueltigen TOTP auch eine erfolgreiche PRF-Entsperrung wieder', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.publicData = publicFactors([prfKey], true);
    profile.protectedData = protectedFactors();
    const service = createService(profile, rejectingTotp());
    const pending = await service.beginUnlock('master-passwort', '123456');

    await expect(
      service.completeUnlock({
        challengeId: requiredChallengeId(pending),
        response: { id: prfKey.credentialId },
        prfResult: Buffer.alloc(32, 9).toString('base64url'),
      }),
    ).rejects.toMatchObject({ code: 'AUTH_FACTOR_REQUIRED' });
    expect(profile.unlocked).toBe(false);
  });

  it('akzeptiert fuer eine PRF-Challenge keinen Presence-Schluessel', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.publicData = publicFactors([prfKey, presenceKey]);
    const service = createService(profile);
    const pending = await service.beginUnlock('master-passwort');

    expect(webauthn.generateAuthenticationOptions).toHaveBeenCalledWith(
      expect.objectContaining({
        allowCredentials: [expect.objectContaining({ id: prfKey.credentialId })],
      }),
    );
    await expect(
      service.completeUnlock({
        challengeId: requiredChallengeId(pending),
        response: { id: presenceKey.credentialId },
      }),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(profile.unlocked).toBe(false);
  });

  it('verwirft eine offene WebAuthn-Anfrage nach dem echten Timeout', async () => {
    vi.useFakeTimers();
    try {
      const profile = new MemoryFactorProfile();
      profile.unlocked = false;
      profile.publicData = publicFactors([presenceKey]);
      const expired = vi.fn();
      const service = new FactorService({
        profile,
        origin: () => 'http://localhost:4173',
        onAuthenticationExpired: expired,
      });
      const pending = await service.beginUnlock('master-passwort');
      const challengeId = requiredChallengeId(pending);

      await vi.advanceTimersByTimeAsync(2 * 60 * 1_000);

      expect(expired).toHaveBeenCalledWith(challengeId);
      expect(profile.unlocked).toBe(false);
      await expect(
        service.completeUnlock({ challengeId, response: { id: presenceKey.credentialId } }),
      ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('bricht eine offene WebAuthn-Anfrage explizit und idempotent ab', async () => {
    const profile = new MemoryFactorProfile();
    profile.unlocked = false;
    profile.publicData = publicFactors([presenceKey]);
    const service = createService(profile);
    const pending = await service.beginUnlock('master-passwort');
    const challengeId = requiredChallengeId(pending);

    expect(service.cancelAuthentication(challengeId)).toBe(true);
    expect(service.cancelAuthentication(challengeId)).toBe(false);
    expect(profile.unlocked).toBe(false);
    await expect(
      service.completeUnlock({ challengeId, response: { id: presenceKey.credentialId } }),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
  });
});

const prfKey = {
  keyId: '11111111-1111-4111-8111-111111111111',
  credentialId: 'prf-credential-identifier-1234',
  publicKey: Buffer.alloc(32, 1).toString('base64url'),
  counter: 0,
  transports: ['usb'],
  mode: 'prf',
  createdAt: '2026-01-01T00:00:00.000Z',
} as const;

const presenceKey = {
  keyId: '22222222-2222-4222-8222-222222222222',
  credentialId: 'presence-credential-identifier-1234',
  publicKey: Buffer.alloc(32, 2).toString('base64url'),
  counter: 0,
  transports: ['usb'],
  mode: 'presence',
  createdAt: '2026-01-02T00:00:00.000Z',
} as const;

function publicFactors(
  securityKeys: readonly (typeof prfKey | typeof presenceKey)[],
  totpEnabled = false,
) {
  return {
    version: 1,
    totpEnabled,
    prfSalt: Buffer.alloc(32, 3).toString('base64url'),
    securityKeys: structuredClone(securityKeys),
  };
}

function protectedFactors() {
  return {
    totp: {
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'Vaulta',
      account: 'Lokal',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    },
    keyNames: {},
  };
}

function rejectingTotp(): TotpService {
  return { verify: () => false } as unknown as TotpService;
}

function requiredChallengeId(result: Awaited<ReturnType<FactorService['beginUnlock']>>): string {
  if (result.challengeId === undefined) throw new Error('Challenge wurde nicht erzeugt');
  return result.challengeId;
}

function createService(profile: MemoryFactorProfile, totp?: TotpService): FactorService {
  return new FactorService({
    profile,
    origin: () => 'http://localhost:4173',
    ...(totp === undefined ? {} : { totp }),
  });
}
