import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { ProfileService } from '../../src/main/services/profile-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const MASTER_PASSWORD = 'Richtig langes Master-Passwort!';
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

async function setupProfile(
  rootDir: string,
  atomicWriter = new AtomicFileWriter(),
): Promise<ProfileService> {
  const profile = new ProfileService({
    rootDir,
    atomicWriter,
    keyDerivation: testDerivation(),
  });
  const pending = await profile.beginSetup(MASTER_PASSWORD, false);
  await profile.completeSetup(pending.pendingId, {});
  return profile;
}

function publicFactors() {
  return {
    version: 1,
    totpEnabled: false,
    prfSalt: Buffer.alloc(32, 4).toString('base64url'),
    securityKeys: [] as Array<{
      keyId: string;
      credentialId: string;
      publicKey: string;
      counter: number;
      transports: string[];
      mode: 'prf';
      createdAt: string;
    }>,
  };
}

function protectedFactors() {
  return { totp: null, keyNames: {} as Record<string, string> };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Atomare Faktortransaktionen im Profilheader', () => {
  it('behält bei einem Abbruch vor dem Replace den vollständig alten Faktorstand', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-factor-crash-'));
    roots.push(root);
    let failFactorWrite = false;
    let factorWriteAttempts = 0;
    const atomicWriter = new AtomicFileWriter({
      beforeReplace: (_temporaryPath, targetPath) => {
        if (!failFactorWrite || path.basename(targetPath) !== 'profile.json') return;
        factorWriteAttempts += 1;
        throw new Error('simulierter Stromausfall vor dem atomaren Replace');
      },
    });
    const profile = await setupProfile(root, atomicWriter);
    const previousPublic = publicFactors();
    const previousProtected = protectedFactors();
    await profile.setPublicFactorData(previousPublic);
    await profile.setProtectedMetadata('factors', previousProtected);
    const before = await readFile(path.join(root, 'profile.json'));

    failFactorWrite = true;
    await expect(
      profile.commitFactorState({
        namespace: 'factors',
        expectedPublicFactorData: previousPublic,
        publicFactorData: { ...previousPublic, totpEnabled: true },
        protectedMetadata: {
          ...previousProtected,
          totp: {
            secret: 'JBSWY3DPEHPK3PXP',
            issuer: 'Vaulta',
            account: 'Lokal',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
          },
        },
      }),
    ).rejects.toThrow('simulierter Stromausfall');

    expect(factorWriteAttempts).toBe(1);
    expect(await readFile(path.join(root, 'profile.json'))).toEqual(before);
    expect(await profile.getPublicFactorData()).toEqual(previousPublic);
    expect(await profile.getProtectedMetadata('factors')).toEqual(previousProtected);
    expect(await profile.getAccessPolicy()).toMatchObject({
      masterOnlyAccess: true,
      additionalKeyIds: [],
    });
    expect((await readdir(root)).some((name) => name.includes('.vaulta-tmp-'))).toBe(false);

    profile.lock();
    const reopened = new ProfileService({ rootDir: root, keyDerivation: testDerivation() });
    await reopened.unlock(MASTER_PASSWORD);
    expect(await reopened.getPublicFactorData()).toEqual(previousPublic);
    expect(await reopened.getProtectedMetadata('factors')).toEqual(previousProtected);
  });

  it('committet bei konkurrierenden PRF-Registrierungen genau einen kohärenten Stand', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-factor-race-'));
    roots.push(root);
    let countFactorWrites = false;
    let factorWrites = 0;
    const atomicWriter = new AtomicFileWriter({
      beforeReplace: (_temporaryPath, targetPath) => {
        if (countFactorWrites && path.basename(targetPath) === 'profile.json') factorWrites += 1;
      },
    });
    const profile = await setupProfile(root, atomicWriter);
    const previousPublic = publicFactors();
    const previousProtected = protectedFactors();
    await profile.setPublicFactorData(previousPublic);
    await profile.setProtectedMetadata('factors', previousProtected);
    const candidates = [
      {
        keyId: '11111111-1111-4111-8111-111111111111',
        name: 'Erster Key',
        secret: Buffer.alloc(32, 1),
      },
      {
        keyId: '22222222-2222-4222-8222-222222222222',
        name: 'Zweiter Key',
        secret: Buffer.alloc(32, 2),
      },
    ];
    countFactorWrites = true;

    const results = await Promise.allSettled(
      candidates.map((candidate) =>
        profile.commitFactorState({
          namespace: 'factors',
          expectedPublicFactorData: previousPublic,
          publicFactorData: {
            ...previousPublic,
            securityKeys: [
              {
                keyId: candidate.keyId,
                credentialId: `credential-${candidate.keyId}`,
                publicKey: Buffer.alloc(32, 7).toString('base64url'),
                counter: 0,
                transports: ['usb'],
                mode: 'prf' as const,
                createdAt: '2026-07-15T00:00:00.000Z',
              },
            ],
          },
          protectedMetadata: {
            ...previousProtected,
            keyNames: { [candidate.keyId]: candidate.name },
          },
          keyMutation: {
            type: 'add',
            keyId: candidate.keyId,
            secret: candidate.secret,
            requireForUnlock: true,
          },
        }),
      ),
    );

    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toMatchObject({ reason: { code: 'CONFLICT' } });
    expect(factorWrites).toBe(1);

    const storedPublic = await profile.getPublicFactorData<ReturnType<typeof publicFactors>>();
    const storedProtected =
      await profile.getProtectedMetadata<ReturnType<typeof protectedFactors>>('factors');
    const policy = await profile.getAccessPolicy();
    const winnerId = storedPublic?.securityKeys[0]?.keyId;
    expect(winnerId).toBeDefined();
    expect(policy).toMatchObject({ masterOnlyAccess: false, additionalKeyIds: [winnerId] });
    expect(Object.keys(storedProtected?.keyNames ?? {})).toEqual([winnerId]);

    const winner = candidates.find((candidate) => candidate.keyId === winnerId);
    if (winner === undefined) throw new Error('Kein Gewinner der Faktortransaktion');
    profile.lock();
    await expect(profile.unlock(MASTER_PASSWORD)).rejects.toMatchObject({
      code: 'AUTH_FACTOR_REQUIRED',
    });
    await profile.unlock(MASTER_PASSWORD, { keyId: winner.keyId, secret: winner.secret });
    expect(profile.isUnlocked()).toBe(true);
  });
});
