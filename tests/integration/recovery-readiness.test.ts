import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { CryptoService } from '../../src/main/security/crypto-service';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { RECOVERY_READINESS_NAMESPACE } from '../../src/main/services/recovery-readiness-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultaError } from '../../src/shared/errors';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const roots: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Recovery-Bereitschaft im Profil-Service', () => {
  it('authentifiziert nur den Recovery-Wrap und verändert weder Profil noch Faktoren', async () => {
    const fixture = await setupProfile();
    const factorMetadata = {
      totp: { secret: 'JBSWY3DPEHPK3PXP' },
      keyNames: { 'technical-key-id': 'Synthetischer Schlüssel' },
    };
    const publicFactors = {
      version: 1,
      totpEnabled: true,
      securityKeys: [],
    };
    await fixture.profile.setProtectedMetadata('factors', factorMetadata);
    await fixture.profile.setPublicFactorData(publicFactors);
    const profilePath = path.join(fixture.root, 'profile.json');
    const beforeBytes = await readFile(profilePath);
    const beforeHeader = await fixture.profile.readPublicHeader();
    const erase = vi.spyOn(fixture.crypto, 'erase');
    const assertAuthorized = vi.fn();

    await expect(
      fixture.profile.verifyRecoveryKey(fixture.recoveryKey, assertAuthorized),
    ).resolves.toBeUndefined();

    expect(assertAuthorized).toHaveBeenCalledTimes(4);
    expect(await readFile(profilePath)).toEqual(beforeBytes);
    expect(await fixture.profile.readPublicHeader()).toEqual(beforeHeader);
    expect(await fixture.profile.getProtectedMetadata('factors')).toEqual(factorMetadata);
    expect(await fixture.profile.getPublicFactorData()).toEqual(publicFactors);
    expect((await readFile(profilePath, 'utf8')).includes(fixture.recoveryKey)).toBe(false);
    expectErasedBuffers(erase.mock.calls);
  });

  it('liefert für falsche Schlüssel nur einen generischen Authentifizierungsfehler', async () => {
    const fixture = await setupProfile();
    const profilePath = path.join(fixture.root, 'profile.json');
    const beforeBytes = await readFile(profilePath);
    const invalidKey = mutateRecoveryKey(fixture.recoveryKey);

    let caught: unknown;
    try {
      await fixture.profile.verifyRecoveryKey(invalidKey);
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(VaultaError);
    expect(caught).toMatchObject({
      code: 'AUTH_FAILED',
      message: 'Der Wiederherstellungsschlüssel ist ungültig.',
    });
    expect(JSON.stringify(caught)).not.toContain(invalidKey);
    expect(await readFile(profilePath)).toEqual(beforeBytes);
  });

  it('bricht nach einer Sperr-Assertion ab und löscht bereits entschlüsseltes Schlüsselmaterial', async () => {
    const fixture = await setupProfile();
    const profilePath = path.join(fixture.root, 'profile.json');
    const beforeBytes = await readFile(profilePath);
    const erase = vi.spyOn(fixture.crypto, 'erase');
    let assertions = 0;
    const assertAuthorized = () => {
      assertions += 1;
      if (assertions === 3) throw new VaultaError('LOCKED', 'Test wurde gesperrt.');
    };

    await expect(
      fixture.profile.verifyRecoveryKey(fixture.recoveryKey, assertAuthorized),
    ).rejects.toMatchObject({ code: 'LOCKED' });

    expect(assertions).toBe(3);
    expect(await readFile(profilePath)).toEqual(beforeBytes);
    expectErasedBuffers(erase.mock.calls);
  });

  it('invalidiert Bereitschaftsmetadaten atomar mit einer Recovery-Rotation', async () => {
    const fixture = await setupProfile();
    const readinessRecord = {
      testedAt: '2026-07-26T12:00:00.000Z',
      success: true,
    };
    const factorMetadata = {
      totp: { secret: 'JBSWY3DPEHPK3PXP' },
      keyNames: {},
    };
    const publicFactors = {
      version: 1,
      totpEnabled: true,
      securityKeys: [],
    };
    await fixture.profile.setProtectedMetadata(RECOVERY_READINESS_NAMESPACE, readinessRecord);
    await fixture.profile.setProtectedMetadata('factors', factorMetadata);
    await fixture.profile.setPublicFactorData(publicFactors);
    const beforeHeader = await fixture.profile.readPublicHeader();
    const rotation = await fixture.profile.beginRecoveryRotation(fixture.masterPassword);
    const confirmation = Object.fromEntries(
      rotation.recovery.confirmationIndexes.map((index) => [
        String(index),
        rotation.recovery.groups[index],
      ]),
    ) as Record<string, string>;

    await fixture.profile.completeRecoveryRotation(rotation.pendingId, confirmation, {
      invalidateProtectedMetadataNamespaces: [RECOVERY_READINESS_NAMESPACE],
    });

    const afterHeader = await fixture.profile.readPublicHeader();
    expect(afterHeader.access).toEqual(beforeHeader.access);
    expect(afterHeader.recovery).not.toEqual(beforeHeader.recovery);
    expect(await fixture.profile.getProtectedMetadata(RECOVERY_READINESS_NAMESPACE)).toBeNull();
    expect(await fixture.profile.getProtectedMetadata('factors')).toEqual(factorMetadata);
    expect(await fixture.profile.getPublicFactorData()).toEqual(publicFactors);
    await expect(fixture.profile.verifyRecoveryKey(fixture.recoveryKey)).rejects.toMatchObject({
      code: 'AUTH_FAILED',
    });
    await expect(
      fixture.profile.verifyRecoveryKey(rotation.recovery.displayKey),
    ).resolves.toBeUndefined();
    const serialized = await readFile(path.join(fixture.root, 'profile.json'), 'utf8');
    expect(serialized).not.toContain(fixture.recoveryKey);
    expect(serialized).not.toContain(rotation.recovery.displayKey);
  });
});

async function setupProfile(): Promise<{
  root: string;
  profile: ProfileService;
  crypto: CryptoService;
  masterPassword: string;
  recoveryKey: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-recovery-readiness-'));
  roots.push(root);
  const crypto = new CryptoService();
  const profile = new ProfileService({
    rootDir: root,
    crypto,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const masterPassword = 'Synthetisches Recovery-Test-Masterpasswort!1';
  const pending = await profile.beginSetup(masterPassword, true);
  if (pending.recovery === null)
    throw new Error('Recovery-Testfixture konnte nicht erstellt werden.');
  const confirmation = Object.fromEntries(
    pending.recovery.confirmationIndexes.map((index) => [
      String(index),
      pending.recovery?.groups[index],
    ]),
  ) as Record<string, string>;
  await profile.completeSetup(pending.pendingId, confirmation);
  return {
    root,
    profile,
    crypto,
    masterPassword,
    recoveryKey: pending.recovery.displayKey,
  };
}

function mutateRecoveryKey(recoveryKey: string): string {
  const position = Array.from(recoveryKey, (character, index) => ({ character, index })).find(
    ({ character, index }) => index > 4 && character !== '-',
  )?.index;
  if (position === undefined) throw new Error('Recovery-Testschlüssel ist unerwartet kurz.');
  const replacement = recoveryKey[position] === 'Z' ? 'Y' : 'Z';
  return `${recoveryKey.slice(0, position)}${replacement}${recoveryKey.slice(position + 1)}`;
}

function expectErasedBuffers(calls: Array<[Buffer | null | undefined]>): void {
  const buffers = calls
    .map(([candidate]) => candidate)
    .filter((candidate): candidate is Buffer => Buffer.isBuffer(candidate));
  expect(buffers.length).toBeGreaterThanOrEqual(4);
  for (const buffer of buffers) expect(buffer.every((byte) => byte === 0)).toBe(true);
}
