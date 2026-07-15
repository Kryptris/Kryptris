import { randomBytes, randomUUID } from 'node:crypto';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import QRCode from 'qrcode';
import { z } from 'zod';

import { VaultaError } from '../../shared/errors';
import type {
  FactorStatus,
  TotpConfiguration,
  UnlockResult,
  WebAuthnAuthenticationResult,
  WebAuthnRegistrationResult,
} from '../../shared/models';
import type { ProfileFactorStateUpdate } from './profile-service';
import { TotpService } from './totp-service';

const FACTOR_NAMESPACE = 'factors';
const RP_ID = 'localhost';
const PENDING_LIFETIME_MS = 2 * 60 * 1_000;

const publicFactorSchema = z
  .object({
    version: z.literal(1),
    totpEnabled: z.boolean(),
    prfSalt: z.string().regex(/^[A-Za-z0-9_-]{40,64}$/u),
    securityKeys: z.array(
      z
        .object({
          keyId: z.string().uuid(),
          credentialId: z.string().min(16).max(2_048),
          publicKey: z.string().min(16).max(8_192),
          counter: z.number().int().nonnegative(),
          transports: z
            .array(z.enum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']))
            .max(10),
          mode: z.enum(['prf', 'presence']),
          createdAt: z.string().datetime(),
        })
        .strict(),
    ),
  })
  .strict();

type PublicFactorData = z.infer<typeof publicFactorSchema>;

interface ProtectedFactorData {
  totp: TotpConfiguration | null;
  keyNames: Record<string, string>;
}

interface AccessPolicy {
  recoveryEnabled: boolean;
  masterOnlyAccess: boolean;
  additionalKeyIds: string[];
}

export interface FactorProfileAdapter {
  isUnlocked(): boolean;
  verifyMasterPassword(masterPassword: string): Promise<boolean>;
  getPublicFactorDataWithMasterPassword<T>(masterPassword: string): Promise<T | null>;
  unlock(masterPassword: string, additional?: { keyId: string; secret: Buffer }): Promise<void>;
  lock(): void;
  getAccessPolicy(): Promise<AccessPolicy>;
  getProtectedMetadata<T>(namespace: string): Promise<T | null>;
  getPublicFactorData<T>(): Promise<T | null>;
  setPublicFactorData(value: unknown): Promise<void>;
  commitFactorState(input: ProfileFactorStateUpdate): Promise<void>;
}

interface PendingRegistration {
  id: string;
  challenge: string;
  keyId: string;
  name: string;
  expiresAt: number;
}

interface PendingAuthentication {
  id: string;
  challenge: string;
  publicData: PublicFactorData;
  allowedKeyIds: string[];
  masterPassword: Buffer;
  totpCode: Buffer | null;
  expiresAt: number;
  timer: NodeJS.Timeout | null;
}

interface PendingTotp {
  id: string;
  config: TotpConfiguration;
  expiresAt: number;
}

export interface FactorServiceOptions {
  profile: FactorProfileAdapter;
  origin: () => string;
  totp?: TotpService;
  now?: () => number;
  setTimer?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  clearTimer?: (timer: NodeJS.Timeout) => void;
  onAuthenticationExpired?: (challengeId: string) => void;
}

function emptyPublicFactors(): PublicFactorData {
  return {
    version: 1,
    totpEnabled: false,
    prfSalt: randomBytes(32).toString('base64url'),
    securityKeys: [],
  };
}

function emptyProtectedFactors(): ProtectedFactorData {
  return { totp: null, keyNames: {} };
}

export class FactorService {
  private readonly profile: FactorProfileAdapter;
  private readonly getOrigin: () => string;
  private readonly totp: TotpService;
  private readonly now: () => number;
  private readonly setTimer: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly clearTimer: (timer: NodeJS.Timeout) => void;
  private readonly onAuthenticationExpired: (challengeId: string) => void;
  private readonly registrations = new Map<string, PendingRegistration>();
  private readonly authentications = new Map<string, PendingAuthentication>();
  private readonly totpSetups = new Map<string, PendingTotp>();

  public constructor(options: FactorServiceOptions) {
    this.profile = options.profile;
    this.getOrigin = options.origin;
    this.totp = options.totp ?? new TotpService();
    this.now = options.now ?? Date.now;
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
    this.onAuthenticationExpired = options.onAuthenticationExpired ?? (() => undefined);
  }

  public async getStatus(revealProtected = this.profile.isUnlocked()): Promise<FactorStatus> {
    const policy = await this.profile.getAccessPolicy();
    if (!revealProtected || !this.profile.isUnlocked()) {
      return {
        totpEnabled: false,
        securityKeys: policy.additionalKeyIds.map((id, index) => ({
          id,
          name: `Kryptografischer Sicherheitsschlüssel ${index + 1}`,
          mode: 'prf' as const,
          createdAt: '',
        })),
        recoveryEnabled: policy.recoveryEnabled,
      };
    }
    const publicData = await this.readPublic();
    let names: Record<string, string> = {};
    if (this.profile.isUnlocked()) names = (await this.readProtected()).keyNames;
    return {
      totpEnabled: publicData.totpEnabled,
      securityKeys: publicData.securityKeys.map((key, index) => ({
        id: key.keyId,
        name: names[key.keyId] ?? `Sicherheitsschlüssel ${index + 1}`,
        mode: key.mode,
        createdAt: key.createdAt,
      })),
      recoveryEnabled: policy.recoveryEnabled,
    };
  }

  public async beginUnlock(masterPassword: string, totpCode?: string): Promise<UnlockResult> {
    this.pruneExpired();
    this.cancelAuthentications();
    try {
      const publicData = this.parsePublic(
        await this.profile.getPublicFactorDataWithMasterPassword<unknown>(masterPassword),
      );
      if (publicData.totpEnabled && totpCode === undefined) {
        this.profile.lock();
        return { status: 'totp-required' };
      }
      const prfKeys = publicData.securityKeys.filter((key) => key.mode === 'prf');
      const allowedKeys = prfKeys.length > 0 ? prfKeys : publicData.securityKeys;
      if (allowedKeys.length > 0) {
        const result = await this.createAuthenticationChallenge(
          allowedKeys,
          publicData,
          masterPassword,
          totpCode,
        );
        this.profile.lock();
        return result;
      }

      await this.profile.unlock(masterPassword);
      await this.verifyTotpGate(publicData, totpCode);
      return { status: 'unlocked' };
    } catch (error) {
      this.profile.lock();
      throw error;
    }
  }

  public async completeUnlock(input: {
    challengeId: string;
    response: unknown;
    prfResult?: string;
  }): Promise<WebAuthnAuthenticationResult> {
    this.pruneExpired();
    const pending = this.authentications.get(input.challengeId);
    if (pending === undefined)
      throw new VaultaError('AUTH_FAILED', 'Die Sicherheitsabfrage ist abgelaufen.');
    this.authentications.delete(input.challengeId);
    if (pending.timer !== null) this.clearTimer(pending.timer);
    pending.timer = null;

    try {
      const response = input.response as AuthenticationResponseJSON;
      const key = pending.publicData.securityKeys.find(
        (candidate) =>
          candidate.credentialId === response.id && pending.allowedKeyIds.includes(candidate.keyId),
      );
      if (key === undefined)
        throw new VaultaError('AUTH_FAILED', 'Dieser Sicherheitsschlüssel ist nicht registriert.');

      const credential: WebAuthnCredential = {
        id: key.credentialId,
        publicKey: Buffer.from(key.publicKey, 'base64url'),
        counter: key.counter,
        transports: key.transports,
      };
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.getOrigin(),
        expectedRPID: RP_ID,
        credential,
        requireUserVerification: false,
      });
      if (!verification.verified)
        throw new VaultaError('AUTH_FAILED', 'Der Sicherheitsschlüssel wurde nicht bestätigt.');

      if (key.mode === 'prf') {
        if (input.prfResult === undefined) {
          throw new VaultaError(
            'AUTH_FAILED',
            'Der Sicherheitsschlüssel liefert kein PRF-Geheimnis.',
          );
        }
        const secret = decodePrf(input.prfResult);
        try {
          await this.profile.unlock(pending.masterPassword.toString('utf8'), {
            keyId: key.keyId,
            secret,
          });
        } finally {
          secret.fill(0);
        }
      } else {
        await this.profile.unlock(pending.masterPassword.toString('utf8'));
      }
      await this.verifyTotpGate(pending.publicData, pending.totpCode?.toString('utf8'));

      const publicData = await this.readPublic();
      const updated: PublicFactorData = {
        ...publicData,
        securityKeys: publicData.securityKeys.map((candidate) =>
          candidate.keyId === key.keyId
            ? { ...candidate, counter: verification.authenticationInfo.newCounter }
            : candidate,
        ),
      };
      await this.profile.setPublicFactorData(updated);
      return { verified: true, unlocked: true };
    } catch (error) {
      this.profile.lock();
      throw error;
    } finally {
      pending.masterPassword.fill(0);
      pending.totpCode?.fill(0);
    }
  }

  public async beginTotpSetup(masterPassword: string): Promise<{
    setupId: string;
    secret: string;
    uri: string;
    qrDataUrl: string;
    explanation: string;
  }> {
    this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(masterPassword))) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist ungültig.');
    }
    const setupId = randomUUID();
    const config: TotpConfiguration = {
      secret: encodeBase32(randomBytes(20)),
      issuer: 'Vaulta',
      account: 'Lokales Profil',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    };
    const uri = this.totp.toOtpAuthUri(config);
    this.totpSetups.set(setupId, {
      id: setupId,
      config,
      expiresAt: this.now() + 10 * 60 * 1_000,
    });
    return {
      setupId,
      secret: config.secret,
      uri,
      qrDataUrl: await QRCode.toDataURL(uri, { errorCorrectionLevel: 'M', margin: 2, width: 240 }),
      explanation:
        'TOTP ist eine zusätzliche lokale Zugangssperre. Es schützt nicht gleichwertig gegen eine vollständige Kopie und Manipulation des Geräts.',
    };
  }

  public async completeTotpSetup(setupId: string, code: string): Promise<void> {
    this.requireUnlocked();
    this.pruneExpired();
    const pending = this.totpSetups.get(setupId);
    if (pending === undefined || !this.totp.verify(pending.config, code)) {
      throw new VaultaError(
        'AUTH_FAILED',
        'Der TOTP-Code ist ungültig oder die Einrichtung ist abgelaufen.',
      );
    }
    this.totpSetups.delete(setupId);
    const previousPublic = await this.readPublic();
    const previousProtected = await this.readProtected();
    const nextProtected = { ...previousProtected, totp: pending.config };
    await this.profile.commitFactorState({
      namespace: FACTOR_NAMESPACE,
      expectedPublicFactorData: previousPublic,
      publicFactorData: { ...previousPublic, totpEnabled: true },
      protectedMetadata: nextProtected,
    });
  }

  public async removeTotp(masterPassword: string): Promise<void> {
    this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(masterPassword))) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist ungültig.');
    }
    const publicData = await this.readPublic();
    const protectedData = await this.readProtected();
    await this.profile.commitFactorState({
      namespace: FACTOR_NAMESPACE,
      expectedPublicFactorData: publicData,
      publicFactorData: { ...publicData, totpEnabled: false },
      protectedMetadata: { ...protectedData, totp: null },
    });
  }

  public async beginSecurityKeyRegistration(input: {
    name: string;
    masterPassword: string;
  }): Promise<{ challengeId: string; options: unknown; prfSalt: string }> {
    this.requireUnlocked();
    this.pruneExpired();
    if (!(await this.profile.verifyMasterPassword(input.masterPassword))) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist ungültig.');
    }
    const publicData = await this.readPublic();
    const options = await generateRegistrationOptions({
      rpName: 'Vaulta',
      rpID: RP_ID,
      userName: 'vaulta-local',
      userDisplayName: 'Vaulta – lokales Profil',
      userID: randomBytes(32),
      attestationType: 'none',
      excludeCredentials: publicData.securityKeys.map((key) => ({
        id: key.credentialId,
        transports: key.transports,
      })),
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
        userVerification: 'preferred',
      },
      preferredAuthenticatorType: 'securityKey',
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60_000,
    });
    const challengeId = randomUUID();
    this.registrations.set(challengeId, {
      id: challengeId,
      challenge: options.challenge,
      keyId: randomUUID(),
      name: input.name.trim(),
      expiresAt: this.now() + PENDING_LIFETIME_MS,
    });
    return { challengeId, options, prfSalt: publicData.prfSalt };
  }

  public async completeSecurityKeyRegistration(input: {
    challengeId: string;
    response: unknown;
    prfResult?: string;
  }): Promise<WebAuthnRegistrationResult> {
    this.requireUnlocked();
    this.pruneExpired();
    const pending = this.registrations.get(input.challengeId);
    if (pending === undefined)
      throw new VaultaError('AUTH_FAILED', 'Die Registrierung ist abgelaufen.');
    this.registrations.delete(input.challengeId);
    const response = input.response as RegistrationResponseJSON;
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: this.getOrigin(),
      expectedRPID: RP_ID,
      requireUserPresence: true,
      requireUserVerification: false,
      supportedAlgorithmIDs: [-7, -257],
    });
    if (!verification.verified)
      throw new VaultaError('AUTH_FAILED', 'Der Sicherheitsschlüssel wurde nicht registriert.');

    const publicData = await this.readPublic();
    const protectedData = await this.readProtected();
    const prfSecret = input.prfResult === undefined ? null : decodePrf(input.prfResult);
    const mode = prfSecret === null ? 'presence' : 'prf';
    const credential = verification.registrationInfo.credential;
    const key = {
      keyId: pending.keyId,
      credentialId: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      transports: credential.transports ?? [],
      mode,
      createdAt: new Date(this.now()).toISOString(),
    } satisfies PublicFactorData['securityKeys'][number];
    const nextPublic = { ...publicData, securityKeys: [...publicData.securityKeys, key] };
    const nextProtected: ProtectedFactorData = {
      ...protectedData,
      keyNames: { ...protectedData.keyNames, [pending.keyId]: pending.name },
    };

    try {
      await this.profile.commitFactorState({
        namespace: FACTOR_NAMESPACE,
        expectedPublicFactorData: publicData,
        publicFactorData: nextPublic,
        protectedMetadata: nextProtected,
        ...(prfSecret === null
          ? {}
          : {
              keyMutation: {
                type: 'add' as const,
                keyId: pending.keyId,
                secret: prfSecret,
                requireForUnlock: true,
              },
            }),
      });
    } finally {
      prfSecret?.fill(0);
    }

    const warning =
      mode === 'prf'
        ? null
        : 'Dieser Schlüssel unterstützt die PRF-Erweiterung nicht. Er dient nur als sichtbare Anwesenheitsprüfung und ist kryptografisch schwächer.';
    return { verified: true, mode, warning };
  }

  public async removeSecurityKey(keyId: string, masterPassword: string): Promise<void> {
    this.requireUnlocked();
    if (!(await this.profile.verifyMasterPassword(masterPassword))) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist ungültig.');
    }
    const publicData = await this.readPublic();
    const target = publicData.securityKeys.find((key) => key.keyId === keyId);
    if (target === undefined)
      throw new VaultaError('NOT_FOUND', 'Der Sicherheitsschlüssel wurde nicht gefunden.');
    const remaining = publicData.securityKeys.filter((key) => key.keyId !== keyId);
    const protectedData = await this.readProtected();
    const keyNames = { ...protectedData.keyNames };
    delete keyNames[keyId];
    await this.profile.commitFactorState({
      namespace: FACTOR_NAMESPACE,
      expectedPublicFactorData: publicData,
      publicFactorData: { ...publicData, securityKeys: remaining },
      protectedMetadata: { ...protectedData, keyNames },
      ...(target.mode === 'prf'
        ? {
            keyMutation: {
              type: 'remove' as const,
              keyId,
              restoreMasterOnlyAccess: !remaining.some((key) => key.mode === 'prf'),
            },
          }
        : {}),
    });
  }

  public clearPending(): void {
    this.cancelAuthentications();
    this.registrations.clear();
    this.totpSetups.clear();
    this.profile.lock();
  }

  public cancelAuthentication(challengeId?: string): boolean {
    if (challengeId === undefined) {
      const hadPending = this.authentications.size > 0;
      this.cancelAuthentications();
      this.profile.lock();
      return hadPending;
    }
    const pending = this.authentications.get(challengeId);
    if (pending === undefined) {
      this.profile.lock();
      return false;
    }
    this.authentications.delete(challengeId);
    this.clearAuthentication(pending);
    this.profile.lock();
    return true;
  }

  private async createAuthenticationChallenge(
    keys: PublicFactorData['securityKeys'],
    publicData: PublicFactorData,
    masterPassword: string,
    totpCode: string | null | undefined,
  ): Promise<UnlockResult> {
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: keys.map((key) => ({ id: key.credentialId, transports: key.transports })),
      userVerification: 'preferred',
      timeout: 60_000,
    });
    const id = randomUUID();
    const pending: PendingAuthentication = {
      id,
      challenge: options.challenge,
      publicData: structuredClone(publicData),
      allowedKeyIds: keys.map((key) => key.keyId),
      masterPassword: Buffer.from(masterPassword, 'utf8'),
      totpCode: totpCode === null || totpCode === undefined ? null : Buffer.from(totpCode, 'utf8'),
      expiresAt: this.now() + PENDING_LIFETIME_MS,
      timer: null,
    };
    pending.timer = this.setTimer(() => this.expireAuthentication(id), PENDING_LIFETIME_MS);
    pending.timer.unref?.();
    this.authentications.set(id, pending);
    return {
      status: 'security-key-required',
      challengeId: id,
      securityKeyOptions: {
        options,
        prfSalt: keys.some((key) => key.mode === 'prf') ? publicData.prfSalt : null,
      },
    };
  }

  private async verifyTotpGate(publicData: PublicFactorData, code?: string): Promise<void> {
    if (!publicData.totpEnabled) return;
    const protectedData = await this.readProtected();
    if (protectedData.totp === null) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Die TOTP-Sperre ist inkonsistent. Der Tresor bleibt gesperrt.',
      );
    }
    if (code === undefined || !this.totp.verify(protectedData.totp, code, { window: 1 })) {
      throw new VaultaError('AUTH_FACTOR_REQUIRED', 'Ein gültiger TOTP-Code ist erforderlich.');
    }
  }

  private async readPublic(): Promise<PublicFactorData> {
    const value = await this.profile.getPublicFactorData<unknown>();
    if (value === null) {
      const initialized = emptyPublicFactors();
      await this.profile.setPublicFactorData(initialized);
      return initialized;
    }
    return this.parsePublic(value);
  }

  private parsePublic(value: unknown): PublicFactorData {
    if (value === null) return emptyPublicFactors();
    const result = publicFactorSchema.safeParse(value);
    if (!result.success)
      throw new VaultaError('CORRUPT_DATA', 'Die Daten der Zusatzfaktoren wurden manipuliert.');
    return result.data;
  }

  private async readProtected(): Promise<ProtectedFactorData> {
    const value = await this.profile.getProtectedMetadata<ProtectedFactorData>(FACTOR_NAMESPACE);
    if (value === null) return emptyProtectedFactors();
    if (
      typeof value !== 'object' ||
      typeof value.keyNames !== 'object' ||
      value.keyNames === null ||
      (value.totp !== null && typeof value.totp !== 'object')
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Die geschützten Faktordaten sind ungültig.');
    }
    return value;
  }

  private requireUnlocked(): void {
    if (!this.profile.isUnlocked()) throw new VaultaError('LOCKED', 'Vaulta ist gesperrt.');
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const [id, pending] of this.registrations)
      if (pending.expiresAt <= now) this.registrations.delete(id);
    for (const [id, pending] of this.totpSetups)
      if (pending.expiresAt <= now) this.totpSetups.delete(id);
    for (const [id, pending] of this.authentications) {
      if (pending.expiresAt > now) continue;
      this.expireAuthentication(id);
    }
  }

  private expireAuthentication(id: string): void {
    const pending = this.authentications.get(id);
    if (pending === undefined) return;
    this.authentications.delete(id);
    this.clearAuthentication(pending);
    this.profile.lock();
    this.onAuthenticationExpired(id);
  }

  private cancelAuthentications(): void {
    for (const pending of this.authentications.values()) this.clearAuthentication(pending);
    this.authentications.clear();
  }

  private clearAuthentication(pending: PendingAuthentication): void {
    if (pending.timer !== null) this.clearTimer(pending.timer);
    pending.timer = null;
    pending.masterPassword.fill(0);
    pending.totpCode?.fill(0);
  }
}

function decodePrf(encoded: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43,44}$/u.test(encoded)) {
    throw new VaultaError('INVALID_INPUT', 'Das PRF-Ergebnis ist ungültig.');
  }
  const result = Buffer.from(encoded, 'base64url');
  if (result.length !== 32)
    throw new VaultaError('INVALID_INPUT', 'Das PRF-Ergebnis hat die falsche Länge.');
  return result;
}

function encodeBase32(input: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let bitCount = 0;
  let output = '';
  for (const byte of input) {
    bits = (bits << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      output += alphabet[(bits >>> bitCount) & 31];
    }
  }
  if (bitCount > 0) output += alphabet[(bits << (5 - bitCount)) & 31];
  return output;
}
