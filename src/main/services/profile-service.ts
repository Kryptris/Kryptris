import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { VaultaError } from '../../shared/errors';
import type { RecoverySetup } from '../../shared/models';
import { type AesGcmEnvelope, CryptoService } from '../security/crypto-service';
import { type Argon2idParameters, KeyDerivationService } from '../security/key-derivation';
import { RecoveryKeyService } from '../security/recovery-key';
import { AtomicFileWriter } from '../storage/atomic-file';
import { assertSafeIdentifier } from '../storage/path-safety';
import { SerialExecutor } from '../storage/serial-executor';

const PROFILE_FILENAME = 'profile.json';
export const PROFILE_FORMAT_VERSION = 1 as const;
const PROFILE_VERSION = PROFILE_FORMAT_VERSION;
const PASSWORD_VERIFIER = Buffer.from('vaulta-password-verifier-v1', 'utf8');
const PROTECTED_METADATA_LIMIT_BYTES = 4 * 1024 * 1024;

export type ProtectedMetadataValue =
  | null
  | boolean
  | number
  | string
  | ProtectedMetadataValue[]
  | { [key: string]: ProtectedMetadataValue };

export interface StoredKdfConfiguration {
  salt: string;
  parameters: Argon2idParameters;
}

export interface StoredAdditionalKeyWrap {
  keyId: string;
  salt: string;
  wrappedProfileKey: AesGcmEnvelope;
}

export interface StoredProfileHeader {
  format: 'vaulta-profile';
  version: typeof PROFILE_VERSION;
  profileId: string;
  createdAt: string;
  updatedAt: string;
  access: {
    kdf: StoredKdfConfiguration;
    passwordVerifier: AesGcmEnvelope;
    wrappedMasterGateKey: AesGcmEnvelope;
    masterOnlyProfileWrap: AesGcmEnvelope | null;
    additionalKeyWraps: StoredAdditionalKeyWrap[];
  };
  recovery: {
    salt: string;
    wrappedProfileKey: AesGcmEnvelope;
  } | null;
  protectedMetadata: AesGcmEnvelope;
  publicFactorData: {
    payload: string;
    mac: string;
  };
}

/** Minimal technical subset required to unlock a native backup. */
export interface ProfileBackupAccessHeader {
  profileId: string;
  access: {
    kdf: StoredKdfConfiguration;
    passwordVerifier: AesGcmEnvelope;
    wrappedMasterGateKey: AesGcmEnvelope;
  };
  recovery: StoredProfileHeader['recovery'];
}

export interface ProfileAccessPolicy {
  recoveryEnabled: boolean;
  masterOnlyAccess: boolean;
  additionalKeyIds: string[];
}

export interface ProfileServiceOptions {
  rootDir: string;
  keyDerivation?: KeyDerivationService;
  crypto?: CryptoService;
  recoveryKeys?: RecoveryKeyService;
  atomicWriter?: AtomicFileWriter;
  now?: () => Date;
}

export interface BeginProfileSetupResult {
  pendingId: string;
  recovery: RecoverySetup | null;
}

export interface AdditionalUnlockKey {
  keyId: string;
  secret: Buffer;
}

export interface AddAdditionalKeyWrapInput extends AdditionalUnlockKey {
  requireForUnlock: boolean;
}

export type ProfileFactorKeyMutation =
  | {
      type: 'add';
      keyId: string;
      secret: Buffer;
      requireForUnlock: boolean;
    }
  | {
      type: 'remove';
      keyId: string;
      restoreMasterOnlyAccess: boolean;
    };

export interface ProfileFactorStateUpdate {
  namespace: string;
  expectedPublicFactorData: unknown;
  publicFactorData: unknown;
  protectedMetadata: unknown;
  keyMutation?: ProfileFactorKeyMutation;
}

export type BackupCredential =
  { type: 'master'; value: string } | { type: 'recovery'; value: string };

interface PendingProfileSetup {
  header: StoredProfileHeader;
  profileKey: Buffer;
  masterGateKey: Buffer;
  recoverySetup: RecoverySetup | null;
  recoverySecret: Buffer | null;
}

interface PendingRecoveryRotation {
  setup: RecoverySetup;
  secret: Buffer;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEnvelope(value: unknown): value is AesGcmEnvelope {
  return (
    isRecord(value) &&
    value.algorithm === 'AES-256-GCM' &&
    typeof value.nonce === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.tag === 'string'
  );
}

export function parseStoredProfileHeader(value: unknown): StoredProfileHeader {
  if (
    !isRecord(value) ||
    value.format !== 'vaulta-profile' ||
    value.version !== PROFILE_VERSION ||
    typeof value.profileId !== 'string' ||
    typeof value.createdAt !== 'string' ||
    typeof value.updatedAt !== 'string' ||
    !isRecord(value.access) ||
    !isRecord(value.access.kdf) ||
    typeof value.access.kdf.salt !== 'string' ||
    !isRecord(value.access.kdf.parameters) ||
    !isEnvelope(value.access.passwordVerifier) ||
    !isEnvelope(value.access.wrappedMasterGateKey) ||
    (value.access.masterOnlyProfileWrap !== null &&
      !isEnvelope(value.access.masterOnlyProfileWrap)) ||
    !Array.isArray(value.access.additionalKeyWraps) ||
    !isEnvelope(value.protectedMetadata) ||
    !isRecord(value.publicFactorData) ||
    typeof value.publicFactorData.payload !== 'string' ||
    typeof value.publicFactorData.mac !== 'string'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Das lokale Profil ist beschädigt.');
  }

  const parameters = value.access.kdf.parameters;
  if (
    parameters.algorithm !== 'argon2id' ||
    typeof parameters.memorySizeKiB !== 'number' ||
    typeof parameters.iterations !== 'number' ||
    typeof parameters.parallelism !== 'number' ||
    parameters.hashLength !== 32
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Die gespeicherten Argon2id-Parameter sind ungültig.');
  }

  const additionalKeyWraps = value.access.additionalKeyWraps.map((item) => {
    if (
      !isRecord(item) ||
      typeof item.keyId !== 'string' ||
      typeof item.salt !== 'string' ||
      !isEnvelope(item.wrappedProfileKey)
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Ein zusätzlicher Schlüssel-Wrap ist beschädigt.');
    }
    return {
      keyId: item.keyId,
      salt: item.salt,
      wrappedProfileKey: item.wrappedProfileKey,
    };
  });

  let recovery: StoredProfileHeader['recovery'] = null;
  if (value.recovery !== null) {
    if (
      !isRecord(value.recovery) ||
      typeof value.recovery.salt !== 'string' ||
      !isEnvelope(value.recovery.wrappedProfileKey)
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Der Wiederherstellungs-Wrap ist beschädigt.');
    }
    recovery = {
      salt: value.recovery.salt,
      wrappedProfileKey: value.recovery.wrappedProfileKey,
    };
  }

  const header: StoredProfileHeader = {
    format: 'vaulta-profile',
    version: PROFILE_VERSION,
    profileId: value.profileId,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    access: {
      kdf: {
        salt: value.access.kdf.salt,
        parameters: {
          algorithm: 'argon2id',
          memorySizeKiB: parameters.memorySizeKiB,
          iterations: parameters.iterations,
          parallelism: parameters.parallelism,
          hashLength: 32,
        },
      },
      passwordVerifier: value.access.passwordVerifier,
      wrappedMasterGateKey: value.access.wrappedMasterGateKey,
      masterOnlyProfileWrap: value.access.masterOnlyProfileWrap,
      additionalKeyWraps,
    },
    recovery,
    protectedMetadata: value.protectedMetadata,
    publicFactorData: {
      payload: value.publicFactorData.payload,
      mac: value.publicFactorData.mac,
    },
  };
  assertSafeIdentifier(header.profileId, 'Profil-ID');
  header.access.additionalKeyWraps.forEach((item) =>
    assertSafeIdentifier(item.keyId, 'Schlüssel-ID'),
  );
  return header;
}

function parseJsonValue(serialized: string): ProtectedMetadataValue {
  try {
    const parsed = JSON.parse(serialized) as unknown;
    return parsed as ProtectedMetadataValue;
  } catch (error) {
    throw new VaultaError('CORRUPT_DATA', 'Die öffentlichen Faktordaten sind ungültig.', null, {
      cause: error,
    });
  }
}

export class ProfileService {
  private readonly rootDir: string;
  private readonly profilePath: string;
  private readonly keyDerivation: KeyDerivationService;
  private readonly crypto: CryptoService;
  private readonly recoveryKeys: RecoveryKeyService;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly now: () => Date;
  private readonly writes = new SerialExecutor();
  private readonly pendingSetups = new Map<string, PendingProfileSetup>();
  private readonly pendingRecoveryRotations = new Map<string, PendingRecoveryRotation>();

  private activeProfileKey: Buffer | null = null;
  private activeMasterGateKey: Buffer | null = null;

  public constructor(options: ProfileServiceOptions) {
    this.rootDir = path.resolve(options.rootDir);
    this.profilePath = path.join(this.rootDir, PROFILE_FILENAME);
    this.crypto = options.crypto ?? new CryptoService();
    this.keyDerivation = options.keyDerivation ?? new KeyDerivationService();
    this.recoveryKeys = options.recoveryKeys ?? new RecoveryKeyService(this.crypto);
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.now = options.now ?? (() => new Date());
  }

  public async hasProfile(): Promise<boolean> {
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.profilePath);
    try {
      await readFile(this.profilePath);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw error;
    }
  }

  public async beginSetup(
    masterPassword: string,
    enableRecovery: boolean,
  ): Promise<BeginProfileSetupResult> {
    if (await this.hasProfile()) {
      throw new VaultaError('CONFLICT', 'Es existiert bereits ein lokales Vaulta-Profil.');
    }

    this.clearPendingSetups();
    const pendingId = randomUUID();
    const profileId = randomUUID();
    const profileKey = this.crypto.randomBytes(32);
    const masterGateKey = this.crypto.randomBytes(32);
    const createdAt = this.now().toISOString();
    const kdf = await this.createKdf(masterPassword);
    const passwordKeys = this.derivePasswordKeys(kdf.derived, profileId);

    let recoverySetup: RecoverySetup | null = null;
    let recoverySecret: Buffer | null = null;
    let recovery: StoredProfileHeader['recovery'] = null;
    if (enableRecovery) {
      const generated = this.recoveryKeys.generate();
      recoverySetup = generated.setup;
      recoverySecret = generated.secret;
      recovery = this.createRecoveryWrap(profileKey, profileId, generated.secret);
    }

    const masterOnlyKey = this.deriveMasterOnlyKey(masterGateKey, profileId);
    const header: StoredProfileHeader = {
      format: 'vaulta-profile',
      version: PROFILE_VERSION,
      profileId,
      createdAt,
      updatedAt: createdAt,
      access: {
        kdf: kdf.configuration,
        passwordVerifier: this.crypto.encrypt(
          PASSWORD_VERIFIER,
          passwordKeys.verifierKey,
          this.passwordVerifierAad(profileId),
        ),
        wrappedMasterGateKey: this.crypto.wrapKey(
          masterGateKey,
          passwordKeys.gateWrapKey,
          `profile:${profileId}:master-gate`,
        ),
        masterOnlyProfileWrap: this.crypto.wrapKey(
          profileKey,
          masterOnlyKey,
          `profile:${profileId}:master-only`,
        ),
        additionalKeyWraps: [],
      },
      recovery,
      protectedMetadata: this.encryptProtectedMetadata({}, profileKey, profileId),
      publicFactorData: this.authenticatePublicFactorData(null, masterGateKey, profileId),
    };

    this.crypto.erase(kdf.derived);
    this.crypto.erase(passwordKeys.verifierKey);
    this.crypto.erase(passwordKeys.gateWrapKey);
    this.crypto.erase(masterOnlyKey);

    this.pendingSetups.set(pendingId, {
      header,
      profileKey,
      masterGateKey,
      recoverySetup,
      recoverySecret,
    });
    return { pendingId, recovery: recoverySetup };
  }

  public async completeSetup(
    pendingId: string,
    confirmation: Record<string, string>,
  ): Promise<void> {
    const pending = this.pendingSetups.get(pendingId);
    if (pending === undefined) {
      throw new VaultaError('NOT_FOUND', 'Die ausstehende Einrichtung wurde nicht gefunden.');
    }
    if (
      pending.recoverySetup !== null &&
      !this.recoveryKeys.verifyConfirmation(pending.recoverySetup, confirmation)
    ) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Die abgefragten Gruppen des Wiederherstellungsschlüssels stimmen nicht überein.',
      );
    }

    await this.writes.run(async () => {
      if (await this.hasProfile()) {
        throw new VaultaError('CONFLICT', 'Es existiert bereits ein lokales Vaulta-Profil.');
      }
      await this.writeHeader(pending.header);
    });
    this.replaceActiveKeys(pending.profileKey, pending.masterGateKey);
    this.pendingSetups.delete(pendingId);
    this.crypto.erase(pending.profileKey);
    this.crypto.erase(pending.masterGateKey);
    this.crypto.erase(pending.recoverySecret);
  }

  public async unlock(masterPassword: string, additionalKey?: AdditionalUnlockKey): Promise<void> {
    const header = await this.readPublicHeader();
    const masterGateKey = await this.unwrapMasterGateKey(header, masterPassword);
    let profileKey: Buffer | null = null;

    try {
      this.verifyPublicFactorData(header, masterGateKey);
      if (additionalKey !== undefined) {
        const slot = header.access.additionalKeyWraps.find(
          (candidate) => candidate.keyId === additionalKey.keyId,
        );
        if (slot === undefined) {
          throw new VaultaError('AUTH_FAILED', 'Der Sicherheitsschlüssel ist nicht registriert.');
        }
        const slotKey = this.deriveAdditionalKey(
          masterGateKey,
          additionalKey.secret,
          header.profileId,
          slot.keyId,
          Buffer.from(slot.salt, 'base64'),
        );
        try {
          profileKey = this.crypto.unwrapKey(
            slot.wrappedProfileKey,
            slotKey,
            `profile:${header.profileId}:additional:${slot.keyId}`,
          );
        } catch (error) {
          throw new VaultaError(
            'AUTH_FAILED',
            'Der zusätzliche Entsperrfaktor ist ungültig.',
            null,
            {
              cause: error,
            },
          );
        } finally {
          this.crypto.erase(slotKey);
        }
      } else if (header.access.masterOnlyProfileWrap !== null) {
        const masterOnlyKey = this.deriveMasterOnlyKey(masterGateKey, header.profileId);
        try {
          profileKey = this.crypto.unwrapKey(
            header.access.masterOnlyProfileWrap,
            masterOnlyKey,
            `profile:${header.profileId}:master-only`,
          );
        } finally {
          this.crypto.erase(masterOnlyKey);
        }
      } else {
        throw new VaultaError(
          'AUTH_FACTOR_REQUIRED',
          'Zum Entsperren ist ein registrierter Sicherheitsschlüssel erforderlich.',
        );
      }

      this.decryptProtectedMetadata(header, profileKey);
      this.replaceActiveKeys(profileKey, masterGateKey);
    } finally {
      this.crypto.erase(profileKey);
      this.crypto.erase(masterGateKey);
    }
  }

  public async verifyMasterPassword(masterPassword: string): Promise<boolean> {
    const header = await this.readPublicHeader();
    let gate: Buffer | null = null;
    try {
      gate = await this.unwrapMasterGateKey(header, masterPassword);
      this.verifyPublicFactorData(header, gate);
      return true;
    } catch {
      return false;
    } finally {
      this.crypto.erase(gate);
    }
  }

  public async getPublicFactorDataWithMasterPassword<T>(masterPassword: string): Promise<T | null> {
    const header = await this.readPublicHeader();
    let gate: Buffer | null = null;
    try {
      gate = await this.unwrapMasterGateKey(header, masterPassword);
      return this.verifyPublicFactorData(header, gate) as T | null;
    } finally {
      this.crypto.erase(gate);
    }
  }

  public lock(): void {
    this.crypto.erase(this.activeProfileKey);
    this.crypto.erase(this.activeMasterGateKey);
    this.activeProfileKey = null;
    this.activeMasterGateKey = null;
    this.clearPendingSetups();
    this.clearPendingRecoveryRotations();
  }

  public isUnlocked(): boolean {
    return this.activeProfileKey !== null && this.activeMasterGateKey !== null;
  }

  public async withProfileKey<T>(operation: (profileKey: Buffer) => Promise<T> | T): Promise<T> {
    const profileKey = this.copyActiveKey(this.activeProfileKey);
    try {
      return await operation(profileKey);
    } finally {
      this.crypto.erase(profileKey);
    }
  }

  public async withBackupAccessKeys<T>(
    operation: (keys: { master: Buffer; recovery: Buffer }) => Promise<T> | T,
  ): Promise<T> {
    const profileKey = this.copyActiveKey(this.activeProfileKey);
    let masterGateKey: Buffer | null = null;
    let master: Buffer | null = null;
    let recovery: Buffer | null = null;
    try {
      masterGateKey = this.copyActiveKey(this.activeMasterGateKey);
      const header = await this.readPublicHeader();
      master = this.deriveBackupAccessKey(masterGateKey, header.profileId, 'master');
      recovery = this.deriveBackupAccessKey(profileKey, header.profileId, 'recovery');
      return await operation({ master, recovery });
    } finally {
      this.crypto.erase(profileKey);
      this.crypto.erase(masterGateKey);
      this.crypto.erase(master);
      this.crypto.erase(recovery);
    }
  }

  public async deriveBackupAccessKeyFromHeader(
    header: ProfileBackupAccessHeader,
    credential: BackupCredential,
  ): Promise<Buffer> {
    if (credential.type === 'master') {
      const gate = await this.unwrapMasterGateKey(header, credential.value);
      try {
        return this.deriveBackupAccessKey(gate, header.profileId, 'master');
      } finally {
        this.crypto.erase(gate);
      }
    }
    const profileKey = this.unwrapProfileKeyWithRecovery(header, credential.value);
    try {
      return this.deriveBackupAccessKey(profileKey, header.profileId, 'recovery');
    } finally {
      this.crypto.erase(profileKey);
    }
  }

  public async changeMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const currentGate = await this.unwrapMasterGateKey(header, currentPassword);
      const activeGate = this.copyActiveKey(this.activeMasterGateKey);
      try {
        if (!this.crypto.equals(currentGate, activeGate)) {
          throw new VaultaError('AUTH_FAILED', 'Das aktuelle Master-Passwort ist falsch.');
        }
        const kdf = await this.createKdf(newPassword);
        const keys = this.derivePasswordKeys(kdf.derived, header.profileId);
        try {
          header.access.kdf = kdf.configuration;
          header.access.passwordVerifier = this.crypto.encrypt(
            PASSWORD_VERIFIER,
            keys.verifierKey,
            this.passwordVerifierAad(header.profileId),
          );
          header.access.wrappedMasterGateKey = this.crypto.wrapKey(
            activeGate,
            keys.gateWrapKey,
            `profile:${header.profileId}:master-gate`,
          );
          header.updatedAt = this.now().toISOString();
          await this.writeHeader(header);
        } finally {
          this.crypto.erase(kdf.derived);
          this.crypto.erase(keys.verifierKey);
          this.crypto.erase(keys.gateWrapKey);
        }
      } finally {
        this.crypto.erase(currentGate);
        this.crypto.erase(activeGate);
      }
    });
  }

  public async recover(recoveryKey: string, newMasterPassword: string): Promise<void> {
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const profileKey = this.unwrapProfileKeyWithRecovery(header, recoveryKey);
      const recoverySecret = this.recoveryKeys.parse(recoveryKey);
      const newMasterGateKey = this.crypto.randomBytes(32);
      try {
        const metadata = this.decryptProtectedMetadata(header, profileKey);
        delete metadata.factors;
        const kdf = await this.createKdf(newMasterPassword);
        const keys = this.derivePasswordKeys(kdf.derived, header.profileId);
        const directKey = this.deriveMasterOnlyKey(newMasterGateKey, header.profileId);
        try {
          header.access = {
            kdf: kdf.configuration,
            passwordVerifier: this.crypto.encrypt(
              PASSWORD_VERIFIER,
              keys.verifierKey,
              this.passwordVerifierAad(header.profileId),
            ),
            wrappedMasterGateKey: this.crypto.wrapKey(
              newMasterGateKey,
              keys.gateWrapKey,
              `profile:${header.profileId}:master-gate`,
            ),
            masterOnlyProfileWrap: this.crypto.wrapKey(
              profileKey,
              directKey,
              `profile:${header.profileId}:master-only`,
            ),
            additionalKeyWraps: [],
          };
          header.recovery = this.createRecoveryWrap(profileKey, header.profileId, recoverySecret);
          header.protectedMetadata = this.encryptProtectedMetadata(
            metadata,
            profileKey,
            header.profileId,
          );
          header.publicFactorData = this.authenticatePublicFactorData(
            null,
            newMasterGateKey,
            header.profileId,
          );
          header.updatedAt = this.now().toISOString();
          await this.writeHeader(header);
          this.replaceActiveKeys(profileKey, newMasterGateKey);
        } finally {
          this.crypto.erase(kdf.derived);
          this.crypto.erase(keys.verifierKey);
          this.crypto.erase(keys.gateWrapKey);
          this.crypto.erase(directKey);
        }
      } finally {
        this.crypto.erase(profileKey);
        this.crypto.erase(recoverySecret);
        this.crypto.erase(newMasterGateKey);
      }
    });
  }

  public async beginRecoveryRotation(masterPassword: string): Promise<{
    pendingId: string;
    recovery: RecoverySetup;
  }> {
    if (!(await this.verifyMasterPassword(masterPassword)) || !this.isUnlocked()) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    }
    this.clearPendingRecoveryRotations();
    const generated = this.recoveryKeys.generate();
    const pendingId = randomUUID();
    this.pendingRecoveryRotations.set(pendingId, {
      setup: generated.setup,
      secret: generated.secret,
    });
    return { pendingId, recovery: generated.setup };
  }

  public async completeRecoveryRotation(
    pendingId: string,
    confirmation: Record<string, string>,
  ): Promise<void> {
    const pending = this.pendingRecoveryRotations.get(pendingId);
    if (pending === undefined) {
      throw new VaultaError('NOT_FOUND', 'Die Wiederherstellungsrotation wurde nicht gefunden.');
    }
    if (!this.recoveryKeys.verifyConfirmation(pending.setup, confirmation)) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Die abgefragten Gruppen des Wiederherstellungsschlüssels stimmen nicht überein.',
      );
    }
    this.pendingRecoveryRotations.delete(pendingId);
    const secret = Buffer.from(pending.secret);
    this.crypto.erase(pending.secret);
    try {
      await this.commitRecoveryRotation(secret);
    } finally {
      this.crypto.erase(secret);
    }
  }

  /**
   * Compatibility helper for the current one-step IPC. New callers should use
   * beginRecoveryRotation/completeRecoveryRotation so the displayed groups are confirmed first.
   */
  public async rotateRecovery(masterPassword: string): Promise<RecoverySetup> {
    if (!(await this.verifyMasterPassword(masterPassword)) || !this.isUnlocked()) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.');
    }
    const generated = this.recoveryKeys.generate();
    try {
      await this.commitRecoveryRotation(generated.secret);
      return generated.setup;
    } finally {
      this.crypto.erase(generated.secret);
    }
  }

  public async addAdditionalKeyWrap(input: AddAdditionalKeyWrapInput): Promise<void> {
    assertSafeIdentifier(input.keyId, 'Schlüssel-ID');
    if (input.secret.length < 16) {
      throw new VaultaError('INVALID_INPUT', 'Das zusätzliche Schlüsselgeheimnis ist zu kurz.');
    }
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      if (header.access.additionalKeyWraps.some((item) => item.keyId === input.keyId)) {
        throw new VaultaError('CONFLICT', 'Dieser zusätzliche Schlüssel ist bereits registriert.');
      }
      const profileKey = this.copyActiveKey(this.activeProfileKey);
      const masterGateKey = this.copyActiveKey(this.activeMasterGateKey);
      const salt = this.crypto.randomBytes(32);
      const wrappingKey = this.deriveAdditionalKey(
        masterGateKey,
        input.secret,
        header.profileId,
        input.keyId,
        salt,
      );
      try {
        header.access.additionalKeyWraps.push({
          keyId: input.keyId,
          salt: salt.toString('base64'),
          wrappedProfileKey: this.crypto.wrapKey(
            profileKey,
            wrappingKey,
            `profile:${header.profileId}:additional:${input.keyId}`,
          ),
        });
        if (input.requireForUnlock) header.access.masterOnlyProfileWrap = null;
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
        this.crypto.erase(masterGateKey);
        this.crypto.erase(salt);
        this.crypto.erase(wrappingKey);
      }
    });
  }

  /**
   * Commits the cryptographic access policy and both factor metadata views as
   * one profile-header generation. The expected public state prevents two
   * concurrent factor operations from silently overwriting each other.
   */
  public async commitFactorState(input: ProfileFactorStateUpdate): Promise<void> {
    this.validateNamespace(input.namespace);
    if (input.keyMutation !== undefined) {
      assertSafeIdentifier(input.keyMutation.keyId, 'Schlüssel-ID');
      if (input.keyMutation.type === 'add' && input.keyMutation.secret.length < 16) {
        throw new VaultaError('INVALID_INPUT', 'Das zusätzliche Schlüsselgeheimnis ist zu kurz.');
      }
    }

    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const profileKey = this.copyActiveKey(this.activeProfileKey);
      const gate = this.copyActiveKey(this.activeMasterGateKey);
      let salt: Buffer | null = null;
      let wrappingKey: Buffer | null = null;
      try {
        const expectedPublic = this.normalizeProtectedValue(input.expectedPublicFactorData);
        const currentPublic = this.verifyPublicFactorData(header, gate);
        if (!isDeepStrictEqual(currentPublic, expectedPublic)) {
          throw new VaultaError(
            'CONFLICT',
            'Die Zusatzfaktoren wurden zwischenzeitlich geändert. Bitte versuche es erneut.',
          );
        }

        const mutation = input.keyMutation;
        if (mutation?.type === 'add') {
          if (header.access.additionalKeyWraps.some((item) => item.keyId === mutation.keyId)) {
            throw new VaultaError(
              'CONFLICT',
              'Dieser zusätzliche Schlüssel ist bereits registriert.',
            );
          }
          salt = this.crypto.randomBytes(32);
          wrappingKey = this.deriveAdditionalKey(
            gate,
            mutation.secret,
            header.profileId,
            mutation.keyId,
            salt,
          );
          header.access.additionalKeyWraps.push({
            keyId: mutation.keyId,
            salt: salt.toString('base64'),
            wrappedProfileKey: this.crypto.wrapKey(
              profileKey,
              wrappingKey,
              `profile:${header.profileId}:additional:${mutation.keyId}`,
            ),
          });
          if (mutation.requireForUnlock) header.access.masterOnlyProfileWrap = null;
        } else if (mutation?.type === 'remove') {
          const remaining = header.access.additionalKeyWraps.filter(
            (item) => item.keyId !== mutation.keyId,
          );
          if (remaining.length === header.access.additionalKeyWraps.length) {
            throw new VaultaError('NOT_FOUND', 'Der zusätzliche Schlüssel wurde nicht gefunden.');
          }
          if (
            remaining.length === 0 &&
            header.access.masterOnlyProfileWrap === null &&
            !mutation.restoreMasterOnlyAccess
          ) {
            throw new VaultaError(
              'CONFLICT',
              'Der letzte kryptografische Zusatzfaktor kann nur mit Wiederherstellung des Master-Zugangs entfernt werden.',
            );
          }
          header.access.additionalKeyWraps = remaining;
          if (mutation.restoreMasterOnlyAccess) {
            const directKey = this.deriveMasterOnlyKey(gate, header.profileId);
            try {
              header.access.masterOnlyProfileWrap = this.crypto.wrapKey(
                profileKey,
                directKey,
                `profile:${header.profileId}:master-only`,
              );
            } finally {
              this.crypto.erase(directKey);
            }
          }
        }

        const metadata = this.decryptProtectedMetadata(header, profileKey);
        metadata[input.namespace] = this.normalizeProtectedValue(input.protectedMetadata);
        header.protectedMetadata = this.encryptProtectedMetadata(
          metadata,
          profileKey,
          header.profileId,
        );
        header.publicFactorData = this.authenticatePublicFactorData(
          input.publicFactorData,
          gate,
          header.profileId,
        );
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
        this.crypto.erase(gate);
        this.crypto.erase(salt);
        this.crypto.erase(wrappingKey);
      }
    });
  }

  public async removeAdditionalKeyWrap(
    keyId: string,
    options: { restoreMasterOnlyAccess: boolean } = { restoreMasterOnlyAccess: false },
  ): Promise<void> {
    assertSafeIdentifier(keyId, 'Schlüssel-ID');
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const remaining = header.access.additionalKeyWraps.filter((item) => item.keyId !== keyId);
      if (remaining.length === header.access.additionalKeyWraps.length) {
        throw new VaultaError('NOT_FOUND', 'Der zusätzliche Schlüssel wurde nicht gefunden.');
      }
      if (
        remaining.length === 0 &&
        header.access.masterOnlyProfileWrap === null &&
        !options.restoreMasterOnlyAccess
      ) {
        throw new VaultaError(
          'CONFLICT',
          'Der letzte kryptografische Zusatzfaktor kann nur mit Wiederherstellung des Master-Zugangs entfernt werden.',
        );
      }

      const profileKey = this.copyActiveKey(this.activeProfileKey);
      const gate = this.copyActiveKey(this.activeMasterGateKey);
      try {
        header.access.additionalKeyWraps = remaining;
        if (options.restoreMasterOnlyAccess) {
          const directKey = this.deriveMasterOnlyKey(gate, header.profileId);
          try {
            header.access.masterOnlyProfileWrap = this.crypto.wrapKey(
              profileKey,
              directKey,
              `profile:${header.profileId}:master-only`,
            );
          } finally {
            this.crypto.erase(directKey);
          }
        }
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
        this.crypto.erase(gate);
      }
    });
  }

  public async getAccessPolicy(): Promise<ProfileAccessPolicy> {
    const header = await this.readPublicHeader();
    return {
      recoveryEnabled: header.recovery !== null,
      masterOnlyAccess: header.access.masterOnlyProfileWrap !== null,
      additionalKeyIds: header.access.additionalKeyWraps.map((item) => item.keyId),
    };
  }

  public async getPublicFactorData<T>(): Promise<T | null> {
    const header = await this.readPublicHeader();
    const gate = this.copyActiveKey(this.activeMasterGateKey);
    try {
      return this.verifyPublicFactorData(header, gate) as T | null;
    } finally {
      this.crypto.erase(gate);
    }
  }

  public async setPublicFactorData(value: unknown): Promise<void> {
    await this.writes.run(async () => {
      const gate = this.copyActiveKey(this.activeMasterGateKey);
      try {
        const header = await this.readPublicHeader();
        header.publicFactorData = this.authenticatePublicFactorData(value, gate, header.profileId);
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(gate);
      }
    });
  }

  public async getProtectedMetadata<T>(namespace: string): Promise<T | null> {
    this.validateNamespace(namespace);
    const header = await this.readPublicHeader();
    const profileKey = this.copyActiveKey(this.activeProfileKey);
    try {
      const metadata = this.decryptProtectedMetadata(header, profileKey);
      return (metadata[namespace] as T | undefined) ?? null;
    } finally {
      this.crypto.erase(profileKey);
    }
  }

  public async setProtectedMetadata(namespace: string, value: unknown): Promise<void> {
    this.validateNamespace(namespace);
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const profileKey = this.copyActiveKey(this.activeProfileKey);
      try {
        const metadata = this.decryptProtectedMetadata(header, profileKey);
        metadata[namespace] = this.normalizeProtectedValue(value);
        header.protectedMetadata = this.encryptProtectedMetadata(
          metadata,
          profileKey,
          header.profileId,
        );
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
      }
    });
  }

  public async deleteProtectedMetadata(namespace: string): Promise<void> {
    this.validateNamespace(namespace);
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const profileKey = this.copyActiveKey(this.activeProfileKey);
      try {
        const metadata = this.decryptProtectedMetadata(header, profileKey);
        delete metadata[namespace];
        header.protectedMetadata = this.encryptProtectedMetadata(
          metadata,
          profileKey,
          header.profileId,
        );
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
      }
    });
  }

  public async readPublicHeader(): Promise<StoredProfileHeader> {
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.profilePath);
    let bytes: Buffer;
    try {
      bytes = await readFile(this.profilePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError('NOT_FOUND', 'Es wurde noch kein Vaulta-Profil eingerichtet.');
      }
      throw error;
    }

    try {
      return parseStoredProfileHeader(JSON.parse(bytes.toString('utf8')) as unknown);
    } catch (error) {
      if (error instanceof VaultaError) throw error;
      throw new VaultaError('CORRUPT_DATA', 'Das lokale Profil ist beschädigt.', null, {
        cause: error,
      });
    }
  }

  private async createKdf(masterPassword: string): Promise<{
    configuration: StoredKdfConfiguration;
    derived: Buffer;
  }> {
    const salt = this.crypto.randomBytes(16);
    const parameters = await this.keyDerivation.calibrate();
    const derived = await this.keyDerivation.derive(masterPassword, salt, parameters);
    return {
      configuration: {
        salt: salt.toString('base64'),
        parameters,
      },
      derived,
    };
  }

  private derivePasswordKeys(
    derived: Buffer,
    profileId: string,
  ): {
    verifierKey: Buffer;
    gateWrapKey: Buffer;
  } {
    const salt = Buffer.from(profileId, 'utf8');
    return {
      verifierKey: this.crypto.deriveKey(derived, 'password-verifier', salt),
      gateWrapKey: this.crypto.deriveKey(derived, 'master-gate-wrap', salt),
    };
  }

  private async unwrapMasterGateKey(
    header: ProfileBackupAccessHeader,
    masterPassword: string,
  ): Promise<Buffer> {
    const salt = Buffer.from(header.access.kdf.salt, 'base64');
    let derived: Buffer | null = null;
    let verifierKey: Buffer | null = null;
    let gateWrapKey: Buffer | null = null;
    try {
      derived = await this.keyDerivation.derive(masterPassword, salt, header.access.kdf.parameters);
      const keys = this.derivePasswordKeys(derived, header.profileId);
      verifierKey = keys.verifierKey;
      gateWrapKey = keys.gateWrapKey;
      const verifier = this.crypto.decrypt(
        header.access.passwordVerifier,
        verifierKey,
        this.passwordVerifierAad(header.profileId),
      );
      const valid = this.crypto.equals(verifier, PASSWORD_VERIFIER);
      this.crypto.erase(verifier);
      if (!valid) throw new Error('Password verifier mismatch');
      return this.crypto.unwrapKey(
        header.access.wrappedMasterGateKey,
        gateWrapKey,
        `profile:${header.profileId}:master-gate`,
      );
    } catch (error) {
      throw new VaultaError('AUTH_FAILED', 'Das Master-Passwort ist falsch.', null, {
        cause: error,
      });
    } finally {
      this.crypto.erase(derived);
      this.crypto.erase(verifierKey);
      this.crypto.erase(gateWrapKey);
    }
  }

  private deriveMasterOnlyKey(masterGateKey: Buffer, profileId: string): Buffer {
    return this.crypto.deriveKey(
      masterGateKey,
      'master-only-profile-wrap',
      Buffer.from(profileId, 'utf8'),
    );
  }

  private deriveAdditionalKey(
    masterGateKey: Buffer,
    additionalSecret: Buffer,
    profileId: string,
    keyId: string,
    salt: Buffer,
  ): Buffer {
    const combined = Buffer.concat([masterGateKey, additionalSecret]);
    try {
      return this.crypto.deriveKey(combined, `additional-profile-wrap:${profileId}:${keyId}`, salt);
    } finally {
      this.crypto.erase(combined);
    }
  }

  private deriveBackupAccessKey(
    sourceKey: Buffer,
    profileId: string,
    kind: 'master' | 'recovery',
  ): Buffer {
    return this.crypto.deriveKey(
      sourceKey,
      `backup-access:${kind}`,
      Buffer.from(profileId, 'utf8'),
    );
  }

  private createRecoveryWrap(
    profileKey: Buffer,
    profileId: string,
    recoverySecret: Buffer,
  ): NonNullable<StoredProfileHeader['recovery']> {
    const salt = this.crypto.randomBytes(32);
    const wrappingKey = this.crypto.deriveKey(recoverySecret, 'recovery-profile-wrap', salt);
    try {
      return {
        salt: salt.toString('base64'),
        wrappedProfileKey: this.crypto.wrapKey(
          profileKey,
          wrappingKey,
          `profile:${profileId}:recovery`,
        ),
      };
    } finally {
      this.crypto.erase(salt);
      this.crypto.erase(wrappingKey);
    }
  }

  private unwrapProfileKeyWithRecovery(
    header: ProfileBackupAccessHeader,
    displayKey: string,
  ): Buffer {
    if (header.recovery === null) {
      throw new VaultaError(
        'AUTH_FAILED',
        'Für dieses Profil ist keine Wiederherstellung eingerichtet.',
      );
    }
    const secret = this.recoveryKeys.parse(displayKey);
    const salt = Buffer.from(header.recovery.salt, 'base64');
    const wrappingKey = this.crypto.deriveKey(secret, 'recovery-profile-wrap', salt);
    try {
      return this.crypto.unwrapKey(
        header.recovery.wrappedProfileKey,
        wrappingKey,
        `profile:${header.profileId}:recovery`,
      );
    } catch (error) {
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.', null, {
        cause: error,
      });
    } finally {
      this.crypto.erase(secret);
      this.crypto.erase(salt);
      this.crypto.erase(wrappingKey);
    }
  }

  private encryptProtectedMetadata(
    metadata: Record<string, ProtectedMetadataValue>,
    profileKey: Buffer,
    profileId: string,
  ): AesGcmEnvelope {
    const serialized = Buffer.from(JSON.stringify(metadata), 'utf8');
    if (serialized.length > PROTECTED_METADATA_LIMIT_BYTES) {
      throw new VaultaError('INVALID_INPUT', 'Die geschützten Profilmetadaten sind zu groß.');
    }
    const key = this.crypto.deriveKey(
      profileKey,
      'protected-profile-metadata',
      Buffer.from(profileId, 'utf8'),
    );
    try {
      return this.crypto.encrypt(serialized, key, this.protectedMetadataAad(profileId));
    } finally {
      this.crypto.erase(serialized);
      this.crypto.erase(key);
    }
  }

  private decryptProtectedMetadata(
    header: StoredProfileHeader,
    profileKey: Buffer,
  ): Record<string, ProtectedMetadataValue> {
    const key = this.crypto.deriveKey(
      profileKey,
      'protected-profile-metadata',
      Buffer.from(header.profileId, 'utf8'),
    );
    const plaintext = this.crypto.decrypt(
      header.protectedMetadata,
      key,
      this.protectedMetadataAad(header.profileId),
    );
    try {
      const parsed = JSON.parse(plaintext.toString('utf8')) as unknown;
      if (!isRecord(parsed)) {
        throw new VaultaError('CORRUPT_DATA', 'Die geschützten Profilmetadaten sind ungültig.');
      }
      return parsed as Record<string, ProtectedMetadataValue>;
    } catch (error) {
      if (error instanceof VaultaError) throw error;
      throw new VaultaError(
        'CORRUPT_DATA',
        'Die geschützten Profilmetadaten sind ungültig.',
        null,
        {
          cause: error,
        },
      );
    } finally {
      this.crypto.erase(key);
      this.crypto.erase(plaintext);
    }
  }

  private authenticatePublicFactorData<T>(
    value: T,
    masterGateKey: Buffer,
    profileId: string,
  ): StoredProfileHeader['publicFactorData'] {
    const normalized = this.normalizeProtectedValue(value);
    const serialized = Buffer.from(JSON.stringify(normalized), 'utf8');
    const payload = serialized.toString('base64');
    let key: Buffer | null = null;
    try {
      key = this.crypto.deriveKey(
        masterGateKey,
        'public-factor-data-auth',
        Buffer.from(profileId, 'utf8'),
      );
      const mac = this.crypto
        .hmacSha256(key, Buffer.concat([Buffer.from(profileId, 'utf8'), serialized]))
        .toString('base64');
      return { payload, mac };
    } finally {
      this.crypto.erase(serialized);
      this.crypto.erase(key);
    }
  }

  private verifyPublicFactorData(
    header: StoredProfileHeader,
    masterGateKey: Buffer,
  ): ProtectedMetadataValue {
    const payload = Buffer.from(header.publicFactorData.payload, 'base64');
    const suppliedMac = Buffer.from(header.publicFactorData.mac, 'base64');
    const key = this.crypto.deriveKey(
      masterGateKey,
      'public-factor-data-auth',
      Buffer.from(header.profileId, 'utf8'),
    );
    const expectedMac = this.crypto.hmacSha256(
      key,
      Buffer.concat([Buffer.from(header.profileId, 'utf8'), payload]),
    );
    try {
      if (!this.crypto.equals(suppliedMac, expectedMac)) {
        throw new VaultaError('CORRUPT_DATA', 'Die öffentlichen Faktordaten wurden verändert.');
      }
      return parseJsonValue(payload.toString('utf8'));
    } finally {
      this.crypto.erase(payload);
      this.crypto.erase(suppliedMac);
      this.crypto.erase(key);
      this.crypto.erase(expectedMac);
    }
  }

  private protectedMetadataAad(profileId: string): Buffer {
    return Buffer.from(`vaulta:profile:${profileId}:protected-metadata:v1`, 'utf8');
  }

  private passwordVerifierAad(profileId: string): Buffer {
    return Buffer.from(`vaulta:profile:${profileId}:password-verifier:v1`, 'utf8');
  }

  private async writeHeader(header: StoredProfileHeader): Promise<void> {
    const bytes = Buffer.from(JSON.stringify(header, null, 2), 'utf8');
    await this.atomicWriter.writeFile(this.profilePath, bytes, async (temporaryPath) => {
      const temporary = await readFile(temporaryPath, 'utf8');
      parseStoredProfileHeader(JSON.parse(temporary) as unknown);
    });
  }

  private replaceActiveKeys(profileKey: Buffer, masterGateKey: Buffer): void {
    this.crypto.erase(this.activeProfileKey);
    this.crypto.erase(this.activeMasterGateKey);
    this.activeProfileKey = Buffer.from(profileKey);
    this.activeMasterGateKey = Buffer.from(masterGateKey);
  }

  private copyActiveKey(key: Buffer | null): Buffer {
    if (key === null) {
      throw new VaultaError('LOCKED', 'Vaulta ist gesperrt.');
    }
    return Buffer.from(key);
  }

  private validateNamespace(namespace: string): void {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(namespace)) {
      throw new VaultaError('INVALID_INPUT', 'Der Metadaten-Namespace ist ungültig.');
    }
  }

  private normalizeProtectedValue(value: unknown): ProtectedMetadataValue {
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(value);
    } catch (error) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Die geschützten Profilmetadaten sind ungültig.',
        null,
        {
          cause: error,
        },
      );
    }
    if (serialized === undefined) {
      throw new VaultaError('INVALID_INPUT', 'Die geschützten Profilmetadaten sind ungültig.');
    }
    const normalized = JSON.parse(serialized) as unknown;
    return normalized as ProtectedMetadataValue;
  }

  private clearPendingSetups(): void {
    for (const pending of this.pendingSetups.values()) {
      this.crypto.erase(pending.profileKey);
      this.crypto.erase(pending.masterGateKey);
      this.crypto.erase(pending.recoverySecret);
    }
    this.pendingSetups.clear();
  }

  private clearPendingRecoveryRotations(): void {
    for (const pending of this.pendingRecoveryRotations.values()) {
      this.crypto.erase(pending.secret);
    }
    this.pendingRecoveryRotations.clear();
  }

  private async commitRecoveryRotation(secret: Buffer): Promise<void> {
    await this.writes.run(async () => {
      const header = await this.readPublicHeader();
      const profileKey = this.copyActiveKey(this.activeProfileKey);
      try {
        header.recovery = this.createRecoveryWrap(profileKey, header.profileId, secret);
        header.updatedAt = this.now().toISOString();
        await this.writeHeader(header);
      } finally {
        this.crypto.erase(profileKey);
      }
    });
  }
}
