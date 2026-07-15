import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import { argon2id } from 'hash-wasm';

import { VaultaError } from '../../shared/errors';

export const PRODUCT_ARGON2_MEMORY_KIB = 256 * 1024;
export const PRODUCT_ARGON2_TARGET_MS = 1_000;
const PRODUCT_ARGON2_MAX_ITERATIONS = 8;
const PRODUCT_ARGON2_MAX_MEMORY_KIB = 512 * 1024;
const PRODUCT_ARGON2_MAX_PARALLELISM = 4;

export interface Argon2idParameters {
  algorithm: 'argon2id';
  memorySizeKiB: number;
  iterations: number;
  parallelism: number;
  hashLength: 32;
}

export const PRODUCT_ARGON2ID_PARAMETERS: Readonly<Argon2idParameters> = Object.freeze({
  algorithm: 'argon2id',
  memorySizeKiB: PRODUCT_ARGON2_MEMORY_KIB,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
});

export interface KeyDerivationServiceOptions {
  parameters?: Argon2idParameters;
  /** Must only be enabled in automated tests. */
  allowUnsafeParametersForTests?: boolean;
  /** Deterministic calibration hook for automated tests. */
  calibrationProbe?: (parameters: Argon2idParameters) => Promise<number>;
  targetDurationMs?: number;
}

function validateInteger(value: number, minimum: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new VaultaError('INVALID_INPUT', `${label} ist ungültig.`);
  }
}

export class KeyDerivationService {
  public readonly parameters: Argon2idParameters;
  private readonly allowUnsafeParametersForTests: boolean;
  private readonly calibrationProbe: (parameters: Argon2idParameters) => Promise<number>;
  private readonly targetDurationMs: number;
  private readonly calibrateOnDemand: boolean;
  private calibration: Promise<Argon2idParameters> | null = null;

  public constructor(options: KeyDerivationServiceOptions = {}) {
    this.parameters = options.parameters ?? { ...PRODUCT_ARGON2ID_PARAMETERS };
    this.allowUnsafeParametersForTests = options.allowUnsafeParametersForTests === true;
    this.calibrateOnDemand = options.parameters === undefined;
    this.targetDurationMs = options.targetDurationMs ?? PRODUCT_ARGON2_TARGET_MS;
    this.calibrationProbe =
      options.calibrationProbe ?? ((parameters) => this.measureSingleIteration(parameters));
    this.validateParameters(this.parameters);
    if (!Number.isFinite(this.targetDurationMs) || this.targetDurationMs < 100) {
      throw new VaultaError('INVALID_INPUT', 'Die Argon2id-Zieldauer ist ungültig.');
    }
  }

  /**
   * Measures this device once and chooses a stored iteration count close to the product target.
   * An explicitly injected parameter set is treated as already calibrated (primarily for tests).
   */
  public async calibrate(): Promise<Argon2idParameters> {
    if (!this.calibrateOnDemand) return { ...this.parameters };
    this.calibration ??= this.runCalibration();
    return { ...(await this.calibration) };
  }

  public async derive(
    password: string,
    salt: Buffer,
    parameters: Argon2idParameters = this.parameters,
  ): Promise<Buffer> {
    if (password.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Das Master-Passwort darf nicht leer sein.');
    }
    if (salt.length < 16) {
      throw new VaultaError('INVALID_INPUT', 'Der Argon2id-Salt ist zu kurz.');
    }
    this.validateParameters(parameters);

    const derived = await argon2id({
      password,
      salt,
      parallelism: parameters.parallelism,
      iterations: parameters.iterations,
      memorySize: parameters.memorySizeKiB,
      hashLength: parameters.hashLength,
      outputType: 'binary',
    });
    return Buffer.from(derived);
  }

  public validateParameters(parameters: Argon2idParameters): void {
    if (parameters.algorithm !== 'argon2id' || parameters.hashLength !== 32) {
      throw new VaultaError('INVALID_INPUT', 'Die Argon2id-Parameter werden nicht unterstützt.');
    }
    validateInteger(parameters.memorySizeKiB, 8, 'Der Argon2id-Speicherbedarf');
    validateInteger(parameters.iterations, 1, 'Die Argon2id-Iterationszahl');
    validateInteger(parameters.parallelism, 1, 'Die Argon2id-Parallelität');

    if (
      parameters.memorySizeKiB < PRODUCT_ARGON2_MEMORY_KIB &&
      !this.allowUnsafeParametersForTests
    ) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Produktive Argon2id-Parameter müssen mindestens 256 MiB Speicher verwenden.',
      );
    }
    if (
      parameters.memorySizeKiB > PRODUCT_ARGON2_MAX_MEMORY_KIB ||
      parameters.iterations > PRODUCT_ARGON2_MAX_ITERATIONS ||
      parameters.parallelism > PRODUCT_ARGON2_MAX_PARALLELISM
    ) {
      throw new VaultaError(
        'INVALID_INPUT',
        'Die Argon2id-Parameter überschreiten die unterstützten Sicherheitsgrenzen.',
      );
    }
  }

  private async runCalibration(): Promise<Argon2idParameters> {
    const probeParameters: Argon2idParameters = {
      ...this.parameters,
      memorySizeKiB: Math.max(this.parameters.memorySizeKiB, PRODUCT_ARGON2_MEMORY_KIB),
      iterations: 1,
    };
    let elapsedMs: number;
    try {
      elapsedMs = await this.calibrationProbe(probeParameters);
    } catch (error) {
      throw new VaultaError(
        'AUTH_FAILED',
        'Das Gerät konnte die sichere Argon2id-Kalibrierung mit 256 MiB nicht zuverlässig ausführen.',
        'Schließe speicherintensive Programme und versuche die Einrichtung erneut.',
        { cause: error },
      );
    }
    if (!Number.isFinite(elapsedMs) || elapsedMs <= 0) {
      throw new VaultaError('INVALID_INPUT', 'Die Argon2id-Kalibrierung lieferte kein Ergebnis.');
    }
    const iterations = Math.min(
      PRODUCT_ARGON2_MAX_ITERATIONS,
      Math.max(1, Math.round(this.targetDurationMs / elapsedMs)),
    );
    const calibrated = { ...probeParameters, iterations };
    this.validateParameters(calibrated);
    return calibrated;
  }

  private async measureSingleIteration(parameters: Argon2idParameters): Promise<number> {
    const salt = randomBytes(16);
    let derived: Buffer | null = null;
    const startedAt = performance.now();
    try {
      derived = await this.derive('vaulta-calibration-probe-v1', salt, parameters);
      return Math.max(performance.now() - startedAt, 0.01);
    } finally {
      salt.fill(0);
      derived?.fill(0);
    }
  }
}
