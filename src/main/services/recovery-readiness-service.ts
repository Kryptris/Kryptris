import { z } from 'zod';

import { VaultaError } from '../../shared/errors';

export const RECOVERY_READINESS_NAMESPACE = 'recovery-readiness';
export const RECOVERY_READINESS_STALE_DAYS = 180;

const DAY_MS = 24 * 60 * 60 * 1_000;
const FIRST_BACKOFF_ATTEMPT = 5;
const MAX_BACKOFF_SECONDS = 60;

const recoveryReadinessRecordSchema = z
  .object({
    testedAt: z.iso.datetime(),
    success: z.boolean(),
  })
  .strict();

export interface RecoveryReadinessRecord {
  readonly testedAt: string;
  readonly success: boolean;
}

export type RecoveryReadinessState =
  'not-configured' | 'never-tested' | 'failed' | 'stale' | 'ready';

export interface RecoveryReadinessStatus {
  readonly state: RecoveryReadinessState;
  readonly lastTestedAt: string | null;
  readonly lastTestSucceeded: boolean | null;
  readonly staleAfterDays: typeof RECOVERY_READINESS_STALE_DAYS;
}

export interface RecoveryReadinessServiceOptions {
  readonly now?: () => number;
}

export interface RecoveryReadinessAttempt {
  /**
   * Records a cryptographically failed Recovery-Key immediately. Callers use
   * this before persisting status and audit so an I/O failure cannot bypass the
   * in-memory throttle.
   */
  readonly authenticationFailed: () => void;
}

/**
 * Maintains only non-secret readiness metadata and an in-memory attempt throttle.
 *
 * Recovery keys never enter this service. The caller performs the cryptographic
 * verification in the profile service and keeps persistence/audit in one wider
 * transaction.
 */
export class RecoveryReadinessService {
  private readonly now: () => number;
  private failedAttempts = 0;
  private blockedUntil = 0;
  private attemptRunning = false;

  public constructor(options: RecoveryReadinessServiceOptions = {}) {
    this.now = options.now ?? Date.now;
  }

  public createRecord(success: boolean): RecoveryReadinessRecord {
    return {
      testedAt: new Date(this.now()).toISOString(),
      success,
    };
  }

  public parseRecord(value: unknown): RecoveryReadinessRecord | null {
    if (value === null || value === undefined) return null;
    const parsed = recoveryReadinessRecordSchema.safeParse(value);
    if (!parsed.success) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Der gespeicherte Recovery-Bereitschaftsstatus ist beschädigt.',
      );
    }
    return parsed.data;
  }

  public status(
    recoveryEnabled: boolean,
    record: RecoveryReadinessRecord | null,
  ): RecoveryReadinessStatus {
    if (!recoveryEnabled) return this.emptyStatus('not-configured');
    if (record === null) return this.emptyStatus('never-tested');

    const common = {
      lastTestedAt: record.testedAt,
      lastTestSucceeded: record.success,
      staleAfterDays: RECOVERY_READINESS_STALE_DAYS,
    } as const;
    if (!record.success) return { state: 'failed', ...common };

    const ageMs = Math.max(0, this.now() - Date.parse(record.testedAt));
    return {
      state: ageMs >= RECOVERY_READINESS_STALE_DAYS * DAY_MS ? 'stale' : 'ready',
      ...common,
    };
  }

  /**
   * Rejects parallel tests instead of queueing a secret-bearing caller.
   * Only generic authentication failures contribute to the dedicated backoff.
   */
  public async runAttempt<T>(
    operation: (attempt: RecoveryReadinessAttempt) => Promise<T>,
  ): Promise<T> {
    if (this.attemptRunning) {
      throw new VaultaError('CONFLICT', 'Ein Recovery-Bereitschaftstest wird bereits ausgeführt.');
    }
    this.assertNotRateLimited();
    this.attemptRunning = true;
    let authenticationFailureRecorded = false;
    const authenticationFailed = (): void => {
      if (authenticationFailureRecorded) return;
      authenticationFailureRecorded = true;
      this.registerAuthenticationFailure();
    };
    try {
      const result = await operation({ authenticationFailed });
      if (!authenticationFailureRecorded) this.resetFailures();
      return result;
    } catch (error) {
      if (
        !authenticationFailureRecorded &&
        error instanceof VaultaError &&
        error.code === 'AUTH_FAILED'
      ) {
        authenticationFailed();
      }
      throw error;
    } finally {
      this.attemptRunning = false;
    }
  }

  /** A newly activated Recovery-Key starts with a fresh, untested state. */
  public resetAfterRecoveryRotation(): void {
    this.resetFailures();
  }

  private emptyStatus(
    state: Extract<RecoveryReadinessState, 'not-configured' | 'never-tested'>,
  ): RecoveryReadinessStatus {
    return {
      state,
      lastTestedAt: null,
      lastTestSucceeded: null,
      staleAfterDays: RECOVERY_READINESS_STALE_DAYS,
    };
  }

  private assertNotRateLimited(): void {
    const remaining = this.blockedUntil - this.now();
    if (remaining <= 0) return;
    throw new VaultaError(
      'AUTH_RATE_LIMITED',
      `Zu viele fehlgeschlagene Recovery-Tests. Warte noch ${Math.ceil(remaining / 1_000)} Sekunden.`,
    );
  }

  private registerAuthenticationFailure(): void {
    this.failedAttempts += 1;
    if (this.failedAttempts < FIRST_BACKOFF_ATTEMPT) return;
    const seconds = Math.min(
      MAX_BACKOFF_SECONDS,
      2 ** (this.failedAttempts - FIRST_BACKOFF_ATTEMPT),
    );
    this.blockedUntil = this.now() + seconds * 1_000;
  }

  private resetFailures(): void {
    this.failedAttempts = 0;
    this.blockedUntil = 0;
  }
}
