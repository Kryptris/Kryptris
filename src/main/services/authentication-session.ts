import { VaultaError } from '../../shared/errors';

export type AuthenticationSessionState = 'locked' | 'authenticating' | 'authenticated';

/**
 * Fail-closed application gate around the lower-level profile key state.
 *
 * A profile key can exist briefly while a local TOTP value is checked. That
 * must never make normal vault IPC available before every configured factor
 * has completed successfully.
 */
export class AuthenticationSession {
  private state: AuthenticationSessionState = 'locked';
  private challengeId: string | null = null;
  private epoch = 0;

  public begin(): number {
    if (this.state !== 'locked') {
      throw new VaultaError(
        'CONFLICT',
        this.state === 'authenticated'
          ? 'Vaulta ist bereits entsperrt.'
          : 'Eine Entsperrung wird bereits ausgeführt.',
      );
    }
    this.epoch += 1;
    this.state = 'authenticating';
    this.challengeId = null;
    return this.epoch;
  }

  public awaitChallenge(challengeId: string, epoch: number): void {
    this.assertEpoch(epoch);
    this.challengeId = challengeId;
  }

  public assertChallenge(challengeId: string): number {
    if (this.state !== 'authenticating' || this.challengeId !== challengeId) {
      throw new VaultaError('AUTH_FAILED', 'Die Sicherheitsabfrage ist nicht mehr aktiv.');
    }
    return this.epoch;
  }

  public cancelChallenge(challengeId: string): boolean {
    if (this.state !== 'authenticating' || this.challengeId !== challengeId) return false;
    this.reset();
    return true;
  }

  public complete(profileUnlocked: boolean, epoch: number): void {
    if (this.state !== 'authenticating' || this.epoch !== epoch || !profileUnlocked) {
      this.reset();
      throw new VaultaError('LOCKED', 'Die Entsperrung wurde nicht vollständig abgeschlossen.');
    }
    this.state = 'authenticated';
    this.challengeId = null;
  }

  public reset(): void {
    this.epoch += 1;
    this.state = 'locked';
    this.challengeId = null;
  }

  public isAuthenticated(profileUnlocked: boolean): boolean {
    return this.state === 'authenticated' && profileUnlocked;
  }

  public requireAuthenticated(profileUnlocked: boolean): number {
    if (!this.isAuthenticated(profileUnlocked)) {
      throw new VaultaError('LOCKED', 'Vaulta ist gesperrt.');
    }
    return this.epoch;
  }

  public assertAuthenticated(epoch: number, profileUnlocked: boolean): void {
    if (this.epoch !== epoch || !this.isAuthenticated(profileUnlocked)) {
      throw new VaultaError('LOCKED', 'Vaulta wurde während des Vorgangs gesperrt.');
    }
  }

  public assertEpoch(epoch: number): void {
    if (this.state !== 'authenticating' || this.epoch !== epoch) {
      throw new VaultaError('LOCKED', 'Die Entsperrung wurde abgebrochen.');
    }
  }

  public getState(): AuthenticationSessionState {
    return this.state;
  }

  public isAuthenticating(epoch: number): boolean {
    return this.state === 'authenticating' && this.epoch === epoch;
  }
}
