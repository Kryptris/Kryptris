import { VaultaError } from '../../shared/errors';

const DEFAULT_SWEEP_INTERVAL_MS = 60 * 60 * 1_000;
const DAY_MS = 24 * 60 * 60 * 1_000;

export interface TrashRetentionSweepContext {
  readonly cutoff: string;
  readonly assertActive: () => void;
}

export interface TrashRetentionServiceOptions {
  readonly now?: () => Date;
  readonly sweepIntervalMs?: number;
  readonly schedule?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  readonly cancelScheduled?: (timer: NodeJS.Timeout) => void;
  readonly onError?: (error: unknown) => void;
}

/** Runs retention only after a complete unlocked interval; no missed run is caught up on unlock. */
export class TrashRetentionService {
  private readonly now: () => Date;
  private readonly sweepIntervalMs: number;
  private readonly schedule: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly cancelScheduled: (timer: NodeJS.Timeout) => void;
  private readonly onError: (error: unknown) => void;
  private timer: NodeJS.Timeout | null = null;
  private generation = 0;
  private running = false;

  public constructor(options: TrashRetentionServiceOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    this.schedule = options.schedule ?? ((callback, delayMs) => setTimeout(callback, delayMs));
    this.cancelScheduled = options.cancelScheduled ?? ((timer) => clearTimeout(timer));
    this.onError = options.onError ?? (() => undefined);
    if (!Number.isSafeInteger(this.sweepIntervalMs) || this.sweepIntervalMs < 1) {
      throw new VaultaError('INVALID_INPUT', 'Das Papierkorb-Prüfintervall ist ungültig.');
    }
  }

  public start(
    retentionDays: number | null,
    sweep: (context: TrashRetentionSweepContext) => Promise<void>,
  ): void {
    this.stop();
    if (retentionDays === null) return;
    if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 3_650) {
      throw new VaultaError('INVALID_INPUT', 'Die Papierkorb-Aufbewahrung ist ungültig.');
    }
    const generation = this.generation;
    this.timer = this.schedule(
      () => void this.run(generation, retentionDays, sweep),
      this.sweepIntervalMs,
    );
  }

  public stop(): void {
    this.generation += 1;
    if (this.timer !== null) this.cancelScheduled(this.timer);
    this.timer = null;
  }

  public isRunning(): boolean {
    return this.running;
  }

  private async run(
    generation: number,
    retentionDays: number,
    sweep: (context: TrashRetentionSweepContext) => Promise<void>,
  ): Promise<void> {
    if (generation !== this.generation || this.running) return;
    this.timer = null;
    this.running = true;
    const assertActive = () => {
      if (generation !== this.generation) {
        throw new VaultaError('CANCELLED', 'Die Papierkorb-Prüfung wurde abgebrochen.');
      }
    };
    try {
      assertActive();
      const cutoff = new Date(this.now().getTime() - retentionDays * DAY_MS).toISOString();
      await sweep({ cutoff, assertActive });
      assertActive();
    } catch (error) {
      if (!(error instanceof VaultaError) || error.code !== 'CANCELLED') this.onError(error);
    } finally {
      this.running = false;
      if (generation === this.generation) {
        this.timer = this.schedule(
          () => void this.run(generation, retentionDays, sweep),
          this.sweepIntervalMs,
        );
      }
    }
  }
}
