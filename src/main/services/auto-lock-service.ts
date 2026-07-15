export interface AutoLockServiceOptions {
  onLock: (reason: string) => void | Promise<void>;
  now?: () => number;
  setTimer?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  clearTimer?: (timer: NodeJS.Timeout) => void;
}

export class AutoLockService {
  private readonly onLock: (reason: string) => void | Promise<void>;
  private readonly now: () => number;
  private readonly setTimer: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly clearTimer: (timer: NodeJS.Timeout) => void;
  private timer: NodeJS.Timeout | null = null;
  private timeoutSeconds = 300;
  private deadlineMs: number | null = null;
  private enabled = false;

  public constructor(options: AutoLockServiceOptions) {
    this.onLock = options.onLock;
    this.now = options.now ?? Date.now;
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
  }

  public start(timeoutSeconds: number): void {
    this.enabled = true;
    this.timeoutSeconds = Math.max(0, timeoutSeconds);
    this.activity();
  }

  public stop(): void {
    this.enabled = false;
    this.deadlineMs = null;
    this.cancelTimer();
  }

  public updateTimeout(timeoutSeconds: number): void {
    this.timeoutSeconds = Math.max(0, timeoutSeconds);
    if (this.enabled) this.activity();
  }

  public activity(): void {
    if (!this.enabled) return;
    this.cancelTimer();
    if (this.timeoutSeconds === 0) {
      this.deadlineMs = null;
      return;
    }
    const delayMs = this.timeoutSeconds * 1_000;
    this.deadlineMs = this.now() + delayMs;
    this.timer = this.setTimer(() => {
      this.timer = null;
      this.deadlineMs = null;
      void Promise.resolve(this.onLock('inactivity')).catch(() => undefined);
    }, delayMs);
  }

  public lockImmediately(reason: string): void {
    if (!this.enabled) return;
    this.stop();
    void Promise.resolve(this.onLock(reason)).catch(() => undefined);
  }

  public lockWhenLeavingIfImmediate(): void {
    if (this.enabled && this.timeoutSeconds === 0) this.lockImmediately('immediate');
  }

  public getDeadline(): string | null {
    return this.deadlineMs === null ? null : new Date(this.deadlineMs).toISOString();
  }

  private cancelTimer(): void {
    if (this.timer === null) return;
    this.clearTimer(this.timer);
    this.timer = null;
  }
}
