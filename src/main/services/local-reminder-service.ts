import type { LocalReminderPreferences } from './windows-integration-service';

const DEFAULT_REMINDER_INTERVAL_MS = 15 * 60 * 1_000;

export interface LocalReminderSnapshot {
  readonly rotationDue: number;
  readonly expirationDue: number;
  readonly staleBackup: boolean;
}

export interface LocalReminderCheckContext {
  readonly assertActive: () => void;
}

export interface LocalReminderNotification {
  on(event: 'click', callback: () => void): void;
}

export interface LocalReminderServiceOptions {
  readonly createNotification: (options: {
    readonly title: string;
    readonly body: string;
  }) => LocalReminderNotification | null;
  readonly onOpenLocked: () => void | Promise<void>;
  readonly intervalMs?: number;
  readonly schedule?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  readonly cancelScheduled?: (timer: NodeJS.Timeout) => void;
  readonly onError?: (error: unknown) => void;
}

interface ReminderRun {
  readonly preferences: LocalReminderPreferences;
  readonly getSnapshot: (context: LocalReminderCheckContext) => Promise<LocalReminderSnapshot>;
}

function hasEnabledReminder(preferences: LocalReminderPreferences): boolean {
  return preferences.rotation || preferences.expiry || preferences.backup;
}

function isValidSnapshot(value: LocalReminderSnapshot): boolean {
  return (
    Number.isSafeInteger(value.rotationDue) &&
    value.rotationDue >= 0 &&
    Number.isSafeInteger(value.expirationDue) &&
    value.expirationDue >= 0
  );
}

function reminderSignature(
  snapshot: LocalReminderSnapshot,
  preferences: LocalReminderPreferences,
): string | null {
  const rotation = preferences.rotation && snapshot.rotationDue > 0;
  const expiry = preferences.expiry && snapshot.expirationDue > 0;
  const backup = preferences.backup && snapshot.staleBackup;
  if (!rotation && !expiry && !backup) return null;
  return `${rotation ? '1' : '0'}${expiry ? '1' : '0'}${backup ? '1' : '0'}`;
}

/**
 * Schedules only generic local reminders. It deliberately keeps no titles, vault identifiers,
 * paths, or entry values and discards an in-flight result as soon as locking invalidates it.
 */
export class LocalReminderService {
  private readonly createNotification: LocalReminderServiceOptions['createNotification'];
  private readonly onOpenLocked: () => void | Promise<void>;
  private readonly intervalMs: number;
  private readonly schedule: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly cancelScheduled: (timer: NodeJS.Timeout) => void;
  private readonly onError: (error: unknown) => void;
  private timer: NodeJS.Timeout | null = null;
  private generation = 0;
  private activeRun = false;
  private run: ReminderRun | null = null;
  private lastNotifiedSignature: string | null = null;

  public constructor(options: LocalReminderServiceOptions) {
    this.createNotification = options.createNotification;
    this.onOpenLocked = options.onOpenLocked;
    this.intervalMs = options.intervalMs ?? DEFAULT_REMINDER_INTERVAL_MS;
    this.schedule = options.schedule ?? ((callback, delayMs) => setTimeout(callback, delayMs));
    this.cancelScheduled = options.cancelScheduled ?? ((timer) => clearTimeout(timer));
    this.onError = options.onError ?? (() => undefined);
    if (!Number.isSafeInteger(this.intervalMs) || this.intervalMs < 1) {
      throw new Error('Das lokale Erinnerungsintervall ist ungültig.');
    }
  }

  /** Starts a new unlocked-only generation. An existing scan is invalidated before it can notify. */
  public start(
    preferences: LocalReminderPreferences,
    getSnapshot: (context: LocalReminderCheckContext) => Promise<LocalReminderSnapshot>,
  ): void {
    this.stop();
    this.lastNotifiedSignature = null;
    if (!hasEnabledReminder(preferences)) return;
    this.run = { preferences, getSnapshot };
    this.scheduleRun(this.generation, 0);
  }

  /** Called synchronously on lock and disposal; late results cannot create a notification. */
  public stop(): void {
    this.generation += 1;
    if (this.timer !== null) this.cancelScheduled(this.timer);
    this.timer = null;
    this.run = null;
  }

  public dispose(): void {
    this.stop();
    this.lastNotifiedSignature = null;
  }

  public isRunning(): boolean {
    return this.activeRun;
  }

  private scheduleRun(generation: number, delayMs: number): void {
    if (generation !== this.generation || this.run === null) return;
    if (this.timer !== null) this.cancelScheduled(this.timer);
    this.timer = this.schedule(() => {
      this.timer = null;
      void this.execute(generation);
    }, delayMs);
  }

  private async execute(generation: number): Promise<void> {
    const run = this.run;
    if (generation !== this.generation || run === null) return;
    if (this.activeRun) return;
    this.activeRun = true;
    const assertActive = () => {
      if (generation !== this.generation || this.run === null) {
        throw new Error('Die lokale Erinnerung wurde abgebrochen.');
      }
    };
    try {
      assertActive();
      const snapshot = await run.getSnapshot({ assertActive });
      assertActive();
      if (!isValidSnapshot(snapshot)) return;
      const signature = reminderSignature(snapshot, run.preferences);
      if (signature === null) {
        this.lastNotifiedSignature = null;
        return;
      }
      if (signature === this.lastNotifiedSignature) return;
      this.lastNotifiedSignature = signature;
      const notification = this.createNotification({
        title: 'Kryptris',
        body: 'Eine lokale Erinnerung ist fällig. Öffne Kryptris, um sie nach dem Entsperren zu prüfen.',
      });
      assertActive();
      if (notification === null) return;
      notification.on('click', () => {
        void Promise.resolve(this.onOpenLocked()).catch((error: unknown) => this.onError(error));
      });
    } catch (error) {
      if (generation === this.generation) this.onError(error);
    } finally {
      this.activeRun = false;
      if (this.run !== null) {
        this.scheduleRun(this.generation, generation === this.generation ? this.intervalMs : 0);
      }
    }
  }
}
