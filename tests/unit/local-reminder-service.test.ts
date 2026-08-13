import { describe, expect, it, vi } from 'vitest';

import {
  LocalReminderService,
  type LocalReminderNotification,
  type LocalReminderSnapshot,
} from '../../src/main/services/local-reminder-service';

interface SchedulerHarness {
  readonly schedule: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  readonly cancel: (timer: NodeJS.Timeout) => void;
  runNext(): void;
  readonly delays: number[];
}

function createSchedulerHarness(): SchedulerHarness {
  const callbacks = new Map<NodeJS.Timeout, () => void>();
  const delays: number[] = [];
  const schedule = (callback: () => void, delayMs: number): NodeJS.Timeout => {
    const timer = {} as NodeJS.Timeout;
    callbacks.set(timer, callback);
    delays.push(delayMs);
    return timer;
  };
  const cancel = (timer: NodeJS.Timeout): void => {
    callbacks.delete(timer);
  };
  return {
    schedule,
    cancel,
    delays,
    runNext: () => {
      const next = callbacks.entries().next().value as [NodeJS.Timeout, () => void] | undefined;
      if (next === undefined) throw new Error('Kein geplanter Lauf vorhanden.');
      callbacks.delete(next[0]);
      next[1]();
    },
  };
}

function flushPromises(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

describe('LocalReminderService', () => {
  it('zeigt ausschließlich einen generischen lokalen Hinweis und sperrt vor dem Öffnen', async () => {
    const scheduler = createSchedulerHarness();
    let click: (() => void) | undefined;
    const createNotification = vi.fn((): LocalReminderNotification => ({
      on: (_event, callback) => {
        click = callback;
      },
    }));
    const onOpenLocked = vi.fn(() => Promise.resolve());
    const service = new LocalReminderService({
      createNotification,
      onOpenLocked,
      schedule: scheduler.schedule,
      cancelScheduled: scheduler.cancel,
      intervalMs: 1_000,
    });

    service.start(
      { rotation: true, expiry: true, backup: true },
      (): Promise<LocalReminderSnapshot> =>
        Promise.resolve({
          rotationDue: 1,
          expirationDue: 1,
          staleBackup: true,
        }),
    );
    scheduler.runNext();
    await flushPromises();

    expect(createNotification).toHaveBeenCalledWith({
      title: 'Kryptris',
      body: 'Eine lokale Erinnerung ist fällig. Öffne Kryptris, um sie nach dem Entsperren zu prüfen.',
    });
    const serialized = JSON.stringify(createNotification.mock.calls[0]);
    expect(serialized).not.toMatch(/Tresor|Eintrag|Passwort|Geheim/i);
    click?.();
    await flushPromises();
    expect(onOpenLocked).toHaveBeenCalledOnce();
  });

  it('startet bei deaktivierten Kategorien keinen Scan', () => {
    const scheduler = createSchedulerHarness();
    const service = new LocalReminderService({
      createNotification: () => null,
      onOpenLocked: () => undefined,
      schedule: scheduler.schedule,
      cancelScheduled: scheduler.cancel,
    });

    service.start(
      { rotation: false, expiry: false, backup: false },
      (): Promise<LocalReminderSnapshot> =>
        Promise.resolve({
          rotationDue: 1,
          expirationDue: 1,
          staleBackup: true,
        }),
    );

    expect(scheduler.delays).toEqual([]);
  });

  it('invalidiert laufende Auswertungen beim Sperren und erstellt keinen späten Hinweis', async () => {
    const scheduler = createSchedulerHarness();
    let resolveSnapshot: ((snapshot: LocalReminderSnapshot) => void) | undefined;
    const createNotification = vi.fn(() => null);
    const service = new LocalReminderService({
      createNotification,
      onOpenLocked: () => undefined,
      schedule: scheduler.schedule,
      cancelScheduled: scheduler.cancel,
    });

    service.start(
      { rotation: true, expiry: false, backup: false },
      () =>
        new Promise<LocalReminderSnapshot>((resolve) => {
          resolveSnapshot = resolve;
        }),
    );
    scheduler.runNext();
    expect(service.isRunning()).toBe(true);
    service.stop();
    resolveSnapshot?.({ rotationDue: 1, expirationDue: 0, staleBackup: false });
    await flushPromises();

    expect(createNotification).not.toHaveBeenCalled();
    expect(service.isRunning()).toBe(false);
  });

  it('koalesziert gleiche fällige Kategorien und prüft erst nach dem Intervall erneut', async () => {
    const scheduler = createSchedulerHarness();
    const createNotification = vi.fn(() => null);
    const getSnapshot = vi.fn((): Promise<LocalReminderSnapshot> =>
      Promise.resolve({ rotationDue: 2, expirationDue: 0, staleBackup: false }),
    );
    const service = new LocalReminderService({
      createNotification,
      onOpenLocked: () => undefined,
      schedule: scheduler.schedule,
      cancelScheduled: scheduler.cancel,
      intervalMs: 1_000,
    });

    service.start({ rotation: true, expiry: false, backup: false }, getSnapshot);
    scheduler.runNext();
    await flushPromises();
    scheduler.runNext();
    await flushPromises();

    expect(getSnapshot).toHaveBeenCalledTimes(2);
    expect(createNotification).toHaveBeenCalledTimes(1);
    expect(scheduler.delays).toEqual([0, 1_000, 1_000]);
  });
});
