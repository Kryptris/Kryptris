import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  TrashRetentionService,
  type TrashRetentionSweepContext,
} from '../../src/main/services/trash-retention-service';

afterEach(() => {
  vi.useRealTimers();
});

describe('TrashRetentionService', () => {
  it('führt beim Standard nie und unmittelbar nach Unlock keinen Sweep aus', async () => {
    vi.useFakeTimers();
    const sweep = vi.fn((context: TrashRetentionSweepContext) => {
      void context;
      return Promise.resolve();
    });
    const service = new TrashRetentionService({
      now: () => new Date('2026-07-21T12:00:00.000Z'),
      sweepIntervalMs: 60_000,
    });

    service.start(null, sweep);
    await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1_000);
    expect(sweep).not.toHaveBeenCalled();

    service.start(30, sweep);
    await vi.advanceTimersByTimeAsync(59_999);
    expect(sweep).not.toHaveBeenCalled();
    service.stop();
  });

  it('berechnet die Grenze erst nach einem vollständigen Laufzeitintervall', async () => {
    vi.useFakeTimers();
    const sweep = vi.fn((context: TrashRetentionSweepContext) => {
      void context;
      return Promise.resolve();
    });
    const service = new TrashRetentionService({
      now: () => new Date('2026-07-21T12:00:00.000Z'),
      sweepIntervalMs: 60_000,
    });
    service.start(30, sweep);

    await vi.advanceTimersByTimeAsync(60_000);

    expect(sweep).toHaveBeenCalledTimes(1);
    expect(sweep.mock.calls[0]?.[0].cutoff).toBe('2026-06-21T12:00:00.000Z');
    service.stop();
  });

  it('koalesziert langsame Läufe und plant erst nach Abschluss erneut', async () => {
    vi.useFakeTimers();
    let finish: (() => void) | undefined;
    const sweep = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const service = new TrashRetentionService({ sweepIntervalMs: 1_000 });
    service.start(7, sweep);

    await vi.advanceTimersByTimeAsync(10_000);
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(service.isRunning()).toBe(true);
    finish?.();
    await Promise.resolve();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(999);
    expect(sweep).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(sweep).toHaveBeenCalledTimes(2);
    service.stop();
  });

  it('invalidiert den laufenden Sweep beim Sperren', async () => {
    vi.useFakeTimers();
    let observedCancellation = false;
    const service = new TrashRetentionService({ sweepIntervalMs: 1_000 });
    service.start(1, ({ assertActive }) => {
      service.stop();
      try {
        assertActive();
      } catch {
        observedCancellation = true;
        return Promise.reject(new Error('wird als Fehler gemeldet'));
      }
      return Promise.resolve();
    });

    await vi.advanceTimersByTimeAsync(1_000);

    expect(observedCancellation).toBe(true);
    expect(service.isRunning()).toBe(false);
  });

  it('weist ungültige Fristen zurück', () => {
    const service = new TrashRetentionService();
    expect(() => service.start(0, () => Promise.resolve())).toThrow(/Aufbewahrung/i);
    expect(() => service.start(3_651, () => Promise.resolve())).toThrow(/Aufbewahrung/i);
  });
});
