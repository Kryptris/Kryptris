import { afterEach, describe, expect, it, vi } from 'vitest';

import { AutoLockService } from '../../src/main/services/auto-lock-service';

afterEach(() => vi.useRealTimers());

describe('AutoLockService – Zustandswechsel', () => {
  it('stellt eine nachvollziehbare Deadline bereit und entfernt sie beim Stoppen', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-14T10:00:00.000Z'));
    const onLock = vi.fn();
    const service = new AutoLockService({ onLock });

    service.start(300);
    expect(service.getDeadline()).toBe('2026-07-14T10:05:00.000Z');
    service.stop();
    expect(service.getDeadline()).toBeNull();
    vi.advanceTimersByTime(300_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it('setzt bei einer Laufzeit-Aenderung die volle neue Frist', () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    const service = new AutoLockService({ onLock });
    service.start(60);
    vi.advanceTimersByTime(30_000);
    service.updateTimeout(10);
    vi.advanceTimersByTime(9_999);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onLock).toHaveBeenCalledWith('inactivity');
  });

  it('behandelt negative Fristen als sofort und sperrt nur im aktiven Zustand', () => {
    const onLock = vi.fn();
    const service = new AutoLockService({ onLock });
    service.lockImmediately('system-lock');
    expect(onLock).not.toHaveBeenCalled();

    service.start(-1);
    expect(service.getDeadline()).toBeNull();
    service.lockWhenLeavingIfImmediate();
    expect(onLock).toHaveBeenCalledWith('immediate');
  });
});
