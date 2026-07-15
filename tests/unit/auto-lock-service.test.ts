import { describe, expect, it, vi } from 'vitest';

import { AutoLockService } from '../../src/main/services/auto-lock-service';

describe('AutoLockService', () => {
  it('setzt die Frist bei Aktivität zurück', () => {
    vi.useFakeTimers();
    const onLock = vi.fn();
    const service = new AutoLockService({ onLock });
    service.start(60);
    vi.advanceTimersByTime(45_000);
    service.activity();
    vi.advanceTimersByTime(45_000);
    expect(onLock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(15_000);
    expect(onLock).toHaveBeenCalledWith('inactivity');
    vi.useRealTimers();
  });

  it('interpretiert sofort als Sperren beim Verlassen', () => {
    const onLock = vi.fn();
    const service = new AutoLockService({ onLock });
    service.start(0);
    service.lockWhenLeavingIfImmediate();
    expect(onLock).toHaveBeenCalledWith('immediate');
  });
});
