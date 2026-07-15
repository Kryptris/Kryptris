import { describe, expect, it, vi } from 'vitest';

import { ClipboardService } from '../../src/main/services/clipboard-service';

class MemoryClipboard {
  public value = '';
  public writeText(value: string): void {
    this.value = value;
  }
  public readText(): string {
    return this.value;
  }
  public clear(): void {
    this.value = '';
  }
}

describe('ClipboardService', () => {
  it('leert nur weiterhin von Vaulta gesetzte Inhalte automatisch', () => {
    vi.useFakeTimers();
    const clipboard = new MemoryClipboard();
    const service = new ClipboardService({ clipboard });
    service.copySecret('canary-secret', 5);
    clipboard.value = 'später kopierter Inhalt';
    vi.advanceTimersByTime(5_000);
    expect(clipboard.value).toBe('später kopierter Inhalt');
    vi.useRealTimers();
  });

  it('leert den eigenen Inhalt nach Ablauf', () => {
    vi.useFakeTimers();
    const clipboard = new MemoryClipboard();
    const onCleared = vi.fn();
    const service = new ClipboardService({ clipboard, onCleared });
    service.copySecret('canary-secret', 5);
    vi.advanceTimersByTime(5_000);
    expect(clipboard.value).toBe('');
    expect(onCleared).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });
});
