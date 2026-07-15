import { afterEach, describe, expect, it, vi } from 'vitest';

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

afterEach(() => vi.useRealTimers());

describe('ClipboardService – Lebenszyklus', () => {
  it('begrenzt die automatische Leerung auf 5 bis 120 Sekunden', () => {
    vi.useFakeTimers();
    const clipboard = new MemoryClipboard();
    const service = new ClipboardService({ clipboard });

    service.copySecret('kurz', 1);
    vi.advanceTimersByTime(4_999);
    expect(clipboard.value).toBe('kurz');
    vi.advanceTimersByTime(1);
    expect(clipboard.value).toBe('');

    service.copySecret('lang', 999);
    vi.advanceTimersByTime(119_999);
    expect(clipboard.value).toBe('lang');
    vi.advanceTimersByTime(1);
    expect(clipboard.value).toBe('');
  });

  it('ersetzt Timer atomar und leert niemals spaeter kopierte Fremdinhalte', () => {
    vi.useFakeTimers();
    const clipboard = new MemoryClipboard();
    const service = new ClipboardService({ clipboard });

    service.copySecret('erstes', 5);
    vi.advanceTimersByTime(2_000);
    service.copySecret('zweites', 5);
    vi.advanceTimersByTime(3_000);
    expect(clipboard.value).toBe('zweites');
    clipboard.value = 'fremd';
    vi.advanceTimersByTime(2_000);
    expect(clipboard.value).toBe('fremd');
  });

  it('leert manuell jeden Inhalt, dispose dagegen nur den eigenen', () => {
    const clipboard = new MemoryClipboard();
    const onCleared = vi.fn();
    const service = new ClipboardService({ clipboard, onCleared });

    clipboard.value = 'fremd';
    expect(service.clearManually()).toBe(true);
    expect(clipboard.value).toBe('');
    expect(onCleared).toHaveBeenCalledOnce();

    service.copySecret('vaulta', 30);
    clipboard.value = 'neuer fremder Inhalt';
    service.dispose();
    expect(clipboard.value).toBe('neuer fremder Inhalt');
  });
});
