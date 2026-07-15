import { timingSafeEqual } from 'node:crypto';

export interface ClipboardAdapter {
  writeText(value: string): void;
  readText(): string;
  clear(): void;
}

export interface ClipboardServiceOptions {
  clipboard: ClipboardAdapter;
  onCleared?: () => void;
  setTimer?: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  clearTimer?: (timer: NodeJS.Timeout) => void;
}

function equalText(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  try {
    if (leftBuffer.length !== rightBuffer.length) return false;
    return timingSafeEqual(leftBuffer, rightBuffer);
  } finally {
    leftBuffer.fill(0);
    rightBuffer.fill(0);
  }
}

export class ClipboardService {
  private readonly clipboard: ClipboardAdapter;
  private readonly onCleared: () => void;
  private readonly setTimer: (callback: () => void, delayMs: number) => NodeJS.Timeout;
  private readonly clearTimer: (timer: NodeJS.Timeout) => void;
  private timer: NodeJS.Timeout | null = null;
  private ownedValue: string | null = null;
  private generation = 0;

  public constructor(options: ClipboardServiceOptions) {
    this.clipboard = options.clipboard;
    this.onCleared = options.onCleared ?? (() => undefined);
    this.setTimer = options.setTimer ?? setTimeout;
    this.clearTimer = options.clearTimer ?? clearTimeout;
  }

  public copySecret(value: string, clearAfterSeconds: number): void {
    this.cancelTimer();
    this.generation += 1;
    const generation = this.generation;
    this.ownedValue = value;
    this.clipboard.writeText(value);
    this.timer = this.setTimer(
      () => {
        this.timer = null;
        if (generation !== this.generation) return;
        this.clearOwnedValue();
      },
      Math.max(5, Math.min(120, clearAfterSeconds)) * 1_000,
    );
  }

  public clearOwnedValue(): boolean {
    this.cancelTimer();
    const ownedValue = this.ownedValue;
    this.ownedValue = null;
    this.generation += 1;
    if (ownedValue === null || !equalText(this.clipboard.readText(), ownedValue)) return false;
    this.clipboard.clear();
    this.onCleared();
    return true;
  }

  public clearManually(): boolean {
    this.cancelTimer();
    this.ownedValue = null;
    this.generation += 1;
    const hadContent = this.clipboard.readText().length > 0;
    this.clipboard.clear();
    this.onCleared();
    return hadContent;
  }

  public dispose(): void {
    this.clearOwnedValue();
  }

  private cancelTimer(): void {
    if (this.timer === null) return;
    this.clearTimer(this.timer);
    this.timer = null;
  }
}
