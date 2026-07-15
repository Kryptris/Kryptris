const DEFAULT_MOUSE_MOVE_THROTTLE_MS = 1_000;

export class TrustedActivityReporter {
  private lastMouseMoveAt: number | null = null;

  public constructor(
    private readonly onActivity: () => void,
    private readonly now: () => number = Date.now,
    private readonly mouseMoveThrottleMs = DEFAULT_MOUSE_MOVE_THROTTLE_MS,
  ) {}

  public reportKeyboardInput(): void {
    this.onActivity();
  }

  public reportMouseInput(type: Electron.MouseInputEvent['type']): void {
    if (type !== 'mouseMove') {
      this.onActivity();
      return;
    }

    const now = this.now();
    if (this.lastMouseMoveAt !== null && now - this.lastMouseMoveAt < this.mouseMoveThrottleMs) {
      return;
    }
    this.lastMouseMoveAt = now;
    this.onActivity();
  }
}
