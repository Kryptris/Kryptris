import { describe, expect, it, vi } from 'vitest';

import { TrustedActivityReporter } from '../../src/main/trusted-activity-reporter';

describe('TrustedActivityReporter', () => {
  it('meldet Tastatur- und diskrete Mausereignisse unmittelbar aus dem Main-Prozess', () => {
    const onActivity = vi.fn();
    const reporter = new TrustedActivityReporter(onActivity);

    reporter.reportKeyboardInput();
    reporter.reportMouseInput('mouseDown');
    reporter.reportMouseInput('mouseWheel');

    expect(onActivity).toHaveBeenCalledTimes(3);
  });

  it('drosselt reine Mausbewegungen auf höchstens eine Meldung pro Sekunde', () => {
    const onActivity = vi.fn();
    let now = 10_000;
    const reporter = new TrustedActivityReporter(onActivity, () => now, 1_000);

    reporter.reportMouseInput('mouseMove');
    now += 999;
    reporter.reportMouseInput('mouseMove');
    now += 1;
    reporter.reportMouseInput('mouseMove');

    expect(onActivity).toHaveBeenCalledTimes(2);
  });
});
