import { describe, expect, it } from 'vitest';

import { DEFAULT_SETTINGS } from '../../src/shared/models';
import { vaultaSettingsSchema } from '../../src/shared/schemas';

describe('W11-Einstellungsschema', () => {
  it('ergänzt sichere Desktop-Defaults für ältere geschützte Einstellungen', () => {
    const legacySettings = Object.fromEntries(
      Object.entries(DEFAULT_SETTINGS).filter(
        ([key]) =>
          ![
            'minimizeToTray',
            'closeToTray',
            'startWithWindows',
            'startMinimized',
            'focusMode',
            'localReminders',
            'onboardingCompleted',
          ].includes(key),
      ),
    );

    expect(vaultaSettingsSchema.parse(legacySettings)).toEqual({
      ...legacySettings,
      minimizeToTray: false,
      closeToTray: false,
      startWithWindows: false,
      startMinimized: false,
      focusMode: false,
      localReminders: { rotation: false, expiry: false, backup: false },
      onboardingCompleted: true,
    });
  });

  it('verwendet für neue Profile den explizit unvollständigen Onboarding-Status', () => {
    expect(vaultaSettingsSchema.parse(DEFAULT_SETTINGS).onboardingCompleted).toBe(false);
  });

  it('weist unvollständige oder erweiterte Reminder-Einstellungen strikt ab', () => {
    expect(
      vaultaSettingsSchema.safeParse({
        ...DEFAULT_SETTINGS,
        localReminders: { rotation: true, expiry: false },
      }).success,
    ).toBe(false);
    expect(
      vaultaSettingsSchema.safeParse({
        ...DEFAULT_SETTINGS,
        localReminders: { rotation: true, expiry: false, backup: true, title: 'nicht erlaubt' },
      }).success,
    ).toBe(false);
  });
});
