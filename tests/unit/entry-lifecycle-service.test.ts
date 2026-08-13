import { describe, expect, it } from 'vitest';

import { EntryLifecycleService } from '../../src/main/services/entry-lifecycle-service';
import { createDefaultEntryLifecycleMetadata } from '../../src/shared/models';
import { credentialEntry } from './service-fixtures';

describe('EntryLifecycleService', () => {
  const service = new EntryLifecycleService();

  it('berechnet die nächste Rotation nach einem Geheimniswechsel ohne Historie', () => {
    const lifecycle = {
      ...createDefaultEntryLifecycleMetadata(),
      rotationIntervalDays: 30,
      nextRotationDate: '2026-01-01',
    };

    expect(service.afterSecretChange('credential', lifecycle, '2026-02-10T23:30:00.000Z')).toEqual({
      ...lifecycle,
      nextRotationDate: '2026-03-12',
    });
    expect(lifecycle.nextRotationDate).toBe('2026-01-01');
  });

  it('behandelt Schaltjahre und Date-only-Grenzen ohne lokale Zeitzonenverschiebung', () => {
    const lifecycle = {
      ...createDefaultEntryLifecycleMetadata(),
      rotationIntervalDays: 2,
    };
    expect(
      service.afterSecretChange('credential', lifecycle, '2028-02-28T23:59:59.000Z'),
    ).toMatchObject({ nextRotationDate: '2028-03-01' });
  });

  it('deaktiviert Rotation vollständig bei bewusster Ausnahme', () => {
    expect(
      service.normalizeForType('credential', {
        rotationIntervalDays: 90,
        nextRotationDate: '2026-08-01',
        rotationExcluded: true,
        twoFactorStatus: 'active',
        expiryReminderDate: null,
      }),
    ).toEqual({
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: true,
      twoFactorStatus: 'active',
      expiryReminderDate: null,
    });
  });

  it('erzwingt typspezifische neutrale Felder', () => {
    const input = {
      rotationIntervalDays: 30,
      nextRotationDate: '2026-08-01',
      rotationExcluded: false,
      twoFactorStatus: 'inactive' as const,
      expiryReminderDate: '2026-09-01',
    };
    expect(service.normalizeForType('software-license', input)).toEqual({
      rotationIntervalDays: null,
      nextRotationDate: null,
      rotationExcluded: false,
      twoFactorStatus: 'unknown',
      expiryReminderDate: '2026-09-01',
    });
    expect(service.normalizeForType('secure-note', input)).toEqual(
      createDefaultEntryLifecycleMetadata(),
    );
  });

  it('meldet fällige Rotation, Erinnerung und fehlenden lokal bestätigten 2FA-Schutz', () => {
    const credential = credentialEntry({ secretChangedAt: '2026-01-01T00:00:00.000Z' });
    credential.lifecycle = {
      ...createDefaultEntryLifecycleMetadata(),
      rotationIntervalDays: 30,
      twoFactorStatus: 'unknown',
    };
    expect(service.status(credential, new Date('2026-02-01T12:00:00.000Z'))).toEqual({
      rotationDue: true,
      nextRotationDate: '2026-01-31',
      reminderDue: false,
      twoFactorMissing: true,
    });
  });

  it.each(['2026-02-30', '2026-2-01', 'kein-datum'])(
    'weist ungültiges Date-only-Format %s zurück',
    (date) => {
      expect(() =>
        service.normalizeForType('credential', {
          ...createDefaultEntryLifecycleMetadata(),
          rotationIntervalDays: 1,
          nextRotationDate: date,
        }),
      ).toThrow(/Rotationsdatum/i);
    },
  );
});
