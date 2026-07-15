import { describe, expect, it } from 'vitest';

import { DEFAULT_SETTINGS, type VaultaSettings } from '../../src/shared/models';
import { isSecurityWeakeningSettingsChange } from '../../src/shared/settings-security';

function changed(patch: Partial<VaultaSettings>): VaultaSettings {
  return { ...DEFAULT_SETTINGS, ...patch };
}

describe('Master-Gate für Sicherheitseinstellungen', () => {
  it.each([
    ['längere Inaktivitätsfrist', DEFAULT_SETTINGS, changed({ autoLockSeconds: 86_400 })],
    ['Sofortmodus', DEFAULT_SETTINGS, changed({ autoLockSeconds: 0 })],
    ['Minimize-Sperre aus', changed({ lockOnMinimize: true }), DEFAULT_SETTINGS],
    ['Windows-Sperre aus', DEFAULT_SETTINGS, changed({ lockOnSystemLock: false })],
    ['Suspend-Sperre aus', DEFAULT_SETTINGS, changed({ lockOnSuspend: false })],
    ['längere Clipboard-Frist', DEFAULT_SETTINGS, changed({ clipboardClearSeconds: 120 })],
    ['Master-Abfrage beim Reveal aus', changed({ requireMasterForReveal: true }), DEFAULT_SETTINGS],
    ['Content Protection aus', DEFAULT_SETTINGS, changed({ contentProtection: false })],
    ['größeres Anhangslimit', DEFAULT_SETTINGS, changed({ attachmentMaxBytes: 200 * 1024 * 1024 })],
    ['automatische Backups aus', changed({ automaticBackups: true }), DEFAULT_SETTINGS],
    ['Backup-Ziel entfernen', changed({ backupFolder: 'C:\\Vaulta-Backups' }), DEFAULT_SETTINGS],
    [
      'weniger Backup-Stände',
      DEFAULT_SETTINGS,
      changed({ backupRotation: { ...DEFAULT_SETTINGS.backupRotation, daily: 1 } }),
    ],
    ['kleineres Audit', DEFAULT_SETTINGS, changed({ auditMaxEvents: 100 })],
    ['kürzere Audit-Aufbewahrung', DEFAULT_SETTINGS, changed({ auditRetentionDays: 1 })],
  ])('erkennt %s als Abschwächung', (_label, current, next) => {
    expect(isSecurityWeakeningSettingsChange(current, next)).toBe(true);
  });

  it('lässt Verschärfungen und einen nativ autorisierten Zielwechsel ohne Master-Gate zu', () => {
    expect(
      isSecurityWeakeningSettingsChange(DEFAULT_SETTINGS, changed({ autoLockSeconds: 60 })),
    ).toBe(false);
    expect(
      isSecurityWeakeningSettingsChange(
        changed({ backupFolder: 'C:\\Alt' }),
        changed({ backupFolder: 'C:\\Neu' }),
      ),
    ).toBe(false);
    expect(
      isSecurityWeakeningSettingsChange(
        DEFAULT_SETTINGS,
        changed({ lockOnMinimize: true, requireMasterForReveal: true }),
      ),
    ).toBe(false);
  });
});
