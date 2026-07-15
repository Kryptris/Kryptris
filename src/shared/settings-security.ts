import type { VaultaSettings } from './models';

/**
 * Returns whether applying `next` would weaken a persisted security control.
 * The Main process remains authoritative; the Renderer uses the same predicate
 * only to decide whether it must ask for the master password before saving.
 */
export function isSecurityWeakeningSettingsChange(
  current: VaultaSettings,
  next: VaultaSettings,
): boolean {
  const autoLockWeakening =
    current.autoLockSeconds !== next.autoLockSeconds &&
    (current.autoLockSeconds === 0 ||
      next.autoLockSeconds === 0 ||
      next.autoLockSeconds > current.autoLockSeconds);

  return (
    autoLockWeakening ||
    (current.lockOnMinimize && !next.lockOnMinimize) ||
    (current.lockOnSystemLock && !next.lockOnSystemLock) ||
    (current.lockOnSuspend && !next.lockOnSuspend) ||
    next.clipboardClearSeconds > current.clipboardClearSeconds ||
    (current.requireMasterForReveal && !next.requireMasterForReveal) ||
    (current.contentProtection && !next.contentProtection) ||
    next.attachmentMaxBytes > current.attachmentMaxBytes ||
    (current.automaticBackups && !next.automaticBackups) ||
    (current.backupFolder !== null && next.backupFolder === null) ||
    next.backupRotation.daily < current.backupRotation.daily ||
    next.backupRotation.weekly < current.backupRotation.weekly ||
    next.backupRotation.monthly < current.backupRotation.monthly ||
    next.auditMaxEvents < current.auditMaxEvents ||
    next.auditRetentionDays < current.auditRetentionDays
  );
}
