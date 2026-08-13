import { VaultaError } from '../../shared/errors';
import type { EntryLifecycleMetadata, EntryType, VaultEntry } from '../../shared/models';
import { createDefaultEntryLifecycleMetadata } from '../../shared/models';

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/u;
const DAY_MS = 24 * 60 * 60 * 1_000;
const EXPIRY_TYPES = new Set<EntryType>(['credit-card', 'software-license', 'file']);

export interface EntryLifecycleStatus {
  readonly rotationDue: boolean;
  readonly nextRotationDate: string | null;
  readonly reminderDue: boolean;
  readonly twoFactorMissing: boolean;
}

/** Central date-only and type semantics for lifecycle metadata; it never retains old secrets. */
export class EntryLifecycleService {
  public normalizeForType(
    type: EntryType,
    lifecycle: EntryLifecycleMetadata | undefined,
  ): EntryLifecycleMetadata {
    const value = lifecycle ?? createDefaultEntryLifecycleMetadata();
    this.assertShape(value);
    const normalized: EntryLifecycleMetadata = { ...value };

    if (type !== 'credential') {
      normalized.rotationIntervalDays = null;
      normalized.nextRotationDate = null;
      normalized.rotationExcluded = false;
      normalized.twoFactorStatus = 'unknown';
    } else {
      normalized.expiryReminderDate = null;
      if (normalized.rotationExcluded) {
        normalized.rotationIntervalDays = null;
        normalized.nextRotationDate = null;
      }
      if (normalized.rotationIntervalDays === null) normalized.nextRotationDate = null;
    }
    if (!EXPIRY_TYPES.has(type)) normalized.expiryReminderDate = null;
    return normalized;
  }

  public afterSecretChange(
    type: EntryType,
    lifecycle: EntryLifecycleMetadata,
    changedAt: string,
  ): EntryLifecycleMetadata {
    const normalized = this.normalizeForType(type, lifecycle);
    if (
      type !== 'credential' ||
      normalized.rotationExcluded ||
      normalized.rotationIntervalDays === null
    ) {
      return normalized;
    }
    const changedDate = this.dateOnlyFromTimestamp(changedAt);
    normalized.nextRotationDate = this.addDays(changedDate, normalized.rotationIntervalDays);
    return normalized;
  }

  public status(entry: VaultEntry, now: Date = new Date()): EntryLifecycleStatus {
    const lifecycle = this.normalizeForType(entry.data.type, entry.lifecycle);
    const today = this.dateOnlyFromTimestamp(now.toISOString());
    const nextRotationDate =
      entry.data.type === 'credential' &&
      !lifecycle.rotationExcluded &&
      lifecycle.rotationIntervalDays !== null
        ? (lifecycle.nextRotationDate ??
          this.addDays(
            this.dateOnlyFromTimestamp(entry.secretChangedAt),
            lifecycle.rotationIntervalDays,
          ))
        : null;
    return {
      rotationDue: nextRotationDate !== null && nextRotationDate <= today,
      nextRotationDate,
      reminderDue: lifecycle.expiryReminderDate !== null && lifecycle.expiryReminderDate <= today,
      twoFactorMissing:
        entry.data.type === 'credential' &&
        lifecycle.twoFactorStatus !== 'active' &&
        !(lifecycle.twoFactorStatus === 'unknown' && entry.data.value.totp !== undefined),
    };
  }

  public assertShape(value: EntryLifecycleMetadata): void {
    if (
      value.rotationIntervalDays !== null &&
      (!Number.isSafeInteger(value.rotationIntervalDays) ||
        value.rotationIntervalDays < 1 ||
        value.rotationIntervalDays > 3_650)
    ) {
      throw new VaultaError('INVALID_INPUT', 'Das Rotationsintervall ist ungültig.');
    }
    if (!['unknown', 'active', 'inactive'].includes(value.twoFactorStatus)) {
      throw new VaultaError('INVALID_INPUT', 'Der lokale 2FA-Status ist ungültig.');
    }
    this.assertDateOnly(value.nextRotationDate, 'Das nächste Rotationsdatum ist ungültig.');
    this.assertDateOnly(value.expiryReminderDate, 'Das Erinnerungsdatum ist ungültig.');
  }

  private assertDateOnly(value: string | null, message: string): void {
    if (value === null) return;
    const match = DATE_ONLY.exec(value);
    if (match === null) throw new VaultaError('INVALID_INPUT', message);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const parsed = new Date(Date.UTC(year, month - 1, day));
    if (
      parsed.getUTCFullYear() !== year ||
      parsed.getUTCMonth() !== month - 1 ||
      parsed.getUTCDate() !== day
    ) {
      throw new VaultaError('INVALID_INPUT', message);
    }
  }

  private dateOnlyFromTimestamp(value: string): string {
    const timestamp = Date.parse(value);
    if (!Number.isFinite(timestamp)) {
      throw new VaultaError('CORRUPT_DATA', 'Ein Lebenszyklus-Zeitstempel ist ungültig.');
    }
    return new Date(timestamp).toISOString().slice(0, 10);
  }

  private addDays(dateOnly: string, days: number): string {
    this.assertDateOnly(dateOnly, 'Ein Lebenszyklus-Datum ist ungültig.');
    const timestamp = Date.parse(`${dateOnly}T00:00:00.000Z`);
    return new Date(timestamp + days * DAY_MS).toISOString().slice(0, 10);
  }
}
