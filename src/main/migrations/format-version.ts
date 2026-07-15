import { VaultaError } from '../../shared/errors';

export function requireCurrentFormatVersion(
  value: unknown,
  currentVersion: number,
  formatName: string,
): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new VaultaError('CORRUPT_DATA', `Die ${formatName}-Formatversion ist ungültig.`);
  }
  if (value > currentVersion) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      `${formatName} verwendet die neuere Formatversion ${value}; unterstützt wird Version ${currentVersion}.`,
      'Öffne diese Daten mit einer neueren Vaulta-Version. Die Datei wurde nicht verändert.',
    );
  }
  if (value < currentVersion) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      `${formatName} verwendet Formatversion ${value}; dafür ist kein verlustfreier Migrationspfad registriert.`,
      'Die Datei wurde nicht verändert. Stelle eine kompatible Vaulta-Version oder ein gültiges Backup bereit.',
    );
  }
  return value;
}
