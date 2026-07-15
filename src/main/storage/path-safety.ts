import path from 'node:path';

import { VaultaError } from '../../shared/errors';

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export function assertSafeIdentifier(value: string, label = 'ID'): void {
  if (!SAFE_IDENTIFIER.test(value)) {
    throw new VaultaError('UNSAFE_PATH', `${label} enthält unzulässige Zeichen.`);
  }
}

export function resolveInside(root: string, ...segments: string[]): string {
  const resolvedRoot = path.resolve(root);
  const resolvedPath = path.resolve(resolvedRoot, ...segments);
  const relative = path.relative(resolvedRoot, resolvedPath);

  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new VaultaError('UNSAFE_PATH', 'Der Dateipfad liegt außerhalb des Vaulta-Datenordners.');
  }
  return resolvedPath;
}

export function normalizeBackupPath(value: string): string {
  if (value.length === 0 || value.includes('\\') || value.startsWith('/')) {
    throw new VaultaError('CORRUPT_DATA', 'Die Sicherung enthält einen unsicheren Dateipfad.');
  }

  const normalized = path.posix.normalize(value);
  if (normalized === '..' || normalized.startsWith('../') || normalized !== value) {
    throw new VaultaError('CORRUPT_DATA', 'Die Sicherung enthält einen unsicheren Dateipfad.');
  }
  return normalized;
}
