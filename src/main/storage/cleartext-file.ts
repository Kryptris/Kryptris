import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rm, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';

export interface CleartextFileWriteOptions {
  replaceExisting?: boolean;
  /**
   * Absolute Verzeichniswurzeln, in die auch ueber Junctions oder symbolische Links niemals
   * geschrieben werden darf. Der Guard laeuft vor jeder bestehenden Dateioperation.
   */
  forbiddenRoots?: readonly string[];
}

/**
 * Schreibt einen bewusst angeforderten Klartextexport direkt an sein finales Ziel.
 * Es entsteht zu keinem Zeitpunkt eine zweite Klartextdatei mit temporaerem Namen.
 */
export async function writeExclusiveCleartextFile(
  destinationPath: string,
  writer: (handle: FileHandle) => Promise<void>,
  options: CleartextFileWriteOptions = {},
): Promise<void> {
  if (!path.isAbsolute(destinationPath) || path.basename(destinationPath).length === 0) {
    throw new VaultaError('UNSAFE_PATH', 'Das Exportziel ist ungueltig.');
  }

  const resolvedDestination = path.resolve(destinationPath);
  await assertOutsideForbiddenRoots(resolvedDestination, options.forbiddenRoots ?? []);
  await mkdir(path.dirname(resolvedDestination), { recursive: true });
  await assertOutsideForbiddenRoots(resolvedDestination, options.forbiddenRoots ?? []);
  const existing = await lstat(resolvedDestination).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });

  if (existing !== null) {
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Das Exportziel ist keine regulaere Datei.');
    }
    if (options.replaceExisting !== true) {
      throw new VaultaError('CONFLICT', 'Am Exportziel existiert bereits eine Datei.');
    }
    await rm(resolvedDestination, { force: true });
  }

  let handle: FileHandle;
  try {
    handle = await open(
      resolvedDestination,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new VaultaError(
        'CONFLICT',
        'Das Exportziel wurde zwischenzeitlich angelegt. Der Export wurde abgebrochen.',
      );
    }
    throw error;
  }

  let success = false;
  try {
    const openedFile = await handle.stat();
    if (!openedFile.isFile()) {
      throw new VaultaError('UNSAFE_PATH', 'Das geoeffnete Exportziel ist keine regulaere Datei.');
    }
    await writer(handle);
    await handle.sync();
    success = true;
  } finally {
    await handle.close().catch(() => undefined);
    if (!success) await rm(resolvedDestination, { force: true }).catch(() => undefined);
  }
}

async function assertOutsideForbiddenRoots(
  destinationPath: string,
  forbiddenRoots: readonly string[],
): Promise<void> {
  if (forbiddenRoots.length === 0) return;

  const canonicalDestination = await resolveProjectedCanonicalPath(destinationPath);
  for (const forbiddenRoot of forbiddenRoots) {
    if (!path.isAbsolute(forbiddenRoot)) {
      throw new VaultaError('UNSAFE_PATH', 'Die geschuetzte Verzeichniswurzel ist ungueltig.');
    }

    const resolvedRoot = path.resolve(forbiddenRoot);
    if (isInsideOrEqual(resolvedRoot, destinationPath)) {
      throw forbiddenDestination();
    }

    let canonicalRoot: string;
    try {
      canonicalRoot = await realpath(resolvedRoot);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new VaultaError(
          'UNSAFE_PATH',
          'Die geschuetzte Verzeichniswurzel ist nicht sicher verfuegbar.',
        );
      }
      throw error;
    }
    if (isInsideOrEqual(canonicalRoot, canonicalDestination)) {
      throw forbiddenDestination();
    }
  }
}

/**
 * Canonicalizes the existing prefix and projects still-missing path components onto it. This
 * catches a Junction or symlink before `mkdir()` can create directories through that alias.
 */
async function resolveProjectedCanonicalPath(destinationPath: string): Promise<string> {
  let existingAncestor = path.dirname(destinationPath);
  while (true) {
    const info = await lstat(existingAncestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (info !== null) break;

    const parent = path.dirname(existingAncestor);
    if (parent === existingAncestor) {
      throw new VaultaError('UNSAFE_PATH', 'Das Exportziel ist nicht sicher aufloesbar.');
    }
    existingAncestor = parent;
  }

  const canonicalAncestor = await realpath(existingAncestor);
  const missingSuffix = path.relative(existingAncestor, destinationPath);
  return path.resolve(canonicalAncestor, missingSuffix);
}

function isInsideOrEqual(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return (
    relative.length === 0 ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function forbiddenDestination(): VaultaError {
  return new VaultaError(
    'UNSAFE_PATH',
    'Das Exportziel liegt in einem geschuetzten Kryptris-Datenordner.',
  );
}
