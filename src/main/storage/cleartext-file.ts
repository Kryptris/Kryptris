import { constants } from 'node:fs';
import { lstat, mkdir, open, rm, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';

export interface CleartextFileWriteOptions {
  replaceExisting?: boolean;
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
  await mkdir(path.dirname(resolvedDestination), { recursive: true });
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
