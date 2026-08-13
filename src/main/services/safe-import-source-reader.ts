import { constants, type Stats } from 'node:fs';
import { lstat, open, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';

/** Matches the import parser limit while keeping the descriptor read bounded. */
export const MAX_IMPORT_SOURCE_BYTES = 50 * 1024 * 1024;

export interface SafeImportSourceReaderOptions {
  readonly maxBytes?: number;
  /**
   * Test-only seam for deterministically exercising the lstat/open race. It is
   * not exposed through IPC and production callers never provide it.
   */
  readonly onInitialPathValidated?: (sourcePath: string) => Promise<void> | void;
  /** Test-only seam for deterministically exercising a swap after open. */
  readonly onHandleOpened?: (sourcePath: string) => Promise<void> | void;
}

/**
 * Reads a user-selected import source only through a descriptor bound to the
 * checked regular file. The renderer never receives, supplies, or observes
 * this primitive; native dialog and preload-owned drag-and-drop paths meet
 * here in the Main process.
 */
export class SafeImportSourceReader {
  private readonly maxBytes: number;
  private readonly onInitialPathValidated: ((sourcePath: string) => Promise<void> | void) | null;
  private readonly onHandleOpened: ((sourcePath: string) => Promise<void> | void) | null;

  public constructor(options: SafeImportSourceReaderOptions = {}) {
    this.maxBytes = options.maxBytes ?? MAX_IMPORT_SOURCE_BYTES;
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1) {
      throw new Error('maxBytes muss eine positive, sichere Ganzzahl sein.');
    }
    this.onInitialPathValidated = options.onInitialPathValidated ?? null;
    this.onHandleOpened = options.onHandleOpened ?? null;
  }

  public async readUtf8(
    sourcePath: string,
    assertAuthorized?: () => Promise<void> | void,
  ): Promise<string> {
    if (
      typeof sourcePath !== 'string' ||
      !path.isAbsolute(sourcePath) ||
      sourcePath.includes('\0')
    ) {
      throw new VaultaError('INVALID_INPUT', 'Die Importquelle ist ungültig.');
    }

    const initialPathState = await this.readPathState(sourcePath, 'NOT_FOUND');
    this.assertRegularFile(initialPathState, 'Die Importquelle muss eine reguläre Datei sein.');
    this.assertSize(initialPathState);
    await assertAuthorized?.();
    await this.onInitialPathValidated?.(sourcePath);
    await assertAuthorized?.();

    let handle: FileHandle | null = null;
    let content: Buffer | null = null;
    try {
      handle = await this.openReadOnly(sourcePath);
      const initialHandleState = await handle.stat();
      this.assertRegularFile(initialHandleState, 'Die Importquelle muss eine reguläre Datei sein.');
      this.assertSize(initialHandleState);
      if (!sameFileIdentity(initialPathState, initialHandleState)) {
        throw this.sourceChanged('Die Importquelle wurde vor dem Einlesen ausgetauscht.');
      }

      const openedPathState = await this.readPathState(sourcePath, 'CONFLICT');
      if (
        openedPathState.isSymbolicLink() ||
        !openedPathState.isFile() ||
        !sameFileIdentity(initialPathState, openedPathState)
      ) {
        throw this.sourceChanged('Die Importquelle wurde vor dem Einlesen ausgetauscht.');
      }

      await assertAuthorized?.();
      await this.onHandleOpened?.(sourcePath);
      await assertAuthorized?.();
      content = await this.readExactlyBounded(handle, initialHandleState.size, assertAuthorized);

      const finalHandleState = await handle.stat();
      const finalPathState = await this.readPathState(sourcePath, 'CONFLICT');
      if (
        !finalHandleState.isFile() ||
        finalPathState.isSymbolicLink() ||
        !finalPathState.isFile() ||
        !sameFileIdentity(initialPathState, finalHandleState) ||
        !sameFileIdentity(initialHandleState, finalHandleState) ||
        !sameFileIdentity(initialPathState, finalPathState) ||
        !sameFileIdentity(finalHandleState, finalPathState)
      ) {
        throw this.sourceChanged('Die Importquelle wurde während des Einlesens verändert.');
      }
      await assertAuthorized?.();
      return content.toString('utf8');
    } finally {
      content?.fill(0);
      await handle?.close().catch(() => undefined);
    }
  }

  private async openReadOnly(sourcePath: string): Promise<FileHandle> {
    const noFollow = typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
    try {
      return await open(sourcePath, constants.O_RDONLY | noFollow);
    } catch (error) {
      throw this.sourceChanged('Die Importquelle konnte nicht sicher geöffnet werden.', error);
    }
  }

  private async readExactlyBounded(
    handle: FileHandle,
    expectedSize: number,
    assertAuthorized: (() => Promise<void> | void) | undefined,
  ): Promise<Buffer> {
    const content = Buffer.allocUnsafe(expectedSize);
    const probe = Buffer.allocUnsafe(1);
    try {
      let offset = 0;
      while (offset < content.length) {
        await assertAuthorized?.();
        const { bytesRead } = await handle.read(content, offset, content.length - offset, offset);
        if (bytesRead === 0) {
          throw this.sourceChanged('Die Importquelle wurde während des Einlesens verändert.');
        }
        offset += bytesRead;
      }
      await assertAuthorized?.();
      const { bytesRead } = await handle.read(probe, 0, probe.length, expectedSize);
      if (bytesRead !== 0) {
        throw this.sourceChanged('Die Importquelle wurde während des Einlesens verändert.');
      }
      return content;
    } catch (error) {
      content.fill(0);
      throw error;
    } finally {
      probe.fill(0);
    }
  }

  private async readPathState(
    sourcePath: string,
    missingCode: 'NOT_FOUND' | 'CONFLICT',
  ): Promise<Stats> {
    try {
      return await lstat(sourcePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        if (missingCode === 'NOT_FOUND') {
          throw new VaultaError('NOT_FOUND', 'Die Importquelle wurde nicht gefunden.');
        }
        throw this.sourceChanged('Die Importquelle wurde während des Einlesens verändert.');
      }
      throw this.sourceChanged(
        'Der Status der Importquelle konnte nicht sicher gelesen werden.',
        error,
      );
    }
  }

  private assertRegularFile(info: Stats, message: string): void {
    if (info.isSymbolicLink() || !info.isFile()) throw new VaultaError('INVALID_INPUT', message);
  }

  private assertSize(info: Stats): void {
    if (!Number.isSafeInteger(info.size) || info.size < 0) {
      throw this.sourceChanged('Die Größe der Importquelle ist ungültig.');
    }
    if (info.size > this.maxBytes) {
      throw new VaultaError('FILE_TOO_LARGE', 'Die Importdatei ist zu groß.');
    }
  }

  private sourceChanged(message: string, cause?: unknown): VaultaError {
    return new VaultaError('CONFLICT', message, null, cause === undefined ? undefined : { cause });
  }
}

function sameFileIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}
