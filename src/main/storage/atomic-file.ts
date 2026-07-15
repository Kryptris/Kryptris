import { constants } from 'node:fs';
import { access, mkdir, open, readdir, rename, rm, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export interface AtomicWriteHooks {
  afterTempSynced?(temporaryPath: string, targetPath: string): Promise<void> | void;
  beforeReplace?(temporaryPath: string, targetPath: string): Promise<void> | void;
  afterReplace?(targetPath: string): Promise<void> | void;
}

export type AtomicFileProducer = (handle: FileHandle, temporaryPath: string) => Promise<void>;

export type AtomicFileVerifier = (temporaryPath: string) => Promise<void>;

export type AtomicFileSourceGuard = (targetPath: string) => Promise<void> | void;

export interface AtomicRecoveryResult {
  readonly restoredPrevious: number;
  readonly removedStalePrevious: number;
  readonly removedTemporary: number;
}

const ATOMIC_TEMPORARY_NAME =
  /^\.(.+)\.vaulta-tmp-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function managedTarget(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate).split(path.sep).join('/');
  if (relative === 'profile.json' || relative === 'audit.vaulta') return true;
  if (/^vaults\/[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/u.test(relative)) return true;
  if (/^attachments\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/u.test(relative)) return true;
  return /^(?:backups|migration-backups)\/[A-Za-z0-9_.-]+\.vaulta-backup$/u.test(relative);
}

export class AtomicFileWriter {
  public constructor(private readonly hooks: AtomicWriteHooks = {}) {}

  public async writeFile(
    targetPath: string,
    contents: Buffer,
    verifier?: AtomicFileVerifier,
    sourceGuard?: AtomicFileSourceGuard,
  ): Promise<void> {
    await this.writeGenerated(
      targetPath,
      async (handle) => {
        await handle.writeFile(contents);
      },
      verifier,
      sourceGuard,
    );
  }

  public async writeGenerated(
    targetPath: string,
    producer: AtomicFileProducer,
    verifier?: AtomicFileVerifier,
    sourceGuard?: AtomicFileSourceGuard,
  ): Promise<void> {
    const directory = path.dirname(targetPath);
    await mkdir(directory, { recursive: true });
    const temporaryPath = path.join(
      directory,
      `.${path.basename(targetPath)}.vaulta-tmp-${randomUUID()}`,
    );
    const previousPath = `${targetPath}.previous`;

    let handle: FileHandle | null = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
    let committed = false;
    let previousCreated = false;

    try {
      await producer(handle, temporaryPath);
      await handle.sync();
      await handle.close();
      handle = null;
      await this.hooks.afterTempSynced?.(temporaryPath, targetPath);
      await verifier?.(temporaryPath);
      await this.hooks.beforeReplace?.(temporaryPath, targetPath);
      await sourceGuard?.(targetPath);
      const targetExists = await access(targetPath).then(
        () => true,
        (error: NodeJS.ErrnoException) => {
          if (error.code === 'ENOENT') return false;
          throw error;
        },
      );
      if (targetExists) {
        await rm(previousPath, { force: true });
        await rename(targetPath, previousPath);
        previousCreated = true;
        await this.syncDirectory(directory);
      }
      await rename(temporaryPath, targetPath);
      committed = true;
      await this.syncDirectory(directory);
      await this.hooks.afterReplace?.(targetPath);
      if (previousCreated) {
        await rm(previousPath, { force: true });
        previousCreated = false;
        await this.syncDirectory(directory);
      }
    } catch (error) {
      if (!committed && previousCreated) {
        await rename(previousPath, targetPath).catch(() => undefined);
        previousCreated = false;
        await this.syncDirectory(directory).catch(() => undefined);
      }
      throw error;
    } finally {
      await handle?.close().catch(() => undefined);
      if (!committed) await rm(temporaryPath, { force: true }).catch(() => undefined);
    }
  }

  public async recoverPreviousIfTargetMissing(targetPath: string): Promise<boolean> {
    const previousPath = `${targetPath}.previous`;
    const targetExists = await access(targetPath).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return false;
        throw error;
      },
    );
    if (targetExists) return false;
    const previousExists = await access(previousPath).then(
      () => true,
      (error: NodeJS.ErrnoException) => {
        if (error.code === 'ENOENT') return false;
        throw error;
      },
    );
    if (!previousExists) return false;
    await rename(previousPath, targetPath);
    await this.syncDirectory(path.dirname(targetPath));
    return true;
  }

  public async cleanupOrphanedTemps(directory: string): Promise<number> {
    const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
    const orphaned = entries.filter(
      (entry) => entry.isFile() && ATOMIC_TEMPORARY_NAME.test(entry.name),
    );
    await Promise.all(
      orphaned.map((entry) => rm(path.join(directory, entry.name), { force: true })),
    );
    return orphaned.length;
  }

  /**
   * Resolves every interrupted atomic exchange below a Vaulta data root before
   * format discovery. A missing target is restored from its confirmed previous
   * generation; a previous generation next to an installed target is a stale
   * post-commit artefact and can be removed. Unverified temporary files are
   * never promoted.
   */
  public async recoverInterruptedWrites(rootDirectory: string): Promise<AtomicRecoveryResult> {
    const root = path.resolve(rootDirectory);
    let restoredPrevious = 0;
    let removedStalePrevious = 0;
    let removedTemporary = 0;
    const touchedDirectories = new Set<string>();

    const walk = async (directory: string): Promise<void> => {
      const entries = await readdir(directory, { withFileTypes: true }).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === 'ENOENT') return [];
          throw error;
        },
      );
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          await walk(entryPath);
          continue;
        }
        if (!entry.isFile()) continue;
        const temporaryMatch = ATOMIC_TEMPORARY_NAME.exec(entry.name);
        if (temporaryMatch !== null) {
          const targetName = temporaryMatch[1];
          if (targetName === undefined || !managedTarget(root, path.join(directory, targetName))) {
            continue;
          }
          await rm(entryPath, { force: true });
          removedTemporary += 1;
          touchedDirectories.add(directory);
          continue;
        }
        if (!entry.name.endsWith('.previous')) continue;

        const targetPath = entryPath.slice(0, -'.previous'.length);
        if (!managedTarget(root, targetPath)) continue;
        const targetExists = await access(targetPath).then(
          () => true,
          (error: NodeJS.ErrnoException) => {
            if (error.code === 'ENOENT') return false;
            throw error;
          },
        );
        if (targetExists) {
          await rm(entryPath, { force: true });
          removedStalePrevious += 1;
        } else {
          await rename(entryPath, targetPath);
          restoredPrevious += 1;
        }
        touchedDirectories.add(directory);
      }
    };

    await walk(root);
    for (const directory of touchedDirectories) await this.syncDirectory(directory);
    return { restoredPrevious, removedStalePrevious, removedTemporary };
  }

  private async syncDirectory(directory: string): Promise<void> {
    let handle: FileHandle | null = null;
    try {
      handle = await open(directory, constants.O_RDONLY);
      await handle.sync();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const expected =
        process.platform === 'win32' ? ['EINVAL', 'EPERM', 'EACCES'] : ['EINVAL', 'EPERM'];
      if (code === undefined || !expected.includes(code)) throw error;
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
}
