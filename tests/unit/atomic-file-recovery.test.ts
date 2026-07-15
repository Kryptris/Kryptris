import { mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function targetPath(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-atomic-'));
  roots.push(root);
  return path.join(root, 'vault.vaulta');
}

describe('AtomicFileWriter Crash-Recovery', () => {
  it('ersetzt einen bestätigten Stand und entfernt den vorherigen Stand erst danach', async () => {
    const target = await targetPath();
    await writeFile(target, 'alt');

    await new AtomicFileWriter().writeFile(target, Buffer.from('neu'));

    await expect(readFile(target, 'utf8')).resolves.toBe('neu');
    await expect(readFile(`${target}.previous`, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('stellt einen nach dem ersten Rename unterbrochenen Stand beim nächsten Lesen wieder her', async () => {
    const target = await targetPath();
    await writeFile(target, 'letzter bestätigter Stand');
    await rename(target, `${target}.previous`);

    const recovered = await new AtomicFileWriter().recoverPreviousIfTargetMissing(target);

    expect(recovered).toBe(true);
    await expect(readFile(target, 'utf8')).resolves.toBe('letzter bestätigter Stand');
  });

  it('überschreibt einen vorhandenen Zielstand bei einem Producer-Fehler nicht', async () => {
    const target = await targetPath();
    await writeFile(target, 'bestätigt');

    await expect(
      new AtomicFileWriter().writeGenerated(target, async (handle) => {
        await handle.writeFile('unvollständig');
        throw new Error('simulierter Abbruch');
      }),
    ).rejects.toThrow('simulierter Abbruch');

    await expect(readFile(target, 'utf8')).resolves.toBe('bestätigt');
  });
});
