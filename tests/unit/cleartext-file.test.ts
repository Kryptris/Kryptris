import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { writeExclusiveCleartextFile } from '../../src/main/storage/cleartext-file';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Direkte Klartextexporte', () => {
  it('schreibt ausschliesslich an den bestaetigten finalen Pfad und synchronisiert das Handle', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-cleartext-final-'));
    roots.push(root);
    const destination = path.join(root, 'Vaulta-Export.json');
    const canary = 'VAULTA-CLEARTEXT-CANARY-FINAL-ONLY';

    await writeExclusiveCleartextFile(destination, async (handle) => {
      expect((await handle.stat()).isFile()).toBe(true);
      await handle.writeFile(canary, { encoding: 'utf8' });
    });

    expect(await readFile(destination, 'utf8')).toBe(canary);
    expect(await readdir(root)).toEqual(['Vaulta-Export.json']);
  });

  it('entfernt den finalen Teilstand bei einem simulierten Abbruch und hinterlaesst kein tmp-Secret', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-cleartext-abort-'));
    roots.push(root);
    const destination = path.join(root, 'ssh-private.key');
    const canary = 'VAULTA-CLEARTEXT-CANARY-MUST-NOT-REMAIN';

    await expect(
      writeExclusiveCleartextFile(destination, async (handle) => {
        await handle.writeFile(canary, { encoding: 'utf8' });
        throw new Error('simulierter Prozessabbruch waehrend des Exports');
      }),
    ).rejects.toThrow('simulierter Prozessabbruch');

    const names = await readdir(root);
    expect(names).toEqual([]);
    expect(names.some((name) => name.endsWith('.tmp'))).toBe(false);
    await expect(readFile(destination, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('ersetzt nur nach ausdruecklicher Freigabe eine regulaere Zieldatei', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-cleartext-replace-'));
    roots.push(root);
    const destination = path.join(root, 'export.csv');
    await writeFile(destination, 'vorher', { encoding: 'utf8' });

    await expect(
      writeExclusiveCleartextFile(destination, async (handle) => handle.writeFile('neu')),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await readFile(destination, 'utf8')).toBe('vorher');

    await writeExclusiveCleartextFile(
      destination,
      async (handle) => handle.writeFile('nach bestaetigtem Ueberschreiben'),
      { replaceExisting: true },
    );
    expect(await readFile(destination, 'utf8')).toBe('nach bestaetigtem Ueberschreiben');
  });
});
