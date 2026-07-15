import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('AtomicFileWriter verwaltete Recovery-Artefakte', () => {
  it('bereinigt nur exakt benannte Artefakte an verwalteten Zielpfaden', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-atomic-managed-'));
    roots.push(root);
    const vaults = path.join(root, 'vaults');
    const backups = path.join(root, 'backups');
    await mkdir(vaults);
    await mkdir(backups);
    const orphanedTemporary = path.join(
      vaults,
      '.vault.vaulta.vaulta-tmp-123e4567-e89b-42d3-a456-426614174000',
    );
    const legitimateSimilarName = path.join(
      backups,
      'manual.vaulta-tmp-not-internal.vaulta-backup',
    );
    const unmanagedPrevious = path.join(root, 'notes.previous');
    await writeFile(orphanedTemporary, 'unbestaetigt');
    await writeFile(legitimateSimilarName, 'behalten');
    await writeFile(unmanagedPrevious, 'behalten');

    const result = await new AtomicFileWriter().recoverInterruptedWrites(root);

    expect(result.removedTemporary).toBe(1);
    await expect(access(orphanedTemporary)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(legitimateSimilarName, 'utf8')).resolves.toBe('behalten');
    await expect(readFile(unmanagedPrevious, 'utf8')).resolves.toBe('behalten');
  });
});
