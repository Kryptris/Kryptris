import { rm } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';

const workspace = resolve(process.cwd());
const releaseDirectory = resolve(workspace, 'release');

if (basename(releaseDirectory) !== 'release' || dirname(releaseDirectory) !== workspace) {
  throw new Error('Das Release-Verzeichnis liegt nicht direkt im Projektstamm.');
}

await rm(releaseDirectory, { recursive: true, force: true });
