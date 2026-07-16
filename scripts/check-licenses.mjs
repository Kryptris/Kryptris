import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

const allowedLicenses = new Set(['0BSD', 'Apache-2.0', 'BSD-3-Clause', 'ISC', 'MIT']);
const require = createRequire(import.meta.url);
const pnpmManifestPath = require.resolve('pnpm');
const pnpmManifest = require(pnpmManifestPath);
const pnpmCli = path.join(path.dirname(pnpmManifestPath), pnpmManifest.bin.pnpm);
console.error(`Führe aus: ${process.execPath} ${pnpmCli} licenses list --prod --json`);
const result = spawnSync(process.execPath, [pnpmCli, 'licenses', 'list', '--prod', '--json'], {
  encoding: 'utf8',
  shell: false,
  windowsHide: true,
});

if (result.error !== undefined) throw result.error;
if (result.status !== 0) {
  process.stderr.write(
    `pnpm-Exit-Code: ${result.status ?? 'null'}; Signal: ${result.signal ?? 'keins'}\n`,
  );
  process.stderr.write(`--- stdout ---\n${result.stdout || '<leer>'}\n`);
  process.stderr.write(`--- stderr ---\n${result.stderr || '<leer>'}\n`);
  throw new Error(`pnpm licenses wurde mit Status ${result.status ?? 'unbekannt'} beendet.`);
}

const report = JSON.parse(result.stdout);
if (report === null || typeof report !== 'object' || Array.isArray(report)) {
  throw new Error('pnpm licenses hat kein gültiges Lizenzobjekt geliefert.');
}

const licenses = Object.keys(report).sort();
const rejected = licenses.filter((license) => !allowedLicenses.has(license));
if (rejected.length > 0) {
  throw new Error(`Nicht freigegebene Produktionslizenz(en): ${rejected.join(', ')}`);
}

const packageCount = Object.values(report).reduce(
  (count, packages) => count + (Array.isArray(packages) ? packages.length : 0),
  0,
);
process.stdout.write(
  `Lizenz-Allowlist bestanden: ${packageCount} Pakete unter ${licenses.join(', ')}.\n`,
);
