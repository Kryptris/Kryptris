import { access, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const compiledBenchmarkPath = path.resolve(
  process.cwd(),
  'dist',
  'main',
  'main',
  'services',
  'performance-benchmark.js',
);

function usage() {
  return [
    'Verwendung: corepack pnpm benchmark:performance [-- --output <datei>]',
    '',
    'Fuehrt nach einem lokalen Build die festen Main-Prozess-Benchmarks mit 1.000-/5.000-/10.000-Eintraegen aus.',
    'Ohne --output wird ausschliesslich JSON auf stdout geschrieben.',
    'Mit --output wird die Datei neu mit exklusivem Schreibzugriff angelegt; vorhandene Dateien',
    'werden nie ueberschrieben.',
  ].join('\n');
}

function parseOutputPath(argumentsList) {
  // `pnpm run <script> -- --output <path>` preserves the script separator in
  // `process.argv` when this command itself delegates through npm. Accept that
  // standard form as well as a direct `node scripts/performance-benchmark.mjs`
  // invocation without weakening the strictly bounded option grammar.
  const normalizedArguments = argumentsList[0] === '--' ? argumentsList.slice(1) : argumentsList;
  if (normalizedArguments.length === 0) return null;
  if (normalizedArguments.length === 1 && ['--help', '-h'].includes(normalizedArguments[0]))
    return 'help';
  if (normalizedArguments.length !== 2 || normalizedArguments[0] !== '--output') {
    throw new Error(`Unbekannte Benchmark-Option.\n\n${usage()}`);
  }
  const output = normalizedArguments[1]?.trim();
  if (output === undefined || output.length === 0) {
    throw new Error(`Der Ausgabeort fehlt.\n\n${usage()}`);
  }
  return path.resolve(process.cwd(), output);
}

async function loadBenchmark() {
  try {
    await access(compiledBenchmarkPath);
  } catch {
    throw new Error('Die Benchmark ist nicht gebaut. Fuehre zuerst `corepack pnpm build` aus.');
  }
  const loaded = require(compiledBenchmarkPath);
  if (typeof loaded.runPerformanceBenchmark !== 'function') {
    throw new Error(
      'Das gebaute Benchmark-Modul ist unvollstaendig. Fuehre einen frischen Build aus.',
    );
  }
  return loaded;
}

try {
  const outputPath = parseOutputPath(process.argv.slice(2));
  if (outputPath === 'help') {
    console.log(usage());
  } else {
    const benchmark = await loadBenchmark();
    const report = await benchmark.runPerformanceBenchmark();
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    if (outputPath === null) {
      process.stdout.write(serialized);
    } else {
      await writeFile(outputPath, serialized, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      process.stdout.write(
        `${JSON.stringify({
          output: outputPath,
          schemaVersion: report.schemaVersion,
          scope: report.scope.process,
        })}\n`,
      );
    }
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(
    `Performance-Benchmark konnte nicht sicher abgeschlossen werden: ${message}\n`,
  );
  process.exitCode = 1;
}
