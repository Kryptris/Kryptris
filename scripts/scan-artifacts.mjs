import { scanArtifacts } from './artifact-scanner.mjs';

const roots = process.argv.slice(2);
const targets = roots.length > 0 ? roots : ['dist', 'release'];

try {
  const result = await scanArtifacts(targets);
  if (result.findings.length > 0) {
    console.error(`Sensible Canary-Daten in Artefakten gefunden:\n${result.findings.join('\n')}`);
    process.exitCode = 1;
  } else {
    console.log(
      `Keine bekannten Canary-Geheimnisse in ${result.filesScanned} geprüften Dateien gefunden.`,
    );
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Artefakt-Scan konnte nicht sicher abgeschlossen werden: ${message}`);
  process.exitCode = 1;
}
