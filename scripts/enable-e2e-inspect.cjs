const { access } = require('node:fs/promises');
const path = require('node:path');
const {
  flipFuses,
  FuseState,
  FuseVersion,
  FuseV1Options,
  getCurrentFuseWire,
} = require('@electron/fuses');

async function main() {
  const argument = process.argv[2];
  if (!argument) throw new Error('Der Pfad zur kopierten E2E-Vaulta.exe fehlt.');
  const executable = path.resolve(argument);
  await access(path.join(path.dirname(executable), '.vaulta-e2e-copy'));

  const before = await getCurrentFuseWire(executable);
  if (before[FuseV1Options.EnableNodeCliInspectArguments] !== FuseState.DISABLE) {
    throw new Error('Die E2E-Kopie stammt nicht aus einem gehärteten Vaulta-Build.');
  }
  await flipFuses(executable, {
    version: FuseVersion.V1,
    [FuseV1Options.EnableNodeCliInspectArguments]: true,
  });
  const after = await getCurrentFuseWire(executable);
  if (after[FuseV1Options.EnableNodeCliInspectArguments] !== FuseState.ENABLE) {
    throw new Error('Die Inspector-Fuse der isolierten E2E-Kopie konnte nicht aktiviert werden.');
  }
  if (before.length !== after.length) {
    throw new Error('Die Fuse-Wire-Länge hat sich beim Erzeugen der E2E-Kopie verändert.');
  }
  for (let index = 0; index < before.length; index += 1) {
    if (index === FuseV1Options.EnableNodeCliInspectArguments) continue;
    if (before[index] !== after[index]) {
      const name = FuseV1Options[index] ?? `Index ${index}`;
      throw new Error(`Neben der Inspector-Fuse wurde unerwartet auch ${name} verändert.`);
    }
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
