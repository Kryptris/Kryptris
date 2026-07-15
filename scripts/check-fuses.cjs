const path = require('node:path');
const { FuseState, FuseV1Options, getCurrentFuseWire } = require('@electron/fuses');

const expected = new Map([
  [FuseV1Options.RunAsNode, FuseState.DISABLE],
  [FuseV1Options.EnableCookieEncryption, FuseState.ENABLE],
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable, FuseState.DISABLE],
  [FuseV1Options.EnableNodeCliInspectArguments, FuseState.DISABLE],
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation, FuseState.ENABLE],
  [FuseV1Options.OnlyLoadAppFromAsar, FuseState.ENABLE],
  [FuseV1Options.GrantFileProtocolExtraPrivileges, FuseState.DISABLE],
]);

async function check(executable) {
  const wire = await getCurrentFuseWire(executable);
  for (const [option, expectedState] of expected) {
    const actual = wire[option];
    if (actual !== expectedState) {
      throw new Error(
        `${FuseV1Options[option]} ist in ${path.basename(executable)} nicht wie erwartet gesetzt.`,
      );
    }
  }
  process.stdout.write(`Fuses geprüft: ${executable}\n`);
}

const executables = process.argv.slice(2);
if (executables.length === 0) throw new Error('Mindestens eine Vaulta.exe ist erforderlich.');
Promise.all(executables.map((executable) => check(path.resolve(executable)))).catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
