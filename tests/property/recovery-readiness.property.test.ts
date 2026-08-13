import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { ProfileService } from '../../src/main/services/profile-service';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

describe('Recovery-Bereitschaft Eigenschaften', () => {
  it('akzeptiert dokumentierte Schreibvarianten, aber keine Einzelzeichenänderung', async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-recovery-property-'));
    try {
      const profile = new ProfileService({
        rootDir: root,
        keyDerivation: new KeyDerivationService({
          parameters: TEST_PARAMETERS,
          allowUnsafeParametersForTests: true,
        }),
      });
      const pending = await profile.beginSetup('Synthetisches Property-Masterpasswort!1', true);
      if (pending.recovery === null)
        throw new Error('Recovery-Property-Fixture konnte nicht erstellt werden.');
      const confirmation = Object.fromEntries(
        pending.recovery.confirmationIndexes.map((index) => [
          String(index),
          pending.recovery?.groups[index],
        ]),
      ) as Record<string, string>;
      await profile.completeSetup(pending.pendingId, confirmation);
      const recoveryKey = pending.recovery.displayKey;
      const groups = recoveryKey.split('-');

      await fc.assert(
        fc.asyncProperty(
          fc.boolean(),
          fc.constantFrom('-', ' ', ' - '),
          fc.constantFrom('', ' ', '\n'),
          async (lowercase, separator, surroundingWhitespace) => {
            const formatted = groups.join(separator);
            const candidate = lowercase ? formatted.toLowerCase() : formatted;
            await expect(
              profile.verifyRecoveryKey(
                `${surroundingWhitespace}${candidate}${surroundingWhitespace}`,
              ),
            ).resolves.toBeUndefined();
          },
        ),
        { numRuns: 30 },
      );

      const mutablePositions = Array.from(recoveryKey, (character, index) => ({
        character,
        index,
      }))
        .filter(({ character, index }) => index > 4 && character !== '-')
        .map(({ index }) => index);
      await fc.assert(
        fc.asyncProperty(fc.constantFrom(...mutablePositions), async (position) => {
          const original = recoveryKey[position]!;
          const replacement = RECOVERY_ALPHABET.split('').find(
            (candidate) => candidate !== original,
          );
          if (replacement === undefined) throw new Error('Testalphabet ist unvollständig.');
          const mutated = `${recoveryKey.slice(0, position)}${replacement}${recoveryKey.slice(position + 1)}`;

          let caught: unknown;
          try {
            await profile.verifyRecoveryKey(mutated);
          } catch (error) {
            caught = error;
          }
          expect(caught).toMatchObject({ code: 'AUTH_FAILED' });
          expect(JSON.stringify(caught)).not.toContain(mutated);
          expect(JSON.stringify(caught)).not.toContain(recoveryKey);
        }),
        { numRuns: Math.max(50, mutablePositions.length) },
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
