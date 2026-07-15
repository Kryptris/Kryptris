import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { ForwardMigrationDispatcher } from '../../src/main/migrations/forward-migration-dispatcher';
import { VaultaError } from '../../src/shared/errors';

const fixtures = path.resolve('tests', 'fixtures', 'migrations');

describe('ForwardMigrationDispatcher', () => {
  it('wendet eine zusammenhaengende Fixture-Kette vorwaerts und ohne Datenverlust an', async () => {
    const source = await readFile(path.join(fixtures, 'dispatcher-v1.json'));
    const expected = JSON.parse(
      await readFile(path.join(fixtures, 'dispatcher-v3.json'), 'utf8'),
    ) as unknown;
    const dispatcher = createFixtureDispatcher();

    const result = await dispatcher.migrate(source);

    expect(JSON.parse(result.value.toString('utf8'))).toEqual(expected);
    expect(result).toMatchObject({
      sourceVersion: 1,
      targetVersion: 3,
      migrated: true,
      appliedVersions: [2, 3],
    });
  });

  it('ist auf der aktuellen Baseline idempotent', async () => {
    const current = await readFile(path.join(fixtures, 'dispatcher-v3.json'));
    const result = await createFixtureDispatcher().migrate(current);

    expect(result.migrated).toBe(false);
    expect(result.appliedVersions).toEqual([]);
    expect(result.value).toBe(current);
  });

  it('lehnt eine unbekannte Zukunftsversion fail-closed ab', async () => {
    const future = fixtureBytes({ version: 4 });

    const error = await captureVaultaError(createFixtureDispatcher().migrate(future));

    expect(error.code).toBe('UNSUPPORTED_FORMAT');
    expect(error.action).toContain('nicht verändert');
  });

  it('erfindet ohne registrierten v0-Schritt keine Legacy-Semantik', async () => {
    const legacy = fixtureBytes({ version: 0 });

    const error = await captureVaultaError(createFixtureDispatcher().migrate(legacy));

    expect(error.code).toBe('UNSUPPORTED_FORMAT');
    expect(error.message).toContain('kein verlustfreier Migrationspfad');
  });

  it('verweigert uebersprungene oder widerspruechliche Registrierungen', () => {
    expect(
      () =>
        new ForwardMigrationDispatcher<Buffer>({
          formatName: 'Testformat',
          currentVersion: 3,
          readVersion,
          validateCurrent: () => undefined,
          steps: [{ fromVersion: 1, toVersion: 3, migrate: (value) => value }],
        }),
    ).toThrowError(expect.objectContaining({ code: 'INTERNAL' }));
  });
});

async function captureVaultaError(promise: Promise<unknown>): Promise<VaultaError> {
  try {
    await promise;
  } catch (error: unknown) {
    if (error instanceof VaultaError) {
      return error;
    }
    throw error;
  }
  throw new Error('Erwarteter VaultaError wurde nicht ausgeloest.');
}

function createFixtureDispatcher() {
  return new ForwardMigrationDispatcher<Buffer>({
    formatName: 'Fixture-Format',
    currentVersion: 3,
    readVersion,
    validateCurrent: (bytes) => {
      const value = parseFixture(bytes);
      if (value.version !== 3 || !Array.isArray(value.records)) throw new Error('ungueltig');
    },
    steps: [
      {
        fromVersion: 1,
        toVersion: 2,
        migrate: (bytes) => {
          const value = parseFixture(bytes);
          return fixtureBytes({ ...value, version: 2, v2Marker: true });
        },
      },
      {
        fromVersion: 2,
        toVersion: 3,
        migrate: (bytes) => {
          const value = parseFixture(bytes);
          return fixtureBytes({ ...value, version: 3, v3Marker: true });
        },
      },
    ],
  });
}

function readVersion(bytes: Buffer): number {
  const value = parseFixture(bytes);
  if (typeof value.version !== 'number') throw new Error('Formatversion fehlt');
  return value.version;
}

function parseFixture(bytes: Buffer): Record<string, unknown> {
  return JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
}

function fixtureBytes(value: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}
