import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  appendFile,
  copyFile,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  truncate,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  OfflineBreachService,
  type OfflineBreachProgress,
} from '../../src/main/services/offline-breach-service';
import { VaultaError } from '../../src/shared/errors';

const INDEX_RECORDS_OFFSET = 64 + 65_537 * 8;
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('OfflineBreachService', () => {
  it('baut einen verifizierten Index streamend und liefert nur redigierte Trefferreferenzen', async () => {
    const fixture = await createFixture(
      [
        { password: 'synthetic-alpha-value', count: 17 },
        { password: 'synthetic-beta-value', count: 3 },
        { password: 'synthetic-gamma-value', count: 4_294_967_295 },
      ],
      { bom: true, newline: '\r\n', finalNewline: true },
    );
    const progress: OfflineBreachProgress[] = [];
    const assertAuthorized = vi.fn();
    const yieldControl = vi.fn();
    const service = new OfflineBreachService({ readChunkBytes: 5, candidateYieldInterval: 1 });

    const built = await service.buildIndex({
      sourcePath: fixture.sourcePath,
      stagingPath: fixture.indexPath,
      context: {
        assertAuthorized,
        onProgress: (event) => {
          progress.push(event);
        },
        yieldControl,
      },
    });

    expect(built).toMatchObject({
      format: 'sha1-count-v1',
      version: 1,
      recordCount: 3,
      sourceBytes: fixture.sourceBytes.length,
      sourceSha256: createHash('sha256').update(fixture.sourceBytes).digest('hex'),
      stagingPath: fixture.indexPath,
    });
    expect(built.indexSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(built.indexBytes).toBe(INDEX_RECORDS_OFFSET + 3 * 24);
    expect(assertAuthorized).toHaveBeenCalled();
    expect(yieldControl).toHaveBeenCalled();
    expect(progress.some((event) => event.phase === 'source-validate')).toBe(true);
    expect(progress.some((event) => event.phase === 'index-validate')).toBe(true);

    await expect(
      service.inspectIndex({
        indexPath: fixture.indexPath,
        expectedIndexSha256: built.indexSha256,
      }),
    ).resolves.toEqual({
      format: 'sha1-count-v1',
      version: 1,
      recordCount: 3,
      sourceSha256: built.sourceSha256,
      indexSha256: built.indexSha256,
      indexBytes: built.indexBytes,
    });

    const scan = await service.scan({
      indexPath: fixture.indexPath,
      expectedIndexSha256: built.indexSha256,
      candidates: [
        candidate('match', 'synthetic-alpha-value'),
        candidate('miss', 'synthetic-not-listed-value'),
        candidate('empty', ''),
        {
          ...candidate('deleted', 'synthetic-beta-value'),
          deletedAt: '2026-07-26T12:00:00.000Z',
        },
        candidate('match', 'synthetic-alpha-value'),
      ],
    });

    expect(scan).toEqual({
      checkedCandidates: 3,
      matches: [
        {
          vaultId: 'vault-main',
          entryId: 'match',
          updatedAt: '2026-07-26T10:00:00.000Z',
        },
      ],
      networkUsed: false,
    });
    const serialized = JSON.stringify(scan);
    expect(serialized).not.toContain('synthetic-alpha-value');
    expect(serialized).not.toContain(sha1('synthetic-alpha-value'));
    expect(serialized).not.toContain('4294967295');
  });

  it.each([
    ['ohne Doppelpunkt', `${'a'.repeat(40)}1`],
    ['zu kurzer Hash', `${'a'.repeat(39)}:1`],
    ['Nicht-Hexzeichen', `${'g'.repeat(40)}:1`],
    ['Vorkommen null', `${'a'.repeat(40)}:0`],
    ['Vorkommen zu gross', `${'a'.repeat(40)}:4294967296`],
    ['fuehrendes Leerzeichen', ` ${'a'.repeat(40)}:1`],
    ['nachgestelltes Leerzeichen', `${'a'.repeat(40)}:1 `],
    ['Kommentar', `# ${'a'.repeat(40)}:1`],
    ['Zusatzspalte', `${'a'.repeat(40)}:1:2`],
    ['Leerzeile', `${'a'.repeat(40)}:1\n\n${'b'.repeat(40)}:1`],
    ['BOM nach Dateianfang', `${'a'.repeat(40)}:1\n\uFEFF${'b'.repeat(40)}:1`],
    ['nur BOM', '\uFEFF'],
  ])('lehnt %s ohne Stagingrest ab', async (_label, content) => {
    const root = await temporaryRoot();
    const sourcePath = path.join(root, 'source.txt');
    const stagingPath = path.join(root, 'index.kbi');
    await writeFile(sourcePath, content, 'utf8');

    await expect(
      new OfflineBreachService({ readChunkBytes: 3 }).buildIndex({
        sourcePath,
        stagingPath,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(stat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('fordert eine streng sortierte und eindeutige Quelle', async () => {
    const root = await temporaryRoot();
    const service = new OfflineBreachService({ readChunkBytes: 7 });
    const first = sha1('synthetic-first');
    const second = sha1('synthetic-second');
    const [lower, higher] = [first, second].sort();

    for (const [name, content] of [
      ['unsorted', `${higher}:1\n${lower}:1`],
      ['duplicate', `${lower}:1\n${lower}:2`],
    ] as const) {
      const sourcePath = path.join(root, `${name}.txt`);
      const stagingPath = path.join(root, `${name}.kbi`);
      await writeFile(sourcePath, content, 'ascii');
      await expect(service.buildIndex({ sourcePath, stagingPath })).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
      await expect(stat(stagingPath)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  });

  it('erzwingt injizierbare Groessen-, Zeilen- und Datensatzgrenzen', async () => {
    const root = await temporaryRoot();
    const one = `${sha1('synthetic-one')}:1`;
    const two = [sha1('synthetic-one'), sha1('synthetic-two')]
      .sort()
      .map((hash) => `${hash}:1`)
      .join('\n');
    const sourcePath = path.join(root, 'source.txt');

    await writeFile(sourcePath, one, 'ascii');
    await expect(
      new OfflineBreachService({ maxSourceBytes: 1 }).buildIndex({
        sourcePath,
        stagingPath: path.join(root, 'size.kbi'),
      }),
    ).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
    await expect(
      new OfflineBreachService({ maxLineBytes: 41 }).buildIndex({
        sourcePath,
        stagingPath: path.join(root, 'line.kbi'),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    await writeFile(sourcePath, two, 'ascii');
    await expect(
      new OfflineBreachService({ maxRecords: 1 }).buildIndex({
        sourcePath,
        stagingPath: path.join(root, 'records.kbi'),
      }),
    ).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
  });

  it('bewahrt eine bereits vorhandene Stagingdatei unveraendert', async () => {
    const root = await temporaryRoot();
    const sourcePath = path.join(root, 'source.txt');
    const stagingPath = path.join(root, 'existing.kbi');
    await writeFile(sourcePath, `${sha1('synthetic-source')}:1`, 'ascii');
    await writeFile(stagingPath, 'technischer-sentinel', 'utf8');

    await expect(
      new OfflineBreachService().buildIndex({ sourcePath, stagingPath }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(readFile(stagingPath, 'utf8')).resolves.toBe('technischer-sentinel');

    await expect(
      new OfflineBreachService().buildIndex({
        sourcePath,
        stagingPath: sourcePath,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(readFile(sourcePath, 'utf8')).resolves.toBe(`${sha1('synthetic-source')}:1`);
  });

  it('bricht priorisiert ab und entfernt die partielle Stagingdatei', async () => {
    const fixture = await createFixture(
      Array.from({ length: 20 }, (_, index) => ({
        password: `synthetic-cancel-${String(index)}`,
        count: index + 1,
      })),
    );
    const abort = new AbortController();

    await expect(
      new OfflineBreachService({ readChunkBytes: 11 }).buildIndex({
        sourcePath: fixture.sourcePath,
        stagingPath: fixture.indexPath,
        context: {
          signal: abort.signal,
          onProgress: (progress) => {
            if (progress.phase === 'source-validate' && progress.completed > 0) abort.abort();
          },
          yieldControl: () => undefined,
        },
      }),
    ).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(stat(fixture.indexPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('verwirft Autorisierungsverlust und eine waehrenddessen veraenderte Quelle', async () => {
    const lockedFixture = await createFixture([
      { password: 'synthetic-authorization-one', count: 1 },
      { password: 'synthetic-authorization-two', count: 2 },
    ]);
    let authorizationChecks = 0;
    await expect(
      new OfflineBreachService({ readChunkBytes: 9 }).buildIndex({
        sourcePath: lockedFixture.sourcePath,
        stagingPath: lockedFixture.indexPath,
        context: {
          assertAuthorized: () => {
            authorizationChecks += 1;
            if (authorizationChecks > 3) {
              throw new VaultaError('LOCKED', 'Die Sitzung wurde gesperrt.');
            }
          },
          yieldControl: () => undefined,
        },
      }),
    ).rejects.toMatchObject({ code: 'LOCKED' });
    await expect(stat(lockedFixture.indexPath)).rejects.toMatchObject({ code: 'ENOENT' });

    const changedFixture = await createFixture(
      Array.from({ length: 12 }, (_, index) => ({
        password: `synthetic-source-change-${String(index)}`,
        count: index + 1,
      })),
    );
    let changed = false;
    await expect(
      new OfflineBreachService({ readChunkBytes: 31 }).buildIndex({
        sourcePath: changedFixture.sourcePath,
        stagingPath: changedFixture.indexPath,
        context: {
          yieldControl: async () => {
            if (changed) return;
            changed = true;
            await appendFile(changedFixture.sourcePath, 'X', 'ascii');
          },
        },
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(stat(changedFixture.indexPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('erkennt Zukunftsversion, Truncation, Prefix-, Sortier- und Checksumfehler', async () => {
    const fixture = await createFixture([
      { password: 'synthetic-integrity-one', count: 1 },
      { password: 'synthetic-integrity-two', count: 2 },
      { password: 'synthetic-integrity-three', count: 3 },
    ]);
    const service = new OfflineBreachService();
    const built = await service.buildIndex({
      sourcePath: fixture.sourcePath,
      stagingPath: fixture.indexPath,
    });

    const futurePath = await copiedIndex(fixture.indexPath, fixture.root, 'future.kbi');
    await writeAt(futurePath, 8, (buffer) => buffer.writeUInt16LE(2));
    await expect(service.inspectIndex({ indexPath: futurePath })).rejects.toMatchObject({
      code: 'UNSUPPORTED_FORMAT',
    });

    const truncatedPath = await copiedIndex(fixture.indexPath, fixture.root, 'truncated.kbi');
    await truncate(truncatedPath, built.indexBytes - 1);
    await expect(service.inspectIndex({ indexPath: truncatedPath })).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });

    const prefixPath = await copiedIndex(fixture.indexPath, fixture.root, 'prefix.kbi');
    await writeAt(prefixPath, 64, (buffer) => buffer.writeBigUInt64LE(1n));
    await expect(service.inspectIndex({ indexPath: prefixPath })).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });

    const orderPath = await copiedIndex(fixture.indexPath, fixture.root, 'order.kbi');
    const zeroDigest = Buffer.alloc(20);
    await writeRaw(orderPath, INDEX_RECORDS_OFFSET + 24, zeroDigest);
    zeroDigest.fill(0);
    await expect(service.inspectIndex({ indexPath: orderPath })).rejects.toMatchObject({
      code: 'CORRUPT_DATA',
    });

    await expect(
      service.inspectIndex({
        indexPath: fixture.indexPath,
        expectedIndexSha256: '0'.repeat(64),
      }),
    ).rejects.toMatchObject({ code: 'CORRUPT_DATA' });
  });

  it('gibt bei Formatfehlern weder Zeileninhalt noch Passwort-Hash aus', async () => {
    const root = await temporaryRoot();
    const sourcePath = path.join(root, 'source.txt');
    const stagingPath = path.join(root, 'index.kbi');
    const syntheticPassword = 'synthetic-redaction-canary';
    const digest = sha1(syntheticPassword);
    await writeFile(sourcePath, `${digest}:1:private-extra`, 'ascii');

    let failure: unknown;
    try {
      await new OfflineBreachService().buildIndex({ sourcePath, stagingPath });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(VaultaError);
    const serialized = JSON.stringify((failure as VaultaError).serialize());
    expect(serialized).not.toContain(syntheticPassword);
    expect(serialized).not.toContain(digest);
    expect(serialized).not.toContain('private-extra');
    expect(serialized).not.toContain(sourcePath);
  });
});

function candidate(entryId: string, password: string) {
  return {
    reference: {
      vaultId: 'vault-main',
      entryId,
      updatedAt: '2026-07-26T10:00:00.000Z',
    },
    password,
    deletedAt: null,
  };
}

function sha1(value: string): string {
  return createHash('sha1').update(value, 'utf8').digest('hex').toUpperCase();
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'kryptris-offline-breach-'));
  roots.push(root);
  return root;
}

async function createFixture(
  records: Array<{ password: string; count: number }>,
  options: { bom?: boolean; newline?: '\n' | '\r\n'; finalNewline?: boolean } = {},
) {
  const root = await temporaryRoot();
  const newline = options.newline ?? '\n';
  const lines = records
    .map((record) => ({ hash: sha1(record.password), count: record.count }))
    .sort((left, right) => left.hash.localeCompare(right.hash, 'en'))
    .map((record) => `${record.hash}:${String(record.count)}`);
  const text = `${options.bom === true ? '\uFEFF' : ''}${lines.join(newline)}${
    options.finalNewline === true ? newline : ''
  }`;
  const sourceBytes = Buffer.from(text, 'utf8');
  const sourcePath = path.join(root, 'source.txt');
  const indexPath = path.join(root, 'staging.kbi');
  await writeFile(sourcePath, sourceBytes);
  return { root, sourcePath, indexPath, sourceBytes };
}

async function copiedIndex(sourcePath: string, root: string, filename: string): Promise<string> {
  const target = path.join(root, filename);
  await copyFile(sourcePath, target);
  return target;
}

async function writeAt(
  filePath: string,
  position: number,
  writer: (buffer: Buffer) => void,
): Promise<void> {
  const buffer = Buffer.alloc(8);
  writer(buffer);
  await writeRaw(filePath, position, buffer);
  buffer.fill(0);
}

async function writeRaw(filePath: string, position: number, contents: Buffer): Promise<void> {
  const handle = await open(filePath, constants.O_RDWR);
  try {
    await handle.write(contents, 0, contents.length, position);
    await handle.sync();
  } finally {
    await handle.close();
  }
}
