import { constants, type Stats } from 'node:fs';
import type * as FsPromises from 'node:fs/promises';
import path from 'node:path';

import { beforeEach, describe, expect, it, vi } from 'vitest';

const fsMocks = vi.hoisted(() => ({
  lstat: vi.fn(),
  open: vi.fn(),
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return { ...actual, lstat: fsMocks.lstat, open: fsMocks.open };
});

import { SafeImportSourceReader } from '../../src/main/services/safe-import-source-reader';

const SOURCE_PATH = path.resolve(process.cwd(), 'synthetischer-import.csv');

describe('SafeImportSourceReader', () => {
  beforeEach(() => {
    fsMocks.lstat.mockReset();
    fsMocks.open.mockReset();
  });

  it('liest eine unveränderte reguläre Datei ausschließlich über den geprüften Handle', async () => {
    const content = Buffer.from('name,url\nBeispiel,https://example.invalid\n', 'utf8');
    const stable = regularFile(101, content.length);
    const handle = handleFor(content, [stable, stable]);
    fsMocks.lstat.mockResolvedValue(stable);
    fsMocks.open.mockResolvedValue(handle);

    const reader = new SafeImportSourceReader();

    await expect(reader.readUtf8(SOURCE_PATH)).resolves.toBe(content.toString('utf8'));
    expect(fsMocks.open).toHaveBeenCalledWith(
      SOURCE_PATH,
      constants.O_RDONLY | (typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0),
    );
    expect(handle.read).toHaveBeenCalled();
    expect(handle.close).toHaveBeenCalledTimes(1);
  });

  it('lehnt einen Austausch zwischen lstat und open über die Handle-Identität ab', async () => {
    const initial = regularFile(201, 5);
    const replacement = regularFile(202, 5);
    const handle = handleFor(Buffer.from('neu\n', 'utf8'), [replacement]);
    fsMocks.lstat.mockResolvedValue(initial);
    fsMocks.open.mockResolvedValue(handle);
    const afterInitialPathValidated = vi.fn();
    const reader = new SafeImportSourceReader({
      onInitialPathValidated: afterInitialPathValidated,
    });

    await expect(reader.readUtf8(SOURCE_PATH)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(afterInitialPathValidated).toHaveBeenCalledWith(SOURCE_PATH);
    expect(handle.read).not.toHaveBeenCalled();
    expect(handle.close).toHaveBeenCalledTimes(1);
  });

  it('lehnt einen Austausch nach dem Öffnen ab, obwohl der Handle noch die geprüfte Datei hält', async () => {
    const content = Buffer.from('alt\n', 'utf8');
    const stable = regularFile(301, content.length);
    const replacement = regularFile(302, content.length);
    const handle = handleFor(content, [stable, stable]);
    fsMocks.lstat
      .mockResolvedValueOnce(stable)
      .mockResolvedValueOnce(stable)
      .mockResolvedValueOnce(replacement);
    fsMocks.open.mockResolvedValue(handle);
    const afterHandleOpened = vi.fn();
    const reader = new SafeImportSourceReader({ onHandleOpened: afterHandleOpened });

    await expect(reader.readUtf8(SOURCE_PATH)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(afterHandleOpened).toHaveBeenCalledWith(SOURCE_PATH);
    expect(handle.read).toHaveBeenCalled();
    expect(handle.close).toHaveBeenCalledTimes(1);
  });

  it('lehnt eine symbolische Importquelle vor dem Öffnen ab', async () => {
    const link = regularFile(401, 8, true);
    fsMocks.lstat.mockResolvedValue(link);
    const reader = new SafeImportSourceReader();

    await expect(reader.readUtf8(SOURCE_PATH)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(fsMocks.open).not.toHaveBeenCalled();
  });

  it('begrenzt den Descriptor-Read auf die geprüfte Größe und erkennt Wachstum', async () => {
    const content = Buffer.from('alt\n', 'utf8');
    const stable = regularFile(501, content.length);
    const handle = handleFor(content, [stable], true);
    fsMocks.lstat.mockResolvedValue(stable);
    fsMocks.open.mockResolvedValue(handle);
    const reader = new SafeImportSourceReader();

    await expect(reader.readUtf8(SOURCE_PATH)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(handle.read).toHaveBeenCalledTimes(2);
    expect(handle.close).toHaveBeenCalledTimes(1);
  });
});

function regularFile(ino: number, size: number, symbolicLink = false): Stats {
  return {
    dev: 17,
    ino,
    size,
    mtimeMs: 1_700_000_000_000,
    ctimeMs: 1_700_000_000_000,
    isFile: () => true,
    isSymbolicLink: () => symbolicLink,
  } as Stats;
}

function handleFor(
  content: Buffer,
  states: readonly Stats[],
  hasUnexpectedExtraByte = false,
): {
  readonly stat: ReturnType<typeof vi.fn>;
  readonly read: ReturnType<typeof vi.fn>;
  readonly close: ReturnType<typeof vi.fn>;
} {
  let statIndex = 0;
  const stat = vi.fn(() => Promise.resolve(states[Math.min(statIndex++, states.length - 1)]));
  const read = vi.fn((target: Buffer, offset: number, length: number, position: number | null) => {
    const start = position ?? 0;
    const source =
      start < content.length
        ? content.subarray(start, Math.min(content.length, start + length))
        : hasUnexpectedExtraByte && start === content.length
          ? Buffer.from([0x78])
          : Buffer.alloc(0);
    source.copy(target, offset);
    return Promise.resolve({ bytesRead: source.length, buffer: target });
  });
  return {
    stat,
    read,
    close: vi.fn(() => Promise.resolve(undefined)),
  };
}
