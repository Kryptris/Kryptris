import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import {
  MULTI_FILE_TRANSACTION_DIRECTORY,
  MultiFileTransactionService,
} from '../../src/main/storage/multi-file-transaction';
import { VaultaError } from '../../src/shared/errors';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Atomare Multi-Datei-Transaktionen', () => {
  it('committet mehrere Byte-Dateien gemeinsam und hinterlaesst keine technischen Artefakte', async () => {
    const root = await createRoot();
    await mkdir(path.join(root, 'vaults'), { recursive: true });
    await writeFile(path.join(root, 'vaults', 'one.vaulta'), Buffer.from('encrypted-old-one'));
    let journalText = '';
    let rollbackBytes = Buffer.alloc(0);
    const service = new MultiFileTransactionService({
      rootDir: root,
      hooks: {
        afterJournalInstalled: async (journalPath) => {
          journalText = await readFile(journalPath, 'utf8');
          rollbackBytes = await readFile(
            path.join(path.dirname(journalPath), 'rollback-000000.bin'),
          );
        },
      },
    });

    const result = await service.execute([
      {
        type: 'write',
        relativePath: 'vaults/one.vaulta',
        contents: Buffer.from('encrypted-new-one-SENSITIVE-CANARY'),
      },
      {
        type: 'write',
        relativePath: 'attachments/item/blob.bin',
        contents: Buffer.from('encrypted-new-two-SECOND-CANARY'),
        expectedSha256: null,
      },
    ]);

    expect(result.changedPaths).toEqual(['vaults/one.vaulta', 'attachments/item/blob.bin']);
    await expect(readFile(path.join(root, 'vaults', 'one.vaulta'), 'utf8')).resolves.toBe(
      'encrypted-new-one-SENSITIVE-CANARY',
    );
    await expect(
      readFile(path.join(root, 'attachments', 'item', 'blob.bin'), 'utf8'),
    ).resolves.toBe('encrypted-new-two-SECOND-CANARY');
    expect(rollbackBytes).toEqual(Buffer.from('encrypted-old-one'));
    expect(journalText).not.toContain('SENSITIVE-CANARY');
    expect(journalText).not.toContain('SECOND-CANARY');
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });

  it('rollt nach einem Fehler hinter dem ersten Teil-Write alle Dateien bytegenau zurueck', async () => {
    const root = await createRoot();
    await mkdir(path.join(root, 'vaults'), { recursive: true });
    const oneBefore = Buffer.from([0x56, 0x4c, 0x54, 0x00, 0xff, 0x01]);
    const twoBefore = Buffer.from([0x56, 0x4c, 0x54, 0x00, 0xfe, 0x02]);
    await writeFile(path.join(root, 'vaults', 'one.vaulta'), oneBefore);
    await writeFile(path.join(root, 'vaults', 'two.vaulta'), twoBefore);
    let failFirstReplacement = true;
    const atomicWriter = new AtomicFileWriter({
      afterReplace: () => {
        if (!failFirstReplacement) return;
        failFirstReplacement = false;
        throw new Error('simulierter Prozessfehler nach dem ersten Replace');
      },
    });
    const service = new MultiFileTransactionService({ rootDir: root, atomicWriter });

    await expect(
      service.execute([
        {
          type: 'write',
          relativePath: 'vaults/one.vaulta',
          contents: Buffer.from('new-one'),
        },
        {
          type: 'write',
          relativePath: 'vaults/two.vaulta',
          contents: Buffer.from('new-two'),
        },
      ]),
    ).rejects.toThrow('simulierter Prozessfehler');

    await expect(readFile(path.join(root, 'vaults', 'one.vaulta'))).resolves.toEqual(oneBefore);
    await expect(readFile(path.join(root, 'vaults', 'two.vaulta'))).resolves.toEqual(twoBefore);
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });

  it('stellt beim Startup eine journalisierte Teiloperation inklusive Loeschung wieder her', async () => {
    const root = await createRoot();
    const vaultDirectory = path.join(root, 'vaults');
    await mkdir(vaultDirectory, { recursive: true });
    const firstBefore = Buffer.from('encrypted-first-before');
    const secondBefore = Buffer.from('encrypted-second-before');
    const firstAfter = Buffer.from('encrypted-first-after');
    const firstPath = path.join(vaultDirectory, 'first.vaulta');
    const secondPath = path.join(vaultDirectory, 'second.vaulta');
    await writeFile(firstPath, firstAfter);

    const transactionRoot = path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY);
    await mkdir(transactionRoot);
    await writeFile(path.join(transactionRoot, 'rollback-000000.bin'), firstBefore);
    await writeFile(path.join(transactionRoot, 'rollback-000001.bin'), secondBefore);
    const transactionId = randomUUID();
    await writeFile(
      path.join(transactionRoot, 'journal.json'),
      JSON.stringify({
        format: 'vaulta-multi-file-transaction',
        version: 1,
        transactionId,
        createdDirectories: [],
        entries: [
          journalEntry('vaults/first.vaulta', 'write', firstBefore, firstAfter, 0),
          journalEntry('vaults/second.vaulta', 'delete', secondBefore, null, 1),
        ],
      }),
    );

    const recovery = await new MultiFileTransactionService({
      rootDir: root,
    }).recoverInterruptedTransaction();

    expect(recovery).toEqual({ status: 'rolled-back', transactionId });
    await expect(readFile(firstPath)).resolves.toEqual(firstBefore);
    await expect(readFile(secondPath)).resolves.toEqual(secondBefore);
    await expect(readFile(transactionRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(
      new MultiFileTransactionService({ rootDir: root }).recoverInterruptedTransaction(),
    ).resolves.toEqual({ status: 'none', transactionId: null });
  });

  it('loescht Dateien erst mit durablem Commit und akzeptiert idempotent fehlende Ziele', async () => {
    const root = await createRoot();
    await mkdir(path.join(root, 'attachments'), { recursive: true });
    const targetPath = path.join(root, 'attachments', 'obsolete.bin');
    const bytes = Buffer.from('encrypted-obsolete');
    await writeFile(targetPath, bytes);
    const service = new MultiFileTransactionService({ rootDir: root });

    await service.execute([
      {
        type: 'delete',
        relativePath: 'attachments/obsolete.bin',
        expectedSha256: sha256(bytes),
      },
      {
        type: 'delete',
        relativePath: 'attachments/already-absent.bin',
        expectedSha256: null,
      },
      {
        type: 'delete',
        relativePath: 'not-created/deep/also-absent.bin',
        expectedSha256: null,
      },
    ]);

    await expect(readFile(targetPath)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });

  it('bestaetigt beim Startup einen durablem Commit-Marker ohne den Zielstand zurueckzurollen', async () => {
    const root = await createRoot();
    const vaultDirectory = path.join(root, 'vaults');
    await mkdir(vaultDirectory);
    const before = Buffer.from('encrypted-before');
    const after = Buffer.from('encrypted-after');
    const targetPath = path.join(vaultDirectory, 'committed.vaulta');
    await writeFile(targetPath, after);

    const transactionRoot = path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY);
    await mkdir(transactionRoot);
    await writeFile(path.join(transactionRoot, 'rollback-000000.bin'), before);
    const transactionId = randomUUID();
    const journalBytes = Buffer.from(
      JSON.stringify({
        format: 'vaulta-multi-file-transaction',
        version: 1,
        transactionId,
        createdDirectories: [],
        entries: [journalEntry('vaults/committed.vaulta', 'write', before, after, 0)],
      }),
    );
    await writeFile(path.join(transactionRoot, 'journal.json'), journalBytes);
    await writeFile(
      path.join(transactionRoot, 'terminal.json'),
      JSON.stringify({
        format: 'vaulta-multi-file-terminal',
        version: 1,
        transactionId,
        journalSha256: sha256(journalBytes),
        outcome: 'committed',
      }),
    );

    await expect(
      new MultiFileTransactionService({ rootDir: root }).recoverInterruptedTransaction(),
    ).resolves.toEqual({ status: 'committed', transactionId });
    await expect(readFile(targetPath)).resolves.toEqual(after);
    await expect(readFile(transactionRoot)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('kopiert eine grosse vorbereitete Datei streaming und schreibt ihren Quellpfad nicht ins Journal', async () => {
    const root = await createRoot();
    const stagingDirectory = path.join(root, 'prepared-input');
    await mkdir(stagingDirectory);
    const sourcePath = path.join(stagingDirectory, 'SOURCE-PATH-CANARY.vatt');
    const sourceBytes = Buffer.alloc(6 * 1024 * 1024 + 73);
    for (let index = 0; index < sourceBytes.length; index += 1) {
      sourceBytes[index] = index % 251;
    }
    await writeFile(sourcePath, sourceBytes);
    let journalText = '';
    const service = new MultiFileTransactionService({
      rootDir: root,
      hooks: {
        afterJournalInstalled: async (journalPath) => {
          journalText = await readFile(journalPath, 'utf8');
        },
      },
    });

    await service.execute([
      {
        type: 'write-file',
        relativePath: 'attachments/target-vault/target-attachment.vatt',
        sourcePath,
        expectedSha256: null,
      },
    ]);

    const targetBytes = await readFile(
      path.join(root, 'attachments', 'target-vault', 'target-attachment.vatt'),
    );
    expect(targetBytes.length).toBe(sourceBytes.length);
    expect(sha256(targetBytes)).toBe(sha256(sourceBytes));
    expect(journalText).not.toContain(sourcePath);
    expect(journalText).not.toContain('SOURCE-PATH-CANARY');
    const retainedSource = await readFile(sourcePath);
    expect(retainedSource.length).toBe(sourceBytes.length);
    expect(sha256(retainedSource)).toBe(sha256(sourceBytes));
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });

  it('rollt zurueck, wenn eine vorbereitete Quelle nach der Journalinstallation ausgetauscht wird', async () => {
    const root = await createRoot();
    const stagingDirectory = path.join(root, 'prepared-input');
    const targetDirectory = path.join(root, 'attachments');
    await mkdir(stagingDirectory);
    await mkdir(targetDirectory);
    const sourcePath = path.join(stagingDirectory, 'replace-me.vatt');
    const originalSourcePath = path.join(stagingDirectory, 'replace-me.original.vatt');
    const sourceBefore = Buffer.from('encrypted-prepared-generation-one');
    const sourceAfter = Buffer.from('encrypted-prepared-generation-two');
    const targetPath = path.join(targetDirectory, 'target.vatt');
    const targetBefore = Buffer.from('encrypted-target-before');
    expect(sourceAfter.length).toBe(sourceBefore.length);
    await writeFile(sourcePath, sourceBefore);
    await writeFile(targetPath, targetBefore);
    const service = new MultiFileTransactionService({
      rootDir: root,
      hooks: {
        afterJournalInstalled: async () => {
          await rename(sourcePath, originalSourcePath);
          await writeFile(sourcePath, sourceAfter);
        },
      },
    });

    const error = await captureVaultaError(
      service.execute([
        {
          type: 'write-file',
          relativePath: 'attachments/target.vatt',
          sourcePath,
          expectedSha256: sha256(targetBefore),
        },
      ]),
    );

    expect(error.code).toBe('CONFLICT');
    await expect(readFile(targetPath)).resolves.toEqual(targetBefore);
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });

  it('weist vorbereitete Quellen hinter einem symbolischen Verzeichnislink vor dem Journal zurueck', async () => {
    const root = await createRoot();
    const realDirectory = path.join(root, 'real-prepared-input');
    const linkedDirectory = path.join(root, 'linked-prepared-input');
    await mkdir(realDirectory);
    await writeFile(path.join(realDirectory, 'source.vatt'), 'encrypted-source');
    await symlink(
      realDirectory,
      linkedDirectory,
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    const service = new MultiFileTransactionService({ rootDir: root });

    const error = await captureVaultaError(
      service.execute([
        {
          type: 'write-file',
          relativePath: 'attachments/target.vatt',
          sourcePath: path.join(linkedDirectory, 'source.vatt'),
          expectedSha256: null,
        },
      ]),
    );

    expect(error.code).toBe('UNSAFE_PATH');
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
    await expect(readFile(path.join(root, 'attachments', 'target.vatt'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('weist Traversal und veraltete Generations-Hashes vor dem Journal zurueck', async () => {
    const root = await createRoot();
    const service = new MultiFileTransactionService({ rootDir: root });

    const traversalError = await captureVaultaError(
      service.execute([
        { type: 'write', relativePath: '../outside.bin', contents: Buffer.from('nope') },
      ]),
    );
    expect(traversalError.code).toBe('INVALID_INPUT');

    await mkdir(path.join(root, 'vaults'));
    await writeFile(path.join(root, 'vaults', 'one.vaulta'), 'current');
    const conflict = await captureVaultaError(
      service.execute([
        {
          type: 'delete',
          relativePath: 'vaults/one.vaulta',
          expectedSha256: sha256(Buffer.from('stale')),
        },
      ]),
    );
    expect(conflict.code).toBe('CONFLICT');
    await expect(readFile(path.join(root, 'vaults', 'one.vaulta'), 'utf8')).resolves.toBe(
      'current',
    );
    await expect(readFile(path.join(root, MULTI_FILE_TRANSACTION_DIRECTORY))).rejects.toMatchObject(
      { code: 'ENOENT' },
    );
  });
});

async function createRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-multi-file-'));
  roots.push(root);
  return root;
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function journalEntry(
  relativePath: string,
  action: 'write' | 'delete',
  source: Buffer,
  target: Buffer | null,
  rollbackIndex: number,
): Record<string, unknown> {
  return {
    relativePath,
    action,
    rollbackFile: `rollback-${String(rollbackIndex).padStart(6, '0')}.bin`,
    sourceExists: true,
    sourceSize: source.length,
    sourceSha256: sha256(source),
    targetExists: target !== null,
    targetSize: target?.length ?? 0,
    targetSha256: target === null ? null : sha256(target),
  };
}

async function captureVaultaError(promise: Promise<unknown>): Promise<VaultaError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof VaultaError) return error;
    throw error;
  }
  throw new Error('VaultaError erwartet');
}
