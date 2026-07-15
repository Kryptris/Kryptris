import { randomUUID } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { EntryInput } from '../../src/shared/models';
import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { AuditService } from '../../src/main/services/audit-service';
import { BackupService } from '../../src/main/services/backup-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

const sandboxes: string[] = [];

interface ScanFinding {
  path: string;
  location: 'content-utf8' | 'content-utf16le' | 'path';
  canaryIndex: number;
}

function testDerivation(): KeyDerivationService {
  return new KeyDerivationService({
    parameters: TEST_PARAMETERS,
    allowUnsafeParametersForTests: true,
  });
}

function capturingAtomicWriter(captureRoot: string): AtomicFileWriter {
  let sequence = 0;
  const capture = async (source: string, kind: 'previous' | 'temporary'): Promise<void> => {
    const target = path.join(
      captureRoot,
      `${kind}-${String(sequence++).padStart(3, '0')}.artifact`,
    );
    await copyFile(source, target).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
    });
  };

  return new AtomicFileWriter({
    afterTempSynced: async (temporaryPath) => capture(temporaryPath, 'temporary'),
    afterReplace: async (targetPath) => capture(`${targetPath}.previous`, 'previous'),
  });
}

async function listFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const visit = async (current: string): Promise<void> => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) await visit(candidate);
      else if (entry.isFile()) files.push(candidate);
    }
  };
  await visit(root);
  return files.sort((left, right) => left.localeCompare(right));
}

async function scanTree(
  root: string,
  canaries: readonly string[],
): Promise<{
  files: string[];
  findings: ScanFinding[];
}> {
  const files = await listFiles(root);
  const findings: ScanFinding[] = [];
  const needles = canaries.map((canary) => ({
    utf8: Buffer.from(canary, 'utf8'),
    utf16le: Buffer.from(canary, 'utf16le'),
  }));

  for (const file of files) {
    const relativePath = path.relative(root, file);
    const content = await readFile(file);
    needles.forEach((needle, canaryIndex) => {
      if (relativePath.includes(canaries[canaryIndex]!)) {
        findings.push({ path: relativePath, location: 'path', canaryIndex });
      }
      if (content.includes(needle.utf8)) {
        findings.push({ path: relativePath, location: 'content-utf8', canaryIndex });
      }
      if (content.includes(needle.utf16le)) {
        findings.push({ path: relativePath, location: 'content-utf16le', canaryIndex });
      }
    });
  }

  return { files, findings };
}

afterEach(async () => {
  await Promise.all(
    sandboxes.splice(0).map((sandbox) => rm(sandbox, { recursive: true, force: true })),
  );
});

describe('Klartext-Canary-Abnahme', () => {
  it('hinterlaesst in Laufzeitwurzel, Backup und atomaren Zwischenstaenden keine Geheimnisse', async () => {
    const sandbox = await mkdtemp(path.join(os.tmpdir(), 'vaulta-plaintext-canary-'));
    sandboxes.push(sandbox);
    const runtimeRoot = path.join(sandbox, 'runtime');
    const captureRoot = path.join(sandbox, '.runtime.vaulta-stage-captured');
    const sourcePath = path.join(sandbox, 'attachment-source.txt');
    await Promise.all([mkdir(runtimeRoot), mkdir(captureRoot)]);

    const runId = randomUUID().replaceAll('-', '').toUpperCase();
    const masterPassword = `VAULTA-CANARY-${runId}-MASTER`;
    const entrySecret = `VAULTA-CANARY-${runId}-ENTRY-PASSWORD`;
    const noteSecret = `VAULTA-CANARY-${runId}-NOTE`;
    const customFieldSecret = `VAULTA-CANARY-${runId}-CUSTOM-FIELD`;
    const attachmentSecret = `VAULTA-CANARY-${runId}-ATTACHMENT`;
    const auditSecret = `VAULTA-CANARY-${runId}-AUDIT`;
    const canaries = [
      masterPassword,
      entrySecret,
      noteSecret,
      customFieldSecret,
      attachmentSecret,
      auditSecret,
    ] as const;

    const atomicWriter = capturingAtomicWriter(captureRoot);
    const profile = new ProfileService({
      rootDir: runtimeRoot,
      keyDerivation: testDerivation(),
      atomicWriter,
    });
    const setup = await profile.beginSetup(masterPassword, false);
    await profile.completeSetup(setup.pendingId, {});

    const vaults = new VaultService({
      rootDir: runtimeRoot,
      profileService: profile,
      atomicWriter,
    });
    const attachments = new AttachmentService({
      rootDir: runtimeRoot,
      vaultService: vaults,
      atomicWriter,
      chunkSize: 4096,
    });
    const audit = new AuditService({
      rootDir: runtimeRoot,
      profileService: profile,
      atomicWriter,
    });
    const backups = new BackupService({
      rootDir: runtimeRoot,
      profileService: profile,
      atomicWriter,
    });

    const vault = await vaults.createVault('Canary-Tresor', '#14b8a6');
    const input: EntryInput = {
      title: 'Canary-Pruefeintrag',
      folderId: null,
      tags: ['abnahme'],
      favorite: false,
      note: noteSecret,
      customFields: [
        {
          id: randomUUID(),
          label: 'Vertrauliches Zusatzfeld',
          type: 'secret',
          value: customFieldSecret,
          secret: true,
          searchable: false,
          order: 0,
        },
      ],
      data: {
        type: 'credential',
        value: {
          username: 'canary@example.invalid',
          password: entrySecret,
          websites: ['https://example.invalid'],
          appNames: [],
        },
      },
    };
    const entry = await vaults.createEntry(vault.id, input);

    const sourceBuffer = Buffer.from(attachmentSecret, 'utf8');
    try {
      await writeFile(sourcePath, sourceBuffer, { mode: 0o600 });
    } finally {
      sourceBuffer.fill(0);
    }
    const attachment = await attachments.encryptFile({
      vaultId: vault.id,
      sourcePath,
      name: 'attachment.txt',
      mediaType: 'text/plain',
    });
    await vaults.mutateVault(vault.id, (document) => {
      const stored = document.entries.find((candidate) => candidate.id === entry.id);
      if (stored === undefined) throw new Error('Canary-Eintrag fehlt');
      stored.attachments.push(attachment);
      return undefined;
    });
    await audit.record({ type: 'entry-created', vaultId: vault.id, entryId: auditSecret });

    const backup = await backups.createBackup();
    await expect(
      backups.inspectBackup(backup.path, { type: 'master', value: masterPassword }),
    ).resolves.toMatchObject({ vaultCount: 1, attachmentCount: 1 });

    await rm(sourcePath, { force: true });
    profile.lock();
    expect(profile.isUnlocked()).toBe(false);
    await expect(stat(sourcePath)).rejects.toMatchObject({ code: 'ENOENT' });

    const scan = await scanTree(sandbox, canaries);
    const relativeFiles = scan.files.map((file) => path.relative(sandbox, file));
    expect(relativeFiles).toEqual(
      expect.arrayContaining([
        path.join('runtime', 'profile.json'),
        path.join('runtime', 'audit.vaulta'),
        path.relative(sandbox, backup.path),
      ]),
    );
    expect(relativeFiles.some((file) => file.endsWith('.vaulta'))).toBe(true);
    expect(relativeFiles.some((file) => file.endsWith('.vatt'))).toBe(true);
    expect(relativeFiles.some((file) => file.includes('temporary-'))).toBe(true);
    expect(relativeFiles.some((file) => file.includes('previous-'))).toBe(true);
    expect(scan.findings).toEqual([]);
  });
});
