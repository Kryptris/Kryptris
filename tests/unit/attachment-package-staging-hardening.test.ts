import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AttachmentService } from '../../src/main/services/attachment-service';
import type { VaultService } from '../../src/main/services/vault-service';

const VAULT_ID = '00000000-0000-4000-8000-000000000711';
const ATTACHMENT_ID = '00000000-0000-4000-8000-000000000712';
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('AttachmentService Paket-Staging-Haertung', () => {
  it('schreibt und verifiziert einen Paket-Anhang über den geprueften Dateideskriptor', async () => {
    const root = await temporaryRoot();
    const stagingDirectory = path.join(root, 'staging');
    await mkdir(stagingDirectory, { recursive: true, mode: 0o700 });
    const input = packageStagingInput(stagingDirectory, () => undefined);

    const metadata = await attachmentService(root).encryptBufferToStaging(input);
    const encrypted = await readFile(input.stagingPath);

    expect(metadata).toMatchObject({
      id: ATTACHMENT_ID,
      size: input.contents.length,
      mediaType: 'text/plain',
    });
    expect(encrypted.toString('utf8')).not.toContain(input.contents.toString('utf8'));
  });

  it('verweigert einen direkten oder Junction-Alias vor dem ersten verschluesselten Byte', async () => {
    const root = await temporaryRoot();
    const outside = path.join(root, 'outside');
    const stagingDirectory = path.join(root, 'staging-alias');
    const sentinel = path.join(outside, 'sentinel.txt');
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');
    const linked = await createDirectoryAlias(outside, stagingDirectory);
    if (!linked) return;

    await expect(
      attachmentService(root).encryptBufferToStaging(
        packageStagingInput(stagingDirectory, () => undefined),
      ),
    ).rejects.toMatchObject({ code: 'UNSAFE_PATH' });

    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readdir(outside)).resolves.toEqual(['sentinel.txt']);
  });

  it('verwirft einen kontrolliert simulierten Directory-Swap vor dem O_NOFOLLOW-Open', async () => {
    const root = await temporaryRoot();
    const outside = path.join(root, 'outside');
    const stagingDirectory = path.join(root, 'staging');
    const sentinel = path.join(outside, 'sentinel.txt');
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await mkdir(stagingDirectory, { recursive: true, mode: 0o700 });
    await writeFile(sentinel, 'unveraendert');

    let checks = 0;
    let linkUnavailable = false;
    const assertStagingDirectory = async (): Promise<void> => {
      checks += 1;
      if (checks !== 1) return;
      await rm(stagingDirectory, { recursive: true, force: true });
      linkUnavailable = !(await createDirectoryAlias(outside, stagingDirectory));
    };

    const operation = attachmentService(root).encryptBufferToStaging(
      packageStagingInput(stagingDirectory, assertStagingDirectory),
    );
    if (linkUnavailable) {
      await expect(operation).resolves.toMatchObject({ id: ATTACHMENT_ID });
      return;
    }
    await expect(operation).rejects.toMatchObject({ code: 'UNSAFE_PATH' });
    await expect(readFile(sentinel, 'utf8')).resolves.toBe('unveraendert');
    await expect(readdir(outside)).resolves.toEqual(['sentinel.txt']);
  });
});

function attachmentService(rootDir: string): AttachmentService {
  return new AttachmentService({
    rootDir,
    vaultService: {} as VaultService,
    chunkSize: 4096,
  });
}

function packageStagingInput(
  stagingDirectory: string,
  assertStagingDirectory: () => Promise<void> | void,
): Parameters<AttachmentService['encryptBufferToStaging']>[0] {
  return {
    targetVaultId: VAULT_ID,
    targetAttachmentId: ATTACHMENT_ID,
    stagingPath: path.join(stagingDirectory, `${ATTACHMENT_ID}.vatt`),
    stagingDirectory,
    assertStagingDirectory,
    name: 'anonymisierter-paket-anhang.txt',
    mediaType: 'text/plain',
    contents: Buffer.from('synthetischer-paket-anhang-ohne-echtes-geheimnis'),
    targetVaultKey: Buffer.alloc(32, 0x5a),
    createdAt: '2026-08-09T10:00:00.000Z',
    assertAuthorized: () => undefined,
  };
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'kryptris-attachment-package-stage-'));
  roots.push(root);
  return root;
}

async function createDirectoryAlias(target: string, alias: string): Promise<boolean> {
  try {
    await symlink(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EPERM') return false;
    throw error;
  }
}
