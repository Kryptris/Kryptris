import { createWriteStream } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';
import { ZipFile } from 'yazl';

const CANARY = 'VAULTA-CANARY-PASSWORD-7f43e7';
const scannerPath = path.resolve(process.cwd(), 'scripts', 'scan-artifacts.mjs');
const temporaryRoots: string[] = [];

interface ScanResult {
  code: number | null;
  stderr: string;
  stdout: string;
}

interface ScannerModule {
  scanArtifacts(
    targets: string[],
    options?: { limits?: Record<string, number> },
  ): Promise<{ findings: string[] }>;
}

function isScannerModule(value: unknown): value is ScannerModule {
  return (
    typeof value === 'object' &&
    value !== null &&
    'scanArtifacts' in value &&
    typeof value.scanArtifacts === 'function'
  );
}

async function loadScanner(): Promise<ScannerModule> {
  const loaded: unknown = await import(
    pathToFileURL(path.resolve(process.cwd(), 'scripts', 'artifact-scanner.mjs')).href
  );
  if (!isScannerModule(loaded)) throw new Error('Scanner-Modul konnte nicht geladen werden.');
  return loaded;
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'vaulta-artifact-scan-'));
  temporaryRoots.push(root);
  return root;
}

function runScanner(target: string): Promise<ScanResult> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, [scannerPath, target], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) =>
      resolveRun({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      }),
    );
  });
}

async function createZip(
  target: string,
  entries: Array<{ name: string; contents: Buffer; mode?: number }>,
): Promise<void> {
  const archive = new ZipFile();
  for (const entry of entries) {
    archive.addBuffer(entry.contents, entry.name, {
      ...(entry.mode === undefined ? {} : { mode: entry.mode }),
    });
  }
  const output = createWriteStream(target, { flags: 'wx', mode: 0o600 });
  archive.outputStream.pipe(output);
  archive.end();
  await new Promise<void>((resolveWrite, reject) => {
    output.once('close', resolveWrite);
    output.once('error', reject);
    archive.once('error', reject);
  });
}

function utf16be(value: string): Buffer {
  const result = Buffer.from(value, 'utf16le');
  result.swap16();
  return result;
}

function createAsar(name: string, contents: Buffer): Buffer {
  const headerJson = Buffer.from(
    JSON.stringify({ files: { [name]: { size: contents.length, offset: '0' } } }),
    'utf8',
  );
  const payloadSize = Math.ceil((4 + headerJson.length) / 4) * 4;
  const headerPickle = Buffer.alloc(4 + payloadSize);
  headerPickle.writeUInt32LE(payloadSize, 0);
  headerPickle.writeUInt32LE(headerJson.length, 4);
  headerJson.copy(headerPickle, 8);
  const sizePickle = Buffer.alloc(8);
  sizePickle.writeUInt32LE(4, 0);
  sizePickle.writeUInt32LE(headerPickle.length, 4);
  return Buffer.concat([sizePickle, headerPickle, contents]);
}

function encryptedEnvelope(): Record<string, string> {
  return {
    algorithm: 'AES-256-GCM',
    nonce: 'AAAAAAAAAAAAAAAA',
    ciphertext: 'AA==',
    tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
  };
}

function lengthPrefixedArtifact(magic: string, header: object): Buffer {
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(headerBytes.length);
  return Buffer.concat([Buffer.from(magic, 'ascii'), length, headerBytes]);
}

function encryptedAttachmentFixture(): Buffer {
  return lengthPrefixedArtifact('VLTATT01', {
    format: 'vaulta-attachment',
    version: 1,
    cipher: 'AES-256-GCM-CHUNKED',
    chunkSize: 4096,
    noncePrefix: Buffer.alloc(8).toString('base64'),
    wrappedFileKey: encryptedEnvelope(),
  });
}

function encryptedContainerFixture(): Buffer {
  return Buffer.from(
    JSON.stringify({
      header: {
        magic: 'VAULTA-CONTAINER',
        version: 1,
        kind: 'vault-document',
        cipher: 'AES-256-GCM',
        contextHash: 'AA==',
      },
      payload: encryptedEnvelope(),
    }),
    'utf8',
  );
}

function offlineBreachIndexFixture(): Buffer {
  const index = Buffer.alloc(64);
  Buffer.from('KRYBRCH1', 'ascii').copy(index, 0);
  index.writeUInt16LE(1, 8);
  index.writeUInt8(1, 10);
  index.writeUInt8(24, 11);
  index.writeBigUInt64LE(1n, 12);
  index.writeUInt32LE(65_537, 20);
  return index;
}

function technicalJournal(): Buffer {
  return Buffer.from(
    JSON.stringify({
      format: 'vaulta-multi-file-transaction',
      version: 1,
      transactionId: '123e4567-e89b-42d3-a456-426614174000',
      createdDirectories: [],
      entries: [],
    }),
    'utf8',
  );
}

describe('Artefakt-Scanner', () => {
  afterEach(async () => {
    await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true })));
  });

  it('scannt komprimierte ZIP-Inhalte statt nur Archivbytes', async () => {
    const root = await temporaryRoot();
    const target = path.join(root, 'release.zip');
    await createZip(target, [{ name: 'payload.txt', contents: Buffer.from(CANARY.repeat(20)) }]);
    expect((await readFile(target)).includes(Buffer.from(CANARY))).toBe(false);

    const result = await runScanner(target);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('release.zip!/payload.txt (UTF-8)');
  });

  it('scannt ASAR-Inhalte auch als verschachtelten ZIP-Eintrag', async () => {
    const root = await temporaryRoot();
    const target = path.join(root, 'nested.zip');
    await createZip(target, [
      {
        name: 'resources/app.asar',
        contents: createAsar('payload.bin', utf16be(CANARY)),
      },
    ]);

    const result = await runScanner(target);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('nested.zip!/resources/app.asar!/payload.bin (UTF-16BE)');
  });

  it('erkennt Canary-Werte in Archivpfaden', async () => {
    const root = await temporaryRoot();
    const target = path.join(root, 'path.zip');
    await createZip(target, [{ name: `safe/${CANARY}.txt`, contents: Buffer.from('clean') }]);

    const result = await runScanner(target);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain(`path.zip!/safe/${CANARY}.txt (Pfad)`);
  });

  it('scannt ein ASAR im reproduzierbaren NSIS-Staging rekursiv und erkennt UTF-16BE', async () => {
    const root = await temporaryRoot();
    const installer = path.join(root, 'Vaulta-1.0.0-Setup.exe');
    const resources = path.join(root, 'win-unpacked', 'resources');
    await mkdir(resources, { recursive: true });
    await writeFile(installer, 'MZ-test-fixture');
    await writeFile(path.join(resources, 'app.asar'), createAsar('payload.bin', utf16be(CANARY)));

    const result = await runScanner(installer);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('app.asar!/payload.bin (UTF-16BE)');
  });

  it('lehnt Symlinks und verdächtige Kompressionsraten fail-closed ab', async () => {
    const root = await temporaryRoot();
    const linkArchive = path.join(root, 'link.zip');
    const bombArchive = path.join(root, 'bomb.zip');
    await createZip(linkArchive, [
      { name: 'link', contents: Buffer.from('target'), mode: 0o120777 },
    ]);
    await createZip(bombArchive, [
      { name: 'zeros.bin', contents: Buffer.alloc(4 * 1024 * 1024), mode: 0o100600 },
    ]);

    const [link, bomb] = await Promise.all([runScanner(linkArchive), runScanner(bombArchive)]);
    expect(link.code).toBe(1);
    expect(link.stderr).toContain('Symbolische Verknüpfung');
    expect(bomb.code).toBe(1);
    expect(bomb.stderr).toContain('Verdächtige Kompressionsrate');
  });

  it('erzwingt konfigurierbare Größenlimits fail-closed', async () => {
    const root = await temporaryRoot();
    const target = path.join(root, 'oversize.bin');
    await writeFile(target, Buffer.alloc(1_025));
    const scanner = await loadScanner();

    await expect(
      scanner.scanArtifacts([target], { limits: { maxFileBytes: 1_024 } }),
    ).rejects.toThrow('Datei ist zu groß');
  });

  it('akzeptiert ein sauberes verschachteltes ZIP/ASAR-Artefakt', async () => {
    const root = await temporaryRoot();
    const target = path.join(root, 'clean.zip');
    await createZip(target, [
      { name: 'resources/app.asar', contents: createAsar('app.js', Buffer.from('safe')) },
    ]);

    const result = await runScanner(target);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Keine bekannten Canary-Geheimnisse');
  });

  it('lehnt persistente Cache-/Berichtspfadreste und temporäre Laufzeitreste geschlossen ab', async () => {
    const scanner = await loadScanner();
    const cacheRoot = await temporaryRoot();
    const dryRunRoot = await temporaryRoot();
    const breachRoot = await temporaryRoot();
    await mkdir(path.join(cacheRoot, '.vaulta-report-cache'), { recursive: true });
    await writeFile(path.join(cacheRoot, '.vaulta-report-cache', 'report.json'), '{}');
    await mkdir(path.join(dryRunRoot, 'kryptris-restore-dry-run-leftover'), { recursive: true });
    await writeFile(
      path.join(dryRunRoot, 'kryptris-restore-dry-run-leftover', 'profile.json'),
      '{}',
    );
    await mkdir(path.join(breachRoot, 'security'), { recursive: true });
    await writeFile(
      path.join(breachRoot, 'security', '.breach-import-123e4567-e89b-42d3-a456-426614174000.tmp'),
      'unbereinigter Index-Zwischenstand',
    );

    await expect(scanner.scanArtifacts([cacheRoot])).rejects.toThrow('Cache- oder Berichtspfad');
    await expect(scanner.scanArtifacts([dryRunRoot])).rejects.toThrow('Restore-Probelauf-Staging');
    await expect(scanner.scanArtifacts([breachRoot])).rejects.toThrow('Datenlecklisten-Staging');
  });

  it('lehnt Klartext in Anhangs-Staging und atomaren Zwischenständen ab', async () => {
    const scanner = await loadScanner();
    const stagingRoot = await temporaryRoot();
    const atomicRoot = await temporaryRoot();
    const stagingFile = path.join(
      stagingRoot,
      '.vaulta-entry-transaction-staging',
      'run-1',
      'attachment.vatt',
    );
    await mkdir(path.dirname(stagingFile), { recursive: true });
    await writeFile(stagingFile, JSON.stringify({ password: 'nicht-canary-klartext' }));
    await writeFile(
      path.join(atomicRoot, '.profile.json.vaulta-tmp-123e4567-e89b-42d3-a456-426614174000'),
      'unverschlüsselter Zwischenstand',
    );

    await expect(scanner.scanArtifacts([stagingRoot])).rejects.toThrow('Klartext-Geheimnisfeld');
    await expect(scanner.scanArtifacts([atomicRoot])).rejects.toThrow(
      'Atomäres temporäres Artefakt',
    );
  });

  it('akzeptiert nur verschlüsseltes Staging sowie geschützte oder öffentliche Rollback-Sidecars', async () => {
    const scanner = await loadScanner();
    const root = await temporaryRoot();
    const stagingFile = path.join(
      root,
      '.vault-package-import-staging',
      '123e4567-e89b-42d3-a456-426614174000',
      'attachment.vatt',
    );
    const transactionDirectory = path.join(root, '.vaulta-multi-file-transaction');
    await mkdir(path.dirname(stagingFile), { recursive: true });
    await mkdir(transactionDirectory, { recursive: true });
    await writeFile(stagingFile, encryptedAttachmentFixture());
    await writeFile(path.join(transactionDirectory, 'journal.json'), technicalJournal());
    await writeFile(
      path.join(transactionDirectory, 'rollback-000000.bin'),
      encryptedContainerFixture(),
    );

    const breachTransactionDirectory = path.join(root, '.vaulta-migration-transaction');
    await mkdir(breachTransactionDirectory, { recursive: true });
    await writeFile(path.join(breachTransactionDirectory, 'journal.json'), technicalJournal());
    await writeFile(
      path.join(breachTransactionDirectory, 'rollback-000000.bin'),
      offlineBreachIndexFixture(),
    );

    await expect(scanner.scanArtifacts([root])).resolves.toMatchObject({ findings: [] });
  });

  it('lehnt Klartextfelder in technischen Journalen auch ohne Canary ab', async () => {
    const scanner = await loadScanner();
    const root = await temporaryRoot();
    const transactionDirectory = path.join(root, '.vaulta-migration-transaction');
    await mkdir(transactionDirectory, { recursive: true });
    await writeFile(
      path.join(transactionDirectory, 'journal.json'),
      JSON.stringify({
        format: 'vaulta-migration-transaction',
        version: 1,
        password: 'nicht-canary-klartext',
      }),
    );

    await expect(scanner.scanArtifacts([root])).rejects.toThrow('Klartext-Geheimnisfeld');
  });
});
