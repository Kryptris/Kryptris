import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const yauzl = require('yauzl');

export const DEFAULT_FORBIDDEN_TEXTS = Object.freeze([
  'VAULTA-CANARY-PASSWORD-7f43e7',
  'VAULTA-CANARY-TOTP-JBSWY3DPEHPK3PXP',
  'VAULTA-CANARY-PRIVATE-KEY',
  'lauri@example.invalid',
]);

const DEFAULT_LIMITS = Object.freeze({
  maxArchiveDepth: 8,
  maxArchiveEntries: 100_000,
  maxArchiveExpandedBytes: 1024 * 1024 * 1024,
  maxAsarHeaderBytes: 64 * 1024 * 1024,
  maxCompressionRatio: 1_000,
  maxFileBytes: 1024 * 1024 * 1024,
  maxFiles: 250_000,
  maxNestedArchiveBytes: 512 * 1024 * 1024,
  maxTotalBytes: 8 * 1024 * 1024 * 1024,
});

const ZIP_EXTENSIONS = new Set(['.jar', '.nupkg', '.zip']);

/**
 * The release scan normally sees application files only.  It is deliberately
 * also safe to point it at a reproducible data-root fixture: that lets the
 * release gate reject a leaked runtime artifact instead of merely looking for
 * a handful of known canary values.
 *
 * These names are the persistent boundaries introduced by waves 7–10.  W11
 * keeps reports and reminders in memory, so it deliberately adds no path to
 * this list.  If a future writer adds a persistent cache, the scan fails
 * closed rather than silently accepting an unencrypted cache directory.
 */
const ENCRYPTED_ATTACHMENT_STAGING_DIRECTORIES = new Set([
  '.vaulta-entry-transaction-staging',
  '.vaulta-duplicate-merge-staging',
  '.vault-package-import-staging',
]);
const TECHNICAL_TRANSACTION_DIRECTORIES = new Set([
  '.vaulta-multi-file-transaction',
  '.vaulta-migration-transaction',
]);
const ATTACHMENT_MAGIC = Buffer.from('VLTATT01', 'ascii');
const BACKUP_MAGIC = Buffer.from('VLTBKP01', 'ascii');
const VAULT_PACKAGE_MAGIC = Buffer.from('KRYVLT01', 'ascii');
const OFFLINE_BREACH_INDEX_MAGIC = Buffer.from('KRYBRCH1', 'ascii');
const ATTACHMENT_HEADER_LIMIT = 64 * 1024;
const BACKUP_HEADER_LIMIT = 2 * 1024 * 1024;
const RUNTIME_POLICY_PREFIX_BYTES = BACKUP_HEADER_LIMIT + 12;
const RUNTIME_POLICY_TAIL_BYTES = 256;
const UUID_V4 = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const BREACH_IMPORT_STAGING_FILE = new RegExp(`^\\.breach-import-${UUID_V4}\\.tmp$`, 'iu');
const VAULTA_ATOMIC_TEMPORARY = new RegExp(`^\\..+\\.vaulta-tmp-${UUID_V4}$`, 'iu');
const ROLLBACK_FILE = /^rollback-[0-9]{6}\.bin$/u;
const MULTI_FILE_TECHNICAL_TEMPORARY = new RegExp(
  `^\\.(?:journal|terminal)\\.json\\.tmp-${UUID_V4}$`,
  'iu',
);
const MIGRATION_TECHNICAL_TEMPORARY = new RegExp(
  `^\\.(?:journal|terminal)-${UUID_V4}\\.tmp$`,
  'iu',
);

/*
 * These names are not valid technical transaction fields.  They are checked
 * only under transient data roots, never across application code, so a source
 * bundle cannot turn ordinary identifiers into a false positive.
 */
const CLEAR_TEXT_SECRET_FIELD =
  /"(?:password|masterPassword|exportPassword|secret|totp(?:Seed)?|private(?:Key|_key)?|recovery(?:Key|_key)?|note|customFields|username|title|websites|appNames|contents|plaintext|cleartext|value|data)"\s*:/iu;

class ArtifactScanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ArtifactScanError';
  }
}

function utf16be(value) {
  const encoded = Buffer.from(value, 'utf16le');
  for (let index = 0; index < encoded.length; index += 2) {
    const low = encoded[index];
    encoded[index] = encoded[index + 1];
    encoded[index + 1] = low;
  }
  return encoded;
}

function createPatterns(values) {
  return values.flatMap((text) => [
    { text, encoding: 'UTF-8', bytes: Buffer.from(text, 'utf8') },
    { text, encoding: 'UTF-16LE', bytes: Buffer.from(text, 'utf16le') },
    { text, encoding: 'UTF-16BE', bytes: utf16be(text) },
  ]);
}

function pathKey(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32' ? resolved.toLocaleLowerCase('en-US') : resolved;
}

function extensionFor(value) {
  return path.posix.extname(value.replaceAll('\\', '/')).toLocaleLowerCase('en-US');
}

function isNestedArchive(value) {
  const extension = extensionFor(value);
  return extension === '.asar' || ZIP_EXTENSIONS.has(extension);
}

function virtualPathParts(value) {
  return value
    .replaceAll('\\', '/')
    .replaceAll('!/', '/')
    .split('/')
    .filter((part) => part.length > 0);
}

function isPersistentCacheDirectory(value) {
  return /^\.vaulta-(?:(?:[a-z0-9]+-)*(?:cache|reports?))$/iu.test(value);
}

function isDryRunDirectory(value) {
  return value.startsWith('kryptris-restore-dry-run-');
}

function isRestoreTransactionDirectory(value) {
  return /^\..+\.vaulta-restore-(?:stage|rollback|discard)$/iu.test(value);
}

function runtimePathContext(virtualPath) {
  const parts = virtualPathParts(virtualPath);
  const cacheDirectory = parts.find(isPersistentCacheDirectory);
  if (cacheDirectory !== undefined) return { kind: 'forbidden-cache', cacheDirectory };

  const dryRunDirectory = parts.find(isDryRunDirectory);
  if (dryRunDirectory !== undefined) return { kind: 'forbidden-dry-run', dryRunDirectory };

  const breachImportStaging = parts.find((part) => BREACH_IMPORT_STAGING_FILE.test(part));
  if (breachImportStaging !== undefined) {
    return { kind: 'forbidden-breach-import-staging', breachImportStaging };
  }

  const stagingIndex = parts.findIndex((part) =>
    ENCRYPTED_ATTACHMENT_STAGING_DIRECTORIES.has(part),
  );
  if (stagingIndex >= 0) {
    return {
      kind: 'attachment-staging',
      remaining: parts.slice(stagingIndex + 1),
      stagingDirectory: parts[stagingIndex],
    };
  }

  const technicalIndex = parts.findIndex((part) => TECHNICAL_TRANSACTION_DIRECTORIES.has(part));
  if (technicalIndex >= 0) {
    return {
      kind: 'technical-transaction',
      remaining: parts.slice(technicalIndex + 1),
      transactionDirectory: parts[technicalIndex],
    };
  }

  const restoreIndex = parts.findIndex(isRestoreTransactionDirectory);
  if (restoreIndex >= 0) {
    return {
      kind: 'restore-tree',
      remaining: parts.slice(restoreIndex + 1),
      restoreDirectory: parts[restoreIndex],
    };
  }

  const baseName = parts.at(-1) ?? '';
  if (VAULTA_ATOMIC_TEMPORARY.test(baseName)) return { kind: 'atomic-temporary' };
  if (baseName.endsWith('.vaulta-backup')) return { kind: 'backup' };
  if (baseName.endsWith('.kryptris-vault')) return { kind: 'vault-package' };
  if (baseName.endsWith('.kbi')) return { kind: 'offline-breach-index' };
  if (baseName.endsWith('.vaulta')) return { kind: 'vault-container' };
  if (baseName.endsWith('.vatt')) return { kind: 'attachment' };
  return { kind: 'none' };
}

function assertRuntimePathAllowed(virtualPath) {
  const context = runtimePathContext(virtualPath);
  if (context.kind === 'forbidden-cache') {
    throw new ArtifactScanError(
      `Unverschlüsselter Cache- oder Berichtspfad im Artefakt ist unzulässig: ${virtualPath}`,
    );
  }
  if (context.kind === 'forbidden-dry-run') {
    throw new ArtifactScanError(
      `Entschlüsseltes Restore-Probelauf-Staging darf nicht als Artefakt verbleiben: ${virtualPath}`,
    );
  }
  if (context.kind === 'forbidden-breach-import-staging') {
    throw new ArtifactScanError(
      `Unbereinigtes Datenlecklisten-Staging darf nicht als Artefakt verbleiben: ${virtualPath}`,
    );
  }
  if (context.kind === 'technical-transaction' && context.remaining.length > 1) {
    throw new ArtifactScanError(
      `Technisches Transaktionsverzeichnis enthält einen unerwarteten Pfad: ${virtualPath}`,
    );
  }
}

function startsWith(buffer, prefix) {
  return buffer.length >= prefix.length && buffer.subarray(0, prefix.length).equals(prefix);
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEnvelope(value) {
  return (
    isRecord(value) &&
    value.algorithm === 'AES-256-GCM' &&
    typeof value.nonce === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.tag === 'string'
  );
}

function parseLengthPrefixedHeader(buffer, magic, maximumLength) {
  if (!startsWith(buffer, magic) || buffer.length < magic.length + 4) return null;
  const headerLength = buffer.readUInt32BE(magic.length);
  const start = magic.length + 4;
  const end = start + headerLength;
  if (headerLength === 0 || headerLength > maximumLength || end > buffer.length) return null;
  try {
    const parsed = JSON.parse(buffer.subarray(start, end).toString('utf8'));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function looksLikeEncryptedAttachment(buffer) {
  const header = parseLengthPrefixedHeader(buffer, ATTACHMENT_MAGIC, ATTACHMENT_HEADER_LIMIT);
  return (
    header !== null &&
    header.format === 'vaulta-attachment' &&
    header.version === 1 &&
    header.cipher === 'AES-256-GCM-CHUNKED' &&
    typeof header.chunkSize === 'number' &&
    typeof header.noncePrefix === 'string' &&
    isEnvelope(header.wrappedFileKey)
  );
}

function looksLikeEncryptedBackup(buffer) {
  const header = parseLengthPrefixedHeader(buffer, BACKUP_MAGIC, BACKUP_HEADER_LIMIT);
  return (
    header !== null &&
    header.format === 'vaulta-backup' &&
    header.version === 1 &&
    header.cipher === 'AES-256-GCM-CHUNKED' &&
    isRecord(header.keyWraps) &&
    isEnvelope(header.keyWraps.master)
  );
}

function looksLikeEncryptedVaultPackage(buffer) {
  const header = parseLengthPrefixedHeader(buffer, VAULT_PACKAGE_MAGIC, ATTACHMENT_HEADER_LIMIT);
  return (
    header !== null &&
    header.format === 'kryptris-vault-package' &&
    header.version === 1 &&
    header.cipher === 'AES-256-GCM-CHUNKED' &&
    isEnvelope(header.wrappedPackageKey)
  );
}

function looksLikeEncryptedContainer(buffer) {
  const text = buffer.toString('utf8');
  return (
    /"magic"\s*:\s*"VAULTA-CONTAINER"/u.test(text) &&
    /"cipher"\s*:\s*"AES-256-GCM"/u.test(text) &&
    /"payload"\s*:\s*\{/u.test(text) &&
    /"ciphertext"\s*:/u.test(text)
  );
}

function looksLikeEncryptedProfile(buffer) {
  const text = buffer.toString('utf8');
  return (
    /"format"\s*:\s*"vaulta-profile"/u.test(text) &&
    /"protectedMetadata"\s*:\s*\{/u.test(text) &&
    /"passwordVerifier"\s*:\s*\{/u.test(text) &&
    /"ciphertext"\s*:/u.test(text)
  );
}

function looksLikeOfflineBreachIndex(buffer) {
  // W9 stores a public SHA-1 threat corpus, not vault material.  It may appear
  // byte-for-byte in a rollback sidecar, so accepting it requires this exact
  // fixed binary header rather than treating arbitrary cleartext as safe.
  return (
    startsWith(buffer, OFFLINE_BREACH_INDEX_MAGIC) &&
    buffer.length >= 64 &&
    buffer.readUInt16LE(8) === 1 &&
    buffer.readUInt8(10) === 1 &&
    buffer.readUInt8(11) === 24 &&
    buffer.readUInt32LE(20) === 65_537
  );
}

function looksLikeProtectedRuntimeArtifact(buffer) {
  return (
    looksLikeEncryptedAttachment(buffer) ||
    looksLikeEncryptedBackup(buffer) ||
    looksLikeEncryptedVaultPackage(buffer) ||
    looksLikeEncryptedContainer(buffer) ||
    looksLikeEncryptedProfile(buffer)
  );
}

function looksLikeAllowedRollbackArtifact(buffer) {
  return looksLikeProtectedRuntimeArtifact(buffer) || looksLikeOfflineBreachIndex(buffer);
}

function assertNoCleartextSecretField(buffer, virtualPath) {
  if (CLEAR_TEXT_SECRET_FIELD.test(buffer.toString('utf8'))) {
    throw new ArtifactScanError(
      `Klartext-Geheimnisfeld in einem geschützten Laufzeitartefakt: ${virtualPath}`,
    );
  }
}

function technicalFileKind(context) {
  if (context.remaining.length !== 1) return 'invalid';
  const [name] = context.remaining;
  if (ROLLBACK_FILE.test(name)) return 'rollback';
  if (name === 'journal.json' || name === 'terminal.json') return 'record';
  if (
    (context.transactionDirectory === '.vaulta-multi-file-transaction' &&
      MULTI_FILE_TECHNICAL_TEMPORARY.test(name)) ||
    (context.transactionDirectory === '.vaulta-migration-transaction' &&
      MIGRATION_TECHNICAL_TEMPORARY.test(name))
  ) {
    return 'record';
  }
  return 'invalid';
}

function inspectRuntimeArtifactContents(virtualPath, buffer) {
  const context = runtimePathContext(virtualPath);
  if (context.kind === 'none') return;
  assertNoCleartextSecretField(buffer, virtualPath);

  if (context.kind === 'attachment-staging') {
    const baseName = context.remaining.at(-1) ?? '';
    if (!baseName.endsWith('.vatt') || !looksLikeEncryptedAttachment(buffer)) {
      throw new ArtifactScanError(
        `Verschlüsseltes Anhangs-Staging enthält keine zulässige Anhangsdatei: ${virtualPath}`,
      );
    }
    return;
  }

  if (context.kind === 'technical-transaction') {
    const kind = technicalFileKind(context);
    if (kind === 'invalid') {
      throw new ArtifactScanError(
        `Technisches Transaktionsverzeichnis enthält eine unbekannte Datei: ${virtualPath}`,
      );
    }
    if (kind === 'rollback' && !looksLikeAllowedRollbackArtifact(buffer)) {
      throw new ArtifactScanError(
        `Technisches Rollback-Sidecar ist weder verschlüsselt noch ein gültiger Offline-Hashindex: ${virtualPath}`,
      );
    }
    return;
  }

  if (context.kind === 'restore-tree') {
    const baseName = context.remaining.at(-1) ?? '';
    if (baseName === '.vaulta-restore-committed') return;
    if (!looksLikeProtectedRuntimeArtifact(buffer)) {
      throw new ArtifactScanError(
        `Restore-Staging enthält keine verschlüsselte Datei: ${virtualPath}`,
      );
    }
    return;
  }

  if (context.kind === 'attachment' && !looksLikeEncryptedAttachment(buffer)) {
    throw new ArtifactScanError(`Anhangsartefakt ist nicht verschlüsselt: ${virtualPath}`);
  }
  if (context.kind === 'backup' && !looksLikeEncryptedBackup(buffer)) {
    throw new ArtifactScanError(`Backup-Artefakt ist nicht verschlüsselt: ${virtualPath}`);
  }
  if (context.kind === 'vault-package' && !looksLikeEncryptedVaultPackage(buffer)) {
    throw new ArtifactScanError(`Tresor-Paket ist nicht verschlüsselt: ${virtualPath}`);
  }
  if (context.kind === 'offline-breach-index' && !looksLikeOfflineBreachIndex(buffer)) {
    throw new ArtifactScanError(`Offline-Datenleckindex ist ungültig: ${virtualPath}`);
  }
  if (context.kind === 'vault-container' && !looksLikeEncryptedContainer(buffer)) {
    throw new ArtifactScanError(`Tresorartefakt ist nicht verschlüsselt: ${virtualPath}`);
  }
  if (context.kind === 'atomic-temporary' && !looksLikeProtectedRuntimeArtifact(buffer)) {
    throw new ArtifactScanError(
      `Atomäres temporäres Artefakt enthält keinen verschlüsselten Zustand: ${virtualPath}`,
    );
  }
}

function scanRuntimePolicyChunk(virtualPath, buffer) {
  if (runtimePathContext(virtualPath).kind !== 'none') {
    assertNoCleartextSecretField(buffer, virtualPath);
  }
}

function normalizeArchivePath(value) {
  if (
    value.length === 0 ||
    value.includes('\0') ||
    value.includes('\\') ||
    value.includes(':') ||
    value.startsWith('/') ||
    /^[A-Za-z]:/u.test(value) ||
    [...value].some((character) => character.charCodeAt(0) < 32)
  ) {
    throw new ArtifactScanError('Ein Archiv enthält einen unsicheren Dateipfad.');
  }
  const directory = value.endsWith('/');
  const withoutTrailingSlash = directory ? value.slice(0, -1) : value;
  const parts = withoutTrailingSlash.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) {
    throw new ArtifactScanError('Ein Archiv enthält einen unsicheren Dateipfad.');
  }
  const normalized = path.posix.normalize(withoutTrailingSlash);
  if (normalized !== withoutTrailingSlash) {
    throw new ArtifactScanError('Ein Archiv enthält einen unsicheren Dateipfad.');
  }
  return { normalized, directory };
}

function isZipSymlink(entry) {
  const hostSystem = entry.versionMadeBy >>> 8;
  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
  const isUnixSymlink = hostSystem === 3 && (unixMode & 0o170000) === 0o120000;
  const windowsAttributes = entry.externalFileAttributes & 0xffff;
  return isUnixSymlink || (windowsAttributes & 0x400) !== 0;
}

function assertArchiveDepth(state, depth, virtualPath) {
  if (depth > state.limits.maxArchiveDepth) {
    throw new ArtifactScanError(`Archivverschachtelung überschreitet das Limit: ${virtualPath}`);
  }
}

function addFinding(state, virtualPath, kind) {
  state.findings.add(`${virtualPath} (${kind})`);
}

function scanVirtualPath(state, virtualPath) {
  assertRuntimePathAllowed(virtualPath);
  for (const value of state.forbiddenTexts) {
    if (virtualPath.includes(value)) addFinding(state, virtualPath, 'Pfad');
  }
}

function consumeBytes(state, amount, virtualPath) {
  state.totalBytes += amount;
  if (state.totalBytes > state.limits.maxTotalBytes) {
    throw new ArtifactScanError(
      `Entpackte Gesamtgröße überschreitet das Scan-Limit bei ${virtualPath}.`,
    );
  }
}

function registerFile(state, virtualPath) {
  state.filesScanned += 1;
  if (state.filesScanned > state.limits.maxFiles) {
    throw new ArtifactScanError(`Dateianzahl überschreitet das Scan-Limit bei ${virtualPath}.`);
  }
  scanVirtualPath(state, virtualPath);
}

function scanBufferContents(state, buffer, virtualPath, countBytes = true) {
  if (countBytes) consumeBytes(state, buffer.length, virtualPath);
  for (const pattern of state.patterns) {
    if (buffer.includes(pattern.bytes)) addFinding(state, virtualPath, pattern.encoding);
  }
}

async function scanReadable(state, readable, virtualPath, collect) {
  const chunks = collect ? [] : null;
  const runtimePolicyApplies = runtimePathContext(virtualPath).kind !== 'none';
  const inspectionChunks = runtimePolicyApplies ? [] : null;
  let collectedBytes = 0;
  let inspectionBytes = 0;
  let tail = Buffer.alloc(0);
  for await (const rawChunk of readable) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
    consumeBytes(state, chunk.length, virtualPath);
    const searchable = tail.length === 0 ? chunk : Buffer.concat([tail, chunk]);
    scanBufferContents(state, searchable, virtualPath, false);
    if (runtimePolicyApplies) scanRuntimePolicyChunk(virtualPath, searchable);
    tail = searchable.subarray(
      Math.max(
        0,
        searchable.length - Math.max(state.maxPatternBytes - 1, RUNTIME_POLICY_TAIL_BYTES),
      ),
    );
    if (inspectionChunks !== null && inspectionBytes < RUNTIME_POLICY_PREFIX_BYTES) {
      const remaining = RUNTIME_POLICY_PREFIX_BYTES - inspectionBytes;
      const prefix = chunk.subarray(0, remaining);
      inspectionChunks.push(Buffer.from(prefix));
      inspectionBytes += prefix.length;
    }
    if (chunks !== null) {
      collectedBytes += chunk.length;
      if (collectedBytes > state.limits.maxNestedArchiveBytes) {
        throw new ArtifactScanError(`Verschachteltes Archiv ist zu groß: ${virtualPath}`);
      }
      chunks.push(Buffer.from(chunk));
    }
  }
  if (inspectionChunks !== null) {
    inspectRuntimeArtifactContents(virtualPath, Buffer.concat(inspectionChunks, inspectionBytes));
  }
  return chunks === null ? null : Buffer.concat(chunks, collectedBytes);
}

async function openZipFile(filePath) {
  return new Promise((resolveOpen, reject) => {
    yauzl.open(
      filePath,
      {
        autoClose: true,
        lazyEntries: true,
        strictFileNames: true,
        validateEntrySizes: true,
      },
      (error, zipFile) => {
        if (error !== null) reject(error);
        else resolveOpen(zipFile);
      },
    );
  });
}

async function openZipBuffer(buffer) {
  return new Promise((resolveOpen, reject) => {
    yauzl.fromBuffer(
      buffer,
      {
        lazyEntries: true,
        strictFileNames: true,
        validateEntrySizes: true,
      },
      (error, zipFile) => {
        if (error !== null) reject(error);
        else resolveOpen(zipFile);
      },
    );
  });
}

async function openZipEntry(zipFile, entry) {
  return new Promise((resolveStream, reject) => {
    zipFile.openReadStream(entry, (error, stream) => {
      if (error !== null) reject(error);
      else resolveStream(stream);
    });
  });
}

async function scanZipEntries(state, zipFile, virtualPath, depth) {
  assertArchiveDepth(state, depth, virtualPath);
  if (zipFile.entryCount > state.limits.maxArchiveEntries) {
    zipFile.close();
    throw new ArtifactScanError(`Archiv enthält zu viele Einträge: ${virtualPath}`);
  }

  const seen = new Set();
  let expandedBytes = 0;
  let entryCount = 0;
  await new Promise((resolveEntries, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      zipFile.close();
      reject(error);
    };
    zipFile.once('error', fail);
    zipFile.once('end', () => {
      if (settled) return;
      settled = true;
      resolveEntries();
    });
    zipFile.on('entry', (entry) => {
      void (async () => {
        entryCount += 1;
        if (entryCount > state.limits.maxArchiveEntries) {
          throw new ArtifactScanError(`Archiv enthält zu viele Einträge: ${virtualPath}`);
        }
        const { normalized, directory } = normalizeArchivePath(entry.fileName);
        const entryPath = `${virtualPath}!/${normalized}`;
        scanVirtualPath(state, entryPath);
        if (seen.has(normalized)) {
          throw new ArtifactScanError(`Archiv enthält einen doppelten Pfad: ${entryPath}`);
        }
        seen.add(normalized);
        if (isZipSymlink(entry)) {
          throw new ArtifactScanError(
            `Symbolische Verknüpfung im Archiv ist unzulässig: ${entryPath}`,
          );
        }
        if (directory) {
          zipFile.readEntry();
          return;
        }
        if (entry.isEncrypted()) {
          throw new ArtifactScanError(
            `Verschlüsselter Archiveintrag kann nicht geprüft werden: ${entryPath}`,
          );
        }
        if (!entry.canDecodeFileData()) {
          throw new ArtifactScanError(`Kompressionsverfahren wird nicht unterstützt: ${entryPath}`);
        }
        if (
          !Number.isSafeInteger(entry.uncompressedSize) ||
          entry.uncompressedSize < 0 ||
          entry.uncompressedSize > state.limits.maxFileBytes
        ) {
          throw new ArtifactScanError(`Archiveintrag ist zu groß: ${entryPath}`);
        }
        if (
          entry.uncompressedSize > 1024 * 1024 &&
          entry.uncompressedSize / Math.max(1, entry.compressedSize) >
            state.limits.maxCompressionRatio
        ) {
          throw new ArtifactScanError(`Verdächtige Kompressionsrate im Archiv: ${entryPath}`);
        }
        expandedBytes += entry.uncompressedSize;
        if (expandedBytes > state.limits.maxArchiveExpandedBytes) {
          throw new ArtifactScanError(
            `Entpackte Archivgröße überschreitet das Limit: ${virtualPath}`,
          );
        }
        registerFile(state, entryPath);
        const nested = isNestedArchive(normalized);
        const stream = await openZipEntry(zipFile, entry);
        const content = await scanReadable(state, stream, entryPath, nested);
        if (nested && content !== null)
          await scanNestedArchive(state, content, entryPath, depth + 1);
        zipFile.readEntry();
      })().catch(fail);
    });
    zipFile.readEntry();
  });
}

async function scanZipPath(state, filePath, virtualPath, depth) {
  const zipFile = await openZipFile(filePath);
  await scanZipEntries(state, zipFile, virtualPath, depth);
}

async function scanZipBuffer(state, buffer, virtualPath, depth) {
  const zipFile = await openZipBuffer(buffer);
  await scanZipEntries(state, zipFile, virtualPath, depth);
}

function parseAsarHeader(buffer, virtualPath, limits) {
  if (buffer.length < 16 || buffer.readUInt32LE(0) !== 4) {
    throw new ArtifactScanError(`ASAR-Header ist ungültig: ${virtualPath}`);
  }
  const headerSize = buffer.readUInt32LE(4);
  if (
    headerSize < 8 ||
    headerSize > limits.maxAsarHeaderBytes ||
    8 + headerSize > buffer.length ||
    buffer.readUInt32LE(8) + 4 !== headerSize
  ) {
    throw new ArtifactScanError(`ASAR-Header ist ungültig: ${virtualPath}`);
  }
  const jsonSize = buffer.readUInt32LE(12);
  if (jsonSize === 0 || jsonSize > headerSize - 8 || 16 + jsonSize > buffer.length) {
    throw new ArtifactScanError(`ASAR-Header ist ungültig: ${virtualPath}`);
  }
  let header;
  try {
    header = JSON.parse(buffer.subarray(16, 16 + jsonSize).toString('utf8'));
  } catch {
    throw new ArtifactScanError(`ASAR-Header ist beschädigt: ${virtualPath}`);
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) {
    throw new ArtifactScanError(`ASAR-Header ist ungültig: ${virtualPath}`);
  }
  return { header, dataOffset: 8 + headerSize };
}

function asRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
}

async function scanAsarBuffer(state, buffer, virtualPath, depth) {
  assertArchiveDepth(state, depth, virtualPath);
  const { header, dataOffset } = parseAsarHeader(buffer, virtualPath, state.limits);
  const root = asRecord(header);
  const rootFiles = asRecord(root?.files);
  if (rootFiles === null) throw new ArtifactScanError(`ASAR-Dateibaum fehlt: ${virtualPath}`);
  const seen = new Set();
  let entryCount = 0;
  let expandedBytes = 0;

  const walk = async (files, parent) => {
    for (const [name, rawNode] of Object.entries(files)) {
      const relative = parent.length === 0 ? name : `${parent}/${name}`;
      const { normalized } = normalizeArchivePath(relative);
      const node = asRecord(rawNode);
      const entryPath = `${virtualPath}!/${normalized}`;
      if (node === null) throw new ArtifactScanError(`ASAR-Eintrag ist ungültig: ${entryPath}`);
      entryCount += 1;
      if (entryCount > state.limits.maxArchiveEntries) {
        throw new ArtifactScanError(`ASAR enthält zu viele Einträge: ${virtualPath}`);
      }
      if (seen.has(normalized)) {
        throw new ArtifactScanError(`ASAR enthält einen doppelten Pfad: ${entryPath}`);
      }
      seen.add(normalized);
      scanVirtualPath(state, entryPath);
      if ('link' in node) {
        throw new ArtifactScanError(`Symbolische Verknüpfung im ASAR ist unzulässig: ${entryPath}`);
      }
      const childFiles = asRecord(node.files);
      if (childFiles !== null) {
        await walk(childFiles, normalized);
        continue;
      }
      if (node.unpacked === true) continue;
      const size = node.size;
      const offsetText = node.offset;
      if (
        typeof size !== 'number' ||
        !Number.isSafeInteger(size) ||
        size < 0 ||
        size > state.limits.maxFileBytes ||
        typeof offsetText !== 'string' ||
        !/^\d+$/u.test(offsetText)
      ) {
        throw new ArtifactScanError(`ASAR-Dateieintrag ist ungültig: ${entryPath}`);
      }
      const offset = Number(offsetText);
      const start = dataOffset + offset;
      const end = start + size;
      if (
        !Number.isSafeInteger(offset) ||
        start < dataOffset ||
        end < start ||
        end > buffer.length
      ) {
        throw new ArtifactScanError(`ASAR-Dateieintrag liegt außerhalb des Archivs: ${entryPath}`);
      }
      expandedBytes += size;
      if (expandedBytes > state.limits.maxArchiveExpandedBytes) {
        throw new ArtifactScanError(`Entpackte ASAR-Größe überschreitet das Limit: ${virtualPath}`);
      }
      registerFile(state, entryPath);
      const contents = buffer.subarray(start, end);
      scanBufferContents(state, contents, entryPath);
      inspectRuntimeArtifactContents(entryPath, contents);
      if (isNestedArchive(normalized)) {
        if (contents.length > state.limits.maxNestedArchiveBytes) {
          throw new ArtifactScanError(`Verschachteltes Archiv ist zu groß: ${entryPath}`);
        }
        await scanNestedArchive(state, contents, entryPath, depth + 1);
      }
    }
  };
  await walk(rootFiles, '');
}

async function scanNestedArchive(state, buffer, virtualPath, depth) {
  const extension = extensionFor(virtualPath);
  if (extension === '.asar') await scanAsarBuffer(state, buffer, virtualPath, depth);
  else if (ZIP_EXTENSIONS.has(extension)) await scanZipBuffer(state, buffer, virtualPath, depth);
}

async function scanInstallerStaging(state, installerPath, virtualPath, depth) {
  const parent = path.dirname(installerPath);
  const candidates = ['win-unpacked', 'win-arm64-unpacked'].map((name) => path.join(parent, name));
  let found = false;
  for (const candidate of candidates) {
    const info = await lstat(candidate).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (info === null) continue;
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new ArtifactScanError(`Installer-Staging ist kein reguläres Verzeichnis: ${candidate}`);
    }
    found = true;
    await walkFilesystem(
      state,
      candidate,
      `${virtualPath}!/${path.basename(candidate)}`,
      depth + 1,
    );
  }
  if (!found) {
    throw new ArtifactScanError(
      `NSIS-Installer kann ohne reproduzierbares win-unpacked-Staging nicht inhaltlich geprüft werden: ${installerPath}`,
    );
  }
}

async function scanRegularFile(state, filePath, virtualPath, size, depth) {
  if (size > state.limits.maxFileBytes) {
    throw new ArtifactScanError(`Datei ist zu groß für einen sicheren Scan: ${virtualPath}`);
  }
  registerFile(state, virtualPath);
  const extension = extensionFor(filePath);
  if (extension === '.asar') {
    if (size > state.limits.maxNestedArchiveBytes) {
      throw new ArtifactScanError(`ASAR ist zu groß für einen sicheren Scan: ${virtualPath}`);
    }
    const contents = await readFile(filePath);
    scanBufferContents(state, contents, virtualPath);
    inspectRuntimeArtifactContents(virtualPath, contents);
    await scanAsarBuffer(state, contents, virtualPath, depth + 1);
    return;
  }

  await scanReadable(state, createReadStream(filePath), virtualPath, false);
  if (ZIP_EXTENSIONS.has(extension)) {
    await scanZipPath(state, filePath, virtualPath, depth + 1);
    return;
  }
  if (extension === '.exe' && /-setup\.exe$/iu.test(path.basename(filePath))) {
    let zipFile = null;
    try {
      zipFile = await openZipFile(filePath);
    } catch {
      // NSIS is not a ZIP. Its exact electron-builder staging tree is scanned below.
    }
    if (zipFile === null) await scanInstallerStaging(state, filePath, virtualPath, depth);
    else await scanZipEntries(state, zipFile, virtualPath, depth + 1);
  }
}

async function walkFilesystem(state, filePath, virtualPath = path.resolve(filePath), depth = 0) {
  const resolved = path.resolve(filePath);
  const key = pathKey(resolved);
  if (state.seenFilesystem.has(key)) return;
  state.seenFilesystem.add(key);
  const info = await lstat(resolved).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (info === null) return;
  if (info.isSymbolicLink()) {
    throw new ArtifactScanError(
      `Symbolische Verknüpfung im Artefakt ist unzulässig: ${virtualPath}`,
    );
  }
  scanVirtualPath(state, virtualPath);
  if (info.isDirectory()) {
    const entries = (await readdir(resolved)).sort((left, right) => left.localeCompare(right));
    for (const entry of entries) {
      await walkFilesystem(state, path.join(resolved, entry), `${virtualPath}/${entry}`, depth);
    }
    return;
  }
  if (!info.isFile()) {
    throw new ArtifactScanError(`Artefakt enthält einen nicht regulären Dateityp: ${virtualPath}`);
  }
  await scanRegularFile(state, resolved, virtualPath, info.size, depth);
}

export async function scanArtifacts(targets, options = {}) {
  const forbiddenTexts = options.forbiddenTexts ?? DEFAULT_FORBIDDEN_TEXTS;
  if (!Array.isArray(forbiddenTexts) || forbiddenTexts.some((value) => typeof value !== 'string')) {
    throw new TypeError('forbiddenTexts muss eine Liste von Zeichenketten sein.');
  }
  const limits = { ...DEFAULT_LIMITS, ...(options.limits ?? {}) };
  const patterns = createPatterns(forbiddenTexts);
  const state = {
    filesScanned: 0,
    findings: new Set(),
    forbiddenTexts,
    limits,
    maxPatternBytes: Math.max(1, ...patterns.map((pattern) => pattern.bytes.length)),
    patterns,
    seenFilesystem: new Set(),
    totalBytes: 0,
  };
  for (const target of targets) await walkFilesystem(state, path.resolve(target));
  if (state.filesScanned === 0) {
    throw new ArtifactScanError('Keines der angegebenen Artefakte enthält prüfbare Dateien.');
  }
  return {
    filesScanned: state.filesScanned,
    findings: [...state.findings].sort((left, right) => left.localeCompare(right)),
    totalBytes: state.totalBytes,
  };
}
