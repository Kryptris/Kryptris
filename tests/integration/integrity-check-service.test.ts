import { mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { KeyDerivationService } from '../../src/main/security/key-derivation';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { AuditService } from '../../src/main/services/audit-service';
import { IntegrityCheckService } from '../../src/main/services/integrity-check-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { VaultService } from '../../src/main/services/vault-service';
import { VaultaError } from '../../src/shared/errors';
import type { AttachmentMetadata, EntryInput, VaultEntry } from '../../src/shared/models';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};
const roots: string[] = [];

interface Fixture {
  readonly root: string;
  readonly profile: ProfileService;
  readonly vaults: VaultService;
  readonly attachments: AttachmentService;
  readonly audit: AuditService;
  readonly vaultId: string;
  readonly entry: VaultEntry;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('Vollständiger Integritätskern', () => {
  it('prüft reale Profil-, Vault-, Audit- und Attachmentcontainer und umgeht den Vaultcache', async () => {
    const current = await fixture();
    const source = path.join(current.root, 'source.bin');
    await writeFile(source, Buffer.from('integrity-chunk-canary-'.repeat(1_200)));
    const metadata = await current.attachments.encryptFile({
      vaultId: current.vaultId,
      sourcePath: source,
      attachmentId: 'attachment-valid',
      mediaType: 'application/octet-stream',
    });
    await attach(current, metadata);
    await current.audit.record({ type: 'attachment-added', vaultId: current.vaultId });
    const service = serviceFor(current);

    await expect(service.scan()).resolves.toMatchObject({
      success: true,
      scannedVaults: 1,
      scannedEntries: 1,
      scannedAttachments: 1,
      findings: [],
      networkUsed: false,
    });

    const cached = await current.vaults.readVault(current.vaultId);
    const vaultPath = path.join(current.root, 'vaults', `${current.vaultId}.vaulta`);
    const encrypted = await readFile(vaultPath);
    const handle = await open(vaultPath, 'r+');
    try {
      const offset = Math.floor(encrypted.length / 2);
      await handle.write(Buffer.from([encrypted[offset]! ^ 1]), 0, 1, offset);
    } finally {
      await handle.close();
    }

    expect(await current.vaults.readVault(current.vaultId)).toEqual(cached);
    const report = await service.scan();
    expect(report.success).toBe(false);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'vault-container-invalid', scope: 'vault' }),
    );
  });

  it('findet fehlende, verwaiste, beschädigte und vom Manifest abweichende Anhänge redigiert', async () => {
    const current = await fixture();
    const source = path.join(current.root, 'attachment-source.bin');
    await writeFile(source, Buffer.from('attachment-integrity-canary-'.repeat(1_000)));

    const missing = await current.attachments.encryptFile({
      vaultId: current.vaultId,
      attachmentId: 'attachment-missing',
      sourcePath: source,
    });
    await attach(current, missing);
    await current.attachments.remove(current.vaultId, missing.id);

    await current.attachments.encryptFile({
      vaultId: current.vaultId,
      attachmentId: 'technical-orphan-canary',
      sourcePath: source,
    });

    const mismatch = await current.attachments.encryptFile({
      vaultId: current.vaultId,
      attachmentId: 'attachment-mismatch',
      sourcePath: source,
    });
    await attach(current, { ...mismatch, size: mismatch.size + 1 });

    const corrupt = await current.attachments.encryptFile({
      vaultId: current.vaultId,
      attachmentId: 'attachment-corrupt',
      sourcePath: source,
    });
    await attach(current, corrupt);
    await corruptEncryptedFile(current.attachments.getEncryptedPath(current.vaultId, corrupt.id));

    const report = await serviceFor(current).scan();
    const codes = report.findings.map((finding) => finding.code);
    const serialized = JSON.stringify(report);

    expect(codes).toEqual(
      expect.arrayContaining([
        'attachment-missing',
        'attachment-orphan',
        'attachment-container-invalid',
        'attachment-metadata-mismatch',
      ]),
    );
    expect(report.scannedAttachments).toBe(3);
    expect(serialized).not.toContain('technical-orphan-canary');
    expect(serialized).not.toContain(mismatch.sha256);
    expect(serialized).not.toContain(source);
    expect(serialized).not.toContain('attachment-integrity-canary');
  });

  it('gibt zwischen echten Attachment-Chunks frei und priorisiert Abbruch vor Audit/Teilreport', async () => {
    const current = await fixture();
    const source = path.join(current.root, 'large-source.bin');
    await writeFile(source, Buffer.alloc(5 * 4_096, 0x5a));
    const metadata = await current.attachments.encryptFile({
      vaultId: current.vaultId,
      attachmentId: 'attachment-cancel',
      sourcePath: source,
    });
    await attach(current, metadata);
    const auditSpy = vi.spyOn(current.audit, 'inspectStoredDocumentFormatVersion');
    let yields = 0;
    const cancellation = new VaultaError('CANCELLED', 'Abgebrochen');

    await expect(
      serviceFor(current).scan({
        yieldControl: () => {
          yields += 1;
          return yields === 4 ? Promise.reject(cancellation) : Promise.resolve();
        },
      }),
    ).rejects.toBe(cancellation);

    expect(yields).toBe(4);
    expect(auditSpy).not.toHaveBeenCalled();
  });
});

async function fixture(): Promise<Fixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-integrity-'));
  roots.push(root);
  const profile = new ProfileService({
    rootDir: root,
    keyDerivation: new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    }),
  });
  const setup = await profile.beginSetup('Integritäts-Master-Passwort!123', false);
  await profile.completeSetup(setup.pendingId, {});
  const vaults = new VaultService({ rootDir: root, profileService: profile });
  const attachments = new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4_096,
  });
  const audit = new AuditService({ rootDir: root, profileService: profile });
  const vault = await vaults.createVault('Integrität', '#14B8A6');
  const entry = await vaults.createEntry(vault.id, entryInput());
  return { root, profile, vaults, attachments, audit, vaultId: vault.id, entry };
}

function serviceFor(current: Fixture): IntegrityCheckService {
  return new IntegrityCheckService({
    profile: current.profile,
    vaults: current.vaults,
    attachments: current.attachments,
    audit: current.audit,
    now: () => new Date('2026-07-26T16:00:00.000Z'),
  });
}

async function attach(current: Fixture, metadata: AttachmentMetadata): Promise<void> {
  await current.vaults.mutateVault(current.vaultId, (document) => {
    const entry = document.entries.find((candidate) => candidate.id === current.entry.id);
    if (entry === undefined) throw new Error('Integritäts-Fixture ohne Eintrag');
    entry.attachments.push(metadata);
  });
}

async function corruptEncryptedFile(target: string): Promise<void> {
  const encrypted = await readFile(target);
  const offset = Math.floor(encrypted.length / 2);
  const handle = await open(target, 'r+');
  try {
    await handle.write(Buffer.from([encrypted[offset]! ^ 1]), 0, 1, offset);
  } finally {
    await handle.close();
  }
}

function entryInput(): EntryInput {
  return {
    title: 'Integritäts-Zugang',
    folderId: null,
    tags: [],
    favorite: false,
    note: '',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: 'integrity@example.invalid',
        password: 'Integrity-Secret!123',
        websites: ['https://example.invalid'],
        appNames: [],
      },
    },
  };
}
