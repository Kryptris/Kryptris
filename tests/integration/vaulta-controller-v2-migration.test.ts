import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type * as ProfileServiceModule from '../../src/main/services/profile-service';

const electronMocks = vi.hoisted(() => ({
  clipboard: {
    writeText: vi.fn(),
    readText: vi.fn(() => ''),
    clear: vi.fn(),
  },
}));

vi.mock('electron', () => ({
  clipboard: electronMocks.clipboard,
  desktopCapturer: { getSources: vi.fn(() => Promise.resolve([])) },
  dialog: { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
  nativeImage: { createFromPath: vi.fn() },
}));

/**
 * The controller creates its ProfileService internally. Keep this integration
 * test on the real profile implementation while using the deliberately small,
 * test-only Argon2id parameters also used by the storage integration suite.
 */
vi.mock('../../src/main/services/profile-service', async (importOriginal) => {
  const original = await importOriginal<typeof ProfileServiceModule>();
  const { KeyDerivationService } = await import('../../src/main/security/key-derivation');

  class TestProfileService extends original.ProfileService {
    public constructor(options: ConstructorParameters<typeof original.ProfileService>[0]) {
      super({
        ...options,
        keyDerivation: new KeyDerivationService({
          parameters: {
            algorithm: 'argon2id',
            memorySizeKiB: 64,
            iterations: 1,
            parallelism: 1,
            hashLength: 32,
          },
          allowUnsafeParametersForTests: true,
        }),
      });
    }
  }

  return { ...original, ProfileService: TestProfileService };
});

import type { EntryInput, VaultDocument, VaultDocumentV1 } from '../../src/shared/models';
import { AttachmentService } from '../../src/main/services/attachment-service';
import { FactorService } from '../../src/main/services/factor-service';
import {
  PersistentMigrationService,
  createVaultDocumentEmbeddedMigrationAdapter,
} from '../../src/main/services/persistent-migration-service';
import { ProfileService } from '../../src/main/services/profile-service';
import { TotpService } from '../../src/main/services/totp-service';
import { VaultService } from '../../src/main/services/vault-service';
import { AtomicFileWriter } from '../../src/main/storage/atomic-file';
import { EncryptedContainerCodec } from '../../src/main/storage/encrypted-container';
import { VaultaController } from '../../src/main/vaulta-controller';

const MASTER_PASSWORD = 'Synthetisches-Migrations-Masterpasswort!123';
const roots: string[] = [];

describe('VaultaController: V1-zu-V2-Migration beim Entsperren', () => {
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
    vi.restoreAllMocks();
  });

  it('migriert beim echten Entsperren mehrere Tresore, bewahrt Anhang und Faktor und bleibt idempotent', async () => {
    const fixture = await createLegacyFixture();
    const { controller, dispose } = createController(fixture.root);

    await expect(controller.initialize()).resolves.toMatchObject({ locked: true });
    await expect(unlock(controller, fixture.totpSecret)).resolves.toEqual({ status: 'unlocked' });

    const state = await controller.getState();
    expect(state).toMatchObject({ locked: false, factorStatus: { totpEnabled: true } });
    expect(state.vaults.map((vault) => vault.id).sort()).toEqual(
      [fixture.firstVaultId, fixture.secondVaultId].sort(),
    );
    const migratedVaults = controllerVaults(controller);
    migratedVaults.clearCachedDocuments();
    await expect(
      migratedVaults.inspectStoredDocumentFormatVersion(fixture.firstVaultId),
    ).resolves.toBe(2);
    await expect(
      migratedVaults.inspectStoredDocumentFormatVersion(fixture.secondVaultId),
    ).resolves.toBe(2);

    const firstDetail = await controller.getEntryDetail({
      vaultId: fixture.firstVaultId,
      entryId: fixture.firstEntryId,
    });
    const secondEntry = await controller.getEntryEditModel({
      vaultId: fixture.secondVaultId,
      entryId: fixture.secondEntryId,
    });
    expect(firstDetail.attachments).toEqual([
      expect.objectContaining({ id: fixture.attachmentId, sha256: fixture.attachmentSha256 }),
    ]);
    expect(firstDetail.lifecycle).toEqual(defaultLifecycle());
    expect(secondEntry.lifecycle).toEqual(defaultLifecycle());
    expect(await readFile(fixture.attachmentPath)).toEqual(fixture.attachmentBytes);
    expect(await controllerProfile(controller).getPublicFactorData()).toEqual(
      fixture.publicFactorData,
    );
    expect(await controllerProfile(controller).getProtectedMetadata('factors')).toEqual(
      fixture.protectedFactorData,
    );
    await expectMigrationArtifactsToExclude(fixture.root, fixture.canaries);

    const backupsAfterFirstUnlock = await migrationBackups(fixture.root);
    expect(backupsAfterFirstUnlock).toHaveLength(1);
    await controller.lock();
    await expect(unlock(controller, fixture.totpSecret)).resolves.toEqual({ status: 'unlocked' });
    expect(await migrationBackups(fixture.root)).toEqual(backupsAfterFirstUnlock);

    dispose();
  });

  it('rollt einen vor dem Controller-Start unterbrochenen Mehrtresor-Commit zurück und migriert danach sauber beim Entsperren', async () => {
    const fixture = await createLegacyFixture();
    await fixture.profile.unlock(MASTER_PASSWORD);
    const targets = new Set([fixture.firstLegacyPath, fixture.secondLegacyPath]);
    let replacements = 0;
    const interrupted = new PersistentMigrationService({
      rootDir: fixture.root,
      profileService: fixture.profile,
      atomicWriter: new AtomicFileWriter({
        afterReplace: (targetPath) => {
          if (!targets.has(targetPath)) return;
          replacements += 1;
          if (replacements === 1) throw new Error('Simulierter Controller-Migrationsabbruch');
        },
      }),
      embeddedInspectors: [createVaultDocumentEmbeddedMigrationAdapter(fixture.vaults)],
    });

    await expect(interrupted.migrate()).rejects.toThrow('Simulierter Controller-Migrationsabbruch');
    expect(replacements).toBe(1);
    await expectMigrationArtifactsToExclude(fixture.root, fixture.canaries);
    fixture.profile.lock();

    const { controller, dispose } = createController(fixture.root);
    await expect(controller.initialize()).resolves.toMatchObject({ locked: true });
    await expect(
      readdir(path.join(fixture.root, '.vaulta-migration-transaction')),
    ).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(unlock(controller, fixture.totpSecret)).resolves.toEqual({ status: 'unlocked' });

    const migratedVaults = controllerVaults(controller);
    migratedVaults.clearCachedDocuments();
    await expect(
      migratedVaults.inspectStoredDocumentFormatVersion(fixture.firstVaultId),
    ).resolves.toBe(2);
    await expect(
      migratedVaults.inspectStoredDocumentFormatVersion(fixture.secondVaultId),
    ).resolves.toBe(2);
    const first = await controller.getEntryEditModel({
      vaultId: fixture.firstVaultId,
      entryId: fixture.firstEntryId,
    });
    const second = await controller.getEntryEditModel({
      vaultId: fixture.secondVaultId,
      entryId: fixture.secondEntryId,
    });
    expect(first.lifecycle).toEqual(defaultLifecycle());
    expect(second.lifecycle).toEqual(defaultLifecycle());
    expect(await readFile(fixture.attachmentPath)).toEqual(fixture.attachmentBytes);
    await expectMigrationArtifactsToExclude(fixture.root, fixture.canaries);

    dispose();
  });

  it('lehnt eine Future-Version beim Controller-Entsperren vor Snapshot und Write ab', async () => {
    const fixture = await createLegacyFixture();
    await fixture.profile.unlock(MASTER_PASSWORD);
    const futurePath = vaultPath(fixture.root, fixture.firstVaultId);
    await fixture.vaults.withVaultKey(fixture.firstVaultId, async (key) => {
      await writeFile(
        futurePath,
        new EncryptedContainerCodec().encodeJson(
          { formatVersion: 3, id: fixture.firstVaultId },
          key,
          'vault',
          fixture.firstVaultId,
        ),
      );
    });
    fixture.vaults.clearCachedDocuments();
    const futureBytes = await readFile(futurePath);
    fixture.profile.lock();

    const { controller, dispose } = createController(fixture.root);
    await controller.initialize();
    await expect(unlock(controller, fixture.totpSecret)).rejects.toMatchObject({
      code: 'UNSUPPORTED_FORMAT',
    });
    expect(await readFile(futurePath)).toEqual(futureBytes);
    expect(await migrationBackups(fixture.root)).toEqual([]);

    dispose();
  });
});

interface LegacyFixture {
  readonly root: string;
  readonly profile: ProfileService;
  readonly vaults: VaultService;
  readonly firstVaultId: string;
  readonly secondVaultId: string;
  readonly firstEntryId: string;
  readonly secondEntryId: string;
  readonly attachmentId: string;
  readonly attachmentSha256: string;
  readonly attachmentPath: string;
  readonly attachmentBytes: Buffer;
  readonly publicFactorData: unknown;
  readonly protectedFactorData: unknown;
  readonly firstLegacyPath: string;
  readonly secondLegacyPath: string;
  readonly totpSecret: string;
  readonly canaries: readonly string[];
}

async function createLegacyFixture(): Promise<LegacyFixture> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vaulta-controller-v2-migration-'));
  roots.push(root);
  const profile = new ProfileService({ rootDir: root });
  const setup = await profile.beginSetup(MASTER_PASSWORD, false);
  await profile.completeSetup(setup.pendingId, {});

  const factorService = new FactorService({ profile, origin: () => 'https://vaulta.invalid' });
  const totpSetup = await factorService.beginTotpSetup(MASTER_PASSWORD);
  await factorService.completeTotpSetup(totpSetup.setupId, currentTotpCode(totpSetup.secret));

  const vaults = new VaultService({ rootDir: root, profileService: profile });
  const first = await vaults.createVault('Migration Privat', '#14b8a6');
  const second = await vaults.createVault('Migration Arbeit', '#334155');
  const firstEntry = await vaults.createEntry(
    first.id,
    credentialInput('Synthetischer Zugang A', 'Synthetisches-Geheimnis-A'),
  );
  const secondEntry = await vaults.createEntry(
    second.id,
    credentialInput('Synthetischer Zugang B', 'Synthetisches-Geheimnis-B'),
  );

  const sourcePath = path.join(root, 'nur-synthetischer-anhang.txt');
  const attachmentCanary = 'Synthetischer-Anhangsinhalt';
  await writeFile(sourcePath, attachmentCanary, 'utf8');
  const attachment = await new AttachmentService({
    rootDir: root,
    vaultService: vaults,
    chunkSize: 4096,
  }).encryptFile({ vaultId: first.id, sourcePath });
  await rm(sourcePath, { force: true });
  await vaults.mutateVault(first.id, (document) => {
    const entry = document.entries.find((candidate) => candidate.id === firstEntry.id);
    if (entry === undefined) throw new Error('Der erste Testeintrag fehlt.');
    entry.attachments.push(attachment);
  });

  const attachmentPath = path.join(root, 'attachments', first.id, `${attachment.id}.vatt`);
  const attachmentBytes = await readFile(attachmentPath);
  const firstLegacy = await installLegacyDocument(vaults, root, first.id);
  const secondLegacy = await installLegacyDocument(vaults, root, second.id);
  const publicFactorData = await profile.getPublicFactorData<unknown>();
  const protectedFactorData = await profile.getProtectedMetadata<unknown>('factors');

  return {
    root,
    profile,
    vaults,
    firstVaultId: first.id,
    secondVaultId: second.id,
    firstEntryId: firstEntry.id,
    secondEntryId: secondEntry.id,
    attachmentId: attachment.id,
    attachmentSha256: attachment.sha256,
    attachmentPath,
    attachmentBytes,
    publicFactorData,
    protectedFactorData,
    firstLegacyPath: firstLegacy.filePath,
    secondLegacyPath: secondLegacy.filePath,
    totpSecret: totpSetup.secret,
    canaries: [
      'Synthetisches-Geheimnis-A',
      'Synthetisches-Geheimnis-B',
      'Synthetischer Zugang A',
      'Synthetischer Zugang B',
      attachmentCanary,
      totpSetup.secret,
    ],
  };
}

function createController(root: string): { controller: VaultaController; dispose: () => void } {
  const controller = new VaultaController({
    rootDir: root,
    version: 'test',
    getWindow: () =>
      ({
        isDestroyed: () => false,
        setContentProtection: vi.fn(),
        webContents: { send: vi.fn() },
      }) as never,
    getOrigin: () => 'https://vaulta.invalid',
    onStateChanged: vi.fn(),
    onLocked: vi.fn(),
    onClipboardCleared: vi.fn(),
    onBackgroundWarning: vi.fn(),
  });
  return { controller, dispose: () => controller.dispose() };
}

function unlock(controller: VaultaController, totpSecret: string) {
  return controller.unlock({
    masterPassword: MASTER_PASSWORD,
    totpCode: currentTotpCode(totpSecret),
  });
}

function controllerProfile(controller: VaultaController): ProfileService {
  return Reflect.get(controller, 'profile') as ProfileService;
}

function controllerVaults(controller: VaultaController): VaultService {
  return Reflect.get(controller, 'vaults') as VaultService;
}

function currentTotpCode(secret: string): string {
  return new TotpService().getCode({
    secret,
    issuer: 'Vaulta',
    account: 'Lokales Profil',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  }).code;
}

async function installLegacyDocument(
  vaults: VaultService,
  root: string,
  vaultId: string,
): Promise<{ filePath: string }> {
  const document = await vaults.readVault(vaultId);
  const legacy = toLegacyDocument(document);
  const filePath = vaultPath(root, vaultId);
  await vaults.withVaultKey(vaultId, async (key) => {
    await writeFile(
      filePath,
      new EncryptedContainerCodec().encodeJson(legacy, key, 'vault', vaultId),
    );
  });
  vaults.clearCachedDocuments();
  return { filePath };
}

function toLegacyDocument(document: VaultDocument): VaultDocumentV1 {
  return {
    formatVersion: 1,
    id: document.id,
    name: document.name,
    color: document.color,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
    folders: structuredClone(document.folders),
    entries: document.entries.map(({ lifecycle: ignoredLifecycle, ...entry }) => {
      void ignoredLifecycle;
      return structuredClone(entry);
    }),
  };
}

function credentialInput(title: string, password: string): EntryInput {
  return {
    title,
    folderId: null,
    tags: ['Migration'],
    favorite: false,
    note: 'Synthetischer Fachwert',
    customFields: [],
    data: {
      type: 'credential',
      value: {
        username: `${title.toLowerCase().replaceAll(' ', '.')}@example.invalid`,
        password,
        websites: ['https://example.invalid'],
        appNames: [],
      },
    },
  };
}

function defaultLifecycle() {
  return {
    rotationIntervalDays: null,
    nextRotationDate: null,
    rotationExcluded: false,
    twoFactorStatus: 'unknown',
    expiryReminderDate: null,
  };
}

async function expectMigrationArtifactsToExclude(
  root: string,
  canaries: readonly string[],
): Promise<void> {
  for (const directory of ['.vaulta-migration-transaction', 'migration-backups']) {
    const files = await readdir(path.join(root, directory)).catch(
      (error: NodeJS.ErrnoException): string[] => {
        if (error.code === 'ENOENT') return [];
        throw error;
      },
    );
    for (const fileName of files) {
      const bytes = await readFile(path.join(root, directory, fileName));
      for (const canary of canaries) {
        expect(bytes.includes(Buffer.from(canary, 'utf8'))).toBe(false);
      }
    }
  }
}

function vaultPath(root: string, vaultId: string): string {
  return path.join(root, 'vaults', `${vaultId}.vaulta`);
}

async function migrationBackups(root: string): Promise<string[]> {
  return readdir(path.join(root, 'migration-backups')).catch(
    (error: NodeJS.ErrnoException): string[] => {
      if (error.code === 'ENOENT') return [];
      throw error;
    },
  );
}
