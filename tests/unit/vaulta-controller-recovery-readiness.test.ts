import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { VaultaController } from '../../src/main/vaulta-controller';
import { VaultaError } from '../../src/shared/errors';

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
  dialog: {
    showOpenDialog: vi.fn(),
    showSaveDialog: vi.fn(),
  },
  nativeImage: { createFromPath: vi.fn() },
}));

interface AuthenticationHarness {
  begin(): number;
  complete(profileUnlocked: boolean, epoch: number): void;
}

const cleanup: Array<{ controller: VaultaController; rootDir: string }> = [];

afterEach(async () => {
  for (const fixture of cleanup) fixture.controller.dispose();
  await Promise.all(
    cleanup.splice(0).map((fixture) => rm(fixture.rootDir, { recursive: true, force: true })),
  );
  vi.restoreAllMocks();
});

describe('VaultaController Recovery-Bereitschaft', () => {
  it('zählt einen falschen Recovery-Key trotz fehlgeschlagenem Status-/Audit-Commit', async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), 'kryptris-controller-recovery-'));
    let profileUnlocked = true;
    const verifyRecoveryKey = vi.fn(() =>
      Promise.reject(new VaultaError('AUTH_FAILED', 'Generischer Authentifizierungsfehler.')),
    );
    const execute = vi.fn(() => Promise.reject(new Error('Synthetischer atomarer Commitfehler.')));
    const controller = new VaultaController({
      rootDir,
      version: 'test',
      getWindow: () =>
        ({
          isDestroyed: () => false,
          webContents: { send: vi.fn() },
          setContentProtection: vi.fn(),
        }) as never,
      getOrigin: () => 'https://vaulta.invalid',
      onStateChanged: vi.fn(),
      onLocked: vi.fn(),
      onClipboardCleared: vi.fn(),
      onBackgroundWarning: vi.fn(),
    });
    cleanup.push({ controller, rootDir });
    Reflect.set(controller, 'profile', {
      isUnlocked: () => profileUnlocked,
      lock: () => {
        profileUnlocked = false;
      },
      withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
      verifyRecoveryKey,
      prepareProtectedMetadataUpdates: vi.fn(() =>
        Promise.resolve({
          relativePath: 'profile.json',
          contents: Buffer.from('encrypted-profile-generation'),
          expectedSha256: null,
        }),
      ),
    });
    Reflect.set(controller, 'audit', {
      withExclusiveWrite: <T>(operation: () => Promise<T>) => operation(),
      prepareRecord: vi.fn(() =>
        Promise.resolve({
          events: [],
          relativePath: 'audit.vaulta',
          contents: Buffer.from('encrypted-audit-generation'),
          expectedSha256: null,
        }),
      ),
    });
    Reflect.set(controller, 'transactions', { execute });
    const authentication = Reflect.get(controller, 'authentication') as AuthenticationHarness;
    const epoch = authentication.begin();
    authentication.complete(profileUnlocked, epoch);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(
        controller.testRecoveryReadiness({
          recoveryKey: 'SYNTHETIC-RECOVERY-KEY-WITHOUT-REAL-SECRET',
        }),
      ).rejects.toThrow('Synthetischer atomarer Commitfehler.');
    }

    await expect(
      controller.testRecoveryReadiness({
        recoveryKey: 'SYNTHETIC-RECOVERY-KEY-WITHOUT-REAL-SECRET',
      }),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' });
    expect(verifyRecoveryKey).toHaveBeenCalledTimes(5);
    expect(execute).toHaveBeenCalledTimes(5);
  });
});
