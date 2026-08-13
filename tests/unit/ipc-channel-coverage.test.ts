// @vitest-environment jsdom
import type { IpcMain } from 'electron';
import { afterEach, describe, expect, it, vi } from 'vitest';

const electronState = vi.hoisted(() => ({
  exposed: new Map<string, unknown>(),
  invokedChannels: [] as string[],
  invocations: [] as Array<{ channel: string; input: unknown }>,
  eventChannels: [] as string[],
  eventListeners: new Map<string, Set<(...args: unknown[]) => void>>(),
  getPathForFile: vi.fn(() => 'C:\\Import\\synthetic-import.csv'),
}));

const handlerState = vi.hoisted(() => ({
  channels: [] as string[],
}));

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: (key: string, value: unknown) => electronState.exposed.set(key, value),
  },
  ipcRenderer: {
    invoke: (channel: string, input: unknown) => {
      electronState.invokedChannels.push(channel);
      electronState.invocations.push({ channel, input });
      return Promise.resolve({ ok: true, value: undefined });
    },
    on: (channel: string, listener: (...args: unknown[]) => void) => {
      electronState.eventChannels.push(channel);
      const listeners = electronState.eventListeners.get(channel) ?? new Set();
      listeners.add(listener);
      electronState.eventListeners.set(channel, listeners);
    },
    removeListener: (channel: string, listener: (...args: unknown[]) => void) => {
      electronState.eventListeners.get(channel)?.delete(listener);
    },
  },
  webUtils: { getPathForFile: electronState.getPathForFile },
}));

vi.mock('../../src/main/ipc/safe-handler', () => ({
  registerSafeHandler: (_context: unknown, channel: string) => {
    handlerState.channels.push(channel);
  },
}));

import { registerIpcHandlers } from '../../src/main/ipc/register-handlers';
import type { VaultaController } from '../../src/main/vaulta-controller';
import '../../src/preload/index';
import { IPC_CHANNELS, type VaultaApi } from '../../src/shared/ipc';
import { IPC_REQUEST_SCHEMAS } from '../../src/shared/schemas';

afterEach(() => {
  vi.useRealTimers();
  document.body.replaceChildren();
});

describe('IPC-Kanalabdeckung', () => {
  it('deckt jeden Request-Kanal in Schema, Handler und Preload exakt einmal ab', async () => {
    const eventChannels = Object.values(IPC_CHANNELS).filter((channel) =>
      channel.startsWith('vaulta:event:'),
    );
    const requestChannels = Object.values(IPC_CHANNELS).filter(
      (channel) => !channel.startsWith('vaulta:event:'),
    );

    handlerState.channels.length = 0;
    registerIpcHandlers({
      ipcMain: {} as IpcMain,
      controller: new Proxy({}, { get: () => () => undefined }) as VaultaController,
      getWindow: () => null,
      getAllowedOrigin: () => 'http://localhost:4173',
    });

    const exposed = electronState.exposed.get('vaulta');
    expect(exposed).toBeDefined();
    const api = exposed as VaultaApi;
    electronState.invokedChannels.length = 0;
    electronState.eventChannels.length = 0;

    const invokeGroups = [
      api.system,
      api.setup,
      api.auth,
      api.vaults,
      api.entries,
      api.attachments,
      api.generator,
      api.totp,
      api.security,
      api.backup,
      api.transfer,
      api.audit,
      api.settings,
      api.factors,
      api.templates,
      api.reports,
      api.productivity,
      api.quality,
      api.window,
    ] as const;
    for (const group of invokeGroups) {
      for (const method of callableValues(group)) {
        await Reflect.apply(method, group, [undefined]);
      }
    }

    const unsubscribers = [
      api.events.onLocked(() => undefined),
      api.events.onStateChanged(() => undefined),
      api.events.onClipboardCleared(() => undefined),
      api.events.onBackgroundWarning(() => undefined),
      api.events.onLocalJobProgress(() => undefined),
    ];
    for (const unsubscribe of unsubscribers) unsubscribe();

    expectUniqueCoverage(Object.keys(IPC_REQUEST_SCHEMAS), requestChannels);
    expectUniqueCoverage(handlerState.channels, requestChannels);
    expectUniqueCoverage(electronState.invokedChannels, requestChannels);
    expectUniqueCoverage(electronState.eventChannels, eventChannels);
  });

  it('stellt Tresor-Pakete nur über die expliziten, pfadlosen Preload-Operationen bereit', async () => {
    const exposed = electronState.exposed.get('vaulta');
    expect(exposed).toBeDefined();
    const api = exposed as VaultaApi;
    electronState.invokedChannels.length = 0;

    await api.transfer.exportVaultPackage({
      vaultId: '00000000-0000-4000-8000-000000000701',
      exportPassword: 'Synthetisches-Paketpasswort-701',
      includeAttachments: true,
    });
    await api.transfer.previewVaultPackage({
      exportPassword: 'Synthetisches-Paketpasswort-701',
    });
    await api.transfer.importVaultPackage({
      token: '00000000-0000-4000-8000-000000000702',
      exportPassword: 'Synthetisches-Paketpasswort-701',
      targetVaultName: 'Anonymisierter Ziel-Tresor',
      allowNameConflict: false,
    });

    expect(electronState.invokedChannels).toEqual([
      IPC_CHANNELS.vaultPackageExport,
      IPC_CHANNELS.vaultPackagePreviewImport,
      IPC_CHANNELS.vaultPackageImport,
    ]);
    const previewSchema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.vaultPackagePreviewImport];
    const importSchema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.vaultPackageImport];
    if (previewSchema === undefined || importSchema === undefined) {
      throw new Error('Die Paket-IPC-Schemas fehlen.');
    }
    expect(
      previewSchema.safeParse({
        exportPassword: 'Synthetisches-Paketpasswort-701',
        packagePath: 'C:\\renderer-darf-diesen-pfad-nicht-senden.kryptris-vault',
      }).success,
    ).toBe(false);
    expect(
      importSchema.safeParse({
        token: '00000000-0000-4000-8000-000000000702',
        exportPassword: 'Synthetisches-Paketpasswort-701',
        targetVaultName: 'Anonymisierter Ziel-Tresor',
        allowNameConflict: false,
        packagePath: 'C:\\renderer-darf-diesen-pfad-nicht-senden.kryptris-vault',
      }).success,
    ).toBe(false);
  });

  it('behaelt Drag-and-drop-Pfade im Preload, verbraucht Tokens einmalig und verwirft sie beim Sperren', async () => {
    const exposed = electronState.exposed.get('vaulta');
    expect(exposed).toBeDefined();
    const api = exposed as VaultaApi;
    const vaultId = '00000000-0000-4000-8000-000000000703';
    const target = document.createElement('div');
    target.setAttribute('data-vaulta-import-drop-target', '');
    document.body.append(target);

    const drops: Array<{ token: string }> = [];
    const unsubscribe = api.transfer.onDroppedImport((drop) => drops.push(drop));
    const drop = createSingleFileDrop();
    target.dispatchEvent(drop);
    expect(drop.defaultPrevented).toBe(true);
    expect(drops).toHaveLength(1);

    const token = drops[0]?.token;
    if (token === undefined) throw new Error('Der Preload hat keinen Importtoken erzeugt.');
    electronState.invokedChannels.length = 0;
    electronState.invocations.length = 0;
    const forgedRendererInput = {
      token,
      vaultId,
      sourcePath: 'C:\\Renderer-darf-diesen-Pfad-nicht-setzen.csv',
    };
    await api.transfer.previewDroppedImport(forgedRendererInput);
    expect(electronState.invokedChannels).toEqual([IPC_CHANNELS.importPreviewDropped]);
    expect(electronState.invocations[0]).toEqual({
      channel: IPC_CHANNELS.importPreviewDropped,
      input: { vaultId, sourcePath: 'C:\\Import\\synthetic-import.csv' },
    });
    expect(JSON.stringify(electronState.invocations[0]?.input)).not.toContain('Renderer-darf');

    await api.transfer.previewDroppedImport({ token, vaultId });
    expect(electronState.invocations[1]).toEqual({
      channel: IPC_CHANNELS.importPreviewDropped,
      input: { vaultId, sourcePath: '' },
    });

    vi.useFakeTimers();
    target.dispatchEvent(createSingleFileDrop());
    const expiredToken = drops[1]?.token;
    if (expiredToken === undefined) throw new Error('Der ablaufende Importtoken fehlt.');
    vi.advanceTimersByTime(60_001);
    await api.transfer.previewDroppedImport({ token: expiredToken, vaultId });
    expect(electronState.invocations[2]).toEqual({
      channel: IPC_CHANNELS.importPreviewDropped,
      input: { vaultId, sourcePath: '' },
    });

    target.dispatchEvent(createSingleFileDrop());
    const lockedToken = drops[2]?.token;
    if (lockedToken === undefined) throw new Error('Der zu sperrende Importtoken fehlt.');
    emitRendererEvent(IPC_CHANNELS.eventLocked);
    await api.transfer.previewDroppedImport({ token: lockedToken, vaultId });
    expect(electronState.invocations[3]).toEqual({
      channel: IPC_CHANNELS.importPreviewDropped,
      input: { vaultId, sourcePath: '' },
    });

    const droppedPreviewSchema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.importPreviewDropped];
    if (droppedPreviewSchema === undefined) throw new Error('Das Drag-and-drop-IPC-Schema fehlt.');
    expect(droppedPreviewSchema.safeParse({ vaultId }).success).toBe(false);
    expect(
      droppedPreviewSchema.safeParse({
        vaultId,
        token,
        sourcePath: 'C:\\Import\\synthetic-import.csv',
      }).success,
    ).toBe(false);
    unsubscribe();
  });
});

function createSingleFileDrop(): Event {
  const file = new File(['synthetic-import'], 'synthetic-import.csv', { type: 'text/csv' });
  const event = new Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'dataTransfer', {
    configurable: true,
    value: {
      files: { length: 1, item: (index: number) => (index === 0 ? file : null) },
      types: ['Files'],
    },
  });
  return event;
}

function emitRendererEvent(channel: string): void {
  for (const listener of electronState.eventListeners.get(channel) ?? []) listener({}, undefined);
}

function expectUniqueCoverage(actual: readonly string[], expected: readonly string[]): void {
  expect([...new Set(actual)].sort()).toEqual([...expected].sort());
  expect(actual).toHaveLength(expected.length);
}

function callableValues(value: object): Array<(...args: unknown[]) => unknown> {
  return Object.keys(value).map((key) => {
    const candidate = Reflect.get(value, key) as unknown;
    if (typeof candidate !== 'function')
      throw new Error(`Preload-Eigenschaft ist keine Funktion: ${key}`);
    return candidate as (...args: unknown[]) => unknown;
  });
}
