import type { IpcMain } from 'electron';
import { describe, expect, it, vi } from 'vitest';

const electronState = vi.hoisted(() => ({
  exposed: new Map<string, unknown>(),
  invokedChannels: [] as string[],
  eventChannels: [] as string[],
}));

const handlerState = vi.hoisted(() => ({
  channels: [] as string[],
}));

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: (key: string, value: unknown) => electronState.exposed.set(key, value),
  },
  ipcRenderer: {
    invoke: (channel: string) => {
      electronState.invokedChannels.push(channel);
      return Promise.resolve({ ok: true, value: undefined });
    },
    on: (channel: string) => {
      electronState.eventChannels.push(channel);
    },
    removeListener: () => undefined,
  },
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
    ];
    for (const unsubscribe of unsubscribers) unsubscribe();

    expectUniqueCoverage(Object.keys(IPC_REQUEST_SCHEMAS), requestChannels);
    expectUniqueCoverage(handlerState.channels, requestChannels);
    expectUniqueCoverage(electronState.invokedChannels, requestChannels);
    expectUniqueCoverage(electronState.eventChannels, eventChannels);
  });
});

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
