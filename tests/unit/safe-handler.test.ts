import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { registerSafeHandler } from '../../src/main/ipc/safe-handler';
import type { IpcResult } from '../../src/shared/ipc';

type RegisteredHandler = (
  event: IpcMainInvokeEvent,
  input: unknown,
) => Promise<IpcResult<{ echoed: string }>>;

describe('registerSafeHandler', () => {
  it('validiert Fenster, Origin und Eingabe vor dem Handler-Aufruf', async () => {
    const harness = createHarness();
    const handler = vi.fn((input: { value: string }) => ({ echoed: input.value }));
    registerSafeHandler(
      harness.context,
      'vaulta:test',
      z.object({ value: z.string().max(20) }).strict(),
      handler,
    );

    await expect(harness.invoke(harness.event, { value: 'lokal' })).resolves.toEqual({
      ok: true,
      value: { echoed: 'lokal' },
    });
    expect(handler).toHaveBeenCalledOnce();
  });

  it('weist fremde WebContents, Subframes und Origins ab', async () => {
    const harness = createHarness();
    registerSafeHandler(
      harness.context,
      'vaulta:test',
      z.object({ value: z.string() }),
      ({ value }) => ({ echoed: value }),
    );

    const foreignSender = harness.makeEvent({ senderId: 99 });
    const subframe = harness.makeEvent({ subframe: true });
    const foreignOrigin = harness.makeEvent({ url: 'https://evil.example/path' });
    for (const event of [foreignSender, subframe, foreignOrigin]) {
      const result = await harness.invoke(event, { value: 'x' });
      expect(result).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });
    }
  });

  it('gibt weder Zod-Details noch interne Fehlertexte an den Renderer weiter', async () => {
    const harness = createHarness();
    const secret = 'canary-interner-fehler';
    registerSafeHandler(
      harness.context,
      'vaulta:test',
      z.object({ value: z.string().max(3) }).strict(),
      () => {
        throw new Error(secret);
      },
    );

    const invalid = await harness.invoke(harness.event, { value: 'zu-lang', extra: secret });
    expect(invalid).toMatchObject({ ok: false, error: { code: 'INVALID_INPUT' } });
    expect(JSON.stringify(invalid)).not.toContain(secret);

    const internal = await harness.invoke(harness.event, { value: 'ok' });
    expect(internal).toMatchObject({ ok: false, error: { code: 'INTERNAL' } });
    expect(JSON.stringify(internal)).not.toContain(secret);
  });
});

function createHarness(): {
  context: {
    ipcMain: IpcMain;
    getWindow: () => BrowserWindow;
    getAllowedOrigin: () => string;
  };
  event: IpcMainInvokeEvent;
  invoke: RegisteredHandler;
  makeEvent: (options?: {
    senderId?: number;
    url?: string;
    subframe?: boolean;
  }) => IpcMainInvokeEvent;
} {
  const windowId = 7;
  let registered: RegisteredHandler | null = null;
  const ipcMain = {
    handle: (_channel: string, handler: RegisteredHandler) => {
      registered = handler;
    },
  } as unknown as IpcMain;
  const window = {
    isDestroyed: () => false,
    webContents: { id: windowId },
  } as unknown as BrowserWindow;
  const makeEvent = (
    options: { senderId?: number; url?: string; subframe?: boolean } = {},
  ): IpcMainInvokeEvent => {
    const mainFrame = { url: options.url ?? 'http://localhost:4173/index.html' };
    return {
      sender: { id: options.senderId ?? windowId, mainFrame },
      senderFrame: options.subframe ? { url: mainFrame.url } : mainFrame,
    } as unknown as IpcMainInvokeEvent;
  };
  const event = makeEvent();
  const context = {
    ipcMain,
    getWindow: () => window,
    getAllowedOrigin: () => 'http://localhost:4173',
  };
  registerSafeHandler(
    context,
    'vaulta:bootstrap',
    z.object({ value: z.string() }),
    ({ value }) => ({ echoed: value }),
  );
  if (registered === null) throw new Error('Der Testhandler wurde nicht registriert.');

  return {
    context,
    event,
    invoke: (invokeEvent, input) => {
      if (registered === null) throw new Error('Der Testhandler fehlt.');
      return registered(invokeEvent, input);
    },
    makeEvent,
  };
}
