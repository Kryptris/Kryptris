import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { z } from 'zod';

import { toVaultaError, VaultaError } from '../../shared/errors';
import type { IpcResult } from '../../shared/ipc';

export interface SafeHandlerContext {
  ipcMain: IpcMain;
  getWindow: () => BrowserWindow | null;
  getAllowedOrigin: () => string;
}

function isTrustedSender(
  event: IpcMainInvokeEvent,
  getWindow: () => BrowserWindow | null,
  getAllowedOrigin: () => string,
): boolean {
  const window = getWindow();
  if (window === null || window.isDestroyed() || event.sender.id !== window.webContents.id)
    return false;
  if (event.senderFrame !== event.sender.mainFrame) return false;
  try {
    return new URL(event.senderFrame.url).origin === getAllowedOrigin();
  } catch {
    return false;
  }
}

export function registerSafeHandler<TInput, TOutput>(
  context: SafeHandlerContext,
  channel: string,
  schema: z.ZodType<TInput>,
  handler: (input: TInput, event: IpcMainInvokeEvent) => Promise<TOutput> | TOutput,
): void {
  context.ipcMain.handle(channel, async (event, rawInput: unknown): Promise<IpcResult<TOutput>> => {
    try {
      if (!isTrustedSender(event, context.getWindow, context.getAllowedOrigin)) {
        throw new VaultaError(
          'INVALID_INPUT',
          'Die Anfrage stammt nicht aus dem Vaulta-Hauptfenster.',
        );
      }
      const parsed = schema.safeParse(rawInput);
      if (!parsed.success) {
        throw new VaultaError(
          'INVALID_INPUT',
          'Die Anfrage enthält ungültige oder zu große Daten.',
          'Prüfe die Eingaben und versuche es erneut.',
        );
      }
      return { ok: true, value: await handler(parsed.data, event) };
    } catch (error) {
      return { ok: false, error: toVaultaError(error).serialize() };
    }
  });
}
