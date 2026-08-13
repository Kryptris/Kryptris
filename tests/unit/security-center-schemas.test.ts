import { describe, expect, it } from 'vitest';

import { IPC_CHANNELS } from '../../src/shared/ipc';
import { IPC_REQUEST_SCHEMAS } from '../../src/shared/schemas';

const requestId = '00000000-0000-4000-8000-000000000001';
const recoveryKey = 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567';

describe('Schemas der Sicherheitszentrale', () => {
  it('akzeptiert nur strikt begrenzte Jobanfragen', () => {
    for (const channel of [
      IPC_CHANNELS.securityCenterScan,
      IPC_CHANNELS.securityIntegrityScan,
      IPC_CHANNELS.securityBreachScan,
    ]) {
      const schema = IPC_REQUEST_SCHEMAS[channel]!;
      expect(schema.safeParse({ requestId, refresh: true }).success).toBe(true);
      expect(schema.safeParse({ requestId, refresh: false, extra: true }).success).toBe(false);
      expect(schema.safeParse({ requestId: 'nicht-technisch' }).success).toBe(false);
    }
  });

  it('begrenzt den Recovery-Key und verwirft unbekannte Felder', () => {
    const schema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.securityRecoveryTest]!;
    expect(schema.safeParse({ recoveryKey }).success).toBe(true);
    expect(schema.safeParse({ recoveryKey: 'zu-kurz' }).success).toBe(false);
    expect(schema.safeParse({ recoveryKey, masterPassword: 'nicht erlaubt' }).success).toBe(false);
  });

  it('nimmt beim Leaklistenimport nur Quelle und echtes Datum, niemals einen Pfad an', () => {
    const schema = IPC_REQUEST_SCHEMAS[IPC_CHANNELS.securityBreachImport]!;
    expect(
      schema.safeParse({
        requestId,
        sourceLabel: 'Lokaler SHA-1-Testbestand',
        sourceDate: '2026-07-25',
      }).success,
    ).toBe(true);
    expect(
      schema.safeParse({
        requestId,
        sourceLabel: 'Liste',
        sourceDate: 'gestern',
      }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        requestId,
        sourceLabel: 'Liste',
        sourceDate: '2026-07-25',
        path: 'C:\\Geheim\\liste.txt',
      }).success,
    ).toBe(false);
  });
});
