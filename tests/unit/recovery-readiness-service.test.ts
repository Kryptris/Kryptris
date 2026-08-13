import { describe, expect, it } from 'vitest';

import { RecoveryReadinessService } from '../../src/main/services/recovery-readiness-service';
import { VaultaError } from '../../src/shared/errors';

const NOW = Date.parse('2026-07-26T12:00:00.000Z');
const DAY_MS = 24 * 60 * 60 * 1_000;

describe('RecoveryReadinessService', () => {
  it('persistiert ausschließlich Zeitpunkt und Erfolg und leitet alle Zustände ab', () => {
    const service = new RecoveryReadinessService({ now: () => NOW });
    const created = service.createRecord(true);

    expect(created).toEqual({
      testedAt: '2026-07-26T12:00:00.000Z',
      success: true,
    });
    expect(Object.keys(created).sort()).toEqual(['success', 'testedAt']);
    expect(service.status(false, created)).toEqual({
      state: 'not-configured',
      lastTestedAt: null,
      lastTestSucceeded: null,
      staleAfterDays: 180,
    });
    expect(service.status(true, null).state).toBe('never-tested');
    expect(service.status(true, created).state).toBe('ready');
    expect(
      service.status(true, {
        testedAt: new Date(NOW - 180 * DAY_MS).toISOString(),
        success: true,
      }).state,
    ).toBe('stale');
    expect(
      service.status(true, {
        testedAt: new Date(NOW - 1).toISOString(),
        success: false,
      }),
    ).toMatchObject({
      state: 'failed',
      lastTestSucceeded: false,
    });
  });

  it('parst alte fehlende Metadaten und lehnt beschädigte oder erweiterte Werte fail-closed ab', () => {
    const service = new RecoveryReadinessService({ now: () => NOW });

    expect(service.parseRecord(null)).toBeNull();
    expect(
      service.parseRecord({
        testedAt: '2026-07-26T12:00:00.000Z',
        success: true,
      }),
    ).toEqual({
      testedAt: '2026-07-26T12:00:00.000Z',
      success: true,
    });
    for (const invalid of [
      {},
      { testedAt: 'kein-datum', success: true },
      { testedAt: '2026-07-26T12:00:00.000Z', success: 'true' },
      {
        testedAt: '2026-07-26T12:00:00.000Z',
        success: true,
        recoveryKeyFragment: 'darf-nicht-gespeichert-werden',
      },
    ]) {
      expect(() => service.parseRecord(invalid)).toThrowError(
        expect.objectContaining({ code: 'CORRUPT_DATA' }),
      );
    }
  });

  it('lehnt parallele Tests ab, statt geheimnistragende Aufrufer zu puffern', async () => {
    const service = new RecoveryReadinessService({ now: () => NOW });
    let finish: ((value: string) => void) | undefined;
    const first = service.runAttempt(
      () =>
        new Promise<string>((resolve) => {
          finish = resolve;
        }),
    );

    await expect(service.runAttempt(() => Promise.resolve('zweiter'))).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    finish?.('erster');
    await expect(first).resolves.toBe('erster');
  });

  it('drosselt ausschließlich Authentifizierungsfehler exponentiell ab dem fünften Versuch', async () => {
    let now = 0;
    const service = new RecoveryReadinessService({ now: () => now });
    const fail = () =>
      service.runAttempt(() =>
        Promise.reject(new VaultaError('AUTH_FAILED', 'Generischer Authentifizierungsfehler.')),
      );

    await expect(
      service.runAttempt(() => Promise.reject(new VaultaError('LOCKED', 'Gesperrt.'))),
    ).rejects.toMatchObject({ code: 'LOCKED' });
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(fail()).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    }
    await expect(service.runAttempt(() => Promise.resolve('zu-früh'))).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    });

    let currentBackoffSeconds = 1;
    for (let failedAttempt = 6; failedAttempt <= 11; failedAttempt += 1) {
      now += currentBackoffSeconds * 1_000;
      await expect(fail()).rejects.toMatchObject({ code: 'AUTH_FAILED' });
      await expect(service.runAttempt(() => Promise.resolve('zu-früh'))).rejects.toMatchObject({
        code: 'AUTH_RATE_LIMITED',
      });
      currentBackoffSeconds = Math.min(60, currentBackoffSeconds * 2);
    }
    now += 59_999;
    await expect(service.runAttempt(() => Promise.resolve('noch-zu-früh'))).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    });
    now += 1;
    await expect(service.runAttempt(() => Promise.resolve('wieder-frei'))).resolves.toBe(
      'wieder-frei',
    );
  });

  it('zählt einen erkannten Fehlversuch auch bei einem anschließenden Commitfehler', async () => {
    const service = new RecoveryReadinessService({ now: () => 0 });

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(
        service.runAttempt((currentAttempt) => {
          currentAttempt.authenticationFailed();
          return Promise.reject(new Error('Synthetischer Status-Commitfehler.'));
        }),
      ).rejects.toThrow('Synthetischer Status-Commitfehler.');
    }

    await expect(service.runAttempt(() => Promise.resolve('zu-früh'))).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    });
  });

  it('setzt die Drosselung nach Erfolg oder Recovery-Rotation vollständig zurück', async () => {
    let now = 0;
    const service = new RecoveryReadinessService({ now: () => now });
    const fail = () =>
      service.runAttempt(() =>
        Promise.reject(new VaultaError('AUTH_FAILED', 'Generischer Authentifizierungsfehler.')),
      );

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(fail()).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    }
    now += 1_000;
    await expect(service.runAttempt(() => Promise.resolve(true))).resolves.toBe(true);
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      await expect(fail()).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    }
    await expect(service.runAttempt(() => Promise.resolve(true))).resolves.toBe(true);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(fail()).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    }
    service.resetAfterRecoveryRotation();
    await expect(service.runAttempt(() => Promise.resolve('rotiert'))).resolves.toBe('rotiert');
  });
});
