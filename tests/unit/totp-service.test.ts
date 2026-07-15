import { describe, expect, it } from 'vitest';

import { TotpService } from '../../src/main/services/totp-service';
import type { TotpConfiguration } from '../../src/shared/models';

const vector: TotpConfiguration = {
  secret: toBase32('12345678901234567890'),
  issuer: 'RFC',
  account: 'test@example.de',
  algorithm: 'SHA1',
  digits: 8,
  period: 30,
};

describe('TotpService', () => {
  const service = new TotpService();

  it.each([
    {
      algorithm: 'SHA1' as const,
      secret: '12345678901234567890',
      expected: '94287082',
    },
    {
      algorithm: 'SHA256' as const,
      secret: '12345678901234567890123456789012',
      expected: '46119246',
    },
    {
      algorithm: 'SHA512' as const,
      secret: '1234567890123456789012345678901234567890123456789012345678901234',
      expected: '90693936',
    },
  ])('besteht den RFC-6238-Testvektor fuer $algorithm ohne Netzwerk', (testVector) => {
    const configuration: TotpConfiguration = {
      ...vector,
      algorithm: testVector.algorithm,
      secret: toBase32(testVector.secret),
    };
    const result = service.getCode(configuration, 59_000);
    expect(result).toEqual({
      code: testVector.expected,
      period: 30,
      remainingSeconds: 1,
    });
    expect(service.verify(configuration, result.code, { at: 59_000, window: 0 })).toBe(true);
  });

  it('liest und schreibt otpauth-Links', () => {
    const uri = service.toOtpAuthUri(vector);
    expect(service.parseOtpAuthUri(uri)).toEqual(vector);
  });

  it('lehnt ungueltige Seeds ab, ohne sie in der Fehlermeldung zu wiederholen', () => {
    const secret = 'nicht gueltig!';
    let thrown: unknown;
    try {
      service.getCode({ ...vector, secret });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    if (!(thrown instanceof Error)) throw new Error('Der erwartete Fehler fehlt.');
    expect(thrown.message).not.toContain(secret);
  });
});

function toBase32(input: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let accumulator = 0;
  let bitCount = 0;
  let encoded = '';

  for (const byte of Buffer.from(input, 'ascii')) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      encoded += alphabet[(accumulator >>> bitCount) & 0x1f];
    }
  }
  if (bitCount > 0) encoded += alphabet[(accumulator << (5 - bitCount)) & 0x1f];
  return encoded;
}
