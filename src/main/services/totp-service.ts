import { createHmac, timingSafeEqual } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type { TotpCode, TotpConfiguration } from '../../shared/models';

export interface TotpVerificationOptions {
  at?: Date | number;
  window?: number;
}

export class TotpService {
  public getCode(config: TotpConfiguration, at: Date | number = Date.now()): TotpCode {
    validateConfiguration(config);
    const seconds = Math.floor(toEpochMilliseconds(at) / 1_000);
    const counter = Math.floor(seconds / config.period);
    const elapsed = seconds % config.period;

    return {
      code: generateHotp(config, counter),
      period: config.period,
      remainingSeconds: config.period - elapsed,
    };
  }

  public verify(
    config: TotpConfiguration,
    code: string,
    options: TotpVerificationOptions = {},
  ): boolean {
    validateConfiguration(config);
    if (!new RegExp(`^\\d{${config.digits}}$`, 'u').test(code)) return false;

    const window = options.window ?? 1;
    if (!Number.isInteger(window) || window < 0 || window > 10) {
      throw invalid('Das TOTP-Prueffenster ist ungueltig.');
    }

    const seconds = Math.floor(toEpochMilliseconds(options.at ?? Date.now()) / 1_000);
    const counter = Math.floor(seconds / config.period);
    const candidate = Buffer.from(code, 'utf8');
    for (let offset = -window; offset <= window; offset += 1) {
      const comparedCounter = counter + offset;
      if (comparedCounter < 0) continue;
      const expected = Buffer.from(generateHotp(config, comparedCounter), 'utf8');
      if (expected.length === candidate.length && timingSafeEqual(expected, candidate)) return true;
    }
    return false;
  }

  public parseOtpAuthUri(uri: string): TotpConfiguration {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw invalid('Der TOTP-Link ist ungueltig.');
    }
    if (parsed.protocol !== 'otpauth:' || parsed.hostname.toLowerCase() !== 'totp') {
      throw invalid('Nur TOTP-Links im otpauth-Format werden unterstuetzt.');
    }

    const label = decodeURIComponent(parsed.pathname.replace(/^\//u, ''));
    const separator = label.indexOf(':');
    const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : '';
    const account = (separator >= 0 ? label.slice(separator + 1) : label).trim();
    const secret = parsed.searchParams.get('secret') ?? '';
    const issuer = (parsed.searchParams.get('issuer') ?? labelIssuer).trim();
    const algorithm = (parsed.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
    const digits = Number.parseInt(parsed.searchParams.get('digits') ?? '6', 10);
    const period = Number.parseInt(parsed.searchParams.get('period') ?? '30', 10);

    if (algorithm !== 'SHA1' && algorithm !== 'SHA256' && algorithm !== 'SHA512') {
      throw invalid('Der TOTP-Algorithmus wird nicht unterstuetzt.');
    }
    if (digits !== 6 && digits !== 8) {
      throw invalid('TOTP-Codes muessen 6 oder 8 Stellen haben.');
    }

    const config: TotpConfiguration = {
      secret: normalizeSecret(secret),
      issuer,
      account,
      algorithm,
      digits,
      period,
    };
    validateConfiguration(config);
    return config;
  }

  public toOtpAuthUri(config: TotpConfiguration): string {
    validateConfiguration(config);
    const label = config.issuer.length > 0 ? `${config.issuer}:${config.account}` : config.account;
    const parameters = new URLSearchParams({
      secret: normalizeSecret(config.secret),
      algorithm: config.algorithm,
      digits: String(config.digits),
      period: String(config.period),
    });
    if (config.issuer.length > 0) parameters.set('issuer', config.issuer);
    return `otpauth://totp/${encodeURIComponent(label)}?${parameters.toString()}`;
  }
}

function generateHotp(config: TotpConfiguration, counter: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(config.algorithm.toLowerCase(), decodeBase32(config.secret))
    .update(counterBuffer)
    .digest();
  const finalByte = digest[digest.length - 1];
  if (finalByte === undefined) throw new Error('Leerer TOTP-Hash.');
  const offset = finalByte & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** config.digits).padStart(config.digits, '0');
}

function decodeBase32(input: string): Buffer {
  const secret = normalizeSecret(input);
  let bits = 0;
  let bitCount = 0;
  const output: number[] = [];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  for (const character of secret) {
    const value = alphabet.indexOf(character);
    if (value < 0) throw invalid('Das TOTP-Geheimnis ist kein gueltiges Base32.');
    bits = (bits << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      output.push((bits >>> bitCount) & 0xff);
    }
  }
  if (output.length === 0) throw invalid('Das TOTP-Geheimnis ist leer.');
  return Buffer.from(output);
}

function normalizeSecret(secret: string): string {
  const normalized = secret.toUpperCase().replace(/[\s=-]/gu, '');
  if (!/^[A-Z2-7]+$/u.test(normalized)) {
    throw invalid('Das TOTP-Geheimnis ist kein gueltiges Base32.');
  }
  return normalized;
}

function validateConfiguration(config: TotpConfiguration): void {
  normalizeSecret(config.secret);
  if (!['SHA1', 'SHA256', 'SHA512'].includes(config.algorithm)) {
    throw invalid('Der TOTP-Algorithmus wird nicht unterstuetzt.');
  }
  if (config.digits !== 6 && config.digits !== 8) {
    throw invalid('TOTP-Codes muessen 6 oder 8 Stellen haben.');
  }
  if (!Number.isInteger(config.period) || config.period < 5 || config.period > 300) {
    throw invalid('Die TOTP-Periode muss zwischen 5 und 300 Sekunden liegen.');
  }
  if (config.account.trim().length === 0) throw invalid('Ein TOTP-Kontoname ist erforderlich.');
}

function toEpochMilliseconds(value: Date | number): number {
  const milliseconds = value instanceof Date ? value.getTime() : value;
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw invalid('Der TOTP-Zeitpunkt ist ungueltig.');
  }
  return milliseconds;
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
