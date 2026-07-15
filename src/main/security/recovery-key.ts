import { randomInt } from 'node:crypto';

import type { RecoverySetup } from '../../shared/models';
import { VaultaError } from '../../shared/errors';
import { CryptoService } from './crypto-service';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PREFIX = 'VLT1';
const ENTROPY_BYTES = 32;
const CHECKSUM_BYTES = 4;
const GROUP_SIZE = 5;
const CONFIRMATION_GROUPS = 3;

export interface GeneratedRecoveryKey {
  setup: RecoverySetup;
  secret: Buffer;
}

function encodeBase32(input: Buffer): string {
  let bits = 0;
  let accumulator = 0;
  let output = '';

  for (const byte of input) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += ALPHABET[(accumulator >>> bits) & 31];
    }
  }
  if (bits > 0) output += ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

function decodeBase32(input: string): Buffer {
  let bits = 0;
  let accumulator = 0;
  const output: number[] = [];

  for (const rawCharacter of input) {
    const character =
      rawCharacter === 'O'
        ? '0'
        : rawCharacter === 'I' || rawCharacter === 'L'
          ? '1'
          : rawCharacter;
    const value = ALPHABET.indexOf(character);
    if (value < 0)
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.');
    accumulator = (accumulator << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }
  return Buffer.from(output);
}

export class RecoveryKeyService {
  public constructor(private readonly crypto = new CryptoService()) {}

  public generate(): GeneratedRecoveryKey {
    const secret = this.crypto.randomBytes(ENTROPY_BYTES);
    const checksum = this.checksum(secret);
    const encoded = encodeBase32(Buffer.concat([secret, checksum]));
    const groups = encoded.match(new RegExp(`.{1,${GROUP_SIZE}}`, 'g')) ?? [];
    const confirmationIndexes = this.pickConfirmationIndexes(groups.length);
    const displayKey = `${PREFIX}-${groups.join('-')}`;

    return {
      setup: { displayKey, groups: [...groups], confirmationIndexes },
      secret,
    };
  }

  public parse(displayKey: string): Buffer {
    const normalized = displayKey.trim().toUpperCase().replace(/[\s-]/g, '');
    if (!normalized.startsWith(PREFIX)) {
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.');
    }

    const encoded = normalized.slice(PREFIX.length);
    const decoded = decodeBase32(encoded);
    if (decoded.length !== ENTROPY_BYTES + CHECKSUM_BYTES) {
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.');
    }
    if (encodeBase32(decoded) !== encoded) {
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.');
    }
    const secret = Buffer.from(decoded.subarray(0, ENTROPY_BYTES));
    const checksum = decoded.subarray(ENTROPY_BYTES);
    if (!this.crypto.equals(checksum, this.checksum(secret))) {
      this.crypto.erase(secret);
      throw new VaultaError('AUTH_FAILED', 'Der Wiederherstellungsschlüssel ist ungültig.');
    }
    return secret;
  }

  public verifyConfirmation(setup: RecoverySetup, confirmation: Record<string, string>): boolean {
    return setup.confirmationIndexes.every((index) => {
      const supplied = confirmation[String(index)]?.trim().toUpperCase();
      return supplied !== undefined && supplied === setup.groups[index];
    });
  }

  private checksum(secret: Buffer): Buffer {
    return this.crypto
      .sha256(Buffer.concat([Buffer.from('vaulta:recovery:v1', 'utf8'), secret]))
      .subarray(0, CHECKSUM_BYTES);
  }

  private pickConfirmationIndexes(groupCount: number): number[] {
    const indexes = new Set<number>();
    while (indexes.size < Math.min(CONFIRMATION_GROUPS, groupCount)) {
      indexes.add(randomInt(groupCount));
    }
    return [...indexes].sort((left, right) => left - right);
  }
}
