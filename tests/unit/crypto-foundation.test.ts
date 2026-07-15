import { describe, expect, it } from 'vitest';
import { argon2id } from 'hash-wasm';

import { VaultaError } from '../../src/shared/errors';
import { CryptoService } from '../../src/main/security/crypto-service';
import {
  KeyDerivationService,
  PRODUCT_ARGON2ID_PARAMETERS,
  PRODUCT_ARGON2_MEMORY_KIB,
  PRODUCT_ARGON2_TARGET_MS,
} from '../../src/main/security/key-derivation';
import { RecoveryKeyService } from '../../src/main/security/recovery-key';
import { EncryptedContainerCodec } from '../../src/main/storage/encrypted-container';

const TEST_PARAMETERS = {
  algorithm: 'argon2id' as const,
  memorySizeKiB: 64,
  iterations: 1,
  parallelism: 1,
  hashLength: 32 as const,
};

describe('Kryptografisches Fundament', () => {
  it('erzwingt im Produkt mindestens 256 MiB Argon2id-Speicher', () => {
    expect(PRODUCT_ARGON2_MEMORY_KIB).toBe(262_144);
    expect(() => new KeyDerivationService({ parameters: TEST_PARAMETERS })).toThrowError(
      VaultaError,
    );
  });

  it('erlaubt explizit injizierte niedrige Parameter ausschließlich für Tests', async () => {
    const derivation = new KeyDerivationService({
      parameters: TEST_PARAMETERS,
      allowUnsafeParametersForTests: true,
    });
    const first = await derivation.derive('ein langes Testpasswort', Buffer.alloc(16, 7));
    const second = await derivation.derive('ein langes Testpasswort', Buffer.alloc(16, 7));
    expect(first).toHaveLength(32);
    expect(first.equals(second)).toBe(true);
  });

  it('entspricht dem Argon2id-Referenzvektor für Version 19', async () => {
    const derived = await argon2id({
      password: 'password',
      salt: 'somesalt',
      memorySize: 65_536,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
      outputType: 'binary',
    });
    expect(Buffer.from(derived).toString('hex')).toBe(
      '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7',
    );
  }, 30_000);

  it('kalibriert die Iterationen geräteabhängig auf ungefähr eine Sekunde', async () => {
    const probes: number[] = [];
    const derivation = new KeyDerivationService({
      calibrationProbe: (parameters) => {
        probes.push(parameters.iterations);
        return Promise.resolve(240);
      },
    });
    const calibrated = await derivation.calibrate();
    const cached = await derivation.calibrate();

    expect(PRODUCT_ARGON2_TARGET_MS).toBe(1_000);
    expect(calibrated).toMatchObject({ memorySizeKiB: 262_144, iterations: 4 });
    expect(cached).toEqual(calibrated);
    expect(probes).toEqual([1]);
  });

  it('begrenzt manipulierte KDF-Parameter vor einer teuren Ableitung', () => {
    const derivation = new KeyDerivationService();
    for (const parameters of [
      { ...PRODUCT_ARGON2ID_PARAMETERS, iterations: 9 },
      { ...PRODUCT_ARGON2ID_PARAMETERS, memorySizeKiB: 512 * 1024 + 1 },
      { ...PRODUCT_ARGON2ID_PARAMETERS, parallelism: 5 },
    ]) {
      expect(() => derivation.validateParameters(parameters)).toThrowError(VaultaError);
    }
  });

  it('erkennt Manipulation und Kontexttausch an AES-GCM-Containern', () => {
    const crypto = new CryptoService();
    const codec = new EncryptedContainerCodec(crypto);
    const key = crypto.randomBytes(32);
    const encoded = codec.encodeJson({ secret: 'nicht im Klartext' }, key, 'vault', 'vault-a');
    expect(encoded.toString('utf8')).not.toContain('nicht im Klartext');
    expect(codec.decodeJson(encoded, key, 'vault', 'vault-a')).toEqual({
      secret: 'nicht im Klartext',
    });
    expect(() => codec.decodeJson(encoded, key, 'vault', 'vault-b')).toThrowError(VaultaError);

    const parsed = JSON.parse(encoded.toString('utf8')) as {
      payload: { ciphertext: string };
    };
    const ciphertext = Buffer.from(parsed.payload.ciphertext, 'base64');
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    parsed.payload.ciphertext = ciphertext.toString('base64');
    expect(() =>
      codec.decodeJson(Buffer.from(JSON.stringify(parsed)), key, 'vault', 'vault-a'),
    ).toThrowError(VaultaError);
  });

  it('entspricht bekannten HKDF-SHA-256- und AES-256-GCM-Vektoren', () => {
    const crypto = new CryptoService();
    const ikm = Buffer.from('0b'.repeat(22), 'hex');
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    expect(crypto.deriveKey(ikm, 'test-vector', salt).toString('hex')).toBe(
      'fbd72d7a0f0d7ff642bc8a2d27fc7f20b45447fa94bd22992dccb63f1d0bdcaa',
    );

    const envelope = crypto.encryptWithNonce(
      Buffer.alloc(16),
      Buffer.alloc(32),
      Buffer.alloc(0),
      Buffer.alloc(12),
    );
    expect(Buffer.from(envelope.ciphertext, 'base64').toString('hex')).toBe(
      'cea7403d4d606b6e074ec5d3baf39d18',
    );
    expect(Buffer.from(envelope.tag, 'base64').toString('hex')).toBe(
      'd0d1c8a799996bf0265b98b5d48ab919',
    );
  });

  it('erzeugt prüfsummengeschützte Recovery-Keys und prüft die abgefragten Gruppen', () => {
    const recovery = new RecoveryKeyService();
    const generated = recovery.generate();
    const parsed = recovery.parse(generated.setup.displayKey);
    expect(parsed.equals(generated.secret)).toBe(true);

    const confirmation = Object.fromEntries(
      generated.setup.confirmationIndexes.map((index) => [
        String(index),
        generated.setup.groups[index],
      ]),
    ) as Record<string, string>;
    expect(recovery.verifyConfirmation(generated.setup, confirmation)).toBe(true);
    const changeIndex = generated.setup.displayKey.indexOf('-') + 2;
    const original = generated.setup.displayKey[changeIndex];
    const changed = `${generated.setup.displayKey.slice(0, changeIndex)}${
      original === 'A' ? 'B' : 'A'
    }${generated.setup.displayKey.slice(changeIndex + 1)}`;
    expect(() => recovery.parse(changed)).toThrowError(VaultaError);
  });
});
