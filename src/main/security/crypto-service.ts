import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from 'node:crypto';

import { VaultaError } from '../../shared/errors';

export const AES_256_KEY_BYTES = 32;
export const AES_GCM_NONCE_BYTES = 12;
export const AES_GCM_TAG_BYTES = 16;

export interface AesGcmEnvelope {
  algorithm: 'AES-256-GCM';
  nonce: string;
  ciphertext: string;
  tag: string;
}

function decodeBase64(value: string, expectedBytes?: number): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new VaultaError('CORRUPT_DATA', 'Die verschlüsselten Daten sind beschädigt.');
  }

  const decoded = Buffer.from(value, 'base64');
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new VaultaError('CORRUPT_DATA', 'Die verschlüsselten Daten sind beschädigt.');
  }
  return decoded;
}

function requireKey(key: Buffer): void {
  if (key.length !== AES_256_KEY_BYTES) {
    throw new VaultaError('INVALID_INPUT', 'Ein kryptografischer Schlüssel hat die falsche Länge.');
  }
}

export class CryptoService {
  public randomBytes(length: number): Buffer {
    if (!Number.isSafeInteger(length) || length <= 0) {
      throw new VaultaError('INVALID_INPUT', 'Die angeforderte Zufallsdatenlänge ist ungültig.');
    }
    return nodeRandomBytes(length);
  }

  public sha256(data: Buffer | string): Buffer {
    return createHash('sha256').update(data).digest();
  }

  public hmacSha256(key: Buffer, data: Buffer | string): Buffer {
    if (key.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Der HMAC-Schlüssel darf nicht leer sein.');
    }
    return createHmac('sha256', key).update(data).digest();
  }

  public deriveKey(inputKeyMaterial: Buffer, info: string, salt: Buffer = Buffer.alloc(0)): Buffer {
    if (inputKeyMaterial.length === 0 || info.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Die Schlüsselableitung ist unvollständig.');
    }

    return Buffer.from(
      hkdfSync('sha256', inputKeyMaterial, salt, Buffer.from(`vaulta:${info}`, 'utf8'), 32),
    );
  }

  public encrypt(
    plaintext: Buffer,
    key: Buffer,
    additionalAuthenticatedData: Buffer,
  ): AesGcmEnvelope {
    return this.encryptWithNonce(
      plaintext,
      key,
      additionalAuthenticatedData,
      this.randomBytes(AES_GCM_NONCE_BYTES),
    );
  }

  public encryptWithNonce(
    plaintext: Buffer,
    key: Buffer,
    additionalAuthenticatedData: Buffer,
    nonce: Buffer,
  ): AesGcmEnvelope {
    requireKey(key);
    if (nonce.length !== AES_GCM_NONCE_BYTES) {
      throw new VaultaError('INVALID_INPUT', 'Der AES-GCM-Nonce hat die falsche Länge.');
    }
    const cipher = createCipheriv('aes-256-gcm', key, nonce, {
      authTagLength: AES_GCM_TAG_BYTES,
    });
    cipher.setAAD(additionalAuthenticatedData);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      algorithm: 'AES-256-GCM',
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
  }

  public decrypt(
    envelope: AesGcmEnvelope,
    key: Buffer,
    additionalAuthenticatedData: Buffer,
  ): Buffer {
    requireKey(key);
    if (envelope.algorithm !== 'AES-256-GCM') {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Der Verschlüsselungsalgorithmus wird nicht unterstützt.',
      );
    }

    const nonce = decodeBase64(envelope.nonce, AES_GCM_NONCE_BYTES);
    const tag = decodeBase64(envelope.tag, AES_GCM_TAG_BYTES);
    const ciphertext = decodeBase64(envelope.ciphertext);

    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce, {
        authTagLength: AES_GCM_TAG_BYTES,
      });
      decipher.setAAD(additionalAuthenticatedData);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (error) {
      throw new VaultaError(
        'CORRUPT_DATA',
        'Die verschlüsselten Daten wurden verändert oder sind beschädigt.',
        'Verwende eine geprüfte Sicherung, falls der Fehler bestehen bleibt.',
        { cause: error },
      );
    }
  }

  public wrapKey(keyToWrap: Buffer, wrappingKey: Buffer, context: string): AesGcmEnvelope {
    requireKey(keyToWrap);
    return this.encrypt(keyToWrap, wrappingKey, Buffer.from(`vaulta:key-wrap:${context}`, 'utf8'));
  }

  public unwrapKey(envelope: AesGcmEnvelope, wrappingKey: Buffer, context: string): Buffer {
    const unwrapped = this.decrypt(
      envelope,
      wrappingKey,
      Buffer.from(`vaulta:key-wrap:${context}`, 'utf8'),
    );
    requireKey(unwrapped);
    return unwrapped;
  }

  public equals(left: Buffer, right: Buffer): boolean {
    return left.length === right.length && timingSafeEqual(left, right);
  }

  public erase(buffer: Buffer | null | undefined): void {
    buffer?.fill(0);
  }
}
