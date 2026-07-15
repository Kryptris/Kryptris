import { VaultaError } from '../../shared/errors';
import { type AesGcmEnvelope, CryptoService } from '../security/crypto-service';

export const ENCRYPTED_CONTAINER_VERSION = 1 as const;

interface ContainerHeader {
  magic: 'VAULTA-CONTAINER';
  version: typeof ENCRYPTED_CONTAINER_VERSION;
  kind: string;
  cipher: 'AES-256-GCM';
  contextHash: string;
}

interface SerializedContainer {
  header: ContainerHeader;
  payload: AesGcmEnvelope;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseEnvelope(value: unknown): AesGcmEnvelope {
  if (
    !isRecord(value) ||
    value.algorithm !== 'AES-256-GCM' ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string' ||
    typeof value.tag !== 'string'
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Der verschlüsselte Container ist beschädigt.');
  }
  return {
    algorithm: value.algorithm,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
    tag: value.tag,
  };
}

export class EncryptedContainerCodec {
  public constructor(private readonly crypto = new CryptoService()) {}

  public encode(plaintext: Buffer, key: Buffer, kind: string, context: string): Buffer {
    const header = this.createHeader(kind, context);
    const payload = this.crypto.encrypt(plaintext, key, this.headerAad(header));
    const container: SerializedContainer = { header, payload };
    return Buffer.from(JSON.stringify(container), 'utf8');
  }

  public decode(containerBytes: Buffer, key: Buffer, kind: string, context: string): Buffer {
    let parsed: unknown;
    try {
      parsed = JSON.parse(containerBytes.toString('utf8')) as unknown;
    } catch (error) {
      throw new VaultaError('CORRUPT_DATA', 'Der verschlüsselte Container ist beschädigt.', null, {
        cause: error,
      });
    }

    if (!isRecord(parsed) || !isRecord(parsed.header)) {
      throw new VaultaError('CORRUPT_DATA', 'Der verschlüsselte Container ist beschädigt.');
    }
    const header = parsed.header;
    const expected = this.createHeader(kind, context);
    if (
      header.magic !== expected.magic ||
      header.version !== expected.version ||
      header.kind !== expected.kind ||
      header.cipher !== expected.cipher ||
      header.contextHash !== expected.contextHash
    ) {
      throw new VaultaError('CORRUPT_DATA', 'Containerformat oder Kontext ist ungültig.');
    }

    return this.crypto.decrypt(parseEnvelope(parsed.payload), key, this.headerAad(expected));
  }

  public encodeJson<T>(value: T, key: Buffer, kind: string, context: string): Buffer {
    return this.encode(Buffer.from(JSON.stringify(value), 'utf8'), key, kind, context);
  }

  public decodeJson<T>(containerBytes: Buffer, key: Buffer, kind: string, context: string): T {
    const plaintext = this.decode(containerBytes, key, kind, context);
    try {
      return JSON.parse(plaintext.toString('utf8')) as T;
    } catch (error) {
      throw new VaultaError('CORRUPT_DATA', 'Der Containerinhalt ist ungültig.', null, {
        cause: error,
      });
    } finally {
      this.crypto.erase(plaintext);
    }
  }

  private createHeader(kind: string, context: string): ContainerHeader {
    if (kind.length === 0 || context.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Der Containerkontext ist unvollständig.');
    }
    return {
      magic: 'VAULTA-CONTAINER',
      version: ENCRYPTED_CONTAINER_VERSION,
      kind,
      cipher: 'AES-256-GCM',
      contextHash: this.crypto.sha256(context).toString('base64'),
    };
  }

  private headerAad(header: ContainerHeader): Buffer {
    return Buffer.from(JSON.stringify(header), 'utf8');
  }
}
