import type {
  AttachmentMetadata,
  CustomField,
  VaultDocument,
  VaultEntry,
} from '../../src/shared/models';

export interface CredentialFixtureOptions {
  id?: string;
  vaultId?: string;
  title?: string;
  username?: string;
  password?: string;
  websites?: string[];
  createdAt?: string;
  updatedAt?: string;
  secretChangedAt?: string;
  deletedAt?: string | null;
  favorite?: boolean;
  attachments?: AttachmentMetadata[];
  customFields?: CustomField[];
}

export function credentialEntry(options: CredentialFixtureOptions = {}): VaultEntry {
  return {
    id: options.id ?? 'entry-1',
    vaultId: options.vaultId ?? 'vault-1',
    title: options.title ?? 'Beispiel',
    folderId: null,
    tags: [],
    favorite: options.favorite ?? false,
    note: '',
    customFields: options.customFields ?? [],
    attachments: options.attachments ?? [],
    data: {
      type: 'credential',
      value: {
        username: options.username ?? 'user@example.de',
        password: options.password ?? 'wL8@N3!yR7#qP2$zK9',
        websites: options.websites ?? ['https://example.de'],
        appNames: [],
      },
    },
    createdAt: options.createdAt ?? '2025-01-01T00:00:00.000Z',
    updatedAt: options.updatedAt ?? '2025-01-01T00:00:00.000Z',
    secretChangedAt: options.secretChangedAt ?? '2025-01-01T00:00:00.000Z',
    lastUsedAt: null,
    deletedAt: options.deletedAt ?? null,
  };
}

export function sshEntry(passphrase = ''): VaultEntry {
  return {
    ...credentialEntry({ id: 'ssh-1', title: 'Server-Schluessel' }),
    data: {
      type: 'ssh-key',
      value: {
        host: 'server.example',
        port: 22,
        username: 'root',
        keyType: 'ed25519',
        fingerprint: 'SHA256:test',
        publicKey: 'ssh-ed25519 public',
        privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----',
        passphrase,
      },
    },
  };
}

export function vaultDocument(entries: VaultEntry[]): VaultDocument {
  return {
    formatVersion: 1,
    id: 'vault-1',
    name: 'Privat',
    color: '#22d3c5',
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2025-01-01T00:00:00.000Z',
    folders: [],
    entries,
  };
}
