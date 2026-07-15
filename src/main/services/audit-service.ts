import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { VaultaError } from '../../shared/errors';
import type { AuditEvent, AuditEventType } from '../../shared/models';
import { requireCurrentFormatVersion } from '../migrations/format-version';
import { CryptoService } from '../security/crypto-service';
import { AtomicFileWriter } from '../storage/atomic-file';
import { EncryptedContainerCodec } from '../storage/encrypted-container';
import { SerialExecutor } from '../storage/serial-executor';
import type { ProfileService } from './profile-service';

const AUDIT_FILENAME = 'audit.vaulta';
const DEFAULT_MAX_EVENTS = 5_000;
const DEFAULT_RETENTION_DAYS = 180;
export const AUDIT_DOCUMENT_FORMAT_VERSION = 1 as const;

interface AuditDocument {
  formatVersion: typeof AUDIT_DOCUMENT_FORMAT_VERSION;
  events: AuditEvent[];
}

export interface AuditServiceOptions {
  rootDir: string;
  profileService: ProfileService;
  crypto?: CryptoService;
  containers?: EncryptedContainerCodec;
  atomicWriter?: AtomicFileWriter;
  maxEvents?: number;
  retentionDays?: number;
  now?: () => Date;
}

export interface AuditRecordInput {
  type: AuditEventType;
  vaultId?: string | null;
  entryId?: string | null;
}

const AUDIT_SUMMARIES: Record<AuditEventType, string> = {
  'profile-created': 'Lokales Profil erstellt',
  unlocked: 'Vaulta entsperrt',
  'unlock-failed': 'Entsperrversuch fehlgeschlagen',
  locked: 'Vaulta gesperrt',
  'vault-created': 'Tresor erstellt',
  'vault-updated': 'Tresor geändert',
  'vault-deleted': 'Tresor gelöscht',
  'entry-created': 'Eintrag erstellt',
  'entry-updated': 'Eintrag geändert',
  'entry-moved-to-trash': 'Eintrag in den Papierkorb verschoben',
  'entry-restored': 'Eintrag wiederhergestellt',
  'entry-purged': 'Eintrag endgültig gelöscht',
  'attachment-added': 'Anhang hinzugefügt',
  'attachment-exported': 'Anhang exportiert',
  'private-key-exported': 'Privaten Schlüssel exportiert',
  'import-completed': 'Import abgeschlossen',
  'export-completed': 'Export abgeschlossen',
  'backup-created': 'Verschlüsselte Sicherung erstellt',
  'backup-restored': 'Verschlüsselte Sicherung wiederhergestellt',
  'settings-updated': 'Sicherheitseinstellungen geändert',
  'factor-added': 'Zusätzlicher Entsperrfaktor registriert',
  'factor-removed': 'Zusätzlicher Entsperrfaktor entfernt',
  'recovery-rotated': 'Wiederherstellungsschlüssel ersetzt',
  'recovery-used': 'Wiederherstellungsschlüssel verwendet',
};

export function readAuditDocumentFormatVersion(value: unknown): number {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VaultaError('CORRUPT_DATA', 'Das Aktivitätsprotokoll ist beschädigt.');
  }
  return requireCurrentFormatVersion(
    'formatVersion' in value ? value.formatVersion : undefined,
    AUDIT_DOCUMENT_FORMAT_VERSION,
    'Vaulta-Aktivitätsprotokoll',
  );
}

function parseAuditDocument(value: unknown): AuditDocument {
  readAuditDocumentFormatVersion(value);
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !('events' in value) ||
    !Array.isArray(value.events)
  ) {
    throw new VaultaError('CORRUPT_DATA', 'Das Aktivitätsprotokoll ist beschädigt.');
  }
  return value as AuditDocument;
}

export class AuditService {
  private readonly auditPath: string;
  private readonly profileService: ProfileService;
  private readonly crypto: CryptoService;
  private readonly containers: EncryptedContainerCodec;
  private readonly atomicWriter: AtomicFileWriter;
  private readonly maxEvents: number;
  private readonly retentionDays: number;
  private readonly now: () => Date;
  private readonly writes = new SerialExecutor();

  public constructor(options: AuditServiceOptions) {
    this.auditPath = path.resolve(options.rootDir, AUDIT_FILENAME);
    this.profileService = options.profileService;
    this.crypto = options.crypto ?? new CryptoService();
    this.containers = options.containers ?? new EncryptedContainerCodec(this.crypto);
    this.atomicWriter = options.atomicWriter ?? new AtomicFileWriter();
    this.maxEvents = options.maxEvents ?? DEFAULT_MAX_EVENTS;
    this.retentionDays = options.retentionDays ?? DEFAULT_RETENTION_DAYS;
    this.now = options.now ?? (() => new Date());
    if (!Number.isSafeInteger(this.maxEvents) || this.maxEvents < 1) {
      throw new VaultaError('INVALID_INPUT', 'Die maximale Protokollgröße ist ungültig.');
    }
    if (!Number.isSafeInteger(this.retentionDays) || this.retentionDays < 1) {
      throw new VaultaError('INVALID_INPUT', 'Die Protokollaufbewahrung ist ungültig.');
    }
  }

  public async record(input: AuditRecordInput): Promise<AuditEvent> {
    return this.writes.run(async () => {
      const now = this.now();
      const document = await this.readDocument();
      const event: AuditEvent = {
        id: randomUUID(),
        occurredAt: now.toISOString(),
        type: input.type,
        vaultId: input.vaultId ?? null,
        entryId: input.entryId ?? null,
        summary: AUDIT_SUMMARIES[input.type],
      };
      document.events.push(event);
      document.events = this.applyRetention(document.events, now);
      await this.writeDocument(document);
      return event;
    });
  }

  public async list(input: { offset?: number; limit?: number } = {}): Promise<AuditEvent[]> {
    const offset = input.offset ?? 0;
    const limit = input.limit ?? 100;
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 1_000
    ) {
      throw new VaultaError('INVALID_INPUT', 'Der Protokollausschnitt ist ungültig.');
    }
    const document = await this.readDocument();
    return document.events
      .slice()
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt))
      .slice(offset, offset + limit);
  }

  public async inspectStoredDocumentFormatVersion(): Promise<number> {
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.auditPath);
    const header = await this.profileService.readPublicHeader();
    return this.profileService.withProfileKey(async (profileKey) => {
      const auditKey = this.crypto.deriveKey(
        profileKey,
        'audit-log',
        Buffer.from(header.profileId, 'utf8'),
      );
      try {
        const bytes = await readFile(this.auditPath).catch((error) => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
          throw error;
        });
        if (bytes === null) return AUDIT_DOCUMENT_FORMAT_VERSION;
        const value = this.containers.decodeJson<unknown>(
          bytes,
          auditKey,
          'audit',
          header.profileId,
        );
        const version = readAuditDocumentFormatVersion(value);
        parseAuditDocument(value);
        return version;
      } finally {
        this.crypto.erase(auditKey);
      }
    });
  }

  public async clear(): Promise<void> {
    await this.writes.run(async () => {
      await this.writeDocument({ formatVersion: AUDIT_DOCUMENT_FORMAT_VERSION, events: [] });
    });
  }

  private applyRetention(events: AuditEvent[], now: Date): AuditEvent[] {
    const cutoff = now.getTime() - this.retentionDays * 24 * 60 * 60 * 1_000;
    return events
      .filter((event) => {
        const timestamp = Date.parse(event.occurredAt);
        return Number.isFinite(timestamp) && timestamp >= cutoff;
      })
      .slice(-this.maxEvents);
  }

  private async readDocument(): Promise<AuditDocument> {
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.auditPath);
    const header = await this.profileService.readPublicHeader();
    return this.profileService.withProfileKey(async (profileKey) => {
      const auditKey = this.crypto.deriveKey(
        profileKey,
        'audit-log',
        Buffer.from(header.profileId, 'utf8'),
      );
      try {
        const bytes = await readFile(this.auditPath).catch((error) => {
          if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
          throw error;
        });
        if (bytes === null) return { formatVersion: AUDIT_DOCUMENT_FORMAT_VERSION, events: [] };
        return parseAuditDocument(
          this.containers.decodeJson<unknown>(bytes, auditKey, 'audit', header.profileId),
        );
      } finally {
        this.crypto.erase(auditKey);
      }
    });
  }

  private async writeDocument(document: AuditDocument): Promise<void> {
    const header = await this.profileService.readPublicHeader();
    await this.profileService.withProfileKey(async (profileKey) => {
      const auditKey = this.crypto.deriveKey(
        profileKey,
        'audit-log',
        Buffer.from(header.profileId, 'utf8'),
      );
      try {
        const bytes = this.containers.encodeJson(document, auditKey, 'audit', header.profileId);
        await this.atomicWriter.writeFile(this.auditPath, bytes, async (temporaryPath) => {
          const temporary = await readFile(temporaryPath);
          parseAuditDocument(
            this.containers.decodeJson<unknown>(temporary, auditKey, 'audit', header.profileId),
          );
        });
      } finally {
        this.crypto.erase(auditKey);
      }
    });
  }
}
