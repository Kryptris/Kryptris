import { createHash, randomUUID } from 'node:crypto';
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

export interface PreparedAuditWrite {
  readonly events: AuditEvent[];
  readonly relativePath: typeof AUDIT_FILENAME;
  readonly contents: Buffer;
  readonly expectedSha256: string | null;
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
  'entry-copied-to-vault': 'Eintrag in einen anderen Tresor kopiert',
  'entry-moved-to-vault': 'Eintrag in einen anderen Tresor verschoben',
  'entries-merged': 'Dubletten zusammengeführt',
  'data-quality-fixed': 'Bestätigte Datenqualitätskorrektur angewendet',
  'trash-auto-purged': 'Abgelaufene Papierkorbeinträge automatisch gelöscht',
  'attachment-added': 'Anhang hinzugefügt',
  'attachment-exported': 'Anhang exportiert',
  'private-key-exported': 'Privaten Schlüssel exportiert',
  'import-completed': 'Import abgeschlossen',
  'export-completed': 'Export abgeschlossen',
  'backup-created': 'Verschlüsselte Sicherung erstellt',
  'backup-restored': 'Verschlüsselte Sicherung wiederhergestellt',
  'backup-dry-run-completed': 'Verschlüsselte Sicherung probeweise geprüft',
  'import-mapping-profile-updated': 'Import-Feldzuordnung aktualisiert',
  'vault-package-exported': 'Verschlüsseltes Tresor-Paket exportiert',
  'vault-package-imported': 'Verschlüsseltes Tresor-Paket importiert',
  'settings-updated': 'Sicherheitseinstellungen geändert',
  'factor-added': 'Zusätzlicher Entsperrfaktor registriert',
  'factor-removed': 'Zusätzlicher Entsperrfaktor entfernt',
  'recovery-rotated': 'Wiederherstellungsschlüssel ersetzt',
  'recovery-used': 'Wiederherstellungsschlüssel verwendet',
  'recovery-readiness-succeeded': 'Wiederherstellungsbereitschaft erfolgreich geprüft',
  'recovery-readiness-failed': 'Wiederherstellungsbereitschaft konnte nicht bestätigt werden',
  'integrity-check-completed': 'Vollständige Integritätsprüfung abgeschlossen',
  'breach-list-imported': 'Lokale Datenleckliste importiert',
  'breach-list-removed': 'Lokale Datenleckliste entfernt',
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

  /** Holds the audit writer while a wider transaction prepares and commits `audit.vaulta`. */
  public async withExclusiveWrite<T>(operation: () => Promise<T>): Promise<T> {
    return this.writes.run(operation);
  }

  /**
   * Prepares one encrypted, redacted audit generation without changing the live file.
   * Callers use this only while `withExclusiveWrite` is held.
   */
  public async prepareRecord(input: AuditRecordInput): Promise<PreparedAuditWrite> {
    return this.prepareRecords([input]);
  }

  /**
   * Prepares one encrypted generation containing every supplied event. Keeping
   * the complete batch in a single generation allows a wider multi-file
   * transaction to commit domain data and its redacted audit trail together.
   */
  public async prepareRecords(inputs: readonly AuditRecordInput[]): Promise<PreparedAuditWrite> {
    if (inputs.length === 0) {
      throw new VaultaError('INVALID_INPUT', 'Mindestens ein Auditereignis ist erforderlich.');
    }
    await this.atomicWriter.recoverPreviousIfTargetMissing(this.auditPath);
    const sourceBytes = await readFile(this.auditPath).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    });
    const header = await this.profileService.readPublicHeader();
    return this.profileService.withProfileKey((profileKey) => {
      const auditKey = this.crypto.deriveKey(
        profileKey,
        'audit-log',
        Buffer.from(header.profileId, 'utf8'),
      );
      try {
        const document =
          sourceBytes === null
            ? { formatVersion: AUDIT_DOCUMENT_FORMAT_VERSION, events: [] }
            : parseAuditDocument(
                this.containers.decodeJson<unknown>(
                  sourceBytes,
                  auditKey,
                  'audit',
                  header.profileId,
                ),
              );
        const now = this.now();
        const events = inputs.map((input): AuditEvent => ({
          id: randomUUID(),
          occurredAt: now.toISOString(),
          type: input.type,
          vaultId: input.vaultId ?? null,
          entryId: input.entryId ?? null,
          summary: AUDIT_SUMMARIES[input.type],
        }));
        document.events.push(...events);
        document.events = this.applyRetention(document.events, now);
        const contents = this.containers.encodeJson(document, auditKey, 'audit', header.profileId);
        parseAuditDocument(
          this.containers.decodeJson<unknown>(contents, auditKey, 'audit', header.profileId),
        );
        return {
          events,
          relativePath: AUDIT_FILENAME,
          contents,
          expectedSha256:
            sourceBytes === null ? null : createHash('sha256').update(sourceBytes).digest('hex'),
        };
      } finally {
        this.crypto.erase(auditKey);
        this.crypto.erase(sourceBytes);
      }
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
