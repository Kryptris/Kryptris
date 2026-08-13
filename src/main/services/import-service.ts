import { randomUUID } from 'node:crypto';

import Papa from 'papaparse';

import { VaultaError } from '../../shared/errors';
import type {
  CustomField,
  EntryInput,
  EntryType,
  ImportFormat,
  ImportMapping,
  ImportPreview,
  TotpConfiguration,
  VaultEntry,
} from '../../shared/models';
import { createDefaultEntryLifecycleMetadata } from '../../shared/models';
import { DuplicateService, type DuplicateCandidate } from './duplicate-service';
import { emptyEntryInput } from './entry-utils';
import { validateImportMapping } from './import-mapping-utils';
import { summarizeImportPreview, type ImportSummary } from './import-summary';
import { TotpService } from './totp-service';

const MAX_IMPORT_BYTES = 50 * 1024 * 1024;
const MAX_IMPORT_ROWS = 100_000;
const IMPORT_SESSION_TTL_MS = 15 * 60 * 1_000;
const IMPORT_MATCHER_VAULT_ID = '00000000-0000-4000-8000-000000000008';
const IMPORT_MATCHER_TIMESTAMP = '1970-01-01T00:00:00.000Z';

type RawRecord = Record<string, unknown>;

export type SupportedImportFormat = ImportFormat;
export type ImportPreviewResult = ImportPreview;

function isWelleTenVendorFormat(format: ImportFormat): boolean {
  return format === 'dashlane-csv' || format === 'nordpass-csv' || format === 'roboform-csv';
}

interface ImportSession {
  createdAt: number;
  format: SupportedImportFormat;
  sourceName: string;
  records: RawRecord[];
  mapping: ImportMapping;
  detectedColumns: string[];
  parserErrors: Array<{ row: number; message: string }>;
  prepared: ImportPreparedEntry[];
  preview: ImportPreviewResult;
}

interface PreparedResult {
  prepared: ImportPreparedEntry;
  warnings: string[];
}

interface ImportDuplicateSource {
  label: string;
  imported: boolean;
  order: number;
}

export interface ImportSource {
  format: SupportedImportFormat;
  content: string;
  sourceName: string;
  mapping?: ImportMapping;
  existingEntries?: readonly VaultEntry[];
}

export interface ImportPreparedEntry {
  sourceIndex: number;
  folderName: string;
  entry: EntryInput;
}

export interface ImportServiceDependencies {
  duplicates: DuplicateService;
}

export class ImportService {
  private readonly sessions = new Map<string, ImportSession>();
  private readonly totpService = new TotpService();
  private readonly duplicates: DuplicateService;

  public constructor(dependencies: Partial<ImportServiceDependencies> = {}) {
    this.duplicates = dependencies.duplicates ?? new DuplicateService();
  }

  public preview(input: ImportSource): ImportPreviewResult {
    this.pruneExpiredSessions();
    ensureSafeSize(input.content);
    if (isWelleTenVendorFormat(input.format)) {
      const detected = this.detectFormat(input.sourceName, input.content);
      if (detected !== input.format) {
        throw new VaultaError(
          'UNSUPPORTED_FORMAT',
          'Die Importdatei besitzt nicht die erwartete, dokumentierte Spaltenstruktur.',
        );
      }
    }
    const parsed = parseSource(input.format, input.content);
    const mapping = validateImportMapping(
      input.mapping ?? detectMapping(parsed.detectedColumns, input.format),
    );
    const token = randomUUID();
    const session: ImportSession = {
      createdAt: Date.now(),
      format: input.format,
      sourceName: sanitizeSourceName(input.sourceName),
      records: parsed.records,
      mapping,
      detectedColumns: parsed.detectedColumns,
      parserErrors: parsed.errors,
      prepared: [],
      preview: {
        token,
        format: input.format,
        sourceName: sanitizeSourceName(input.sourceName),
        candidates: [],
        errors: [],
        detectedColumns: parsed.detectedColumns,
        mapping,
      },
    };
    this.rebuild(session, input.existingEntries ?? []);
    this.sessions.set(token, session);
    return structuredClone(session.preview);
  }

  public remap(
    token: string,
    mapping: ImportMapping,
    existingEntries: readonly VaultEntry[] = [],
  ): ImportPreviewResult {
    const session = this.requireSession(token);
    session.mapping = validateImportMapping(mapping);
    this.rebuild(session, existingEntries);
    return structuredClone(session.preview);
  }

  public materialize(token: string, selectedRows: readonly number[]): ImportPreparedEntry[] {
    const session = this.requireSession(token);
    const selection = new Set(selectedRows);
    return session.prepared
      .filter((candidate) => selection.has(candidate.sourceIndex))
      .map((candidate) => structuredClone(candidate));
  }

  /**
   * Counts the current preview without ever returning a title, account name or
   * imported secret. The controller can combine these counts with its atomic
   * execution result for the final import notification.
   */
  public summary(token: string, selectedRows?: readonly number[]): ImportSummary {
    const session = this.requireSession(token);
    return summarizeImportPreview(session.preview, selectedRows);
  }

  public discard(token: string): void {
    this.sessions.delete(token);
  }

  public clear(): void {
    this.sessions.clear();
  }

  public detectFormat(_sourceName: string, content: string): SupportedImportFormat | null {
    try {
      ensureSafeSize(content);
    } catch {
      return null;
    }
    const trimmed = content.replace(/^\uFEFF/u, '').trimStart();
    if (trimmed.length === 0) return null;
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const root: unknown = JSON.parse(trimmed);
        const record = asRecord(root);
        if (record !== null && Array.isArray(record.items) && 'encrypted' in record) {
          return 'bitwarden-json';
        }
        if (record !== null && 'vaults' in record) return 'protonpass-json';
        return 'generic-json';
      } catch {
        return null;
      }
    }
    return detectCsvFormat(content);
  }

  private rebuild(session: ImportSession, existingEntries: readonly VaultEntry[]): void {
    const prepared: ImportPreparedEntry[] = [];
    const candidates: ImportPreview['candidates'] = [];
    const errors = [...session.parserErrors];
    const preparedRows: Array<{ result: PreparedResult; sourceIndex: number }> = [];

    for (let index = 0; index < session.records.length; index += 1) {
      const record = session.records[index];
      if (record === undefined) continue;
      try {
        const result = this.prepareRecord(session.format, record, session.mapping, index);
        preparedRows.push({ result, sourceIndex: index });
      } catch {
        errors.push({ row: index + 1, message: 'Dieser Datensatz konnte nicht gelesen werden.' });
      }
    }

    this.duplicates.withMatcher((matcher) => {
      const knownReferences = new Map<string, ImportDuplicateSource>();
      for (let index = 0; index < existingEntries.length; index += 1) {
        const entry = existingEntries[index]!;
        matcher.add(entry);
        if (entry.deletedAt === null) {
          knownReferences.set(duplicateReferenceKey(entry.vaultId, entry.id), {
            label: entry.id,
            imported: false,
            order: index,
          });
        }
      }

      for (const row of preparedRows) {
        const { entry } = row.result.prepared;
        const matcherEntry = importMatcherEntry(entry, row.sourceIndex);
        const matches = matcher.add(matcherEntry);
        const duplicateOf = selectDuplicateSource(matches, matcherEntry, knownReferences);
        if (duplicateOf !== null) row.result.warnings.push('Moegliche Dublette erkannt.');

        const credential = entry.data.type === 'credential' ? entry.data.value : null;
        candidates.push({
          sourceIndex: row.sourceIndex,
          title: entry.title,
          username: credential?.username ?? '',
          website: credential?.websites[0] ?? '',
          type: entry.data.type,
          duplicateOf,
          warnings: [...new Set(row.result.warnings)],
          selected: duplicateOf === null,
        });
        prepared.push(row.result.prepared);
        knownReferences.set(duplicateReferenceKey(matcherEntry.vaultId, matcherEntry.id), {
          label: `import:${row.sourceIndex}`,
          imported: true,
          order: row.sourceIndex,
        });
      }
    });

    session.prepared = prepared;
    session.preview = {
      token: session.preview.token,
      format: session.format,
      sourceName: session.sourceName,
      candidates,
      errors,
      detectedColumns: session.detectedColumns,
      mapping: session.mapping,
    };
  }

  private prepareRecord(
    format: SupportedImportFormat,
    record: RawRecord,
    mapping: ImportMapping,
    sourceIndex: number,
  ): PreparedResult {
    if (format === 'bitwarden-json') return this.prepareBitwarden(record, sourceIndex);
    if (format === 'protonpass-json') return this.prepareProton(record, sourceIndex);
    return this.prepareMapped(record, mapping, sourceIndex, format);
  }

  private prepareMapped(
    record: RawRecord,
    mapping: ImportMapping,
    sourceIndex: number,
    format: SupportedImportFormat,
  ): PreparedResult {
    const rawTitle = readColumn(record, mapping.title);
    const title = rawTitle.trim() || `Importierter Eintrag ${sourceIndex + 1}`;
    const username = readColumn(record, mapping.username).trim();
    const password = readColumn(record, mapping.password);
    const website = readColumn(record, mapping.url).trim();
    const note = readColumn(record, mapping.note);
    const folderName = readColumn(record, mapping.folder).trim();
    const tags = splitTags(readColumn(record, mapping.tags));
    const entry = emptyEntryInput('credential', title);
    if (entry.data.type !== 'credential') throw new Error('Unerwarteter Eintragstyp.');
    entry.data.value = {
      username,
      password,
      websites: website.length > 0 ? [website] : [],
      appNames: [],
    };
    entry.note = note;
    entry.tags = tags;
    entry.favorite = parseBoolean(readFirst(record, ['favorite', 'favourite', 'fav']));

    const warnings = basicWarnings(rawTitle, username, password, website);
    const totpValue = readFirst(record, [
      'otpauth',
      'otpAuth',
      'otpSecret',
      'totp',
      'one-time password',
    ]);
    if (totpValue.length > 0) {
      const totp = this.parseTotp(totpValue, title, username);
      if (totp === null) warnings.push('Der TOTP-Wert war ungueltig und wurde ausgelassen.');
      else entry.data.value.totp = totp;
    }
    if (format === 'firefox-csv' && website.length === 0) {
      const fallbackUrl = readFirst(record, ['formActionOrigin', 'hostname']);
      if (fallbackUrl.length > 0) entry.data.value.websites = [fallbackUrl];
    }

    return { prepared: { sourceIndex, folderName, entry }, warnings };
  }

  private prepareBitwarden(record: RawRecord, sourceIndex: number): PreparedResult {
    const rawTitle = stringValue(record.name);
    const title = rawTitle.trim() || `Importierter Eintrag ${sourceIndex + 1}`;
    const typeNumber = numberValue(record.type, 1);
    const type: EntryType =
      typeNumber === 2
        ? 'secure-note'
        : typeNumber === 3
          ? 'credit-card'
          : typeNumber === 4
            ? 'identity'
            : 'credential';
    const entry = emptyEntryInput(type, title);
    const notes = stringValue(record.notes);
    const warnings: string[] =
      rawTitle.trim().length === 0 ? ['Titel fehlte und wurde ersetzt.'] : [];
    entry.favorite = Boolean(record.favorite);
    entry.folderId = null;
    entry.customFields = bitwardenCustomFields(record.fields);
    const folderName = stringValue(record.__folderName);

    if (entry.data.type === 'credential') {
      const login = asRecord(record.login) ?? {};
      const username = stringValue(login.username).trim();
      const password = stringValue(login.password);
      const websites = arrayValue(login.uris)
        .map((item) => stringValue(asRecord(item)?.uri).trim())
        .filter(Boolean);
      entry.data.value = { username, password, websites, appNames: [] };
      entry.note = notes;
      warnings.push(...basicWarnings(rawTitle, username, password, websites[0] ?? ''));
      const totpValue = stringValue(login.totp);
      if (totpValue.length > 0) {
        const totp = this.parseTotp(totpValue, title, username);
        if (totp === null) warnings.push('Der TOTP-Wert war ungueltig und wurde ausgelassen.');
        else entry.data.value.totp = totp;
      }
    } else if (entry.data.type === 'secure-note') {
      entry.data.value.markdown = notes;
    } else if (entry.data.type === 'credit-card') {
      const card = asRecord(record.card) ?? {};
      entry.data.value = {
        cardName: title,
        cardholder: stringValue(card.cardholderName),
        number: stringValue(card.number),
        expiryMonth: numberValue(card.expMonth, 0),
        expiryYear: numberValue(card.expYear, 0),
        cvc: stringValue(card.code),
        pin: '',
        issuer: stringValue(card.brand),
        cardType: stringValue(card.brand),
        billingAddress: '',
        servicePhone: '',
        website: '',
      };
      entry.note = notes;
    } else if (entry.data.type === 'identity') {
      const identity = asRecord(record.identity) ?? {};
      entry.data.value = {
        salutation: stringValue(identity.title),
        firstName: stringValue(identity.firstName),
        middleName: stringValue(identity.middleName),
        lastName: stringValue(identity.lastName),
        birthDate: '',
        emails: compact([stringValue(identity.email)]),
        phones: compact([stringValue(identity.phone)]),
        addresses: [],
        idNumber: '',
        passportNumber: stringValue(identity.passportNumber),
        taxNumber: stringValue(identity.ssn),
      };
      entry.note = [notes, formatAddress(identity)].filter(Boolean).join('\n\n');
    }

    if (arrayValue(record.attachments).length > 0) {
      warnings.push('Anhaenge muessen ueber den geschuetzten Anhangsimport uebernommen werden.');
    }
    return { prepared: { sourceIndex, folderName, entry }, warnings };
  }

  private prepareProton(record: RawRecord, sourceIndex: number): PreparedResult {
    const data = asRecord(record.data) ?? record;
    const metadata = asRecord(data.metadata) ?? asRecord(record.metadata) ?? {};
    const content = asRecord(data.content) ?? asRecord(record.content) ?? record;
    const rawTitle = readFirst(metadata, ['name', 'title']) || readFirst(record, ['name', 'title']);
    const title = rawTitle.trim() || `Importierter Eintrag ${sourceIndex + 1}`;
    const itemType = readFirst(content, ['itemType', 'type']).toLowerCase();
    const note = readFirst(metadata, ['note', 'notes']) || readFirst(content, ['note', 'notes']);
    const folderName = stringValue(record.__vaultName);

    if (itemType.includes('note')) {
      const entry = emptyEntryInput('secure-note', title);
      if (entry.data.type !== 'secure-note') throw new Error('Unerwarteter Eintragstyp.');
      entry.data.value.markdown = note || readFirst(content, ['content', 'text']);
      return {
        prepared: { sourceIndex, folderName, entry },
        warnings: rawTitle.length === 0 ? ['Titel fehlte und wurde ersetzt.'] : [],
      };
    }

    const entry = emptyEntryInput('credential', title);
    if (entry.data.type !== 'credential') throw new Error('Unerwarteter Eintragstyp.');
    const username = readFirst(content, ['itemUsername', 'username', 'email']).trim();
    const password = readFirst(content, ['itemPassword', 'password']);
    const urls = arrayValue(content.urls)
      .map((item) =>
        typeof item === 'string' ? item : readFirst(asRecord(item) ?? {}, ['url', 'value']),
      )
      .map((value) => value.trim())
      .filter(Boolean);
    const fallbackUrl = readFirst(content, ['url', 'website']).trim();
    if (urls.length === 0 && fallbackUrl.length > 0) urls.push(fallbackUrl);
    entry.data.value = { username, password, websites: urls, appNames: [] };
    entry.note = note;
    entry.customFields = protonCustomFields(data.extraFields ?? record.extraFields);
    const warnings = basicWarnings(rawTitle, username, password, urls[0] ?? '');
    const totpValue = readFirst(content, ['totpUri', 'totp', 'otp']);
    if (totpValue.length > 0) {
      const totp = this.parseTotp(totpValue, title, username);
      if (totp === null) warnings.push('Der TOTP-Wert war ungueltig und wurde ausgelassen.');
      else entry.data.value.totp = totp;
    }
    return { prepared: { sourceIndex, folderName, entry }, warnings };
  }

  private parseTotp(value: string, title: string, username: string): TotpConfiguration | null {
    try {
      if (value.toLowerCase().startsWith('otpauth://'))
        return this.totpService.parseOtpAuthUri(value);
      return this.totpService.parseOtpAuthUri(
        `otpauth://totp/${encodeURIComponent(`${title}:${username || title}`)}?secret=${encodeURIComponent(value)}&issuer=${encodeURIComponent(title)}`,
      );
    } catch {
      return null;
    }
  }

  private requireSession(token: string): ImportSession {
    const session = this.sessions.get(token);
    if (session === undefined || Date.now() - session.createdAt > IMPORT_SESSION_TTL_MS) {
      this.sessions.delete(token);
      throw new VaultaError('NOT_FOUND', 'Die Importvorschau ist abgelaufen.');
    }
    return session;
  }

  private pruneExpiredSessions(): void {
    const now = Date.now();
    for (const [token, session] of this.sessions) {
      if (now - session.createdAt > IMPORT_SESSION_TTL_MS) this.sessions.delete(token);
    }
  }
}

function parseSource(
  format: SupportedImportFormat,
  content: string,
): {
  records: RawRecord[];
  detectedColumns: string[];
  errors: Array<{ row: number; message: string }>;
} {
  if (format.endsWith('-csv')) return parseCsv(content);
  return parseJson(format, content);
}

/**
 * Format selection is deliberately based on complete, documented header
 * signatures. The filename is untrusted presentation data and is never used to
 * choose a parser.
 */
function detectCsvFormat(content: string): SupportedImportFormat | null {
  try {
    const parsed = Papa.parse<Record<string, string>>(content.replace(/^\uFEFF/u, ''), {
      header: true,
      preview: 1,
      skipEmptyLines: 'greedy',
      transformHeader: (header) => header.trim(),
    });
    const headers = parsed.meta.fields?.filter((field) => field.length > 0) ?? [];
    if (headers.length < 2) return null;
    const normalized = new Set(headers.map(normalizeName));

    if (
      hasHeaders(normalized, 'username', 'title', 'password', 'url', 'otpsecret') &&
      hasAnyHeader(normalized, 'note', 'category')
    ) {
      return 'dashlane-csv';
    }
    if (
      hasHeaders(
        normalized,
        'name',
        'url',
        'username',
        'password',
        'note',
        'cardholdername',
        'cardnumber',
        'cvc',
        'expirydate',
        'zipcode',
        'folder',
        'fullname',
        'phonenumber',
        'email',
        'address1',
        'address2',
        'city',
        'country',
        'state',
        'totp',
        'sharedfolder',
      )
    ) {
      return 'nordpass-csv';
    }
    if (hasHeaders(normalized, 'name', 'url', 'login', 'pwd', 'rffields')) {
      return 'roboform-csv';
    }
    if (hasHeaders(normalized, 'url', 'username', 'password', 'name', 'grouping', 'fav')) {
      return 'lastpass-csv';
    }
    if (hasHeaders(normalized, 'title', 'url', 'username', 'password', 'otpauth', 'archived')) {
      return 'onepassword-csv';
    }
    if (hasHeaders(normalized, 'url', 'username', 'password', 'formactionorigin', 'httprealm')) {
      return 'firefox-csv';
    }
    if (hasHeaders(normalized, 'group', 'title', 'username', 'password', 'url', 'notes')) {
      return 'keepass-csv';
    }
    if (hasHeaders(normalized, 'name', 'url', 'username', 'password')) return 'chrome-csv';
    return 'generic-csv';
  } catch {
    return null;
  }
}

function hasHeaders(headers: ReadonlySet<string>, ...expected: readonly string[]): boolean {
  return expected.every((header) => headers.has(normalizeName(header)));
}

function hasAnyHeader(headers: ReadonlySet<string>, ...expected: readonly string[]): boolean {
  return expected.some((header) => headers.has(normalizeName(header)));
}

function parseCsv(content: string): {
  records: RawRecord[];
  detectedColumns: string[];
  errors: Array<{ row: number; message: string }>;
} {
  const parsed = Papa.parse<Record<string, string>>(content.replace(/^\uFEFF/u, ''), {
    header: true,
    skipEmptyLines: 'greedy',
    transformHeader: (header) => header.trim(),
  });
  if (parsed.data.length > MAX_IMPORT_ROWS)
    throw invalid('Die Importdatei enthaelt zu viele Datensaetze.');
  const columns = parsed.meta.fields?.filter((field) => field.length > 0) ?? [];
  return {
    records: parsed.data.map((record) => ({ ...record })),
    detectedColumns: columns,
    errors: parsed.errors.map((error) => ({
      row: (error.row ?? 0) + 1,
      message: 'Eine CSV-Zeile konnte nicht eindeutig gelesen werden.',
    })),
  };
}

function parseJson(
  format: SupportedImportFormat,
  content: string,
): {
  records: RawRecord[];
  detectedColumns: string[];
  errors: Array<{ row: number; message: string }>;
} {
  let root: unknown;
  try {
    root = JSON.parse(content.replace(/^\uFEFF/u, ''));
  } catch {
    throw new VaultaError('CORRUPT_DATA', 'Die JSON-Importdatei ist ungueltig.');
  }

  let records: RawRecord[];
  if (format === 'bitwarden-json') records = bitwardenRecords(root);
  else if (format === 'protonpass-json') records = protonRecords(root);
  else records = genericJsonRecords(root);

  if (records.length > MAX_IMPORT_ROWS)
    throw invalid('Die Importdatei enthaelt zu viele Datensaetze.');
  return { records, detectedColumns: collectColumns(records), errors: [] };
}

function bitwardenRecords(root: unknown): RawRecord[] {
  const source = asRecord(root);
  if (source === null || !Array.isArray(source.items)) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      'Die Datei ist kein unterstuetzter Bitwarden-Export.',
    );
  }
  if (source.encrypted === true) {
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      'Verschluesselte Bitwarden-Exporte muessen vor dem Import in Bitwarden entsperrt werden.',
    );
  }
  const folders = new Map<string, string>();
  for (const rawFolder of arrayValue(source.folders)) {
    const folder = asRecord(rawFolder);
    if (folder !== null) folders.set(stringValue(folder.id), stringValue(folder.name));
  }
  return source.items.flatMap((item) => {
    const record = asRecord(item);
    return record === null
      ? []
      : [{ ...record, __folderName: folders.get(stringValue(record.folderId)) ?? '' }];
  });
}

function protonRecords(root: unknown): RawRecord[] {
  const source = asRecord(root);
  if (source === null)
    throw new VaultaError('UNSUPPORTED_FORMAT', 'Die Datei ist kein Proton-Pass-Export.');
  const result: RawRecord[] = [];
  const vaults = asRecord(source.vaults);
  if (vaults !== null) {
    for (const vaultValue of Object.values(vaults)) {
      const vault = asRecord(vaultValue);
      if (vault === null) continue;
      const vaultName = readFirst(vault, ['name', 'vaultName']);
      for (const item of collectionValues(vault.items)) {
        const record = asRecord(item);
        if (record !== null) result.push({ ...record, __vaultName: vaultName });
      }
    }
  }
  if (result.length === 0) {
    for (const item of collectionValues(source.items)) {
      const record = asRecord(item);
      if (record !== null) result.push(record);
    }
  }
  if (result.length === 0) {
    throw new VaultaError('UNSUPPORTED_FORMAT', 'Der Proton-Pass-Export enthaelt keine Eintraege.');
  }
  return result;
}

function genericJsonRecords(root: unknown): RawRecord[] {
  const source = asRecord(root);
  const values = Array.isArray(root)
    ? root
    : source !== null && Array.isArray(source.items)
      ? source.items
      : source !== null && Array.isArray(source.entries)
        ? source.entries
        : [];
  if (values.length === 0) {
    throw new VaultaError('UNSUPPORTED_FORMAT', 'Die JSON-Datei enthaelt keine Eintragsliste.');
  }
  return values.flatMap((value) => {
    const record = asRecord(value);
    return record === null ? [] : [record];
  });
}

function detectMapping(columns: readonly string[], format: SupportedImportFormat): ImportMapping {
  const column = (...names: string[]): string => {
    for (const name of names) {
      const found = columns.find((candidate) => normalizeName(candidate) === normalizeName(name));
      if (found !== undefined) return found;
    }
    return '';
  };
  if (format === 'bitwarden-json' || format === 'protonpass-json') {
    return {
      title: 'name',
      username: 'username',
      password: 'password',
      url: 'url',
      note: 'notes',
      folder: 'folder',
      tags: 'tags',
    };
  }
  return {
    title: column('title', 'name', 'hostname'),
    username: column('username', 'user name', 'login_username', 'login', 'email'),
    password: column('password', 'login_password', 'pwd'),
    url: column('url', 'website', 'login_uri', 'hostname', 'origin'),
    note: column('note', 'notes', 'extra', 'comments'),
    folder: column('folder', 'group', 'grouping', 'vault', 'category'),
    tags: column('tags', 'tag'),
  };
}

function basicWarnings(
  title: string,
  username: string,
  password: string,
  website: string,
): string[] {
  const warnings: string[] = [];
  if (title.trim().length === 0) warnings.push('Titel fehlte und wurde ersetzt.');
  if (username.length === 0) warnings.push('Benutzername fehlt.');
  if (password.length === 0) warnings.push('Passwort fehlt.');
  if (website.length === 0) warnings.push('Webseite oder App-Bezeichnung fehlt.');
  return warnings;
}

function importMatcherEntry(entry: EntryInput, sourceIndex: number): VaultEntry {
  return {
    ...structuredClone(entry),
    id: `import:${sourceIndex}`,
    vaultId: IMPORT_MATCHER_VAULT_ID,
    attachments: [],
    lifecycle: structuredClone(entry.lifecycle ?? createDefaultEntryLifecycleMetadata()),
    createdAt: IMPORT_MATCHER_TIMESTAMP,
    updatedAt: IMPORT_MATCHER_TIMESTAMP,
    secretChangedAt: IMPORT_MATCHER_TIMESTAMP,
    lastUsedAt: null,
    deletedAt: null,
  };
}

function selectDuplicateSource(
  matches: readonly DuplicateCandidate[],
  importedEntry: VaultEntry,
  knownReferences: ReadonlyMap<string, ImportDuplicateSource>,
): string | null {
  const importedReference = duplicateReferenceKey(importedEntry.vaultId, importedEntry.id);
  const sources = matches.flatMap((candidate) =>
    [candidate.left, candidate.right].flatMap((reference) => {
      const key = duplicateReferenceKey(reference.vaultId, reference.entryId);
      if (key === importedReference) return [];
      const source = knownReferences.get(key);
      return source === undefined ? [] : [source];
    }),
  );
  sources.sort(
    (left, right) =>
      Number(left.imported) - Number(right.imported) ||
      left.order - right.order ||
      left.label.localeCompare(right.label, 'en'),
  );
  return sources[0]?.label ?? null;
}

function duplicateReferenceKey(vaultId: string, entryId: string): string {
  return JSON.stringify([vaultId, entryId]);
}

function bitwardenCustomFields(value: unknown): CustomField[] {
  return arrayValue(value).flatMap((item, index) => {
    const field = asRecord(item);
    const label = stringValue(field?.name).trim();
    if (field === null || label.length === 0) return [];
    const type = numberValue(field.type, 0);
    return [
      {
        id: randomUUID(),
        label,
        type:
          type === 2 ? ('boolean' as const) : type === 1 ? ('secret' as const) : ('text' as const),
        value: type === 2 ? parseBoolean(stringValue(field.value)) : stringValue(field.value),
        secret: type === 1,
        searchable: type !== 1,
        order: index,
      },
    ];
  });
}

function protonCustomFields(value: unknown): CustomField[] {
  return arrayValue(value).flatMap((item, index) => {
    const field = asRecord(item);
    if (field === null) return [];
    const label = readFirst(field, ['fieldName', 'name', 'label']).trim();
    if (label.length === 0) return [];
    const fieldType = readFirst(field, ['type', 'fieldType']).toLowerCase();
    const secret = fieldType.includes('hidden') || fieldType.includes('secret');
    return [
      {
        id: randomUUID(),
        label,
        type: secret ? ('secret' as const) : ('text' as const),
        value: readFirst(field, ['data', 'value', 'content']),
        secret,
        searchable: !secret,
        order: index,
      },
    ];
  });
}

function formatAddress(identity: RawRecord): string {
  return compact([
    stringValue(identity.address1),
    stringValue(identity.address2),
    [stringValue(identity.postalCode), stringValue(identity.city)].filter(Boolean).join(' '),
    stringValue(identity.state),
    stringValue(identity.country),
  ]).join('\n');
}

function readColumn(record: RawRecord, column: string): string {
  if (column.length === 0) return '';
  const direct = Object.entries(record).find(
    ([key]) => normalizeName(key) === normalizeName(column),
  );
  if (direct !== undefined) return stringValue(direct[1]);
  let current: unknown = record;
  for (const part of column.split('.')) {
    const object = asRecord(current);
    if (object === null) return '';
    const pair = Object.entries(object).find(([key]) => normalizeName(key) === normalizeName(part));
    if (pair === undefined) return '';
    current = pair[1];
  }
  return stringValue(current);
}

function readFirst(record: RawRecord, names: readonly string[]): string {
  for (const name of names) {
    const value = readColumn(record, name);
    if (value.length > 0) return value;
  }
  return '';
}

function collectColumns(records: readonly RawRecord[]): string[] {
  return [...new Set(records.slice(0, 100).flatMap((record) => Object.keys(record)))]
    .filter((column) => !column.startsWith('__'))
    .sort((left, right) => left.localeCompare(right, 'de'));
}

function collectionValues(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  const object = asRecord(value);
  return object === null ? [] : Object.values(object);
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asRecord(value: unknown): RawRecord | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as RawRecord)
    : null;
}

function stringValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(stringValue(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'yes', 'ja', 'y'].includes(stringValue(value).trim().toLowerCase());
}

function splitTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,;|]/u)
        .map((tag) => tag.trim())
        .filter(Boolean),
    ),
  ];
}

function compact(values: readonly string[]): string[] {
  return values.map((value) => value.trim()).filter(Boolean);
}

function normalizeName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, '');
}

function sanitizeSourceName(value: string): string {
  const name =
    value
      .split(/[\\/]/u)
      .pop()
      ?.split('')
      .filter((character) => {
        const code = character.charCodeAt(0);
        return code > 31 && code !== 127;
      })
      .join('')
      .trim() ?? '';
  return name.slice(0, 120) || 'Importdatei';
}

function ensureSafeSize(content: string): void {
  if (Buffer.byteLength(content, 'utf8') > MAX_IMPORT_BYTES) {
    throw new VaultaError('FILE_TOO_LARGE', 'Die Importdatei ist groesser als 50 MB.');
  }
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
