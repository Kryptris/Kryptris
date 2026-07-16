import { VaultaError } from '../../shared/errors';
import type {
  DisplayField,
  EntryDetail,
  EntryListQuery,
  EntrySummary,
  SecurityFinding,
  SecuritySeverity,
  VaultEntry,
} from '../../shared/models';
import { entrySubtitle } from './entry-utils';
import { SecurityCheckService } from './security-check-service';

const SEVERITY_ORDER: Record<SecuritySeverity, number> = {
  good: 0,
  info: 1,
  warning: 2,
  critical: 3,
};

function text(
  path: string,
  label: string,
  value: string | number | boolean,
  options: Partial<Pick<DisplayField, 'kind' | 'secret' | 'copyable' | 'openable'>> = {},
): DisplayField {
  const serialized = String(value);
  const secret = options.secret ?? false;
  const field: DisplayField = {
    path,
    label,
    kind: options.kind ?? (typeof value === 'boolean' ? 'boolean' : 'text'),
    secret,
    copyable: options.copyable ?? serialized.length > 0,
    openable: options.openable ?? false,
  };
  if (!secret) field.value = serialized;
  return field;
}

function safeHttps(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function fieldsForEntry(entry: VaultEntry): DisplayField[] {
  const fields: DisplayField[] = [];
  switch (entry.data.type) {
    case 'credential': {
      fields.push(text('data.username', 'Benutzername', entry.data.value.username));
      fields.push(text('data.password', 'Passwort', entry.data.value.password, { secret: true }));
      entry.data.value.websites.forEach((website, index) =>
        fields.push(
          text(
            `data.websites.${index}`,
            index === 0 ? 'Webseite' : `Webseite ${index + 1}`,
            website,
            {
              kind: 'url',
              openable: safeHttps(website),
            },
          ),
        ),
      );
      entry.data.value.appNames.forEach((appName, index) =>
        fields.push(
          text(`data.appNames.${index}`, index === 0 ? 'App' : `App ${index + 1}`, appName),
        ),
      );
      break;
    }
    case 'secure-note':
      fields.push(text('data.markdown', 'Inhalt', entry.data.value.markdown, { kind: 'markdown' }));
      break;
    case 'credit-card':
      fields.push(text('data.cardName', 'Kartenname', entry.data.value.cardName));
      fields.push(text('data.cardholder', 'Karteninhaber', entry.data.value.cardholder));
      fields.push(text('data.number', 'Kartennummer', entry.data.value.number, { secret: true }));
      fields.push(
        text(
          'data.expiry',
          'Ablaufdatum',
          entry.data.value.expiryMonth > 0
            ? `${String(entry.data.value.expiryMonth).padStart(2, '0')}/${entry.data.value.expiryYear}`
            : '',
          { kind: 'date' },
        ),
      );
      fields.push(text('data.cvc', 'CVC/CVV', entry.data.value.cvc, { secret: true }));
      fields.push(text('data.pin', 'PIN', entry.data.value.pin, { secret: true }));
      fields.push(text('data.issuer', 'Herausgeber', entry.data.value.issuer));
      fields.push(text('data.cardType', 'Kartentyp', entry.data.value.cardType));
      fields.push(
        text('data.billingAddress', 'Rechnungsadresse', entry.data.value.billingAddress, {
          kind: 'multiline',
        }),
      );
      fields.push(text('data.servicePhone', 'Service-Telefon', entry.data.value.servicePhone));
      fields.push(
        text('data.website', 'Webseite', entry.data.value.website, {
          kind: 'url',
          openable: safeHttps(entry.data.value.website),
        }),
      );
      break;
    case 'identity': {
      fields.push(text('data.salutation', 'Anrede', entry.data.value.salutation));
      fields.push(text('data.firstName', 'Vorname', entry.data.value.firstName));
      fields.push(text('data.middleName', 'Weitere Vornamen', entry.data.value.middleName));
      fields.push(text('data.lastName', 'Nachname', entry.data.value.lastName));
      fields.push(
        text('data.birthDate', 'Geburtsdatum', entry.data.value.birthDate, { kind: 'date' }),
      );
      entry.data.value.emails.forEach((email, index) =>
        fields.push(
          text(`data.emails.${index}`, index === 0 ? 'E-Mail' : `E-Mail ${index + 1}`, email),
        ),
      );
      entry.data.value.phones.forEach((phone, index) =>
        fields.push(
          text(`data.phones.${index}`, index === 0 ? 'Telefon' : `Telefon ${index + 1}`, phone),
        ),
      );
      entry.data.value.addresses.forEach((address, index) =>
        fields.push(
          text(
            `data.addresses.${index}`,
            address.label || `Adresse ${index + 1}`,
            [
              address.street,
              `${address.postalCode} ${address.city}`.trim(),
              address.region,
              address.country,
            ]
              .filter(Boolean)
              .join('\n'),
            { kind: 'multiline' },
          ),
        ),
      );
      fields.push(
        text('data.idNumber', 'Ausweisnummer', entry.data.value.idNumber, { secret: true }),
      );
      fields.push(
        text('data.passportNumber', 'Reisepassnummer', entry.data.value.passportNumber, {
          secret: true,
        }),
      );
      fields.push(
        text('data.taxNumber', 'Steuerdaten', entry.data.value.taxNumber, { secret: true }),
      );
      break;
    }
    case 'wifi':
      fields.push(text('data.ssid', 'SSID', entry.data.value.ssid));
      fields.push(text('data.password', 'Passwort', entry.data.value.password, { secret: true }));
      fields.push(text('data.security', 'Sicherheitsart', entry.data.value.security));
      fields.push(text('data.hidden', 'Verstecktes Netzwerk', entry.data.value.hidden));
      fields.push(text('data.routerAddress', 'Router-Adresse', entry.data.value.routerAddress));
      fields.push(
        text('data.routerUsername', 'Router-Benutzername', entry.data.value.routerUsername),
      );
      break;
    case 'software-license':
      fields.push(text('data.product', 'Produkt', entry.data.value.product));
      fields.push(text('data.manufacturer', 'Hersteller', entry.data.value.manufacturer));
      fields.push(text('data.version', 'Version', entry.data.value.version));
      fields.push(
        text('data.licenseKey', 'Lizenzschlüssel', entry.data.value.licenseKey, { secret: true }),
      );
      fields.push(text('data.licensedTo', 'Lizenziert für', entry.data.value.licensedTo));
      fields.push(
        text('data.purchaseDate', 'Kaufdatum', entry.data.value.purchaseDate, { kind: 'date' }),
      );
      fields.push(
        text('data.activationDate', 'Aktivierungsdatum', entry.data.value.activationDate, {
          kind: 'date',
        }),
      );
      fields.push(
        text('data.expiryDate', 'Ablaufdatum', entry.data.value.expiryDate, { kind: 'date' }),
      );
      fields.push(text('data.orderNumber', 'Bestellnummer', entry.data.value.orderNumber));
      fields.push(
        text('data.downloadUrl', 'Download-Adresse', entry.data.value.downloadUrl, {
          kind: 'url',
          openable: safeHttps(entry.data.value.downloadUrl),
        }),
      );
      fields.push(text('data.purchasePrice', 'Kaufpreis', entry.data.value.purchasePrice));
      break;
    case 'ssh-key':
      fields.push(text('data.host', 'Host', entry.data.value.host));
      fields.push(text('data.port', 'Port', entry.data.value.port));
      fields.push(text('data.username', 'Benutzername', entry.data.value.username));
      fields.push(text('data.keyType', 'Schlüsseltyp', entry.data.value.keyType));
      fields.push(text('data.fingerprint', 'Fingerabdruck', entry.data.value.fingerprint));
      fields.push(
        text('data.publicKey', 'Öffentlicher Schlüssel', entry.data.value.publicKey, {
          kind: 'multiline',
        }),
      );
      fields.push(
        text('data.privateKey', 'Privater Schlüssel', entry.data.value.privateKey, {
          kind: 'multiline',
          secret: true,
        }),
      );
      fields.push(
        text('data.passphrase', 'Passphrase', entry.data.value.passphrase, { secret: true }),
      );
      break;
    case 'file':
    case 'custom':
      fields.push(
        text('data.description', 'Beschreibung', entry.data.value.description, {
          kind: 'multiline',
        }),
      );
      break;
  }

  for (const custom of [...entry.customFields].sort((left, right) => left.order - right.order)) {
    fields.push(
      text(`custom.${custom.id}`, custom.label, custom.value, {
        kind:
          custom.type === 'url'
            ? 'url'
            : custom.type === 'date'
              ? 'date'
              : custom.type === 'boolean'
                ? 'boolean'
                : custom.type === 'text' && String(custom.value).includes('\n')
                  ? 'multiline'
                  : custom.type === 'secret'
                    ? 'secret'
                    : 'text',
        secret: custom.secret || custom.type === 'secret',
        openable: custom.type === 'url' && safeHttps(String(custom.value)),
      }),
    );
  }
  return fields.filter((field) => field.secret || (field.value ?? '').length > 0);
}

function entrySearchText(entry: VaultEntry): string {
  const parts = [entry.title, entry.note, ...entry.tags];
  switch (entry.data.type) {
    case 'credential':
      parts.push(
        entry.data.value.username,
        ...entry.data.value.websites,
        ...entry.data.value.appNames,
      );
      break;
    case 'secure-note':
      parts.push(entry.data.value.markdown);
      break;
    case 'credit-card':
      parts.push(
        entry.data.value.cardName,
        entry.data.value.cardholder,
        entry.data.value.issuer,
        entry.data.value.cardType,
      );
      break;
    case 'identity':
      parts.push(
        entry.data.value.firstName,
        entry.data.value.lastName,
        ...entry.data.value.emails,
        ...entry.data.value.phones,
      );
      break;
    case 'wifi':
      parts.push(
        entry.data.value.ssid,
        entry.data.value.routerAddress,
        entry.data.value.routerUsername,
      );
      break;
    case 'software-license':
      parts.push(entry.data.value.product, entry.data.value.manufacturer, entry.data.value.version);
      break;
    case 'ssh-key':
      parts.push(entry.data.value.host, entry.data.value.username, entry.data.value.fingerprint);
      break;
    case 'file':
    case 'custom':
      parts.push(entry.data.value.description);
      break;
  }
  parts.push(
    ...entry.customFields.filter((field) => field.searchable).map((field) => String(field.value)),
  );
  return parts.join('\n').normalize('NFKC').toLocaleLowerCase('de');
}

function highestSeverity(findings: SecurityFinding[]): SecuritySeverity {
  return findings.reduce<SecuritySeverity>(
    (highest, finding) =>
      SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[highest] ? finding.severity : highest,
    'good',
  );
}

export class EntryViewService {
  private readonly securityReports = new Map<string, SecurityFinding[]>();

  public constructor(private readonly security = new SecurityCheckService()) {}

  public list(entries: readonly VaultEntry[], query: EntryListQuery): EntrySummary[] {
    const report = this.securityReportFor(entries);
    const findingsByEntry = new Map<string, SecurityFinding[]>();
    for (const finding of report.findings) {
      const existing = findingsByEntry.get(finding.entryId) ?? [];
      existing.push(finding);
      findingsByEntry.set(finding.entryId, existing);
    }
    const normalizedSearch = query.search.trim().normalize('NFKC').toLocaleLowerCase('de');
    return entries
      .filter((entry) => {
        const deleted = entry.deletedAt !== null;
        if (query.view === 'trash' ? !deleted : deleted) return false;
        if (query.view === 'favorites' && !entry.favorite) return false;
        if (query.view === 'recent' && entry.lastUsedAt === null) return false;
        if (query.types.length > 0 && !query.types.includes(entry.data.type)) return false;
        if (query.tags.length > 0 && !query.tags.every((tag) => entry.tags.includes(tag)))
          return false;
        if (query.folderId !== null && entry.folderId !== query.folderId) return false;
        const severity = highestSeverity(findingsByEntry.get(entry.id) ?? []);
        if (query.security.length > 0 && !query.security.includes(severity)) return false;
        return normalizedSearch.length === 0 || entrySearchText(entry).includes(normalizedSearch);
      })
      .sort((left, right) => {
        if (query.view === 'recent') {
          return (right.lastUsedAt ?? '').localeCompare(left.lastUsedAt ?? '');
        }
        return left.title.localeCompare(right.title, 'de', { sensitivity: 'base' });
      })
      .map((entry) => ({
        id: entry.id,
        vaultId: entry.vaultId,
        type: entry.data.type,
        title: entry.title,
        subtitle: entrySubtitle(entry),
        favorite: entry.favorite,
        tags: [...entry.tags],
        folderId: entry.folderId,
        securityState: highestSeverity(findingsByEntry.get(entry.id) ?? []),
        updatedAt: entry.updatedAt,
        deletedAt: entry.deletedAt,
      }));
  }

  private securityReportFor(entries: readonly VaultEntry[]): { findings: SecurityFinding[] } {
    const activeEntries = entries.filter((entry) => entry.deletedAt === null);
    const revision = activeEntries
      .map((entry) => `${entry.id}:${entry.updatedAt}:${entry.secretChangedAt}`)
      .sort()
      .join('|');
    const cached = this.securityReports.get(revision);
    if (cached !== undefined) return { findings: cached };

    const findings = this.security.scan(activeEntries).findings;
    this.securityReports.clear();
    this.securityReports.set(revision, findings);
    return { findings };
  }

  public detail(entry: VaultEntry): EntryDetail {
    return {
      id: entry.id,
      vaultId: entry.vaultId,
      type: entry.data.type,
      title: entry.title,
      favorite: entry.favorite,
      tags: [...entry.tags],
      folderId: entry.folderId,
      note: entry.note,
      fields: fieldsForEntry(entry),
      attachments: entry.attachments.map((attachment) => ({ ...attachment })),
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      deletedAt: entry.deletedAt,
    };
  }

  public fieldValue(entry: VaultEntry, fieldPath: string): string {
    const field = fieldsForEntry(entry).find((candidate) => candidate.path === fieldPath);
    if (field === undefined) throw new VaultaError('NOT_FOUND', 'Das Feld wurde nicht gefunden.');
    if (fieldPath.startsWith('custom.')) {
      const custom = entry.customFields.find((candidate) => `custom.${candidate.id}` === fieldPath);
      if (custom === undefined)
        throw new VaultaError('NOT_FOUND', 'Das Feld wurde nicht gefunden.');
      return typeof custom.value === 'boolean'
        ? custom.value
          ? 'Ja'
          : 'Nein'
        : String(custom.value);
    }
    return this.dataFieldValue(entry, fieldPath);
  }

  private dataFieldValue(entry: VaultEntry, path: string): string {
    if (path === 'data.expiry' && entry.data.type === 'credit-card') {
      return `${String(entry.data.value.expiryMonth).padStart(2, '0')}/${entry.data.value.expiryYear}`;
    }
    if (path.startsWith('data.addresses.') && entry.data.type === 'identity') {
      const index = Number(path.split('.')[2]);
      const address = entry.data.value.addresses[index];
      if (address === undefined)
        throw new VaultaError('NOT_FOUND', 'Die Adresse wurde nicht gefunden.');
      return [
        address.street,
        `${address.postalCode} ${address.city}`.trim(),
        address.region,
        address.country,
      ]
        .filter(Boolean)
        .join('\n');
    }
    const parts = path.split('.');
    if (parts[0] !== 'data') throw new VaultaError('INVALID_INPUT', 'Der Feldpfad ist ungültig.');
    const key = parts[1];
    if (key === undefined || !Object.prototype.hasOwnProperty.call(entry.data.value, key)) {
      throw new VaultaError('NOT_FOUND', 'Das Feld wurde nicht gefunden.');
    }
    const raw = (entry.data.value as unknown as Record<string, unknown>)[key];
    if (Array.isArray(raw)) {
      const index = Number(parts[2]);
      const values: unknown[] = raw;
      const value: unknown = values[index];
      if (typeof value !== 'string')
        throw new VaultaError('NOT_FOUND', 'Das Feld wurde nicht gefunden.');
      return value;
    }
    if (typeof raw === 'string' || typeof raw === 'number') return String(raw);
    if (typeof raw === 'boolean') return raw ? 'Ja' : 'Nein';
    throw new VaultaError('NOT_FOUND', 'Das Feld wurde nicht gefunden.');
  }
}
