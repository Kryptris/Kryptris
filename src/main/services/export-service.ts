import { VaultaError } from '../../shared/errors';
import type { VaultDocument, VaultEntry } from '../../shared/models';

export interface CleartextExportOptions {
  includeAttachmentMetadata?: boolean;
  includeTrash?: boolean;
}

export interface PreparedCleartextExport {
  content: string;
  mediaType: string;
  extension: 'json' | 'csv';
  entryCount: number;
}

export class ExportService {
  public prepare(
    format: 'json' | 'csv',
    vaults: readonly VaultDocument[],
    options: CleartextExportOptions = {},
  ): PreparedCleartextExport {
    const entries = collectEntries(vaults, options.includeTrash ?? false);
    if (format === 'json') {
      return {
        content: this.prepareJson(vaults, options),
        mediaType: 'application/json; charset=utf-8',
        extension: 'json',
        entryCount: entries.length,
      };
    }
    if (format === 'csv') {
      return {
        content: this.prepareCsv(vaults, options),
        mediaType: 'text/csv; charset=utf-8',
        extension: 'csv',
        entryCount: entries.length,
      };
    }
    throw new VaultaError(
      'UNSUPPORTED_FORMAT',
      'Dieses Klartext-Exportformat wird nicht unterstuetzt.',
    );
  }

  private prepareJson(vaults: readonly VaultDocument[], options: CleartextExportOptions): string {
    const includeTrash = options.includeTrash ?? false;
    const includeAttachments = options.includeAttachmentMetadata ?? false;
    const payload = {
      format: 'vaulta-cleartext-json',
      formatVersion: 1,
      exportedAt: new Date().toISOString(),
      warning: 'Diese Datei enthaelt unverschluesselte Geheimnisse.',
      vaults: vaults.map((vault) => ({
        id: vault.id,
        name: vault.name,
        color: vault.color,
        createdAt: vault.createdAt,
        updatedAt: vault.updatedAt,
        folders: vault.folders,
        entries: vault.entries
          .filter((entry) => includeTrash || entry.deletedAt === null)
          .map((entry) => exportableEntry(entry, includeAttachments)),
      })),
    };
    return `${JSON.stringify(payload, null, 2)}\n`;
  }

  private prepareCsv(vaults: readonly VaultDocument[], options: CleartextExportOptions): string {
    const includeTrash = options.includeTrash ?? false;
    const includeAttachments = options.includeAttachmentMetadata ?? false;
    const headers = [
      'vault_name',
      'vault_id',
      'entry_id',
      'type',
      'title',
      'username',
      'password',
      'url',
      'note',
      'folder_id',
      'tags',
      'favorite',
      'deleted_at',
      'custom_fields',
      'data',
      'attachments',
    ];
    const rows: string[][] = [headers];

    for (const vault of vaults) {
      for (const entry of vault.entries) {
        if (!includeTrash && entry.deletedAt !== null) continue;
        const credential = entry.data.type === 'credential' ? entry.data.value : null;
        rows.push([
          vault.name,
          vault.id,
          entry.id,
          entry.data.type,
          entry.title,
          credential?.username ?? '',
          credential?.password ?? '',
          credential?.websites[0] ?? '',
          entry.note,
          entry.folderId ?? '',
          entry.tags.join(';'),
          String(entry.favorite),
          entry.deletedAt ?? '',
          JSON.stringify(entry.customFields),
          JSON.stringify(entry.data.value),
          includeAttachments ? JSON.stringify(entry.attachments) : '',
        ]);
      }
    }

    return `\uFEFF${rows.map((row) => row.map(csvCell).join(',')).join('\r\n')}\r\n`;
  }
}

function collectEntries(vaults: readonly VaultDocument[], includeTrash: boolean): VaultEntry[] {
  return vaults.flatMap((vault) =>
    vault.entries.filter((entry) => includeTrash || entry.deletedAt === null),
  );
}

function exportableEntry(entry: VaultEntry, includeAttachments: boolean): Record<string, unknown> {
  return {
    id: entry.id,
    title: entry.title,
    folderId: entry.folderId,
    tags: entry.tags,
    favorite: entry.favorite,
    note: entry.note,
    customFields: entry.customFields,
    ...(includeAttachments ? { attachments: entry.attachments } : {}),
    data: entry.data,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    secretChangedAt: entry.secretChangedAt,
    lastUsedAt: entry.lastUsedAt,
    deletedAt: entry.deletedAt,
  };
}

function csvCell(value: string): string {
  // Fuehrende Formelzeichen werden neutralisiert, damit Tabellenprogramme keine
  // importierten Geheimnisse als Formel ausfuehren. JSON bleibt der verlustfreie Export.
  const safe = /^[=+\-@]/u.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/gu, '""')}"`;
}
