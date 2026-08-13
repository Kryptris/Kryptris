import { randomUUID } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type {
  BatchEntryInput,
  BatchEntryResult,
  SavedView,
  SavedViewFilters,
  SavedViewRecord,
  TagSummary,
  VaultDocument,
  VaultEntry,
} from '../../shared/models';
import { normalizeTagKey, normalizeTagName, normalizeTags } from '../../shared/tags';

export interface SavedViewInput {
  id?: string;
  vaultId: string;
  name: string;
  filters: SavedViewFilters;
}

export interface BatchMutationResult extends BatchEntryResult {
  purgedAttachmentIds: string[];
}

export class ProductivityService {
  private readonly savedViews = new Map<string, SavedViewRecord>();

  public constructor(
    initialSavedViews: readonly SavedViewRecord[] = [],
    private readonly now: () => Date = () => new Date(),
  ) {
    for (const view of initialSavedViews) this.savedViews.set(view.id, structuredClone(view));
  }

  public listSavedViews(vaultId: string, document: VaultDocument): SavedView[] {
    const folderIds = new Set(document.folders.map((folder) => folder.id));
    const tagNames = new Set(document.entries.flatMap((entry) => entry.tags.map(normalizeTagKey)));
    return [...this.savedViews.values()]
      .filter((view) => view.vaultId === vaultId)
      .sort((left, right) => left.order - right.order || left.name.localeCompare(right.name, 'de'))
      .map((view) => ({
        ...structuredClone(view),
        invalidReferences: {
          folder: view.filters.folderId !== null && !folderIds.has(view.filters.folderId),
          tags: view.filters.tags.filter((tag) => !tagNames.has(normalizeTagKey(tag))),
        },
      }));
  }

  public saveSavedView(input: SavedViewInput): SavedViewRecord {
    const name = input.name.normalize('NFKC').trim().replace(/\s+/gu, ' ');
    if (name.length < 1 || name.length > 200) throw invalid('Der Ansichtsname ist ungültig.');
    const existing = input.id === undefined ? undefined : this.savedViews.get(input.id);
    if (input.id !== undefined && (existing === undefined || existing.vaultId !== input.vaultId)) {
      throw new VaultaError('NOT_FOUND', 'Die gespeicherte Ansicht wurde nicht gefunden.');
    }
    const duplicate = [...this.savedViews.values()].some(
      (view) =>
        view.vaultId === input.vaultId &&
        view.id !== input.id &&
        view.name.normalize('NFKC').toLocaleLowerCase('de') === name.toLocaleLowerCase('de'),
    );
    if (duplicate)
      throw new VaultaError('CONFLICT', 'Eine Ansicht mit diesem Namen existiert bereits.');

    const timestamp = this.now().toISOString();
    const order =
      existing?.order ??
      [...this.savedViews.values()].filter((view) => view.vaultId === input.vaultId).length;
    const view: SavedViewRecord = {
      id: existing?.id ?? randomUUID(),
      vaultId: input.vaultId,
      name,
      filters: cloneFilters(input.filters),
      order,
      createdAt: existing?.createdAt ?? timestamp,
      updatedAt: timestamp,
    };
    this.savedViews.set(view.id, structuredClone(view));
    return structuredClone(view);
  }

  public reorderSavedViews(vaultId: string, orderedIds: readonly string[]): void {
    const current = [...this.savedViews.values()]
      .filter((view) => view.vaultId === vaultId)
      .map((view) => view.id)
      .sort();
    const requested = [...orderedIds].sort();
    if (
      new Set(orderedIds).size !== orderedIds.length ||
      JSON.stringify(current) !== JSON.stringify(requested)
    ) {
      throw invalid('Die Sortierung passt nicht zu den gespeicherten Ansichten.');
    }
    const timestamp = this.now().toISOString();
    orderedIds.forEach((id, order) => {
      const view = this.savedViews.get(id);
      if (view === undefined) return;
      view.order = order;
      view.updatedAt = timestamp;
    });
  }

  public deleteSavedView(vaultId: string, id: string): void {
    const view = this.savedViews.get(id);
    if (view === undefined || view.vaultId !== vaultId) {
      throw new VaultaError('NOT_FOUND', 'Die gespeicherte Ansicht wurde nicht gefunden.');
    }
    this.savedViews.delete(id);
    this.compactSavedViewOrder(vaultId);
  }

  public deleteSavedViewsForVault(vaultId: string): void {
    for (const view of this.savedViews.values()) {
      if (view.vaultId === vaultId) this.savedViews.delete(view.id);
    }
  }

  public snapshot(): SavedViewRecord[] {
    return [...this.savedViews.values()]
      .sort(
        (left, right) =>
          left.vaultId.localeCompare(right.vaultId) ||
          left.order - right.order ||
          left.name.localeCompare(right.name, 'de'),
      )
      .map((view) => structuredClone(view));
  }

  public listTags(document: VaultDocument): TagSummary[] {
    const tags = new Map<string, TagSummary>();
    for (const entry of document.entries) {
      const seen = new Set<string>();
      for (const rawTag of entry.tags) {
        const name = normalizeTagName(rawTag);
        const normalizedName = normalizeTagKey(name);
        if (name.length === 0 || seen.has(normalizedName)) continue;
        seen.add(normalizedName);
        const existing = tags.get(normalizedName);
        if (existing === undefined) {
          tags.set(normalizedName, { name, normalizedName, usageCount: 1 });
        } else {
          existing.usageCount += 1;
        }
      }
    }
    return [...tags.values()].sort(
      (left, right) =>
        right.usageCount - left.usageCount || left.name.localeCompare(right.name, 'de'),
    );
  }

  public renameTag(document: VaultDocument, sourceTag: string, targetTag: string): string[] {
    const sourceKey = normalizeTagKey(sourceTag);
    const targetName = normalizeTagName(targetTag);
    const targetKey = normalizeTagKey(targetName);
    if (sourceKey.length === 0 || targetName.length === 0)
      throw invalid('Der Tagname ist ungültig.');
    const known = new Set(document.entries.flatMap((entry) => entry.tags.map(normalizeTagKey)));
    if (!known.has(sourceKey)) throw new VaultaError('NOT_FOUND', 'Der Tag wurde nicht gefunden.');
    if (sourceKey !== targetKey && known.has(targetKey)) {
      throw new VaultaError('CONFLICT', 'Der Ziel-Tag existiert bereits. Verwende Zusammenführen.');
    }
    return this.rewriteTags(document, new Set([sourceKey]), targetName);
  }

  public mergeTags(
    document: VaultDocument,
    sourceTags: readonly string[],
    targetTag: string,
  ): string[] {
    const sourceKeys = new Set(sourceTags.map(normalizeTagKey));
    const targetName = normalizeTagName(targetTag);
    if (sourceKeys.size === 0 || sourceKeys.has('') || targetName.length === 0) {
      throw invalid('Die Tag-Auswahl ist ungültig.');
    }
    const known = new Set(document.entries.flatMap((entry) => entry.tags.map(normalizeTagKey)));
    const missing = [...sourceKeys].filter((key) => !known.has(key));
    if (missing.length > 0)
      throw new VaultaError('NOT_FOUND', 'Mindestens ein Tag wurde nicht gefunden.');
    sourceKeys.add(normalizeTagKey(targetName));
    return this.rewriteTags(document, sourceKeys, targetName);
  }

  public deleteTag(document: VaultDocument, tag: string): string[] {
    const sourceKey = normalizeTagKey(tag);
    const known = document.entries.some((entry) =>
      entry.tags.some((item) => normalizeTagKey(item) === sourceKey),
    );
    if (!known) throw new VaultaError('NOT_FOUND', 'Der Tag wurde nicht gefunden.');
    const timestamp = this.now().toISOString();
    const affected: string[] = [];
    for (const entry of document.entries) {
      const next = entry.tags.filter((item) => normalizeTagKey(item) !== sourceKey);
      if (next.length === entry.tags.length) continue;
      entry.tags = normalizeTags(next);
      entry.updatedAt = timestamp;
      affected.push(entry.id);
    }
    return affected;
  }

  public applyBatch(document: VaultDocument, input: BatchEntryInput): BatchMutationResult {
    if (input.vaultId !== document.id)
      throw invalid('Batch-Aktion und Tresor passen nicht zusammen.');
    if (input.entryIds.length === 0 || new Set(input.entryIds).size !== input.entryIds.length) {
      throw invalid('Die Batch-Auswahl ist ungültig.');
    }
    if (input.action.type === 'copy-to-vault' || input.action.type === 'move-to-vault') {
      throw new VaultaError(
        'UNSUPPORTED_FORMAT',
        'Tresorübergreifendes Kopieren und Verschieben wird durch den separaten Transfer-Service bereitgestellt.',
      );
    }
    const byId = new Map(document.entries.map((entry) => [entry.id, entry]));
    const selected = input.entryIds.map((id) => {
      const entry = byId.get(id);
      if (entry === undefined)
        throw new VaultaError('NOT_FOUND', 'Ein ausgewählter Eintrag wurde nicht gefunden.');
      return entry;
    });
    this.validateBatchState(document, selected, input);

    const timestamp = this.now().toISOString();
    const changed = new Set<string>();
    const purgedAttachmentIds: string[] = [];
    switch (input.action.type) {
      case 'favorite':
        for (const entry of selected) {
          if (entry.favorite === input.action.value) continue;
          entry.favorite = input.action.value;
          changed.add(entry.id);
        }
        break;
      case 'tags-add': {
        const additions = normalizeTags(input.action.tags);
        for (const entry of selected) {
          const next = normalizeTags([...entry.tags, ...additions]);
          if (sameTags(entry.tags, next)) continue;
          entry.tags = next;
          changed.add(entry.id);
        }
        break;
      }
      case 'tags-remove': {
        const removals = new Set(input.action.tags.map(normalizeTagKey));
        for (const entry of selected) {
          const next = normalizeTags(
            entry.tags.filter((tag) => !removals.has(normalizeTagKey(tag))),
          );
          if (sameTags(entry.tags, next)) continue;
          entry.tags = next;
          changed.add(entry.id);
        }
        break;
      }
      case 'folder-set':
        for (const entry of selected) {
          if (entry.folderId === input.action.folderId) continue;
          entry.folderId = input.action.folderId;
          changed.add(entry.id);
        }
        break;
      case 'trash':
        for (const entry of selected) {
          entry.deletedAt = timestamp;
          changed.add(entry.id);
        }
        break;
      case 'restore':
        for (const entry of selected) {
          entry.deletedAt = null;
          changed.add(entry.id);
        }
        break;
      case 'purge': {
        const selectedIds = new Set(selected.map((entry) => entry.id));
        purgedAttachmentIds.push(
          ...selected.flatMap((entry) => entry.attachments.map((item) => item.id)),
        );
        document.entries = document.entries.filter((entry) => !selectedIds.has(entry.id));
        selectedIds.forEach((id) => changed.add(id));
        break;
      }
    }
    for (const entry of selected) if (changed.has(entry.id)) entry.updatedAt = timestamp;
    return { affected: changed.size, entryIds: [...changed], purgedAttachmentIds };
  }

  private validateBatchState(
    document: VaultDocument,
    entries: readonly VaultEntry[],
    input: BatchEntryInput,
  ): void {
    const action = input.action;
    if (
      action.type === 'folder-set' &&
      action.folderId !== null &&
      !document.folders.some((folder) => folder.id === action.folderId)
    ) {
      throw new VaultaError('NOT_FOUND', 'Der Zielordner wurde nicht gefunden.');
    }
    if (action.type === 'trash' && entries.some((entry) => entry.deletedAt !== null)) {
      throw new VaultaError(
        'CONFLICT',
        'Bereits gelöschte Einträge können nicht erneut verschoben werden.',
      );
    }
    if (
      ['favorite', 'tags-add', 'tags-remove', 'folder-set'].includes(action.type) &&
      entries.some((entry) => entry.deletedAt !== null)
    ) {
      throw new VaultaError(
        'CONFLICT',
        'Einträge im Papierkorb können nur wiederhergestellt oder endgültig gelöscht werden.',
      );
    }
    if (
      (action.type === 'restore' || action.type === 'purge') &&
      entries.some((entry) => entry.deletedAt === null)
    ) {
      throw new VaultaError('CONFLICT', 'Diese Aktion gilt nur für Einträge im Papierkorb.');
    }
    if (action.type === 'purge' && action.confirmationCount !== entries.length) {
      throw invalid('Die bestätigte Anzahl stimmt nicht mit der Auswahl überein.');
    }
  }

  private rewriteTags(
    document: VaultDocument,
    sourceKeys: Set<string>,
    targetName: string,
  ): string[] {
    const timestamp = this.now().toISOString();
    const affected: string[] = [];
    for (const entry of document.entries) {
      if (!entry.tags.some((tag) => sourceKeys.has(normalizeTagKey(tag)))) continue;
      const retained = entry.tags.filter((tag) => !sourceKeys.has(normalizeTagKey(tag)));
      entry.tags = normalizeTags([...retained, targetName]);
      entry.updatedAt = timestamp;
      affected.push(entry.id);
    }
    return affected;
  }

  private compactSavedViewOrder(vaultId: string): void {
    [...this.savedViews.values()]
      .filter((view) => view.vaultId === vaultId)
      .sort((left, right) => left.order - right.order)
      .forEach((view, order) => void (view.order = order));
  }
}

function cloneFilters(filters: SavedViewFilters): SavedViewFilters {
  return {
    search: filters.search,
    view: filters.view,
    types: [...filters.types],
    tags: normalizeTags(filters.tags),
    folderId: filters.folderId,
    security: [...filters.security],
    smartView: filters.smartView,
  };
}

function sameTags(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((tag, index) => normalizeTagKey(tag) === normalizeTagKey(right[index] ?? ''))
  );
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
