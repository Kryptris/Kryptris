import type { SavedViewRecord, VaultDocument, VaultEntry } from '../../shared/models';
import {
  DataQualityError,
  type DataQualityFixCode,
  type DataQualityFixPlan,
  type DataQualityLocation,
  type DataQualityReference,
} from './data-quality-service';

export interface DataQualityFixSnapshot {
  document: VaultDocument;
  savedViews: readonly SavedViewRecord[];
}

export interface DataQualityFixApplyOptions {
  now?: Date;
  assertAuthorized?: () => void;
}

export interface DataQualityFixResult {
  document: VaultDocument;
  savedViews: SavedViewRecord[];
  appliedFindingId: string;
  updatedAt: string;
}

type UrlLocation = Extract<DataQualityLocation, { kind: 'url' }>;

type PreparedFix =
  | {
      kind: 'replace-entry-url';
      entryIndex: number;
      location: UrlLocation;
      value: string;
    }
  | {
      kind: 'remove-entry-website';
      entryIndex: number;
      websiteIndex: number;
    }
  | {
      kind: 'replace-entry-title';
      entryIndex: number;
      value: string;
    }
  | {
      kind: 'clear-entry-folder';
      entryIndex: number;
    }
  | {
      kind: 'remove-saved-view-references';
      savedViewIndex: number;
      clearFolder: boolean;
      removeTagIndexes: number[];
    }
  | {
      kind: 'update-attachment-metadata';
      entryIndex: number;
      attachmentIndex: number;
      size: number;
      sha256: string;
    };

const FIX_TO_MUTATION: Readonly<Record<DataQualityFixCode, PreparedFix['kind']>> = {
  'normalize-url-https-whitespace': 'replace-entry-url',
  'remove-exact-duplicate-url': 'remove-entry-website',
  'replace-unambiguous-title': 'replace-entry-title',
  'clear-orphan-folder': 'clear-entry-folder',
  'remove-saved-view-references': 'remove-saved-view-references',
  'update-authenticated-attachment-metadata': 'update-attachment-metadata',
};

const FIX_TO_FINDING_CODES: Readonly<Record<DataQualityFixCode, readonly string[]>> = {
  'normalize-url-https-whitespace': ['url-needs-normalization'],
  'remove-exact-duplicate-url': ['duplicate-website'],
  'replace-unambiguous-title': ['empty-title', 'import-placeholder-title'],
  'clear-orphan-folder': ['orphan-folder-reference'],
  'remove-saved-view-references': ['saved-view-orphan-reference'],
  'update-authenticated-attachment-metadata': ['attachment-metadata-mismatch'],
};

const SHA256_HEX = /^[a-f\d]{64}$/u;

/**
 * Applies an already-reviewed data-quality plan to fresh snapshots. This service deliberately does
 * not repeat URL, title, duplicate, folder, tag, expiry, TOTP, or attachment heuristics.
 */
export class DataQualityFixService {
  public apply(
    input: DataQualityFixSnapshot,
    plan: DataQualityFixPlan,
    options: DataQualityFixApplyOptions = {},
  ): DataQualityFixResult {
    const assertAuthorized = options.assertAuthorized ?? noOp;
    const updatedAt = validateNow(options.now).toISOString();
    assertAuthorized();

    const prepared = prepareFix(input, plan);
    assertAuthorized();

    const output = cloneSnapshot(input);
    applyPreparedFix(output, prepared, updatedAt);
    return {
      document: output.document,
      savedViews: output.savedViews,
      appliedFindingId: plan.findingId,
      updatedAt,
    };
  }
}

function prepareFix(input: DataQualityFixSnapshot, plan: DataQualityFixPlan): PreparedFix {
  validateEnvelope(input, plan);
  const expectedMutation = FIX_TO_MUTATION[plan.fixCode];
  if (plan.mutation.kind !== expectedMutation) throw inconsistentPlan();
  validateFindingId(plan);

  switch (plan.mutation.kind) {
    case 'replace-entry-url':
      return prepareUrlReplacement(
        input,
        plan.reference,
        plan.mutation.location,
        plan.mutation.value,
      );
    case 'remove-entry-website':
      return prepareWebsiteRemoval(input, plan.reference, plan.mutation.index);
    case 'replace-entry-title':
      return prepareTitleReplacement(input, plan.reference, plan.mutation.value);
    case 'clear-entry-folder':
      return {
        kind: 'clear-entry-folder',
        entryIndex: requireEntryIndex(input, plan.reference),
      };
    case 'remove-saved-view-references':
      return prepareSavedViewUpdate(
        input,
        plan.reference,
        plan.mutation.clearFolder,
        plan.mutation.removeTagIndexes,
      );
    case 'update-attachment-metadata':
      if (!isRecord(plan.mutation.metadata)) throw inconsistentPlan();
      return prepareAttachmentUpdate(
        input,
        plan.reference,
        plan.mutation.attachmentId,
        plan.mutation.metadata.size,
        plan.mutation.metadata.sha256,
      );
  }
}

function validateEnvelope(input: DataQualityFixSnapshot, plan: DataQualityFixPlan): void {
  if (
    !isRecord(input) ||
    !isRecord(input.document) ||
    !Array.isArray(input.document.entries) ||
    !Array.isArray(input.savedViews)
  ) {
    throw invalidInput('Die Datenqualitaets-Snapshots sind ungueltig.');
  }
  if (
    !isRecord(plan) ||
    typeof plan.findingId !== 'string' ||
    plan.findingId.length === 0 ||
    typeof plan.fixCode !== 'string' ||
    !Object.hasOwn(FIX_TO_MUTATION, plan.fixCode) ||
    !isRecord(plan.reference) ||
    !isRecord(plan.mutation) ||
    typeof plan.mutation.kind !== 'string'
  ) {
    throw inconsistentPlan();
  }
  if (
    !['entry', 'saved-view', 'attachment'].includes(String(plan.reference.kind)) ||
    typeof plan.reference.vaultId !== 'string' ||
    typeof plan.reference.updatedAt !== 'string'
  ) {
    throw inconsistentPlan();
  }
  if (plan.reference.vaultId !== input.document.id) throw staleReference();
}

function validateFindingId(plan: DataQualityFixPlan): void {
  const subjectId = referenceId(plan.reference);
  const codes = FIX_TO_FINDING_CODES[plan.fixCode];
  const valid = codes.some((code) =>
    plan.findingId.startsWith(`${plan.reference.kind}:${subjectId}:${code}:`),
  );
  if (!valid) throw inconsistentPlan();
}

function prepareUrlReplacement(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
  location: UrlLocation,
  value: string,
): PreparedFix {
  const entryIndex = requireEntryIndex(input, reference);
  const entry = input.document.entries[entryIndex]!;
  if (!isRecord(location) || location.kind !== 'url') throw inconsistentPlan();
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) {
    throw inconsistentPlan();
  }

  switch (location.field) {
    case 'credential-website':
      requireFixedUrlLocation(location, true);
      if (
        entry.data.type !== 'credential' ||
        location.index === null ||
        location.index >= entry.data.value.websites.length
      ) {
        throw inconsistentPlan();
      }
      break;
    case 'credit-card-website':
      requireFixedUrlLocation(location, false);
      if (entry.data.type !== 'credit-card') throw inconsistentPlan();
      break;
    case 'license-download-url':
      requireFixedUrlLocation(location, false);
      if (entry.data.type !== 'software-license') throw inconsistentPlan();
      break;
    case 'custom-url-field': {
      if (
        !isValidIndex(location.index) ||
        typeof location.customFieldId !== 'string' ||
        location.customFieldId.length === 0
      ) {
        throw inconsistentPlan();
      }
      const field = entry.customFields[location.index];
      if (
        !field ||
        field.id !== location.customFieldId ||
        field.type !== 'url' ||
        typeof field.value !== 'string'
      ) {
        throw inconsistentPlan();
      }
      break;
    }
    default:
      throw inconsistentPlan();
  }

  return { kind: 'replace-entry-url', entryIndex, location: clone(location), value };
}

function prepareWebsiteRemoval(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
  websiteIndex: number,
): PreparedFix {
  const entryIndex = requireEntryIndex(input, reference);
  const entry = input.document.entries[entryIndex]!;
  if (
    entry.data.type !== 'credential' ||
    !isValidIndex(websiteIndex) ||
    websiteIndex >= entry.data.value.websites.length
  ) {
    throw inconsistentPlan();
  }
  return { kind: 'remove-entry-website', entryIndex, websiteIndex };
}

function prepareTitleReplacement(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
  value: string,
): PreparedFix {
  const entryIndex = requireEntryIndex(input, reference);
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > 200 ||
    value !== value.normalize('NFKC').trim()
  ) {
    throw inconsistentPlan();
  }
  return { kind: 'replace-entry-title', entryIndex, value };
}

function prepareSavedViewUpdate(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
  clearFolder: boolean,
  removeTagIndexes: number[],
): PreparedFix {
  const savedViewIndex = requireSavedViewIndex(input, reference);
  const view = input.savedViews[savedViewIndex]!;
  if (
    typeof clearFolder !== 'boolean' ||
    !Array.isArray(removeTagIndexes) ||
    (!clearFolder && removeTagIndexes.length === 0)
  ) {
    throw inconsistentPlan();
  }
  let previousIndex = -1;
  for (const index of removeTagIndexes) {
    if (!isValidIndex(index) || index <= previousIndex || index >= view.filters.tags.length) {
      throw inconsistentPlan();
    }
    previousIndex = index;
  }
  return {
    kind: 'remove-saved-view-references',
    savedViewIndex,
    clearFolder,
    removeTagIndexes: [...removeTagIndexes],
  };
}

function prepareAttachmentUpdate(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
  attachmentId: string,
  size: number,
  sha256: string,
): PreparedFix {
  if (reference.kind !== 'attachment' || reference.entryId === null) throw inconsistentPlan();
  if (attachmentId !== reference.attachmentId) throw inconsistentPlan();
  if (!Number.isSafeInteger(size) || size < 0 || !SHA256_HEX.test(sha256)) {
    throw inconsistentPlan();
  }
  const entryIndex = requireEntryById(
    input,
    reference.entryId,
    reference.updatedAt,
    reference.vaultId,
  );
  const attachments = input.document.entries[entryIndex]!.attachments;
  const attachmentIndexes = attachments.flatMap((attachment, index) =>
    attachment.id === attachmentId ? [index] : [],
  );
  if (attachmentIndexes.length === 0) throw staleReference();
  if (attachmentIndexes.length !== 1) throw invalidInput('Attachment-IDs sind nicht eindeutig.');
  return {
    kind: 'update-attachment-metadata',
    entryIndex,
    attachmentIndex: attachmentIndexes[0]!,
    size,
    sha256,
  };
}

function requireEntryIndex(input: DataQualityFixSnapshot, reference: DataQualityReference): number {
  if (reference.kind !== 'entry') throw inconsistentPlan();
  return requireEntryById(input, reference.entryId, reference.updatedAt, reference.vaultId);
}

function requireEntryById(
  input: DataQualityFixSnapshot,
  entryId: string,
  updatedAt: string,
  vaultId: string,
): number {
  const indexes = input.document.entries.flatMap((entry, index) =>
    entry.id === entryId ? [index] : [],
  );
  if (indexes.length === 0) throw staleReference();
  if (indexes.length !== 1) throw invalidInput('Eintrags-IDs sind nicht eindeutig.');
  const entry = input.document.entries[indexes[0]!]!;
  if (entry.vaultId !== vaultId || entry.vaultId !== input.document.id) {
    throw invalidInput('Der Eintrag gehoert nicht zum Vault-Dokument.');
  }
  if (entry.updatedAt !== updatedAt) throw staleReference();
  return indexes[0]!;
}

function requireSavedViewIndex(
  input: DataQualityFixSnapshot,
  reference: DataQualityReference,
): number {
  if (reference.kind !== 'saved-view') throw inconsistentPlan();
  const indexes = input.savedViews.flatMap((view, index) =>
    view.id === reference.savedViewId && view.vaultId === reference.vaultId ? [index] : [],
  );
  if (indexes.length === 0) throw staleReference();
  if (indexes.length !== 1) throw invalidInput('Saved-View-IDs sind nicht eindeutig.');
  if (input.savedViews[indexes[0]!]!.updatedAt !== reference.updatedAt) throw staleReference();
  return indexes[0]!;
}

function requireFixedUrlLocation(location: UrlLocation, withIndex: boolean): void {
  if (location.customFieldId !== null) throw inconsistentPlan();
  if (withIndex) {
    if (!isValidIndex(location.index)) throw inconsistentPlan();
  } else if (location.index !== null) {
    throw inconsistentPlan();
  }
}

function applyPreparedFix(
  output: { document: VaultDocument; savedViews: SavedViewRecord[] },
  prepared: PreparedFix,
  updatedAt: string,
): void {
  switch (prepared.kind) {
    case 'replace-entry-url': {
      const entry = output.document.entries[prepared.entryIndex]!;
      applyUrlReplacement(entry, prepared.location, prepared.value);
      touchEntry(entry, output.document, updatedAt);
      return;
    }
    case 'remove-entry-website': {
      const entry = output.document.entries[prepared.entryIndex]!;
      if (entry.data.type !== 'credential') throw impossibleState();
      entry.data.value.websites.splice(prepared.websiteIndex, 1);
      touchEntry(entry, output.document, updatedAt);
      return;
    }
    case 'replace-entry-title': {
      const entry = output.document.entries[prepared.entryIndex]!;
      entry.title = prepared.value;
      touchEntry(entry, output.document, updatedAt);
      return;
    }
    case 'clear-entry-folder': {
      const entry = output.document.entries[prepared.entryIndex]!;
      entry.folderId = null;
      touchEntry(entry, output.document, updatedAt);
      return;
    }
    case 'remove-saved-view-references': {
      const view = output.savedViews[prepared.savedViewIndex]!;
      if (prepared.clearFolder) view.filters.folderId = null;
      const removedIndexes = new Set(prepared.removeTagIndexes);
      view.filters.tags = view.filters.tags.filter((_, index) => !removedIndexes.has(index));
      view.updatedAt = updatedAt;
      output.document.updatedAt = updatedAt;
      return;
    }
    case 'update-attachment-metadata': {
      const entry = output.document.entries[prepared.entryIndex]!;
      const attachment = entry.attachments[prepared.attachmentIndex]!;
      attachment.size = prepared.size;
      attachment.sha256 = prepared.sha256;
      touchEntry(entry, output.document, updatedAt);
    }
  }
}

function applyUrlReplacement(entry: VaultEntry, location: UrlLocation, value: string): void {
  switch (location.field) {
    case 'credential-website':
      if (entry.data.type !== 'credential' || location.index === null) throw impossibleState();
      entry.data.value.websites[location.index] = value;
      return;
    case 'credit-card-website':
      if (entry.data.type !== 'credit-card') throw impossibleState();
      entry.data.value.website = value;
      return;
    case 'license-download-url':
      if (entry.data.type !== 'software-license') throw impossibleState();
      entry.data.value.downloadUrl = value;
      return;
    case 'custom-url-field':
      if (location.index === null) throw impossibleState();
      entry.customFields[location.index]!.value = value;
  }
}

function touchEntry(entry: VaultEntry, document: VaultDocument, updatedAt: string): void {
  entry.updatedAt = updatedAt;
  document.updatedAt = updatedAt;
}

function cloneSnapshot(input: DataQualityFixSnapshot): {
  document: VaultDocument;
  savedViews: SavedViewRecord[];
} {
  return {
    document: structuredClone(input.document),
    savedViews: structuredClone(input.savedViews) as SavedViewRecord[],
  };
}

function validateNow(value: Date | undefined): Date {
  const now = value ?? new Date();
  if (Number.isNaN(now.getTime())) {
    throw invalidInput('Der Aenderungszeitpunkt ist ungueltig.');
  }
  return new Date(now.getTime());
}

function referenceId(reference: DataQualityReference): string {
  if (reference.kind === 'entry') return reference.entryId;
  if (reference.kind === 'saved-view') return reference.savedViewId;
  return reference.attachmentId;
}

function isValidIndex(value: number | null): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalidInput(message: string): DataQualityError {
  return new DataQualityError('INVALID_INPUT', message);
}

function inconsistentPlan(): DataQualityError {
  return invalidInput('Der Datenqualitaets-Fixplan ist inkonsistent.');
}

function staleReference(): DataQualityError {
  return new DataQualityError(
    'STALE_REFERENCE',
    'Der Datenqualitaets-Fixplan ist nicht mehr aktuell.',
  );
}

function impossibleState(): Error {
  return new Error('Validated data-quality fix reached an impossible state.');
}

function noOp(): void {}

function clone<T>(value: T): T {
  return structuredClone(value);
}
