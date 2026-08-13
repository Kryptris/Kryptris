import { createHash, type Hash } from 'node:crypto';

export interface RevisionTokenEntry {
  readonly id: string;
  readonly updatedAt: string;
  readonly deletedAt?: string | null;
}

export interface RevisionTokenDocument {
  readonly id: string;
  readonly updatedAt: string;
  readonly entries: readonly RevisionTokenEntry[];
}

const TOKEN_DOMAIN = 'kryptris:document-revision-token:v1';

/**
 * Builds a bounded cache revision from technical document metadata only.
 *
 * The deliberately narrow structural input lets callers pass vault documents
 * directly while preventing titles, field values, attachments or other secrets
 * from becoming part of the token.
 */
export class RevisionTokenService {
  public create(
    documents: readonly RevisionTokenDocument[],
    additional: readonly string[] = [],
  ): string {
    const hash = createHash('sha256');
    update(hash, 'domain', TOKEN_DOMAIN);

    const orderedDocuments = [...documents].sort(compareDocuments);
    update(hash, 'document-count', String(orderedDocuments.length));
    for (const document of orderedDocuments) {
      update(hash, 'vault-id', document.id);
      update(hash, 'document-revision', document.updatedAt);

      const orderedEntries = [...document.entries].sort(compareEntries);
      update(hash, 'entry-count', String(orderedEntries.length));
      for (const entry of orderedEntries) {
        update(hash, 'entry-id', entry.id);
        update(hash, 'entry-revision', entry.updatedAt);
        updateNullable(hash, 'entry-deleted-revision', entry.deletedAt);
      }
    }

    const orderedAdditional = [...additional].sort(compareStrings);
    update(hash, 'additional-count', String(orderedAdditional.length));
    for (const value of orderedAdditional) update(hash, 'additional', value);

    return `sha256:${hash.digest('hex')}`;
  }
}

function compareDocuments(left: RevisionTokenDocument, right: RevisionTokenDocument): number {
  return (
    compareStrings(left.id, right.id) ||
    compareStrings(left.updatedAt, right.updatedAt) ||
    compareEntryCollections(left.entries, right.entries)
  );
}

function compareEntries(left: RevisionTokenEntry, right: RevisionTokenEntry): number {
  return (
    compareStrings(left.id, right.id) ||
    compareStrings(left.updatedAt, right.updatedAt) ||
    compareNullableStrings(left.deletedAt, right.deletedAt)
  );
}

function compareEntryCollections(
  left: readonly RevisionTokenEntry[],
  right: readonly RevisionTokenEntry[],
): number {
  if (left.length !== right.length) return left.length - right.length;
  const orderedLeft = [...left].sort(compareEntries);
  const orderedRight = [...right].sort(compareEntries);
  for (let index = 0; index < orderedLeft.length; index += 1) {
    const result = compareEntries(orderedLeft[index]!, orderedRight[index]!);
    if (result !== 0) return result;
  }
  return 0;
}

function compareNullableStrings(
  left: string | null | undefined,
  right: string | null | undefined,
): number {
  if (left === null || left === undefined) {
    return right === null || right === undefined ? 0 : -1;
  }
  if (right === null || right === undefined) return 1;
  return compareStrings(left, right);
}

function compareStrings(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function update(hash: Hash, label: string, value: string): void {
  const encoded = Buffer.from(value, 'utf8');
  hash.update(label, 'utf8');
  hash.update('\0', 'utf8');
  hash.update(String(encoded.byteLength), 'utf8');
  hash.update('\0', 'utf8');
  hash.update(encoded);
}

function updateNullable(hash: Hash, label: string, value: string | null | undefined): void {
  if (value === null || value === undefined) {
    update(hash, label, '<none>');
    return;
  }
  update(hash, label, value);
}
