const TAG_WHITESPACE = /\s+/gu;

export function normalizeTagName(value: string): string {
  return value.normalize('NFKC').trim().replace(TAG_WHITESPACE, ' ');
}

export function normalizeTagKey(value: string): string {
  return normalizeTagName(value).toLocaleUpperCase('de').toLocaleLowerCase('de');
}

export function normalizeTags(values: readonly string[]): string[] {
  const normalized = new Map<string, string>();
  for (const value of values) {
    const name = normalizeTagName(value);
    if (name.length === 0) continue;
    const key = normalizeTagKey(name);
    if (!normalized.has(key)) normalized.set(key, name);
  }
  return [...normalized.values()];
}
