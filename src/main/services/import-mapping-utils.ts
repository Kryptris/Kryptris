import { VaultaError } from '../../shared/errors';
import type { ImportMapping } from '../../shared/models';

export const IMPORT_MAPPING_FIELDS = [
  'title',
  'username',
  'password',
  'url',
  'note',
  'folder',
  'tags',
] as const satisfies ReadonlyArray<keyof ImportMapping>;

/**
 * Validates the non-secret column names used by a generic CSV mapping. The
 * returned copy is deliberately safe to place into protected profile metadata:
 * it contains only column selectors and never an imported value.
 */
export function validateImportMapping(mapping: ImportMapping): ImportMapping {
  const result = {} as ImportMapping;
  for (const key of IMPORT_MAPPING_FIELDS) {
    const value = mapping[key];
    if (typeof value !== 'string' || value.length > 200 || /[\r\n\0]/u.test(value)) {
      throw new VaultaError('INVALID_INPUT', 'Die Importzuordnung ist ungueltig.');
    }
    result[key] = value;
  }
  return result;
}
