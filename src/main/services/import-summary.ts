import type { ImportPreview, ImportSummary } from '../../shared/models';

export type { ImportSummary } from '../../shared/models';

export function summarizeImportPreview(
  preview: Pick<ImportPreview, 'candidates' | 'errors'>,
  selectedRows?: readonly number[],
): ImportSummary {
  const selected =
    selectedRows === undefined
      ? new Set(
          preview.candidates
            .filter((candidate) => candidate.selected)
            .map((candidate) => candidate.sourceIndex),
        )
      : new Set(selectedRows);
  const newEntries = preview.candidates.filter((candidate) =>
    selected.has(candidate.sourceIndex),
  ).length;
  return {
    newEntries,
    skippedEntries: preview.candidates.length - newEntries,
    duplicates: preview.candidates.filter((candidate) => candidate.duplicateOf !== null).length,
    warnings: preview.candidates.reduce((count, candidate) => count + candidate.warnings.length, 0),
    invalidRows: preview.errors.length,
  };
}
