// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DataQualityViews,
  type DataQualityViewsProps,
  type RefreshableQualityScanRequest,
} from '../../src/renderer/components/DataQualityViews';
import type {
  DataQualityFixPreviewDto,
  DataQualityFixResultDto,
  DataQualityReportDto,
  DuplicateEntryReferenceDto,
  DuplicateMergeDescriptionDto,
  DuplicateMergeResultDto,
  DuplicateScanDto,
} from '../../src/shared/models';

const LEFT_REFERENCE: DuplicateEntryReferenceDto = {
  vaultId: 'vault-a',
  entryId: 'entry-left',
  updatedAt: '2026-07-21T10:00:00.000Z',
};

const RIGHT_REFERENCE: DuplicateEntryReferenceDto = {
  vaultId: 'vault-a',
  entryId: 'entry-right',
  updatedAt: '2026-07-22T10:00:00.000Z',
};

const DUPLICATE_SCAN: DuplicateScanDto = {
  activeEntryCount: 8,
  truncated: false,
  candidates: [
    {
      left: {
        ...LEFT_REFERENCE,
        title: 'Portal links',
        subtitle: 'person@example.invalid',
      },
      right: {
        ...RIGHT_REFERENCE,
        title: 'Portal rechts',
        subtitle: 'person@example.invalid',
      },
      type: 'credential',
      confidence: 'likely',
      reasons: ['title', 'credential-username'],
    },
  ],
};

const MERGE_DESCRIPTION: DuplicateMergeDescriptionDto = {
  survivor: {
    ...LEFT_REFERENCE,
    title: 'Portal links',
    subtitle: 'person@example.invalid',
  },
  duplicate: {
    ...RIGHT_REFERENCE,
    title: 'Portal rechts',
    subtitle: 'person@example.invalid',
  },
  type: 'credential',
  scalarFields: [
    {
      field: 'credential.username',
      label: 'Benutzername',
      secret: false,
      survivorPreview: 'person-a',
      duplicatePreview: 'person-b',
    },
  ],
  collectionFields: [
    {
      field: 'credential.websites',
      label: 'Websites',
      survivorCount: 1,
      duplicateCount: 2,
      supportsUnion: true,
    },
  ],
  potentialAttachmentDuplicates: 1,
  duplicateDisposition: 'trash',
};

const MERGE_RESULT: DuplicateMergeResultDto = {
  survivor: LEFT_REFERENCE,
  duplicate: RIGHT_REFERENCE,
  copiedAttachments: 1,
  deduplicatedAttachments: 1,
};

const QUALITY_REPORT: DataQualityReportDto = {
  generatedAt: '2026-07-23T10:00:00.000Z',
  vaultId: 'vault-a',
  scannedEntries: 8,
  findings: [
    {
      id: 'finding-1',
      code: 'invalid-url',
      severity: 'warning',
      reference: {
        kind: 'entry',
        ...LEFT_REFERENCE,
      },
      fixCode: 'normalize-url-https-whitespace',
    },
  ],
  networkUsed: false,
};

const FIX_PREVIEW: DataQualityFixPreviewDto = {
  token: 'one-time-preview-token',
  findingId: 'finding-1',
  title: 'Webadresse normalisieren',
  description: 'Leerzeichen werden entfernt und HTTPS wird ergänzt.',
  expiresAt: '2026-07-23T10:05:00.000Z',
};

const FIX_RESULT: DataQualityFixResultDto = {
  affectedEntryIds: ['entry-left'],
  savedViewsChanged: 0,
};

const createProps = (overrides: Partial<DataQualityViewsProps> = {}): DataQualityViewsProps => ({
  progress: null,
  onScanDuplicates: vi.fn((): Promise<DuplicateScanDto> => Promise.resolve(DUPLICATE_SCAN)),
  onDescribeMerge: vi.fn((): Promise<DuplicateMergeDescriptionDto> =>
    Promise.resolve(MERGE_DESCRIPTION),
  ),
  onMerge: vi.fn((): Promise<DuplicateMergeResultDto> => Promise.resolve(MERGE_RESULT)),
  onTrashCandidate: vi.fn((): Promise<unknown> => Promise.resolve(undefined)),
  onScanDataQuality: vi.fn((): Promise<DataQualityReportDto> => Promise.resolve(QUALITY_REPORT)),
  onPreviewFix: vi.fn((): Promise<DataQualityFixPreviewDto> => Promise.resolve(FIX_PREVIEW)),
  onApplyFix: vi.fn((): Promise<DataQualityFixResultDto> => Promise.resolve(FIX_RESULT)),
  onCancel: vi.fn((): Promise<boolean> => Promise.resolve(true)),
  ...overrides,
});

afterEach(() => {
  cleanup();
});

describe('DataQualityViews', () => {
  it('wechselt Tabs per Tastatur und zeigt redigierte deutsche Befunde mit Fix-Vorschau', async () => {
    const captured: { qualityScanRequest?: RefreshableQualityScanRequest } = {};
    const onScanDataQuality = vi.fn(
      (request: RefreshableQualityScanRequest): Promise<DataQualityReportDto> => {
        captured.qualityScanRequest = request;
        return Promise.resolve(QUALITY_REPORT);
      },
    );
    const props = createProps({ onScanDataQuality });
    render(<DataQualityViews {...props} />);

    const duplicateTab = screen.getByRole('tab', { name: 'Dubletten' });
    const qualityTab = screen.getByRole('tab', { name: 'Datenqualität' });
    duplicateTab.focus();
    fireEvent.keyDown(duplicateTab, { key: 'ArrowRight' });

    expect(qualityTab).toHaveFocus();
    expect(qualityTab).toHaveAttribute('aria-selected', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Datenqualität prüfen' }));

    expect(
      await screen.findByRole('heading', { name: 'Ungültige Webadresse' }),
    ).toBeInTheDocument();
    expect(screen.queryByText('invalid-url')).not.toBeInTheDocument();
    expect(onScanDataQuality).toHaveBeenCalledTimes(1);
    const qualityScanRequest = captured.qualityScanRequest;
    if (qualityScanRequest === undefined) throw new Error('Scan-Anfrage fehlt.');
    expect(qualityScanRequest.refresh).toBe(false);
    expect(qualityScanRequest.requestId).not.toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Korrektur prüfen' }));
    const preview = await screen.findByRole('dialog', { name: 'Webadresse normalisieren' });
    expect(within(preview).getByText(FIX_PREVIEW.description)).toBeInTheDocument();
    expect(within(preview).queryByText(FIX_PREVIEW.token)).not.toBeInTheDocument();
    fireEvent.click(within(preview).getByRole('button', { name: 'Vorschau bestätigen' }));

    await waitFor(() => expect(props.onApplyFix).toHaveBeenCalledWith(FIX_PREVIEW.token));
    expect(await screen.findByText('Korrektur angewendet')).toBeInTheDocument();
  });

  it('übermittelt die gewählten Skalar- und Collection-Quellen erst nach Merge-Bestätigung', async () => {
    const props = createProps();
    render(<DataQualityViews {...props} />);

    fireEvent.click(screen.getByRole('button', { name: 'Dubletten prüfen' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Links als Haupteintrag' }));

    const dialog = await screen.findByRole('dialog', { name: 'Dubletten zusammenführen' });
    const mergeButton = within(dialog).getByRole('button', {
      name: 'Auswahl zusammenführen',
    });
    expect(mergeButton).toBeDisabled();

    fireEvent.click(within(dialog).getByRole('radio', { name: /Aus doppeltem Eintrag/ }));
    fireEvent.click(within(dialog).getByRole('radio', { name: /Nur doppelter Eintrag/ }));
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /Merge verbindlich bestätigen/ }));
    fireEvent.click(mergeButton);

    await waitFor(() =>
      expect(props.onMerge).toHaveBeenCalledWith({
        survivor: LEFT_REFERENCE,
        duplicate: RIGHT_REFERENCE,
        fieldChoices: [{ field: 'credential.username', source: 'duplicate' }],
        collectionChoices: [{ field: 'credential.websites', strategy: 'duplicate' }],
      }),
    );
    expect(await screen.findByText('Einträge zusammengeführt')).toBeInTheDocument();
  });

  it('bestätigt den Papierkorb pro Kandidatenseite und setzt den Fokus sicher zurück', async () => {
    const props = createProps();
    render(<DataQualityViews {...props} />);

    fireEvent.click(screen.getByRole('button', { name: 'Dubletten prüfen' }));
    const trashButtons = await screen.findAllByRole('button', {
      name: 'In Papierkorb verschieben',
    });
    fireEvent.click(trashButtons[0]!);

    const dialog = screen.getByRole('dialog', {
      name: 'Eintrag in den Papierkorb verschieben',
    });
    expect(within(dialog).getByText('Portal links')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'In Papierkorb verschieben' }));

    await waitFor(() => expect(props.onTrashCandidate).toHaveBeenCalledWith(LEFT_REFERENCE));
    await waitFor(() => expect(screen.getByRole('tab', { name: /Dubletten/ })).toHaveFocus());
    expect(
      screen.queryByRole('heading', { name: 'Eintrag in den Papierkorb verschieben' }),
    ).not.toBeInTheDocument();
  });
});
