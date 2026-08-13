// @vitest-environment jsdom
/* eslint-disable @typescript-eslint/require-await */

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SecurityView, type SecurityViewProps } from '../../src/renderer/components/SecurityView';
import type {
  BreachListStatusDto,
  SecurityCenterCardId,
  SecurityCenterReportDto,
} from '../../src/shared/models';

const NOW = '2026-07-14T02:00:00.000Z';
const CARD_IDS: SecurityCenterCardId[] = [
  'credentials',
  'data-quality',
  'factors',
  'backup',
  'recovery',
  'kdf',
  'integrity',
  'breach-list',
];

const centerReport: SecurityCenterReportDto = {
  generatedAt: NOW,
  score: 73,
  cards: CARD_IDS.map((id) => ({
    id,
    severity: id === 'credentials' ? 'warning' : 'good',
    findingCodes: id === 'credentials' ? ['credential-findings'] : [],
    count: id === 'credentials' ? 1 : 0,
    calculatedAt: NOW,
    action: 'none',
  })),
  entryFindings: [
    {
      id: 'finding-1',
      vaultId: 'vault-2',
      vaultName: 'Arbeit',
      entryId: 'entry-2',
      entryTitle: 'Synthetischer Zugang',
      kind: 'old',
      severity: 'warning',
      title: 'Rotation prüfen',
      recommendation: 'Prüfe das Änderungsdatum beim Dienst.',
    },
  ],
  networkUsed: false,
};

const readyBreachStatus: BreachListStatusDto = {
  state: 'ready',
  sourceLabel: 'Anonymisierte Testliste',
  sourceDate: '2026-07-01',
  importedAt: NOW,
  recordCount: 42,
  corpusSha256: '0'.repeat(64),
  networkUsed: false,
};

function createProps(overrides: Partial<SecurityViewProps> = {}): SecurityViewProps {
  return {
    progressEvents: [],
    notify: vi.fn(),
    onScanCenter: vi.fn(async () => centerReport),
    onGetRecoveryReadiness: vi.fn(async () => ({
      state: 'ready' as const,
      lastTestedAt: NOW,
      lastTestSucceeded: true,
      staleAfterDays: 180,
    })),
    onTestRecoveryReadiness: vi.fn(async () => ({
      state: 'ready' as const,
      lastTestedAt: NOW,
      lastTestSucceeded: true,
      staleAfterDays: 180,
    })),
    onScanIntegrity: vi.fn(async () => ({
      reportId: 'integrity-report-1',
      generatedAt: NOW,
      success: true,
      scannedVaults: 2,
      scannedEntries: 12,
      scannedAttachments: 1,
      findings: [],
      networkUsed: false as const,
    })),
    onSaveIntegrityReport: vi.fn(async () => true),
    onGetBreachListStatus: vi.fn(async () => readyBreachStatus),
    onImportBreachList: vi.fn(async () => readyBreachStatus),
    onScanBreachList: vi.fn(async () => ({
      generatedAt: NOW,
      checkedEntries: 2,
      checkedPasswords: 2,
      findings: [],
      networkUsed: false as const,
    })),
    onRemoveBreachList: vi.fn(async () => ({
      state: 'not-configured' as const,
      sourceLabel: null,
      sourceDate: null,
      importedAt: null,
      recordCount: 0,
      corpusSha256: null,
      networkUsed: false as const,
    })),
    onCancel: vi.fn(async () => true),
    onNavigate: vi.fn(),
    onOpenSettings: vi.fn(),
    onOpenEntry: vi.fn(),
    ...overrides,
  };
}

beforeEach(() => {
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => 'security-request-1') });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Sicherheitszentrale', () => {
  it('erklärt den lokalen Vorsorgewert und öffnet Befunde im richtigen Tresor', async () => {
    const props = createProps();
    render(<SecurityView {...props} />);

    expect(await screen.findByRole('heading', { name: 'Sicherheitszentrale' })).toBeInTheDocument();
    expect(await screen.findByLabelText('Lokaler Vorsorgewert 73 von 100')).toBeInTheDocument();
    expect(screen.getByText(/keine Aussage über Malware/u)).toBeInTheDocument();
    expect(screen.getByText(/kompromittiertes Windows-System/u)).toBeInTheDocument();
    expect(screen.getAllByText(/Kein Netzwerk verwendet/u).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: /Rotation prüfen/u }));
    expect(props.onOpenEntry).toHaveBeenCalledWith('vault-2', 'entry-2');
  });

  it('leert den Wiederherstellungsschlüssel beim Schließen und übergibt ihn nur an die sichere API', async () => {
    const props = createProps();
    render(<SecurityView {...props} />);
    await screen.findByLabelText('Lokaler Vorsorgewert 73 von 100');

    const recoveryPanel = screen
      .getByRole('heading', { name: 'Wiederherstellungsbereitschaft' })
      .closest('section');
    expect(recoveryPanel).not.toBeNull();
    fireEvent.click(within(recoveryPanel!).getByRole('button', { name: 'Schlüssel lokal testen' }));

    let dialog = screen.getByRole('dialog', { name: 'Wiederherstellungsschlüssel testen' });
    const keyInput = within(dialog).getByLabelText('Wiederherstellungsschlüssel');
    fireEvent.change(keyInput, { target: { value: 'SYNTHETISCHER-TESTSCHLUESSEL' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Dialog schließen' }));

    fireEvent.click(within(recoveryPanel!).getByRole('button', { name: 'Schlüssel lokal testen' }));
    dialog = screen.getByRole('dialog', { name: 'Wiederherstellungsschlüssel testen' });
    expect(within(dialog).getByLabelText('Wiederherstellungsschlüssel')).toHaveValue('');

    fireEvent.change(within(dialog).getByLabelText('Wiederherstellungsschlüssel'), {
      target: { value: 'SYNTHETISCHER-TESTSCHLUESSEL' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Schlüssel lokal prüfen' }));

    await waitFor(() =>
      expect(props.onTestRecoveryReadiness).toHaveBeenCalledWith({
        recoveryKey: 'SYNTHETISCHER-TESTSCHLUESSEL',
      }),
    );
    expect(
      screen.queryByRole('dialog', { name: 'Wiederherstellungsschlüssel testen' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('SYNTHETISCHER-TESTSCHLUESSEL')).not.toBeInTheDocument();
  });

  it('ordnet Fortschritt nach Job und requestId zu und bricht exakt die aktive Prüfung ab', async () => {
    let resolveCenter: ((report: SecurityCenterReportDto) => void) | undefined;
    const centerPromise = new Promise<SecurityCenterReportDto>((resolve) => {
      resolveCenter = resolve;
    });
    const props = createProps({
      progressEvents: [
        {
          requestId: 'security-request-1',
          job: 'integrity',
          phase: 'audit',
          completed: 99,
          total: 100,
        },
        {
          requestId: 'security-request-1',
          job: 'security-center',
          phase: 'entries',
          completed: 2,
          total: 5,
        },
      ],
      onScanCenter: vi.fn(() => centerPromise),
    });
    render(<SecurityView {...props} />);

    expect(
      await screen.findByText(/Einträge werden lokal bewertet · 2 von 5/u),
    ).toBeInTheDocument();
    expect(screen.queryByText(/99 von 100/u)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Abbrechen' }));
    await waitFor(() => expect(props.onCancel).toHaveBeenCalledWith('security-request-1'));

    resolveCenter?.(centerReport);
    await screen.findByLabelText('Lokaler Vorsorgewert 73 von 100');
  });

  it('fordert Importmetadaten an und schützt das Entfernen mit einer Bestätigung', async () => {
    const props = createProps();
    render(<SecurityView {...props} />);
    await screen.findByText('Anonymisierte Testliste');

    fireEvent.click(screen.getByRole('button', { name: 'Liste ersetzen' }));
    const importDialog = screen.getByRole('dialog', { name: 'Lokale Datenleckliste importieren' });
    fireEvent.change(within(importDialog).getByLabelText(/Bezeichnung der Quelle/u), {
      target: { value: 'Lokaler Stand Juli' },
    });
    fireEvent.change(within(importDialog).getByLabelText(/Stand der Liste/u), {
      target: { value: '2026-07-01' },
    });
    fireEvent.click(within(importDialog).getByRole('button', { name: 'Lokale Datei auswählen' }));

    await waitFor(() =>
      expect(props.onImportBreachList).toHaveBeenCalledWith({
        requestId: 'security-request-1',
        sourceLabel: 'Lokaler Stand Juli',
        sourceDate: '2026-07-01',
      }),
    );

    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Lokale Datenleckliste importieren' }),
      ).toBeNull(),
    );
    const removeList = screen.getByRole('button', { name: 'Liste entfernen' });
    await waitFor(() => expect(removeList).toBeEnabled());
    fireEvent.click(removeList);
    const removeDialog = screen.getByRole('dialog', { name: 'Lokale Datenleckliste entfernen?' });
    const removeButton = within(removeDialog).getByRole('button', { name: 'Liste entfernen' });
    expect(removeButton).toBeDisabled();
    fireEvent.click(
      within(removeDialog).getByRole('checkbox', {
        name: /von diesem Gerät entfernen/u,
      }),
    );
    expect(removeButton).toBeEnabled();
  });
});
