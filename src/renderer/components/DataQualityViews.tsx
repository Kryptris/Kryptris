import {
  AlertTriangle,
  Check,
  Database,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import type { KeyboardEvent } from 'react';
import { useEffect, useId, useRef, useState } from 'react';

import {
  ENTRY_TYPE_LABELS,
  type DataQualityFindingCode,
  type DataQualityFindingDto,
  type DataQualityFixPreviewDto,
  type DataQualityFixResultDto,
  type DataQualityReferenceDto,
  type DataQualityReportDto,
  type DuplicateCandidateDto,
  type DuplicateEntryReferenceDto,
  type DuplicateMergeChoiceDto,
  type DuplicateMergeCollectionChoiceDto,
  type DuplicateMergeDescriptionDto,
  type DuplicateMergeResultDto,
  type DuplicateReasonCode,
  type DuplicateScanDto,
  type LocalJobProgressEvent,
} from '../../shared/models';
import { formatDate, getErrorMessage } from '../utils';
import { Button, EmptyState, InlineNotice, LoadingState, Modal } from './ui';

type QualityTab = 'duplicates' | 'data-quality';
type ScanKind = 'duplicates' | 'data-quality';

export interface RefreshableQualityScanRequest {
  requestId: string;
  refresh: boolean;
}

export interface DuplicateMergeDescriptionRequest {
  survivor: DuplicateEntryReferenceDto;
  duplicate: DuplicateEntryReferenceDto;
}

export interface DuplicateMergeExecutionRequest extends DuplicateMergeDescriptionRequest {
  fieldChoices: DuplicateMergeChoiceDto[];
  collectionChoices: DuplicateMergeCollectionChoiceDto[];
}

export interface DataQualityViewsProps {
  progress: LocalJobProgressEvent | null;
  onScanDuplicates: (request: RefreshableQualityScanRequest) => Promise<DuplicateScanDto>;
  onDescribeMerge: (
    request: DuplicateMergeDescriptionRequest,
  ) => Promise<DuplicateMergeDescriptionDto>;
  onMerge: (request: DuplicateMergeExecutionRequest) => Promise<DuplicateMergeResultDto>;
  onTrashCandidate: (reference: DuplicateEntryReferenceDto) => Promise<unknown>;
  onScanDataQuality: (request: RefreshableQualityScanRequest) => Promise<DataQualityReportDto>;
  onPreviewFix: (findingId: string) => Promise<DataQualityFixPreviewDto>;
  onApplyFix: (token: string) => Promise<DataQualityFixResultDto>;
  onCancel: (requestId: string) => Promise<boolean>;
  onOpenFinding?: (reference: DataQualityReferenceDto) => void;
}

const DUPLICATE_REASON_LABELS: Record<DuplicateReasonCode, string> = {
  title: 'Gleicher oder sehr ähnlicher Titel',
  'credential-username': 'Übereinstimmender Benutzername',
  'credential-website-host': 'Gleiche Website',
  'credential-app-name': 'Gleiche Anwendung',
  'credential-password': 'Übereinstimmendes Passwort',
  'credential-totp-secret': 'Gleiche Zwei-Faktor-Konfiguration',
  'secure-note-content': 'Übereinstimmender Notizinhalt',
  'credit-card-number': 'Gleiche Kartennummer',
  'credit-card-cardholder': 'Gleicher Karteninhaber',
  'credit-card-issuer': 'Gleicher Kartenaussteller',
  'credit-card-expiry': 'Gleiches Ablaufdatum',
  'credit-card-website-host': 'Gleiche Karten-Website',
  'identity-name': 'Übereinstimmender Name',
  'identity-email': 'Übereinstimmende E-Mail-Adresse',
  'identity-phone': 'Übereinstimmende Telefonnummer',
  'identity-address': 'Übereinstimmende Adresse',
  'identity-government-id': 'Übereinstimmendes Ausweisdokument',
  'wifi-ssid': 'Gleicher WLAN-Name',
  'wifi-router-host': 'Gleiche Router-Adresse',
  'wifi-router-username': 'Gleicher Router-Benutzername',
  'wifi-password': 'Übereinstimmendes WLAN-Passwort',
  'software-product': 'Gleiches Softwareprodukt',
  'software-order-number': 'Gleiche Bestellnummer',
  'software-download-host': 'Gleiche Download-Website',
  'software-license-key': 'Übereinstimmender Lizenzschlüssel',
  'ssh-host': 'Gleicher SSH-Host',
  'ssh-username': 'Gleicher SSH-Benutzername',
  'ssh-fingerprint': 'Übereinstimmender Fingerabdruck',
  'ssh-public-key': 'Übereinstimmender öffentlicher Schlüssel',
  'ssh-private-key': 'Übereinstimmender privater Schlüssel',
  'file-description': 'Übereinstimmende Dateibeschreibung',
  'file-attachment': 'Gleicher authentifizierter Anhang',
  'custom-description': 'Übereinstimmende Beschreibung',
  'custom-field': 'Übereinstimmendes eigenes Feld',
  'custom-secret-field': 'Übereinstimmendes geheimes Feld',
};

const DATA_QUALITY_COPY: Record<DataQualityFindingCode, { title: string; description: string }> = {
  'invalid-url': {
    title: 'Ungültige Webadresse',
    description: 'Eine gespeicherte Webadresse kann nicht zuverlässig als URL verarbeitet werden.',
  },
  'url-needs-normalization': {
    title: 'Webadresse kann vereinheitlicht werden',
    description:
      'Leerzeichen oder ein fehlendes HTTPS-Schema verhindern eine einheitliche Darstellung.',
  },
  'duplicate-website': {
    title: 'Website doppelt eingetragen',
    description: 'Dieselbe Website ist in diesem Eintrag mehrfach hinterlegt.',
  },
  'similar-website': {
    title: 'Sehr ähnliche Websites',
    description:
      'Mehrere Websites dieses Eintrags sind sehr ähnlich und sollten bewusst geprüft werden.',
  },
  'empty-title': {
    title: 'Titel fehlt',
    description: 'Ein Eintrag besitzt keinen verständlichen Titel.',
  },
  'import-placeholder-title': {
    title: 'Platzhaltertitel aus Import',
    description: 'Ein importierter Eintrag verwendet noch einen allgemeinen Platzhaltertitel.',
  },
  'expired-credit-card': {
    title: 'Kreditkarte abgelaufen',
    description: 'Das hinterlegte Ablaufdatum dieser Kreditkarte liegt in der Vergangenheit.',
  },
  'expired-license': {
    title: 'Lizenz abgelaufen',
    description: 'Das hinterlegte Ablaufdatum dieser Softwarelizenz liegt in der Vergangenheit.',
  },
  'unusual-totp-parameters': {
    title: 'Ungewöhnliche Zwei-Faktor-Einstellungen',
    description:
      'Zeitraum, Stellenzahl oder Algorithmus weichen von häufig verwendeten Einstellungen ab.',
  },
  'attachment-metadata-mismatch': {
    title: 'Anhangsmetadaten passen nicht',
    description: 'Gespeicherte Metadaten und authentifizierter Anhang stimmen nicht überein.',
  },
  'attachment-file-missing': {
    title: 'Anhangsdatei fehlt',
    description: 'Zu einem gespeicherten Anhang wurde keine zugehörige lokale Datei gefunden.',
  },
  'attachment-file-corrupt': {
    title: 'Anhang konnte nicht verifiziert werden',
    description: 'Die lokale Anhangsdatei hat die authentifizierte Prüfung nicht bestanden.',
  },
  'attachment-file-orphan': {
    title: 'Verwaiste Anhangsdatei',
    description: 'Eine lokale Anhangsdatei ist keinem vorhandenen Eintrag mehr zugeordnet.',
  },
  'orphan-folder-reference': {
    title: 'Ordnerzuordnung ist verwaist',
    description: 'Ein Eintrag verweist auf einen Ordner, der nicht mehr vorhanden ist.',
  },
  'saved-view-orphan-reference': {
    title: 'Gespeicherte Ansicht enthält verwaiste Verweise',
    description:
      'Eine gespeicherte Ansicht verweist auf einen nicht mehr vorhandenen Ordner oder Tag.',
  },
};

const PROGRESS_PHASE_LABELS: Record<string, string> = {
  indexing: 'Einträge werden vorbereitet',
  matching: 'Mögliche Dubletten werden verglichen',
  entries: 'Einträge werden geprüft',
  attachments: 'Anhänge werden authentifiziert geprüft',
  'saved-views': 'Gespeicherte Ansichten werden geprüft',
};

const toReference = (reference: DuplicateEntryReferenceDto): DuplicateEntryReferenceDto => ({
  vaultId: reference.vaultId,
  entryId: reference.entryId,
  updatedAt: reference.updatedAt,
});

const sameReference = (
  left: DuplicateEntryReferenceDto,
  right: DuplicateEntryReferenceDto,
): boolean => left.vaultId === right.vaultId && left.entryId === right.entryId;

const findingReferenceLabel = (finding: DataQualityFindingDto): string => {
  switch (finding.reference.kind) {
    case 'entry':
      return 'Eintrag';
    case 'saved-view':
      return 'Gespeicherte Ansicht';
    case 'attachment':
      return 'Anhang';
  }
};

export function DataQualityViews({
  progress,
  onScanDuplicates,
  onDescribeMerge,
  onMerge,
  onTrashCandidate,
  onScanDataQuality,
  onPreviewFix,
  onApplyFix,
  onCancel,
  onOpenFinding,
}: DataQualityViewsProps) {
  const [activeTab, setActiveTab] = useState<QualityTab>('duplicates');
  const [duplicateScan, setDuplicateScan] = useState<DuplicateScanDto | null>(null);
  const [qualityReport, setQualityReport] = useState<DataQualityReportDto | null>(null);
  const [activeJob, setActiveJob] = useState<{
    requestId: string;
    kind: ScanKind;
  } | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveMessage, setLiveMessage] = useState('');
  const [mergeDescription, setMergeDescription] = useState<DuplicateMergeDescriptionDto | null>(
    null,
  );
  const [fieldChoices, setFieldChoices] = useState<
    Record<string, DuplicateMergeChoiceDto['source']>
  >({});
  const [collectionChoices, setCollectionChoices] = useState<
    Record<string, DuplicateMergeCollectionChoiceDto['strategy']>
  >({});
  const [mergeConfirmed, setMergeConfirmed] = useState(false);
  const [describeBusy, setDescribeBusy] = useState(false);
  const [mergeBusy, setMergeBusy] = useState(false);
  const [mergeResult, setMergeResult] = useState<DuplicateMergeResultDto | null>(null);
  const [trashCandidate, setTrashCandidate] = useState<DuplicateCandidateDto['left'] | null>(null);
  const [trashBusy, setTrashBusy] = useState(false);
  const [trashError, setTrashError] = useState<string | null>(null);
  const [fixPreview, setFixPreview] = useState<DataQualityFixPreviewDto | null>(null);
  const [previewBusyFindingId, setPreviewBusyFindingId] = useState<string | null>(null);
  const [fixBusy, setFixBusy] = useState(false);
  const [fixResult, setFixResult] = useState<DataQualityFixResultDto | null>(null);

  const duplicateTabId = useId();
  const duplicatePanelId = useId();
  const qualityTabId = useId();
  const qualityPanelId = useId();
  const duplicateTabRef = useRef<HTMLButtonElement>(null);
  const qualityTabRef = useRef<HTMLButtonElement>(null);
  const activeJobRef = useRef(activeJob);
  const cancelRef = useRef(onCancel);

  useEffect(() => {
    activeJobRef.current = activeJob;
  }, [activeJob]);

  useEffect(() => {
    cancelRef.current = onCancel;
  }, [onCancel]);

  useEffect(
    () => () => {
      const job = activeJobRef.current;
      if (job !== null) void cancelRef.current(job.requestId).catch(() => undefined);
    },
    [],
  );

  const currentProgress =
    progress !== null &&
    progress.requestId === activeJob?.requestId &&
    progress.job === activeJob.kind
      ? progress
      : null;

  const selectTab = (tab: QualityTab, focus = false) => {
    setActiveTab(tab);
    if (focus) {
      const target = tab === 'duplicates' ? duplicateTabRef.current : qualityTabRef.current;
      target?.focus();
    }
  };

  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    let next: QualityTab | null = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      next = activeTab === 'duplicates' ? 'data-quality' : 'duplicates';
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      next = activeTab === 'duplicates' ? 'data-quality' : 'duplicates';
    } else if (event.key === 'Home') {
      next = 'duplicates';
    } else if (event.key === 'End') {
      next = 'data-quality';
    }
    if (next === null) return;
    event.preventDefault();
    selectTab(next, true);
  };

  const runDuplicateScan = async (refresh: boolean) => {
    if (activeJobRef.current !== null) return;
    const requestId = crypto.randomUUID();
    const job = { requestId, kind: 'duplicates' as const };
    activeJobRef.current = job;
    setActiveJob(job);
    setError(null);
    setMergeResult(null);
    setLiveMessage(
      refresh ? 'Dublettenprüfung wird aktualisiert.' : 'Dublettenprüfung wurde gestartet.',
    );
    try {
      const result = await onScanDuplicates({ requestId, refresh });
      setDuplicateScan(result);
      setLiveMessage(
        result.candidates.length === 1
          ? 'Ein mögliches Dublettenpaar wurde gefunden.'
          : `${String(result.candidates.length)} mögliche Dublettenpaare wurden gefunden.`,
      );
    } catch (scanError: unknown) {
      setError(getErrorMessage(scanError));
      setLiveMessage('Die Dublettenprüfung konnte nicht abgeschlossen werden.');
    } finally {
      if (activeJobRef.current?.requestId === requestId) {
        activeJobRef.current = null;
        setActiveJob(null);
      }
      setCancelling(false);
    }
  };

  const runDataQualityScan = async (refresh: boolean) => {
    if (activeJobRef.current !== null) return;
    const requestId = crypto.randomUUID();
    const job = { requestId, kind: 'data-quality' as const };
    activeJobRef.current = job;
    setActiveJob(job);
    setError(null);
    setFixResult(null);
    setLiveMessage(
      refresh
        ? 'Datenqualitätsprüfung wird aktualisiert.'
        : 'Datenqualitätsprüfung wurde gestartet.',
    );
    try {
      const result = await onScanDataQuality({ requestId, refresh });
      setQualityReport(result);
      setLiveMessage(
        result.findings.length === 1
          ? 'Ein Datenqualitätsbefund wurde gefunden.'
          : `${String(result.findings.length)} Datenqualitätsbefunde wurden gefunden.`,
      );
    } catch (scanError: unknown) {
      setError(getErrorMessage(scanError));
      setLiveMessage('Die Datenqualitätsprüfung konnte nicht abgeschlossen werden.');
    } finally {
      if (activeJobRef.current?.requestId === requestId) {
        activeJobRef.current = null;
        setActiveJob(null);
      }
      setCancelling(false);
    }
  };

  const cancelActiveJob = async () => {
    const job = activeJobRef.current;
    if (job === null || cancelling) return;
    setCancelling(true);
    try {
      const cancelled = await onCancel(job.requestId);
      setLiveMessage(
        cancelled
          ? 'Abbruch wurde angefordert.'
          : 'Die Prüfung war bereits abgeschlossen oder wurde schon beendet.',
      );
    } catch (cancelError: unknown) {
      setError(getErrorMessage(cancelError));
      setLiveMessage('Die Prüfung konnte nicht abgebrochen werden.');
      setCancelling(false);
    }
  };

  const openMerge = async (candidate: DuplicateCandidateDto, survivorSide: 'left' | 'right') => {
    const survivor = survivorSide === 'left' ? candidate.left : candidate.right;
    const duplicate = survivorSide === 'left' ? candidate.right : candidate.left;
    setDescribeBusy(true);
    setError(null);
    setMergeResult(null);
    try {
      const description = await onDescribeMerge({
        survivor: toReference(survivor),
        duplicate: toReference(duplicate),
      });
      setMergeDescription(description);
      setFieldChoices(
        Object.fromEntries(description.scalarFields.map((field) => [field.field, 'survivor'])),
      );
      setCollectionChoices(
        Object.fromEntries(description.collectionFields.map((field) => [field.field, 'union'])),
      );
      setMergeConfirmed(false);
      setLiveMessage('Merge-Vorschau wurde geöffnet.');
    } catch (descriptionError: unknown) {
      setError(getErrorMessage(descriptionError));
      setLiveMessage('Die Merge-Vorschau konnte nicht geladen werden.');
    } finally {
      setDescribeBusy(false);
    }
  };

  const closeMerge = () => {
    if (mergeBusy) return;
    setMergeDescription(null);
    setFieldChoices({});
    setCollectionChoices({});
    setMergeConfirmed(false);
  };

  const executeMerge = async () => {
    if (mergeDescription === null || !mergeConfirmed) return;
    setMergeBusy(true);
    setError(null);
    try {
      const result = await onMerge({
        survivor: toReference(mergeDescription.survivor),
        duplicate: toReference(mergeDescription.duplicate),
        fieldChoices: mergeDescription.scalarFields.map((field) => ({
          field: field.field,
          source: fieldChoices[field.field] ?? 'survivor',
        })),
        collectionChoices: mergeDescription.collectionFields.map((field) => ({
          field: field.field,
          strategy: collectionChoices[field.field] ?? 'union',
        })),
      });
      setMergeResult(result);
      setDuplicateScan((current) =>
        current === null
          ? current
          : {
              ...current,
              candidates: current.candidates.filter(
                (candidate) =>
                  !sameReference(candidate.left, result.survivor) &&
                  !sameReference(candidate.right, result.survivor) &&
                  !sameReference(candidate.left, result.duplicate) &&
                  !sameReference(candidate.right, result.duplicate),
              ),
            },
      );
      setMergeDescription(null);
      setFieldChoices({});
      setCollectionChoices({});
      setMergeConfirmed(false);
      setLiveMessage(
        'Die Einträge wurden zusammengeführt. Der doppelte Eintrag liegt im Papierkorb.',
      );
    } catch (mergeError: unknown) {
      setError(getErrorMessage(mergeError));
      setLiveMessage('Die Einträge konnten nicht zusammengeführt werden.');
    } finally {
      setMergeBusy(false);
    }
  };

  const keepSeparate = (candidate: DuplicateCandidateDto) => {
    setDuplicateScan((current) =>
      current === null
        ? current
        : {
            ...current,
            candidates: current.candidates.filter(
              (currentCandidate) =>
                !(
                  sameReference(currentCandidate.left, candidate.left) &&
                  sameReference(currentCandidate.right, candidate.right)
                ),
            ),
          },
    );
    setLiveMessage(
      'Die beiden Einträge bleiben unverändert und wurden aus dieser Ergebnisliste ausgeblendet.',
    );
  };

  const openTrashConfirmation = (candidate: DuplicateCandidateDto['left']) => {
    setTrashError(null);
    setTrashCandidate(candidate);
  };

  const closeTrashConfirmation = () => {
    if (trashBusy) return;
    setTrashCandidate(null);
    setTrashError(null);
  };

  const confirmTrashCandidate = async () => {
    if (trashCandidate === null) return;
    const reference = toReference(trashCandidate);
    setTrashBusy(true);
    setTrashError(null);
    setError(null);
    try {
      await onTrashCandidate(reference);
      setDuplicateScan((current) =>
        current === null
          ? current
          : {
              ...current,
              candidates: current.candidates.filter(
                (candidate) =>
                  !sameReference(candidate.left, reference) &&
                  !sameReference(candidate.right, reference),
              ),
            },
      );
      setTrashCandidate(null);
      setLiveMessage('Der ausgewählte Eintrag wurde in den Papierkorb verschoben.');
      window.setTimeout(() => duplicateTabRef.current?.focus(), 0);
    } catch (trashFailure: unknown) {
      const message = getErrorMessage(trashFailure);
      setTrashError(message);
      setLiveMessage('Der Eintrag konnte nicht in den Papierkorb verschoben werden.');
    } finally {
      setTrashBusy(false);
    }
  };

  const openFixPreview = async (finding: DataQualityFindingDto) => {
    setPreviewBusyFindingId(finding.id);
    setError(null);
    setFixResult(null);
    try {
      const preview = await onPreviewFix(finding.id);
      setFixPreview(preview);
      setLiveMessage('Die Korrekturvorschau wurde geöffnet.');
    } catch (previewError: unknown) {
      setError(getErrorMessage(previewError));
      setLiveMessage('Die Korrekturvorschau konnte nicht geladen werden.');
    } finally {
      setPreviewBusyFindingId(null);
    }
  };

  const closeFixPreview = () => {
    if (!fixBusy) setFixPreview(null);
  };

  const applyFix = async () => {
    if (fixPreview === null) return;
    setFixBusy(true);
    setError(null);
    try {
      const result = await onApplyFix(fixPreview.token);
      setFixResult(result);
      setFixPreview(null);
      setQualityReport(null);
      setLiveMessage('Die bestätigte Korrektur wurde angewendet.');
    } catch (fixError: unknown) {
      setError(getErrorMessage(fixError));
      setLiveMessage('Die Korrektur konnte nicht angewendet werden.');
    } finally {
      setFixBusy(false);
    }
  };

  return (
    <section className="tool-view data-quality-view" aria-labelledby="data-quality-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon" aria-hidden="true">
            <Database />
          </span>
          <div>
            <p className="eyebrow">Lokale Datenpflege</p>
            <h1 id="data-quality-title">Dubletten und Datenqualität</h1>
            <p>Finde mögliche Mehrfacheinträge und Pflegefehler, ohne Inhalte zu übertragen.</p>
          </div>
        </div>
      </header>

      <div className="quality-tabs" role="tablist" aria-label="Bereich auswählen">
        <button
          ref={duplicateTabRef}
          type="button"
          role="tab"
          id={duplicateTabId}
          aria-controls={duplicatePanelId}
          aria-selected={activeTab === 'duplicates'}
          tabIndex={activeTab === 'duplicates' ? 0 : -1}
          className={activeTab === 'duplicates' ? 'is-active' : ''}
          onClick={() => selectTab('duplicates')}
          onKeyDown={handleTabKeyDown}
        >
          <Search aria-hidden="true" />
          <span>Dubletten</span>
          {duplicateScan !== null && (
            <strong aria-label={`${String(duplicateScan.candidates.length)} Treffer`}>
              {String(duplicateScan.candidates.length)}
            </strong>
          )}
        </button>
        <button
          ref={qualityTabRef}
          type="button"
          role="tab"
          id={qualityTabId}
          aria-controls={qualityPanelId}
          aria-selected={activeTab === 'data-quality'}
          tabIndex={activeTab === 'data-quality' ? 0 : -1}
          className={activeTab === 'data-quality' ? 'is-active' : ''}
          onClick={() => selectTab('data-quality')}
          onKeyDown={handleTabKeyDown}
        >
          <ShieldCheck aria-hidden="true" />
          <span>Datenqualität</span>
          {qualityReport !== null && (
            <strong aria-label={`${String(qualityReport.findings.length)} Befunde`}>
              {String(qualityReport.findings.length)}
            </strong>
          )}
        </button>
      </div>

      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {liveMessage}
      </p>

      {error !== null && (
        <InlineNotice kind="error" title="Aktion fehlgeschlagen">
          {error}
        </InlineNotice>
      )}

      {activeJob !== null && (
        <JobProgress
          kind={activeJob.kind}
          progress={currentProgress}
          cancelling={cancelling}
          onCancel={() => void cancelActiveJob()}
        />
      )}

      {activeTab === 'duplicates' ? (
        <section
          role="tabpanel"
          id={duplicatePanelId}
          aria-labelledby={duplicateTabId}
          aria-busy={activeJob?.kind === 'duplicates'}
          tabIndex={0}
        >
          <DuplicatePanel
            scan={duplicateScan}
            busy={activeJob !== null || describeBusy}
            mergeResult={mergeResult}
            onScan={(refresh) => void runDuplicateScan(refresh)}
            onKeepSeparate={keepSeparate}
            onOpenMerge={(candidate, survivor) => void openMerge(candidate, survivor)}
            onTrashCandidate={openTrashConfirmation}
          />
        </section>
      ) : (
        <section
          role="tabpanel"
          id={qualityPanelId}
          aria-labelledby={qualityTabId}
          aria-busy={activeJob?.kind === 'data-quality'}
          tabIndex={0}
        >
          <QualityPanel
            report={qualityReport}
            busy={activeJob !== null}
            previewBusyFindingId={previewBusyFindingId}
            fixResult={fixResult}
            onScan={(refresh) => void runDataQualityScan(refresh)}
            onPreviewFix={(finding) => void openFixPreview(finding)}
            {...(onOpenFinding === undefined ? {} : { onOpenFinding })}
          />
        </section>
      )}

      <MergeDialog
        description={mergeDescription}
        fieldChoices={fieldChoices}
        collectionChoices={collectionChoices}
        confirmed={mergeConfirmed}
        busy={mergeBusy}
        onFieldChoice={(field, source) => {
          setFieldChoices((current) => ({ ...current, [field]: source }));
          setMergeConfirmed(false);
        }}
        onCollectionChoice={(field, strategy) => {
          setCollectionChoices((current) => ({ ...current, [field]: strategy }));
          setMergeConfirmed(false);
        }}
        onConfirmedChange={setMergeConfirmed}
        onClose={closeMerge}
        onMerge={() => void executeMerge()}
      />

      <TrashCandidateDialog
        candidate={trashCandidate}
        busy={trashBusy}
        error={trashError}
        onClose={closeTrashConfirmation}
        onConfirm={() => void confirmTrashCandidate()}
      />

      <FixPreviewDialog
        preview={fixPreview}
        busy={fixBusy}
        onClose={closeFixPreview}
        onApply={() => void applyFix()}
      />
    </section>
  );
}

function JobProgress({
  kind,
  progress,
  cancelling,
  onCancel,
}: {
  kind: ScanKind;
  progress: LocalJobProgressEvent | null;
  cancelling: boolean;
  onCancel: () => void;
}) {
  const total = Math.max(1, progress?.total ?? 1);
  const completed = Math.min(total, Math.max(0, progress?.completed ?? 0));
  const title = kind === 'duplicates' ? 'Dubletten werden geprüft' : 'Datenqualität wird geprüft';
  const phase =
    progress === null
      ? 'Prüfung wird vorbereitet'
      : (PROGRESS_PHASE_LABELS[progress.phase] ?? 'Lokale Prüfung läuft');

  return (
    <section className="quality-job" aria-labelledby="quality-job-title">
      <div>
        <strong id="quality-job-title">{title}</strong>
        <span>
          {phase}
          {progress !== null && progress.total > 0
            ? ` · ${String(completed)} von ${String(progress.total)}`
            : ''}
        </span>
      </div>
      <progress
        max={total}
        value={completed}
        aria-label={`${title}: ${phase}`}
        aria-valuetext={
          progress !== null && progress.total > 0
            ? `${String(completed)} von ${String(progress.total)} abgeschlossen`
            : 'Wird vorbereitet'
        }
      />
      <Button variant="ghost" icon={<X aria-hidden="true" />} busy={cancelling} onClick={onCancel}>
        Abbrechen
      </Button>
    </section>
  );
}

function DuplicatePanel({
  scan,
  busy,
  mergeResult,
  onScan,
  onKeepSeparate,
  onOpenMerge,
  onTrashCandidate,
}: {
  scan: DuplicateScanDto | null;
  busy: boolean;
  mergeResult: DuplicateMergeResultDto | null;
  onScan: (refresh: boolean) => void;
  onKeepSeparate: (candidate: DuplicateCandidateDto) => void;
  onOpenMerge: (candidate: DuplicateCandidateDto, survivor: 'left' | 'right') => void;
  onTrashCandidate: (candidate: DuplicateCandidateDto['left']) => void;
}) {
  return (
    <div className="quality-panel">
      <header className="quality-panel__header">
        <div>
          <h2>Mögliche Dubletten</h2>
          <p>
            Gründe werden aus normalisierten Merkmalen abgeleitet. Werte bleiben im entsperrten
            Arbeitsspeicher.
          </p>
        </div>
        <Button
          icon={<RefreshCw aria-hidden="true" />}
          busy={busy}
          onClick={() => onScan(scan !== null)}
        >
          {scan === null ? 'Jetzt prüfen' : 'Aktualisieren'}
        </Button>
      </header>

      {mergeResult !== null && (
        <InlineNotice kind="success" title="Einträge zusammengeführt">
          {mergeResult.copiedAttachments === 1
            ? 'Ein Anhang wurde übernommen.'
            : `${String(mergeResult.copiedAttachments)} Anhänge wurden übernommen.`}{' '}
          {mergeResult.deduplicatedAttachments === 1
            ? 'Ein bereits vorhandener Anhang wurde nicht doppelt gespeichert.'
            : `${String(mergeResult.deduplicatedAttachments)} bereits vorhandene Anhänge wurden nicht doppelt gespeichert.`}
        </InlineNotice>
      )}

      {scan === null ? (
        busy ? (
          <LoadingState label="Dubletten werden lokal gesucht …" />
        ) : (
          <EmptyState
            title="Noch keine Dublettenprüfung"
            description="Starte die lokale Prüfung. Es werden keine Daten übertragen oder dauerhaft indiziert."
            action={
              <Button icon={<Search aria-hidden="true" />} onClick={() => onScan(false)}>
                Dubletten prüfen
              </Button>
            }
          />
        )
      ) : (
        <>
          <div className="quality-summary" aria-label="Zusammenfassung der Dublettenprüfung">
            <span>
              <strong>{String(scan.activeEntryCount)}</strong>
              <small>aktive Einträge geprüft</small>
            </span>
            <span>
              <strong>{String(scan.candidates.length)}</strong>
              <small>mögliche Paare</small>
            </span>
            <span>
              <strong>{scan.truncated ? 'Begrenzt' : 'Vollständig'}</strong>
              <small>Ergebnisumfang</small>
            </span>
          </div>
          {scan.truncated && (
            <InlineNotice kind="warning" title="Ergebnisliste wurde begrenzt">
              Es existieren weitere mögliche Paare. Bearbeite Treffer und aktualisiere die Prüfung
              anschließend.
            </InlineNotice>
          )}
          {scan.candidates.length === 0 ? (
            <EmptyState
              title="Keine möglichen Dubletten"
              description="Für den aktuellen Stand wurden keine ausreichend ähnlichen Einträge gefunden."
            />
          ) : (
            <div className="duplicate-list">
              {scan.candidates.map((candidate) => (
                <article
                  className="duplicate-card"
                  key={`${candidate.left.vaultId}:${candidate.left.entryId}:${candidate.right.vaultId}:${candidate.right.entryId}`}
                >
                  <header>
                    <div>
                      <span
                        className={`status-pill ${
                          candidate.confidence === 'likely' ? 'status-pill--warning' : ''
                        }`}
                      >
                        {candidate.confidence === 'likely'
                          ? 'Wahrscheinliche Dublette'
                          : 'Mögliche Dublette'}
                      </span>
                      <span>{ENTRY_TYPE_LABELS[candidate.type]}</span>
                    </div>
                    <small>{String(candidate.reasons.length)} nachvollziehbare Gründe</small>
                  </header>
                  <div className="duplicate-card__entries">
                    <DuplicateSide
                      label="Eintrag links"
                      candidate={candidate.left}
                      busy={busy}
                      onTrash={onTrashCandidate}
                    />
                    <span className="duplicate-card__separator" aria-hidden="true">
                      ⇄
                    </span>
                    <DuplicateSide
                      label="Eintrag rechts"
                      candidate={candidate.right}
                      busy={busy}
                      onTrash={onTrashCandidate}
                    />
                  </div>
                  <div className="duplicate-card__reasons">
                    <strong>Warum dieses Paar angezeigt wird</strong>
                    <ul>
                      {candidate.reasons.map((reason) => (
                        <li key={reason}>
                          <Check aria-hidden="true" />
                          <span>{DUPLICATE_REASON_LABELS[reason]}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <footer>
                    <Button
                      variant="ghost"
                      disabled={busy}
                      onClick={() => onKeepSeparate(candidate)}
                    >
                      Getrennt behalten
                    </Button>
                    <div>
                      <Button disabled={busy} onClick={() => onOpenMerge(candidate, 'left')}>
                        Links als Haupteintrag
                      </Button>
                      <Button
                        variant="primary"
                        disabled={busy}
                        onClick={() => onOpenMerge(candidate, 'right')}
                      >
                        Rechts als Haupteintrag
                      </Button>
                    </div>
                  </footer>
                </article>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function DuplicateSide({
  label,
  candidate,
  busy,
  onTrash,
}: {
  label: string;
  candidate: DuplicateCandidateDto['left'];
  busy: boolean;
  onTrash: (candidate: DuplicateCandidateDto['left']) => void;
}) {
  return (
    <div className="duplicate-side">
      <small>{label}</small>
      <strong>{candidate.title || 'Eintrag ohne Titel'}</strong>
      {candidate.vaultName && <span>Tresor: {candidate.vaultName}</span>}
      <span>{candidate.subtitle || 'Keine zusätzliche Beschreibung'}</span>
      <time dateTime={candidate.updatedAt}>Geändert: {formatDate(candidate.updatedAt)}</time>
      <Button
        variant="danger"
        icon={<Trash2 aria-hidden="true" />}
        disabled={busy}
        onClick={() => onTrash(candidate)}
      >
        In Papierkorb verschieben
      </Button>
    </div>
  );
}

function QualityPanel({
  report,
  busy,
  previewBusyFindingId,
  fixResult,
  onScan,
  onPreviewFix,
  onOpenFinding,
}: {
  report: DataQualityReportDto | null;
  busy: boolean;
  previewBusyFindingId: string | null;
  fixResult: DataQualityFixResultDto | null;
  onScan: (refresh: boolean) => void;
  onPreviewFix: (finding: DataQualityFindingDto) => void;
  onOpenFinding?: (reference: DataQualityReferenceDto) => void;
}) {
  return (
    <div className="quality-panel">
      <header className="quality-panel__header">
        <div>
          <h2>Lokale Datenqualitätsprüfung</h2>
          <p>
            Fachliche Korrekturen werden nie automatisch ausgeführt. Jede unterstützte Änderung
            erhält zuerst eine Vorschau.
          </p>
        </div>
        <Button
          icon={<RefreshCw aria-hidden="true" />}
          busy={busy}
          onClick={() => onScan(report !== null)}
        >
          {report === null ? 'Jetzt prüfen' : 'Aktualisieren'}
        </Button>
      </header>

      {fixResult !== null && (
        <InlineNotice kind="success" title="Korrektur angewendet">
          {fixResult.affectedEntryIds.length === 1
            ? 'Ein Eintrag wurde angepasst.'
            : `${String(fixResult.affectedEntryIds.length)} Einträge wurden angepasst.`}{' '}
          {fixResult.savedViewsChanged === 1
            ? 'Eine gespeicherte Ansicht wurde bereinigt.'
            : `${String(fixResult.savedViewsChanged)} gespeicherte Ansichten wurden bereinigt.`}{' '}
          Starte die Prüfung erneut, um den aktuellen Stand zu sehen.
        </InlineNotice>
      )}

      {report === null ? (
        busy ? (
          <LoadingState label="Datenqualität wird lokal geprüft …" />
        ) : (
          <EmptyState
            title="Noch keine Datenqualitätsprüfung"
            description="Die Prüfung untersucht Einträge, Anhänge und fachliche Referenzen ausschließlich lokal."
            action={
              <Button icon={<ShieldCheck aria-hidden="true" />} onClick={() => onScan(false)}>
                Datenqualität prüfen
              </Button>
            }
          />
        )
      ) : (
        <>
          <div className="quality-summary" aria-label="Zusammenfassung der Datenqualitätsprüfung">
            <span>
              <strong>{String(report.scannedEntries)}</strong>
              <small>Einträge geprüft</small>
            </span>
            <span>
              <strong>{String(report.findings.length)}</strong>
              <small>Befunde</small>
            </span>
            <span>
              <strong>{formatDate(report.generatedAt)}</strong>
              <small>Stand der Prüfung</small>
            </span>
          </div>
          <InlineNotice kind="success" title="Offline geprüft">
            Die Prüfung hat keinen Netzwerkzugriff verwendet.
          </InlineNotice>
          {report.findings.length === 0 ? (
            <EmptyState
              title="Keine Datenqualitätsbefunde"
              description="Für den geprüften Stand wurden keine unterstützten Pflegeprobleme gefunden."
            />
          ) : (
            <div className="quality-finding-list" aria-label="Datenqualitätsbefunde">
              {report.findings.map((finding) => {
                const copy = DATA_QUALITY_COPY[finding.code];
                return (
                  <article className="quality-finding" key={finding.id}>
                    <span
                      className={`quality-finding__icon quality-finding__icon--${finding.severity}`}
                      aria-hidden="true"
                    >
                      {finding.severity === 'warning' ? <AlertTriangle /> : <ShieldCheck />}
                    </span>
                    <div>
                      <header>
                        <div>
                          <span className="status-pill">
                            {finding.severity === 'warning' ? 'Prüfen' : 'Hinweis'}
                          </span>
                          <small>{findingReferenceLabel(finding)}</small>
                        </div>
                        <h3>{copy.title}</h3>
                      </header>
                      <p>{copy.description}</p>
                    </div>
                    <div className="quality-finding__action">
                      {onOpenFinding !== undefined &&
                        (finding.reference.kind === 'entry' ||
                          (finding.reference.kind === 'attachment' &&
                            finding.reference.entryId !== null)) && (
                          <Button variant="ghost" onClick={() => onOpenFinding(finding.reference)}>
                            Eintrag öffnen
                          </Button>
                        )}
                      {finding.fixCode === null ? (
                        <span>Manuell prüfen</span>
                      ) : (
                        <Button
                          icon={<Wrench aria-hidden="true" />}
                          busy={previewBusyFindingId === finding.id}
                          disabled={
                            previewBusyFindingId !== null && previewBusyFindingId !== finding.id
                          }
                          onClick={() => onPreviewFix(finding)}
                        >
                          Korrektur prüfen
                        </Button>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function MergeDialog({
  description,
  fieldChoices,
  collectionChoices,
  confirmed,
  busy,
  onFieldChoice,
  onCollectionChoice,
  onConfirmedChange,
  onClose,
  onMerge,
}: {
  description: DuplicateMergeDescriptionDto | null;
  fieldChoices: Record<string, DuplicateMergeChoiceDto['source']>;
  collectionChoices: Record<string, DuplicateMergeCollectionChoiceDto['strategy']>;
  confirmed: boolean;
  busy: boolean;
  onFieldChoice: (field: string, source: DuplicateMergeChoiceDto['source']) => void;
  onCollectionChoice: (
    field: string,
    strategy: DuplicateMergeCollectionChoiceDto['strategy'],
  ) => void;
  onConfirmedChange: (confirmed: boolean) => void;
  onClose: () => void;
  onMerge: () => void;
}) {
  return (
    <Modal
      open={description !== null}
      title="Dubletten zusammenführen"
      description="Wähle für jedes Feld nachvollziehbar die Quelle. Der Haupteintrag bleibt bestehen."
      size="wide"
      onClose={onClose}
      closeLabel="Merge-Vorschau schließen"
      footer={
        <div className="merge-dialog__footer">
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            Abbrechen
          </Button>
          <Button variant="primary" busy={busy} disabled={!confirmed} onClick={onMerge}>
            Auswahl zusammenführen
          </Button>
        </div>
      }
    >
      {description !== null && (
        <div className="merge-dialog">
          <div className="merge-overview">
            <div>
              <small>Haupteintrag bleibt erhalten</small>
              <strong>{description.survivor.title || 'Eintrag ohne Titel'}</strong>
              <span>{description.survivor.subtitle || 'Keine zusätzliche Beschreibung'}</span>
            </div>
            <span aria-hidden="true">←</span>
            <div>
              <small>Doppelter Eintrag kommt in den Papierkorb</small>
              <strong>{description.duplicate.title || 'Eintrag ohne Titel'}</strong>
              <span>{description.duplicate.subtitle || 'Keine zusätzliche Beschreibung'}</span>
            </div>
          </div>

          {description.scalarFields.length > 0 && (
            <section aria-labelledby="merge-fields-title">
              <div className="subsection-heading">
                <div>
                  <h3 id="merge-fields-title">Werte pro Feld wählen</h3>
                  <p>Geheime Vorschauen bleiben so redigiert, wie der Main-Prozess sie liefert.</p>
                </div>
              </div>
              <div className="merge-field-list">
                {description.scalarFields.map((field) => (
                  <fieldset className="merge-field" key={field.field}>
                    <legend>
                      {field.label}
                      {field.secret && <span>Geheimes Feld</span>}
                    </legend>
                    <div className="merge-field__options">
                      <label
                        className={
                          (fieldChoices[field.field] ?? 'survivor') === 'survivor'
                            ? 'is-selected'
                            : ''
                        }
                      >
                        <input
                          type="radio"
                          name={`merge-field-${field.field}`}
                          value="survivor"
                          checked={(fieldChoices[field.field] ?? 'survivor') === 'survivor'}
                          onChange={() => onFieldChoice(field.field, 'survivor')}
                        />
                        <span>
                          <strong>Aus Haupteintrag</strong>
                          <span className="merge-value">{field.survivorPreview || 'Leer'}</span>
                        </span>
                      </label>
                      <label
                        className={fieldChoices[field.field] === 'duplicate' ? 'is-selected' : ''}
                      >
                        <input
                          type="radio"
                          name={`merge-field-${field.field}`}
                          value="duplicate"
                          checked={fieldChoices[field.field] === 'duplicate'}
                          onChange={() => onFieldChoice(field.field, 'duplicate')}
                        />
                        <span>
                          <strong>Aus doppeltem Eintrag</strong>
                          <span className="merge-value">{field.duplicatePreview || 'Leer'}</span>
                        </span>
                      </label>
                    </div>
                  </fieldset>
                ))}
              </div>
            </section>
          )}

          {description.collectionFields.length > 0 && (
            <section aria-labelledby="merge-collections-title">
              <div className="subsection-heading">
                <div>
                  <h3 id="merge-collections-title">Sammlungen zusammenführen</h3>
                  <p>Wähle Haupteintrag, doppelten Eintrag oder die Vereinigungsmenge.</p>
                </div>
              </div>
              <div className="merge-collection-list">
                {description.collectionFields.map((field) => (
                  <fieldset className="merge-collection" key={field.field}>
                    <legend>{field.label}</legend>
                    <label>
                      <input
                        type="radio"
                        name={`merge-collection-${field.field}`}
                        checked={collectionChoices[field.field] === 'survivor'}
                        onChange={() => onCollectionChoice(field.field, 'survivor')}
                      />
                      <span>
                        Nur Haupteintrag
                        <small>{String(field.survivorCount)} vorhanden</small>
                      </span>
                    </label>
                    <label>
                      <input
                        type="radio"
                        name={`merge-collection-${field.field}`}
                        checked={collectionChoices[field.field] === 'duplicate'}
                        onChange={() => onCollectionChoice(field.field, 'duplicate')}
                      />
                      <span>
                        Nur doppelter Eintrag
                        <small>{String(field.duplicateCount)} vorhanden</small>
                      </span>
                    </label>
                    <label>
                      <input
                        type="radio"
                        name={`merge-collection-${field.field}`}
                        checked={(collectionChoices[field.field] ?? 'union') === 'union'}
                        onChange={() => onCollectionChoice(field.field, 'union')}
                      />
                      <span>
                        Zusammenführen
                        <small>Einmalige Werte aus beiden Einträgen</small>
                      </span>
                    </label>
                  </fieldset>
                ))}
              </div>
            </section>
          )}

          {description.potentialAttachmentDuplicates > 0 && (
            <InlineNotice kind="info" title="Anhangsprüfung">
              {description.potentialAttachmentDuplicates === 1
                ? 'Ein möglicherweise gleicher Anhang wird vor dem Merge über den authentifizierten Inhaltspfad verifiziert.'
                : `${String(description.potentialAttachmentDuplicates)} möglicherweise gleiche Anhänge werden vor dem Merge über den authentifizierten Inhaltspfad verifiziert.`}
            </InlineNotice>
          )}

          <label className="merge-confirmation">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => onConfirmedChange(event.currentTarget.checked)}
            />
            <span>
              <strong>Merge verbindlich bestätigen</strong>
              Ich habe die Feldquellen geprüft. Der doppelte Eintrag wird nach erfolgreichem,
              atomarem Merge in den Papierkorb verschoben.
            </span>
          </label>
        </div>
      )}
    </Modal>
  );
}

function TrashCandidateDialog({
  candidate,
  busy,
  error,
  onClose,
  onConfirm,
}: {
  candidate: DuplicateCandidateDto['left'] | null;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={candidate !== null}
      title="Eintrag in den Papierkorb verschieben"
      description="Der andere Eintrag bleibt unverändert. Es werden keine Werte zusammengeführt."
      size="small"
      onClose={onClose}
      closeLabel="Papierkorb-Bestätigung schließen"
      footer={
        <div className="merge-dialog__footer">
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            Abbrechen
          </Button>
          <Button
            variant="danger"
            icon={<Trash2 aria-hidden="true" />}
            busy={busy}
            onClick={onConfirm}
          >
            In Papierkorb verschieben
          </Button>
        </div>
      }
    >
      {candidate !== null && (
        <div className="trash-candidate-confirmation">
          <InlineNotice kind="warning" title="Ausgewählten Eintrag verschieben">
            <strong>{candidate.title || 'Eintrag ohne Titel'}</strong>
            {candidate.subtitle && <span>{candidate.subtitle}</span>}
          </InlineNotice>
          <p>
            Der Eintrag kann über den Papierkorb wiederhergestellt werden. Dieses Dublettenpaar
            verschwindet anschließend aus der aktuellen Ergebnisliste.
          </p>
          {error !== null && (
            <InlineNotice kind="error" title="Verschieben fehlgeschlagen">
              {error}
            </InlineNotice>
          )}
        </div>
      )}
    </Modal>
  );
}

function FixPreviewDialog({
  preview,
  busy,
  onClose,
  onApply,
}: {
  preview: DataQualityFixPreviewDto | null;
  busy: boolean;
  onClose: () => void;
  onApply: () => void;
}) {
  return (
    <Modal
      open={preview !== null}
      title={preview?.title ?? 'Korrekturvorschau'}
      description="Prüfe die fachliche Änderung, bevor Kryptris sie anwendet."
      size="medium"
      onClose={onClose}
      closeLabel="Korrekturvorschau schließen"
      footer={
        <div className="merge-dialog__footer">
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            Abbrechen
          </Button>
          <Button
            variant="primary"
            icon={<Wrench aria-hidden="true" />}
            busy={busy}
            onClick={onApply}
          >
            Vorschau bestätigen
          </Button>
        </div>
      }
    >
      {preview !== null && (
        <div className="quality-fix-preview">
          <span aria-hidden="true">
            <Wrench />
          </span>
          <div>
            <strong>Vorgeschlagene Änderung</strong>
            <p>{preview.description}</p>
            <small>Vorschau gültig bis {formatDate(preview.expiresAt)}</small>
          </div>
        </div>
      )}
    </Modal>
  );
}
