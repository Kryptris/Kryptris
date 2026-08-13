import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  Database,
  FileCheck2,
  HardDriveDownload,
  Info,
  KeyRound,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
  WifiOff,
  X,
} from 'lucide-react';
import type { CSSProperties, FormEvent, ReactNode } from 'react';
import { useEffect, useRef, useState } from 'react';

import type {
  BreachListStatusDto,
  BreachScanReportDto,
  IntegrityFindingCode,
  IntegrityReportDto,
  LocalJobKind,
  LocalJobProgressEvent,
  RecoveryReadinessState,
  RecoveryReadinessStatusDto,
  SecurityCenterAction,
  SecurityCenterCardDto,
  SecurityCenterCardId,
  SecurityCenterFindingCode,
  SecurityCenterReportDto,
  SecuritySeverity,
} from '../../shared/models';
import type { Notify, WorkspaceSection } from '../types';
import { formatDate, getErrorMessage } from '../utils';
import { Button, EmptyState, Field, InlineNotice, LoadingState, Modal, PasswordInput } from './ui';

interface SecurityJob {
  requestId: string;
  kind: Extract<LocalJobKind, 'security-center' | 'integrity' | 'breach-import' | 'breach-scan'>;
}

export interface SecurityViewProps {
  progressEvents: LocalJobProgressEvent[];
  notify: Notify;
  onScanCenter: (input: {
    requestId: string;
    refresh?: boolean;
  }) => Promise<SecurityCenterReportDto>;
  onGetRecoveryReadiness: () => Promise<RecoveryReadinessStatusDto>;
  onTestRecoveryReadiness: (input: { recoveryKey: string }) => Promise<RecoveryReadinessStatusDto>;
  onScanIntegrity: (input: { requestId: string; refresh?: boolean }) => Promise<IntegrityReportDto>;
  onSaveIntegrityReport: (input: { reportId: string }) => Promise<boolean>;
  onGetBreachListStatus: () => Promise<BreachListStatusDto>;
  onImportBreachList: (input: {
    requestId: string;
    sourceLabel: string;
    sourceDate: string;
  }) => Promise<BreachListStatusDto | null>;
  onScanBreachList: (input: {
    requestId: string;
    refresh?: boolean;
  }) => Promise<BreachScanReportDto>;
  onRemoveBreachList: () => Promise<BreachListStatusDto>;
  onCancel: (requestId: string) => Promise<boolean>;
  onNavigate: (section: WorkspaceSection) => void;
  onOpenSettings: (tab: 'security' | 'factors') => void;
  onOpenEntry: (vaultId: string, entryId: string) => void;
}

const CARD_COPY: Record<SecurityCenterCardId, { title: string; description: string }> = {
  credentials: {
    title: 'Zugangsdaten',
    description: 'Bewertet schwache, wiederverwendete und veraltete Passwörter lokal.',
  },
  'data-quality': {
    title: 'Datenqualität',
    description: 'Findet unvollständige oder technisch auffällige Tresoreinträge.',
  },
  factors: {
    title: 'Zusätzliche Faktoren',
    description: 'Prüft, ob ein zusätzlicher lokaler Entsperrfaktor eingerichtet ist.',
  },
  backup: {
    title: 'Backups',
    description: 'Bewertet die lokale Backup-Konfiguration und den letzten Sicherungsstand.',
  },
  recovery: {
    title: 'Wiederherstellung',
    description: 'Zeigt, ob der Wiederherstellungsschlüssel zuletzt erfolgreich geprüft wurde.',
  },
  kdf: {
    title: 'Schlüsselableitung',
    description: 'Prüft die lokalen Parameter der Master-Passwort-Ableitung.',
  },
  integrity: {
    title: 'Datenintegrität',
    description: 'Prüft Container, Verweise und Anhänge ohne Geheimwerte auszugeben.',
  },
  'breach-list': {
    title: 'Lokaler Datenleckabgleich',
    description: 'Vergleicht Passwörter ausschließlich mit einer lokal importierten Hashliste.',
  },
};

const FINDING_COPY: Record<SecurityCenterFindingCode, string> = {
  'credential-findings': 'Zugangsdaten benötigen Aufmerksamkeit.',
  'data-quality-findings': 'Datenqualitätsbefunde liegen vor.',
  'additional-factor-missing': 'Kein zusätzlicher Entsperrfaktor ist eingerichtet.',
  'automatic-backup-disabled': 'Automatische Backups sind deaktiviert.',
  'automatic-backup-missing': 'Es wurde noch kein automatisches Backup erstellt.',
  'automatic-backup-stale': 'Das letzte automatische Backup ist veraltet.',
  'recovery-not-configured': 'Kein Wiederherstellungsschlüssel ist eingerichtet.',
  'recovery-never-tested': 'Der Wiederherstellungsschlüssel wurde noch nie geprüft.',
  'recovery-test-failed': 'Die letzte Wiederherstellungsprüfung ist fehlgeschlagen.',
  'recovery-test-stale': 'Die letzte erfolgreiche Wiederherstellungsprüfung ist veraltet.',
  'kdf-outdated': 'Die Parameter der Schlüsselableitung sollten aktualisiert werden.',
  'integrity-not-run': 'Die Datenintegrität wurde noch nicht geprüft.',
  'integrity-failed': 'Die letzte Integritätsprüfung hat Befunde ergeben.',
  'breach-list-not-configured': 'Es ist keine lokale Datenleckliste eingerichtet.',
  'breach-list-missing': 'Die eingerichtete Datenleckliste fehlt.',
  'breach-list-corrupt': 'Die lokale Datenleckliste ist beschädigt.',
  'breached-passwords-found': 'Der lokale Abgleich hat betroffene Passwörter erkannt.',
};

const ACTION_COPY: Record<SecurityCenterAction, string> = {
  'review-credentials': 'Zugangsdaten prüfen',
  'review-data-quality': 'Datenpflege öffnen',
  'open-factor-settings': 'Faktoren verwalten',
  'open-backups': 'Backups öffnen',
  'test-recovery': 'Schlüssel testen',
  'change-master-password': 'Master-Passwort ändern',
  'run-integrity': 'Integrität prüfen',
  'configure-breach-list': 'Liste importieren',
  'review-breach-findings': 'Befunde anzeigen',
  none: 'Kein Handlungsbedarf',
};

const INTEGRITY_COPY: Record<IntegrityFindingCode, string> = {
  'profile-invalid': 'Das Profilformat konnte nicht verifiziert werden.',
  'profile-metadata-invalid': 'Geschützte Profilmetadaten sind ungültig.',
  'profile-factor-invalid': 'Die Metadaten eines Zusatzfaktors sind ungültig.',
  'vault-registry-mismatch': 'Tresorregister und gespeicherte Tresore stimmen nicht überein.',
  'vault-container-invalid': 'Ein Tresorcontainer konnte nicht verifiziert werden.',
  'audit-invalid': 'Das lokale Aktivitätsprotokoll konnte nicht verifiziert werden.',
  'duplicate-vault-id': 'Eine Tresor-ID kommt mehrfach vor.',
  'duplicate-folder-id': 'Eine Ordner-ID kommt mehrfach vor.',
  'duplicate-entry-id': 'Eine Eintrags-ID kommt mehrfach vor.',
  'entry-vault-mismatch': 'Ein Eintrag verweist auf den falschen Tresor.',
  'folder-reference-invalid': 'Eine Ordnerzuordnung ist verwaist.',
  'saved-view-reference-invalid': 'Eine gespeicherte Ansicht enthält verwaiste Verweise.',
  'attachment-reference-duplicate': 'Eine Anhangsreferenz kommt mehrfach vor.',
  'attachment-missing': 'Eine referenzierte Anhangsdatei fehlt.',
  'attachment-orphan': 'Eine Anhangsdatei ist keinem Eintrag zugeordnet.',
  'attachment-container-invalid': 'Ein Anhangscontainer konnte nicht verifiziert werden.',
  'attachment-metadata-mismatch': 'Anhangscontainer und Metadaten stimmen nicht überein.',
};

const RECOVERY_COPY: Record<RecoveryReadinessState, { title: string; kind: SecuritySeverity }> = {
  'not-configured': { title: 'Nicht eingerichtet', kind: 'warning' },
  'never-tested': { title: 'Noch nie geprüft', kind: 'warning' },
  failed: { title: 'Letzter Test fehlgeschlagen', kind: 'critical' },
  stale: { title: 'Erfolgreicher Test ist veraltet', kind: 'warning' },
  ready: { title: 'Erfolgreich geprüft', kind: 'good' },
};

const BREACH_STATUS_COPY: Record<
  BreachListStatusDto['state'],
  { title: string; kind: SecuritySeverity }
> = {
  'not-configured': { title: 'Nicht eingerichtet', kind: 'info' },
  ready: { title: 'Bereit für lokalen Abgleich', kind: 'good' },
  missing: { title: 'Lokale Listendatei fehlt', kind: 'warning' },
  corrupt: { title: 'Lokale Listendatei ist beschädigt', kind: 'critical' },
};

const PROGRESS_PHASE_COPY: Record<string, string> = {
  entries: 'Einträge werden lokal bewertet',
  profile: 'Profilcontainer wird geprüft',
  vaults: 'Tresorcontainer werden geprüft',
  references: 'Lokale Verweise werden geprüft',
  attachments: 'Anhänge werden authentifiziert geprüft',
  audit: 'Aktivitätsprotokoll wird geprüft',
  'source-validate': 'Quelldatei wird validiert und indexiert',
  'index-validate': 'Lokaler Index wird verifiziert',
  'password-scan': 'Passwörter werden lokal abgeglichen',
};

export function SecurityView({
  progressEvents,
  notify,
  onScanCenter,
  onGetRecoveryReadiness,
  onTestRecoveryReadiness,
  onScanIntegrity,
  onSaveIntegrityReport,
  onGetBreachListStatus,
  onImportBreachList,
  onScanBreachList,
  onRemoveBreachList,
  onCancel,
  onNavigate,
  onOpenSettings,
  onOpenEntry,
}: SecurityViewProps) {
  const [center, setCenter] = useState<SecurityCenterReportDto | null>(null);
  const [recovery, setRecovery] = useState<RecoveryReadinessStatusDto | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityReportDto | null>(null);
  const [breachStatus, setBreachStatus] = useState<BreachListStatusDto | null>(null);
  const [breachReport, setBreachReport] = useState<BreachScanReportDto | null>(null);
  const [activeJob, setActiveJob] = useState<SecurityJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [loadingMetadata, setLoadingMetadata] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liveMessage, setLiveMessage] = useState('');
  const [recoveryDialogOpen, setRecoveryDialogOpen] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState('');
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [sourceLabel, setSourceLabel] = useState('');
  const [sourceDate, setSourceDate] = useState('');
  const [removeDialogOpen, setRemoveDialogOpen] = useState(false);
  const [removeConfirmed, setRemoveConfirmed] = useState(false);
  const [removeBusy, setRemoveBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const activeJobRef = useRef<SecurityJob | null>(null);
  const mountedRef = useRef(true);
  const initialLoadStartedRef = useRef(false);
  const findingsRef = useRef<HTMLElement>(null);
  const breachFindingsRef = useRef<HTMLElement>(null);

  const setJob = (job: SecurityJob | null) => {
    activeJobRef.current = job;
    setActiveJob(job);
  };

  const currentProgress =
    activeJob === null
      ? null
      : (progressEvents.find(
          (event) => event.job === activeJob.kind && event.requestId === activeJob.requestId,
        ) ?? null);

  const runCenterScan = async (refresh: boolean) => {
    if (activeJobRef.current !== null) return;
    const job = { requestId: crypto.randomUUID(), kind: 'security-center' as const };
    setJob(job);
    setError(null);
    setLiveMessage('Die lokale Sicherheitsbewertung wurde gestartet.');
    try {
      const report = await onScanCenter({ requestId: job.requestId, refresh });
      if (!mountedRef.current) return;
      setCenter(report);
      setLiveMessage(`Lokaler Vorsorgewert: ${String(report.score)} von 100.`);
    } catch (scanError: unknown) {
      if (!mountedRef.current) return;
      setError(getErrorMessage(scanError));
      setLiveMessage('Die lokale Sicherheitsbewertung konnte nicht abgeschlossen werden.');
    } finally {
      const currentJob = activeJobRef.current as SecurityJob | null;
      if (mountedRef.current && currentJob?.requestId === job.requestId) setJob(null);
      if (mountedRef.current) setCancelling(false);
    }
  };

  useEffect(() => {
    mountedRef.current = true;
    if (!initialLoadStartedRef.current) {
      initialLoadStartedRef.current = true;
      void Promise.all([onGetRecoveryReadiness(), onGetBreachListStatus()])
        .then(([nextRecovery, nextBreach]) => {
          if (!mountedRef.current) return;
          setRecovery(nextRecovery);
          setBreachStatus(nextBreach);
        })
        .catch((metadataError: unknown) => {
          if (mountedRef.current) setError(getErrorMessage(metadataError));
        })
        .finally(() => {
          if (mountedRef.current) setLoadingMetadata(false);
        });
      void runCenterScan(false);
    }
    return () => {
      mountedRef.current = false;
      const job = activeJobRef.current;
      if (job !== null) void onCancel(job.requestId).catch(() => undefined);
    };
    // Die Callback-Referenzen stammen aus der API-Bridge; der Guard verhindert Doppelstarts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refreshCenter = () => {
    void runCenterScan(true);
  };

  const finishJob = (job: SecurityJob) => {
    if (activeJobRef.current?.requestId === job.requestId) setJob(null);
    setCancelling(false);
  };

  const refreshCenterAfterAction = () => {
    if (activeJobRef.current === null) void runCenterScan(true);
  };

  const runIntegrity = async (refresh: boolean) => {
    if (activeJobRef.current !== null) return;
    const job = { requestId: crypto.randomUUID(), kind: 'integrity' as const };
    setJob(job);
    setError(null);
    setLiveMessage('Die lokale Integritätsprüfung wurde gestartet.');
    try {
      const report = await onScanIntegrity({ requestId: job.requestId, refresh });
      if (!mountedRef.current) return;
      setIntegrity(report);
      setLiveMessage(
        report.success
          ? 'Die lokale Integritätsprüfung wurde ohne Befund abgeschlossen.'
          : `Die Integritätsprüfung hat ${String(report.findings.length)} Befunde ergeben.`,
      );
    } catch (scanError: unknown) {
      if (!mountedRef.current) return;
      setError(getErrorMessage(scanError));
      setLiveMessage('Die Integritätsprüfung konnte nicht abgeschlossen werden.');
    } finally {
      if (mountedRef.current) {
        finishJob(job);
        refreshCenterAfterAction();
      }
    }
  };

  const submitRecoveryTest = async (event: FormEvent) => {
    event.preventDefault();
    if (recoveryBusy || recoveryKey.trim().length === 0) return;
    const submittedKey = recoveryKey;
    setRecoveryBusy(true);
    setRecoveryError(null);
    try {
      const status = await onTestRecoveryReadiness({ recoveryKey: submittedKey });
      if (!mountedRef.current) return;
      setRecovery(status);
      setRecoveryDialogOpen(false);
      notify(
        status.state === 'ready' ? 'success' : 'warning',
        status.state === 'ready'
          ? 'Wiederherstellungsschlüssel erfolgreich geprüft'
          : 'Wiederherstellungsprüfung nicht erfolgreich',
      );
      refreshCenterAfterAction();
    } catch (testError: unknown) {
      if (mountedRef.current) {
        setRecoveryError(getErrorMessage(testError));
        void onGetRecoveryReadiness()
          .then((status) => {
            if (mountedRef.current) {
              setRecovery(status);
              refreshCenterAfterAction();
            }
          })
          .catch(() => undefined);
      }
    } finally {
      if (mountedRef.current) {
        setRecoveryKey('');
        setRecoveryBusy(false);
      }
    }
  };

  const closeRecoveryDialog = () => {
    setRecoveryDialogOpen(false);
    setRecoveryKey('');
    setRecoveryError(null);
  };

  const submitBreachImport = async (event: FormEvent) => {
    event.preventDefault();
    if (
      activeJobRef.current !== null ||
      sourceLabel.trim().length === 0 ||
      sourceDate.length === 0
    ) {
      return;
    }
    const job = { requestId: crypto.randomUUID(), kind: 'breach-import' as const };
    setJob(job);
    setImportDialogOpen(false);
    setError(null);
    setLiveMessage('Die lokale Datenleckliste wird validiert und indexiert.');
    try {
      const status = await onImportBreachList({
        requestId: job.requestId,
        sourceLabel: sourceLabel.trim(),
        sourceDate,
      });
      if (!mountedRef.current) return;
      if (status === null) {
        setLiveMessage('Der Import wurde vor der Dateiauswahl beendet.');
        return;
      }
      setBreachStatus(status);
      setBreachReport(null);
      setSourceLabel('');
      setSourceDate('');
      notify('success', 'Lokale Datenleckliste importiert', 'Es wurde kein Netzwerk verwendet.');
    } catch (importError: unknown) {
      if (!mountedRef.current) return;
      setError(getErrorMessage(importError));
      setLiveMessage('Die lokale Datenleckliste konnte nicht importiert werden.');
    } finally {
      if (mountedRef.current) {
        finishJob(job);
        refreshCenterAfterAction();
      }
    }
  };

  const runBreachScan = async (refresh: boolean) => {
    if (activeJobRef.current !== null || breachStatus?.state !== 'ready') return;
    const job = { requestId: crypto.randomUUID(), kind: 'breach-scan' as const };
    setJob(job);
    setError(null);
    setLiveMessage('Der vollständig lokale Datenleckabgleich wurde gestartet.');
    try {
      const report = await onScanBreachList({ requestId: job.requestId, refresh });
      if (!mountedRef.current) return;
      setBreachReport(report);
      setLiveMessage(
        report.findings.length === 0
          ? 'Der lokale Datenleckabgleich wurde ohne Befund abgeschlossen.'
          : `${String(report.findings.length)} betroffene Einträge wurden lokal erkannt.`,
      );
    } catch (scanError: unknown) {
      if (!mountedRef.current) return;
      setError(getErrorMessage(scanError));
      setLiveMessage('Der lokale Datenleckabgleich konnte nicht abgeschlossen werden.');
      void onGetBreachListStatus()
        .then((status) => {
          if (mountedRef.current) setBreachStatus(status);
        })
        .catch(() => undefined);
    } finally {
      if (mountedRef.current) {
        finishJob(job);
        refreshCenterAfterAction();
      }
    }
  };

  const removeBreachList = async () => {
    if (!removeConfirmed || removeBusy || activeJobRef.current !== null) return;
    setRemoveBusy(true);
    try {
      const status = await onRemoveBreachList();
      if (!mountedRef.current) return;
      setBreachStatus(status);
      setBreachReport(null);
      setRemoveDialogOpen(false);
      setRemoveConfirmed(false);
      notify('success', 'Lokale Datenleckliste entfernt');
      refreshCenterAfterAction();
    } catch (removeError: unknown) {
      if (mountedRef.current) setError(getErrorMessage(removeError));
    } finally {
      if (mountedRef.current) setRemoveBusy(false);
    }
  };

  const cancelActiveJob = async () => {
    const job = activeJobRef.current;
    if (job === null || cancelling) return;
    setCancelling(true);
    try {
      const accepted = await onCancel(job.requestId);
      setLiveMessage(
        accepted
          ? 'Der Abbruch wurde angefordert.'
          : 'Die lokale Prüfung war bereits abgeschlossen.',
      );
    } catch (cancelError: unknown) {
      setError(getErrorMessage(cancelError));
    } finally {
      if (mountedRef.current) setCancelling(false);
    }
  };

  const saveIntegrityReport = async () => {
    if (integrity === null || saveBusy) return;
    setSaveBusy(true);
    try {
      const saved = await onSaveIntegrityReport({ reportId: integrity.reportId });
      if (saved) notify('success', 'Technischer Integritätsbericht gespeichert');
    } catch (saveError: unknown) {
      setError(getErrorMessage(saveError));
    } finally {
      setSaveBusy(false);
    }
  };

  const handleCardAction = (card: SecurityCenterCardDto) => {
    switch (card.action) {
      case 'review-credentials':
        findingsRef.current?.focus();
        break;
      case 'review-data-quality':
        onNavigate('quality');
        break;
      case 'open-factor-settings':
        onOpenSettings('factors');
        break;
      case 'change-master-password':
        onOpenSettings('security');
        break;
      case 'open-backups':
        onNavigate('backup');
        break;
      case 'test-recovery':
        setRecoveryDialogOpen(true);
        break;
      case 'run-integrity':
        void runIntegrity(true);
        break;
      case 'configure-breach-list':
        setImportDialogOpen(true);
        break;
      case 'review-breach-findings':
        breachFindingsRef.current?.focus();
        break;
      case 'none':
        break;
    }
  };

  return (
    <section className="tool-view security-center" aria-labelledby="security-center-title">
      <p className="sr-only" aria-live="polite">
        {liveMessage}
      </p>
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon" aria-hidden="true">
            <ShieldCheck />
          </span>
          <div>
            <p className="eyebrow">Vollständig offline</p>
            <h1 id="security-center-title">Sicherheitszentrale</h1>
            <p>Lokale Vorsorge, Wiederherstellung und technische Datenintegrität im Überblick.</p>
          </div>
        </div>
        <Button
          icon={<RefreshCw aria-hidden="true" />}
          busy={activeJob?.kind === 'security-center'}
          disabled={activeJob !== null && activeJob.kind !== 'security-center'}
          onClick={refreshCenter}
        >
          Neu bewerten
        </Button>
      </header>

      <InlineNotice kind="info" title="Was der Vorsorgewert aussagt">
        Der Wert bewertet ausschließlich lokale Kryptris-Einstellungen und Tresordaten. Er ist keine
        Aussage über Malware, ein kompromittiertes Windows-System oder die Sicherheit anderer
        Programme.
      </InlineNotice>

      {error !== null && (
        <InlineNotice kind="error" title="Aktion nicht abgeschlossen">
          {error}
        </InlineNotice>
      )}

      {activeJob !== null && (
        <SecurityJobProgress
          job={activeJob}
          progress={currentProgress}
          cancelling={cancelling}
          onCancel={() => void cancelActiveJob()}
        />
      )}

      {center === null ? (
        <LoadingState label="Die lokale Sicherheitsbewertung wird vorbereitet …" />
      ) : (
        <>
          <section className="security-center__overview" aria-labelledby="local-score-title">
            <div
              className="score-ring"
              style={{ '--score': `${String(center.score * 3.6)}deg` } as CSSProperties}
              aria-label={`Lokaler Vorsorgewert ${String(center.score)} von 100`}
            >
              <strong>{String(center.score)}</strong>
              <span>von 100</span>
            </div>
            <div>
              <p className="eyebrow">Lokaler Vorsorgewert</p>
              <h2 id="local-score-title">
                {center.score >= 80
                  ? 'Gute lokale Vorsorge'
                  : center.score >= 55
                    ? 'Einige Bereiche brauchen Aufmerksamkeit'
                    : 'Wichtige lokale Maßnahmen sind offen'}
              </h2>
              <p>Berechnet am {formatDate(center.generatedAt)}</p>
            </div>
            <div className="offline-seal">
              <WifiOff aria-hidden="true" />
              <strong>Kein Netzwerk verwendet</strong>
              <span>Passwörter, Hashes und Prüfergebnisse blieben auf diesem Gerät.</span>
            </div>
          </section>

          <div className="security-center__cards" aria-label="Lokale Sicherheitsbereiche">
            {center.cards.map((card) => (
              <SecurityCenterCard
                key={card.id}
                card={card}
                disabled={activeJob !== null}
                onAction={() => handleCardAction(card)}
              />
            ))}
          </div>

          <section
            className="tool-card security-center__findings"
            aria-labelledby="credential-findings-title"
            ref={findingsRef}
            tabIndex={-1}
          >
            <header>
              <div>
                <KeyRound aria-hidden="true" />
                <div>
                  <h2 id="credential-findings-title">Zugangsdaten mit Handlungsbedarf</h2>
                  <p>Die Liste enthält keine Passwörter oder Hashwerte.</p>
                </div>
              </div>
              <span>{String(center.entryFindings.length)}</span>
            </header>
            {center.entryFindings.length === 0 ? (
              <EmptyState
                title="Keine Zugangsdaten-Befunde"
                description="Die lokale Bewertung hat derzeit keine konkreten Eintragsempfehlungen."
              />
            ) : (
              <div className="security-center__finding-list">
                {center.entryFindings.map((finding) => (
                  <button
                    type="button"
                    key={finding.id}
                    className={`security-center__finding security-center__finding--${finding.severity}`}
                    onClick={() => onOpenEntry(finding.vaultId, finding.entryId)}
                  >
                    <FindingIcon severity={finding.severity} />
                    <span>
                      <strong>{finding.title}</strong>
                      <small>
                        {finding.entryTitle} · Tresor {finding.vaultName}
                      </small>
                      <span>{finding.recommendation}</span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </section>
        </>
      )}

      <section className="security-center__details" aria-label="Vertiefende lokale Prüfungen">
        <RecoveryPanel
          status={recovery}
          loading={loadingMetadata}
          disabled={activeJob !== null}
          onTest={() => setRecoveryDialogOpen(true)}
        />
        <IntegrityPanel
          report={integrity}
          busy={activeJob?.kind === 'integrity'}
          saveBusy={saveBusy}
          disabled={activeJob !== null && activeJob.kind !== 'integrity'}
          onScan={() => void runIntegrity(true)}
          onSave={() => void saveIntegrityReport()}
        />
      </section>

      <BreachPanel
        status={breachStatus}
        report={breachReport}
        loading={loadingMetadata}
        busy={activeJob?.kind === 'breach-import' || activeJob?.kind === 'breach-scan'}
        disabled={activeJob !== null}
        findingsRef={breachFindingsRef}
        onImport={() => setImportDialogOpen(true)}
        onScan={() => void runBreachScan(true)}
        onRemove={() => setRemoveDialogOpen(true)}
        onOpenEntry={onOpenEntry}
      />

      <Modal
        open={recoveryDialogOpen}
        title="Wiederherstellungsschlüssel testen"
        description="Der Schlüssel wird nur im Main-Prozess geprüft und weder gespeichert noch protokolliert."
        size="small"
        onClose={closeRecoveryDialog}
      >
        <form
          className="security-center__dialog-form"
          onSubmit={(event) => void submitRecoveryTest(event)}
        >
          <Field
            label="Wiederherstellungsschlüssel"
            hint="Gib den vollständigen Schlüssel ein. Der normale Entsperrversuch und dieser Test besitzen getrennte Fehlversuchszähler."
          >
            <PasswordInput
              value={recoveryKey}
              onChange={setRecoveryKey}
              autoComplete="off"
              autoFocus
              ariaLabel="Wiederherstellungsschlüssel"
            />
          </Field>
          {recoveryError !== null && (
            <InlineNotice kind="error" title="Prüfung fehlgeschlagen">
              {recoveryError}
            </InlineNotice>
          )}
          <div className="security-center__dialog-actions">
            <Button
              type="button"
              variant="ghost"
              disabled={recoveryBusy}
              onClick={closeRecoveryDialog}
            >
              Abbrechen
            </Button>
            <Button
              type="submit"
              variant="primary"
              busy={recoveryBusy}
              disabled={recoveryKey.trim().length === 0}
            >
              Schlüssel lokal prüfen
            </Button>
          </div>
        </form>
      </Modal>

      <Modal
        open={importDialogOpen}
        title="Lokale Datenleckliste importieren"
        description="Kryptris akzeptiert das dokumentierte SHA-1-Count-Format. Nach der Metadateneingabe wählst du eine lokale Datei aus."
        size="small"
        onClose={() => setImportDialogOpen(false)}
      >
        <form
          className="security-center__dialog-form"
          onSubmit={(event) => void submitBreachImport(event)}
        >
          <Field
            label="Bezeichnung der Quelle"
            hint="Nur eine sachliche Bezeichnung, keine Webadresse oder vertrauliche Notiz."
          >
            <input
              autoFocus
              aria-label="Bezeichnung der Quelle"
              value={sourceLabel}
              maxLength={120}
              onChange={(event) => setSourceLabel(event.currentTarget.value)}
            />
          </Field>
          <Field
            label="Stand der Liste"
            hint="Das veröffentlichte Datum des lokalen Datenbestands."
          >
            <input
              type="date"
              aria-label="Stand der Liste"
              value={sourceDate}
              onChange={(event) => setSourceDate(event.currentTarget.value)}
            />
          </Field>
          <InlineNotice kind="info">
            Der Import validiert und indexiert die Datei lokal. Kryptris lädt keine Liste aus dem
            Internet.
          </InlineNotice>
          <div className="security-center__dialog-actions">
            <Button type="button" variant="ghost" onClick={() => setImportDialogOpen(false)}>
              Abbrechen
            </Button>
            <Button
              type="submit"
              variant="primary"
              icon={<HardDriveDownload aria-hidden="true" />}
              disabled={sourceLabel.trim().length === 0 || sourceDate.length === 0}
            >
              Lokale Datei auswählen
            </Button>
          </div>
        </form>
      </Modal>

      <Modal
        open={removeDialogOpen}
        title="Lokale Datenleckliste entfernen?"
        description="Der lokale Hashindex und seine Metadaten werden entfernt. Tresoreinträge bleiben unverändert."
        size="small"
        onClose={() => {
          if (!removeBusy) {
            setRemoveDialogOpen(false);
            setRemoveConfirmed(false);
          }
        }}
      >
        <div className="security-center__dialog-form">
          <InlineNotice kind="warning" title="Erneuter Import erforderlich">
            Weitere Datenleckabgleiche sind erst nach einem neuen lokalen Import möglich.
          </InlineNotice>
          <label className="check-row">
            <input
              type="checkbox"
              checked={removeConfirmed}
              onChange={(event) => setRemoveConfirmed(event.currentTarget.checked)}
            />
            <span>Ich möchte die lokale Datenleckliste von diesem Gerät entfernen.</span>
          </label>
          <div className="security-center__dialog-actions">
            <Button
              variant="ghost"
              disabled={removeBusy}
              onClick={() => {
                setRemoveDialogOpen(false);
                setRemoveConfirmed(false);
              }}
            >
              Abbrechen
            </Button>
            <Button
              variant="danger"
              icon={<Trash2 aria-hidden="true" />}
              busy={removeBusy}
              disabled={!removeConfirmed}
              onClick={() => void removeBreachList()}
            >
              Liste entfernen
            </Button>
          </div>
        </div>
      </Modal>
    </section>
  );
}

function SecurityCenterCard({
  card,
  disabled,
  onAction,
}: {
  card: SecurityCenterCardDto;
  disabled: boolean;
  onAction: () => void;
}) {
  const copy = CARD_COPY[card.id];
  return (
    <article className={`security-center-card security-center-card--${card.severity}`}>
      <header>
        <FindingIcon severity={card.severity} />
        <span>
          <strong>{copy.title}</strong>
          <small>{severityLabel(card.severity)}</small>
        </span>
        <b aria-label={`${String(card.count)} Befunde`}>{String(card.count)}</b>
      </header>
      <p>{copy.description}</p>
      {card.findingCodes.length > 0 && (
        <ul>
          {card.findingCodes.map((code) => (
            <li key={code}>{FINDING_COPY[code]}</li>
          ))}
        </ul>
      )}
      <footer>
        <span>
          {card.calculatedAt === null ? 'Noch nicht berechnet' : formatDate(card.calculatedAt)}
        </span>
        {card.action === 'none' ? (
          <span className="security-center-card__complete">
            <CheckCircle2 aria-hidden="true" />
            Kein Handlungsbedarf
          </span>
        ) : (
          <Button variant="ghost" disabled={disabled} onClick={onAction}>
            {ACTION_COPY[card.action]}
          </Button>
        )}
      </footer>
    </article>
  );
}

function RecoveryPanel({
  status,
  loading,
  disabled,
  onTest,
}: {
  status: RecoveryReadinessStatusDto | null;
  loading: boolean;
  disabled: boolean;
  onTest: () => void;
}) {
  const copy = status === null ? null : RECOVERY_COPY[status.state];
  return (
    <section className="tool-card security-center__detail-card" aria-labelledby="recovery-title">
      <header>
        <div>
          <KeyRound aria-hidden="true" />
          <div>
            <h2 id="recovery-title">Wiederherstellungsbereitschaft</h2>
            <p>Der Schlüssel selbst wird nie angezeigt oder im Bericht gespeichert.</p>
          </div>
        </div>
      </header>
      {loading && status === null ? (
        <LoadingState label="Wiederherstellungsstatus wird geladen …" />
      ) : status === null || copy === null ? (
        <p className="security-center__muted">Status nicht verfügbar.</p>
      ) : (
        <div className="security-center__detail-body">
          <StatusBadge severity={copy.kind}>{copy.title}</StatusBadge>
          <dl className="security-center__metadata">
            <div>
              <dt>Letzter Test</dt>
              <dd>{status.lastTestedAt === null ? 'Noch nie' : formatDate(status.lastTestedAt)}</dd>
            </div>
            <div>
              <dt>Erneut fällig nach</dt>
              <dd>{String(status.staleAfterDays)} Tagen</dd>
            </div>
          </dl>
          {status.state !== 'not-configured' && (
            <Button variant="ghost" disabled={disabled} onClick={onTest}>
              Schlüssel lokal testen
            </Button>
          )}
          {status.state === 'not-configured' && (
            <p className="security-center__muted">
              Richte zuerst in den Einstellungen einen Wiederherstellungsschlüssel ein.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function IntegrityPanel({
  report,
  busy,
  saveBusy,
  disabled,
  onScan,
  onSave,
}: {
  report: IntegrityReportDto | null;
  busy: boolean;
  saveBusy: boolean;
  disabled: boolean;
  onScan: () => void;
  onSave: () => void;
}) {
  return (
    <section className="tool-card security-center__detail-card" aria-labelledby="integrity-title">
      <header>
        <div>
          <FileCheck2 aria-hidden="true" />
          <div>
            <h2 id="integrity-title">Technische Integritätsprüfung</h2>
            <p>Prüft lokale Container, IDs, Verweise, Anhänge und Auditdaten.</p>
          </div>
        </div>
      </header>
      <div className="security-center__detail-body">
        {report === null ? (
          <p className="security-center__muted">In dieser Sitzung liegt noch kein Bericht vor.</p>
        ) : (
          <>
            <StatusBadge severity={report.success ? 'good' : 'critical'}>
              {report.success
                ? 'Ohne Befund abgeschlossen'
                : `${String(report.findings.length)} technische Befunde`}
            </StatusBadge>
            <p className="security-center__muted">
              {String(report.scannedVaults)} Tresore, {String(report.scannedEntries)} Einträge und{' '}
              {String(report.scannedAttachments)} Anhänge geprüft · {formatDate(report.generatedAt)}
            </p>
            {report.findings.length > 0 && (
              <ul className="security-center__technical-findings">
                {report.findings.map((finding) => (
                  <li key={finding.id}>
                    <FindingIcon severity={finding.severity} />
                    <span>
                      <strong>{INTEGRITY_COPY[finding.code]}</strong>
                      <small>
                        Bereich: {integrityScopeLabel(finding.scope)} ·{' '}
                        {finding.severity === 'critical' ? 'Kritisch' : 'Warnung'}
                      </small>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
        <div className="security-center__inline-actions">
          <Button
            variant="ghost"
            icon={<RefreshCw aria-hidden="true" />}
            busy={busy}
            disabled={disabled}
            onClick={onScan}
          >
            Integrität prüfen
          </Button>
          {report !== null && (
            <Button
              variant="ghost"
              icon={<Save aria-hidden="true" />}
              busy={saveBusy}
              disabled={busy}
              onClick={onSave}
            >
              Technischen Bericht speichern
            </Button>
          )}
        </div>
      </div>
    </section>
  );
}

function BreachPanel({
  status,
  report,
  loading,
  busy,
  disabled,
  findingsRef,
  onImport,
  onScan,
  onRemove,
  onOpenEntry,
}: {
  status: BreachListStatusDto | null;
  report: BreachScanReportDto | null;
  loading: boolean;
  busy: boolean;
  disabled: boolean;
  findingsRef: React.RefObject<HTMLElement | null>;
  onImport: () => void;
  onScan: () => void;
  onRemove: () => void;
  onOpenEntry: (vaultId: string, entryId: string) => void;
}) {
  const statusCopy = status === null ? null : BREACH_STATUS_COPY[status.state];
  return (
    <section
      className="tool-card security-center__breach"
      aria-labelledby="breach-title"
      ref={findingsRef}
      tabIndex={-1}
    >
      <header>
        <div>
          <Database aria-hidden="true" />
          <div>
            <h2 id="breach-title">Lokaler Datenleckabgleich</h2>
            <p>Eine importierte Hashliste wird ausschließlich auf diesem Gerät verwendet.</p>
          </div>
        </div>
      </header>
      {loading && status === null ? (
        <LoadingState label="Status der lokalen Datenleckliste wird geladen …" />
      ) : status === null || statusCopy === null ? (
        <p className="security-center__muted">Status nicht verfügbar.</p>
      ) : (
        <div className="security-center__breach-body">
          <div className="security-center__breach-status">
            <StatusBadge severity={statusCopy.kind}>{statusCopy.title}</StatusBadge>
            {status.state !== 'not-configured' && (
              <dl className="security-center__metadata">
                <div>
                  <dt>Quelle</dt>
                  <dd>{status.sourceLabel ?? 'Ohne Bezeichnung'}</dd>
                </div>
                <div>
                  <dt>Stand</dt>
                  <dd>{status.sourceDate ?? 'Unbekannt'}</dd>
                </div>
                <div>
                  <dt>Importiert</dt>
                  <dd>
                    {status.importedAt === null ? 'Unbekannt' : formatDate(status.importedAt)}
                  </dd>
                </div>
                <div>
                  <dt>Datensätze</dt>
                  <dd>{new Intl.NumberFormat('de-DE').format(status.recordCount)}</dd>
                </div>
              </dl>
            )}
            <div className="security-center__inline-actions">
              <Button
                variant="ghost"
                icon={<HardDriveDownload aria-hidden="true" />}
                disabled={disabled}
                onClick={onImport}
              >
                {status.state === 'not-configured' ? 'Liste importieren' : 'Liste ersetzen'}
              </Button>
              {status.state === 'ready' && (
                <Button
                  variant="ghost"
                  icon={<RefreshCw aria-hidden="true" />}
                  busy={busy}
                  disabled={disabled}
                  onClick={onScan}
                >
                  Lokal abgleichen
                </Button>
              )}
              {status.state !== 'not-configured' && (
                <Button
                  variant="danger"
                  icon={<Trash2 aria-hidden="true" />}
                  disabled={disabled}
                  onClick={onRemove}
                >
                  Liste entfernen
                </Button>
              )}
            </div>
          </div>
          <div className="security-center__breach-results">
            {report === null ? (
              <EmptyState
                title="Noch kein Abgleich in dieser Sitzung"
                description="Der Abgleich gibt weder Passwörter noch Hashwerte aus."
              />
            ) : (
              <>
                <div className="security-center__result-summary">
                  <StatusBadge severity={report.findings.length === 0 ? 'good' : 'critical'}>
                    {report.findings.length === 0
                      ? 'Keine Treffer'
                      : `${String(report.findings.length)} betroffene Einträge`}
                  </StatusBadge>
                  <span>
                    {String(report.checkedPasswords)} Passwörter in {String(report.checkedEntries)}{' '}
                    Einträgen geprüft · {formatDate(report.generatedAt)}
                  </span>
                </div>
                {report.findings.length > 0 && (
                  <div className="security-center__finding-list">
                    {report.findings.map((finding) => (
                      <button
                        type="button"
                        key={finding.id}
                        className="security-center__finding security-center__finding--critical"
                        onClick={() => onOpenEntry(finding.vaultId, finding.entryId)}
                      >
                        <CircleAlert aria-hidden="true" />
                        <span>
                          <strong>Passwort in lokaler Datenleckliste gefunden</strong>
                          <small>
                            {finding.entryTitle} · Tresor {finding.vaultName}
                          </small>
                          <span>Ändere dieses Passwort beim betroffenen Dienst.</span>
                        </span>
                      </button>
                    ))}
                  </div>
                )}
                <p className="security-center__network-proof">
                  <WifiOff aria-hidden="true" />
                  Die Prüfung hat keinen Netzwerkzugriff verwendet.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

function SecurityJobProgress({
  job,
  progress,
  cancelling,
  onCancel,
}: {
  job: SecurityJob;
  progress: LocalJobProgressEvent | null;
  cancelling: boolean;
  onCancel: () => void;
}) {
  const total = Math.max(1, progress?.total ?? 1);
  const completed = Math.min(total, Math.max(0, progress?.completed ?? 0));
  const phase =
    progress === null
      ? 'Lokale Aufgabe wird vorbereitet'
      : (PROGRESS_PHASE_COPY[progress.phase] ?? 'Lokale Aufgabe läuft');
  const title = {
    'security-center': 'Sicherheitsbereiche werden bewertet',
    integrity: 'Datenintegrität wird geprüft',
    'breach-import': 'Datenleckliste wird importiert',
    'breach-scan': 'Lokaler Datenleckabgleich läuft',
  }[job.kind];
  return (
    <section className="security-center__job" aria-labelledby="security-job-title">
      <div>
        <strong id="security-job-title">{title}</strong>
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

function StatusBadge({ severity, children }: { severity: SecuritySeverity; children: ReactNode }) {
  return (
    <span className={`security-center__status security-center__status--${severity}`}>
      {children}
    </span>
  );
}

function FindingIcon({ severity }: { severity: SecuritySeverity }) {
  if (severity === 'critical') return <CircleAlert aria-hidden="true" />;
  if (severity === 'warning') return <AlertTriangle aria-hidden="true" />;
  if (severity === 'good') return <CheckCircle2 aria-hidden="true" />;
  return <Info aria-hidden="true" />;
}

function severityLabel(severity: SecuritySeverity): string {
  return {
    good: 'Gut',
    info: 'Hinweis',
    warning: 'Warnung',
    critical: 'Kritisch',
  }[severity];
}

function integrityScopeLabel(scope: IntegrityReportDto['findings'][number]['scope']): string {
  return {
    profile: 'Profil',
    vault: 'Tresor',
    audit: 'Protokoll',
    attachment: 'Anhang',
    reference: 'Verweis',
  }[scope];
}
