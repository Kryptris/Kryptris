import {
  Activity,
  ArchiveRestore,
  CalendarClock,
  Check,
  Clock3,
  DatabaseBackup,
  FolderOpen,
  History,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type {
  AppState,
  AuditEvent,
  BackupHealthFailureCode,
  BackupHealthSnapshot,
  BackupInfo,
  RestoreDryRunResult,
} from '../../shared/models';
import type { Notify } from '../types';
import { formatBytes, formatDate, getErrorMessage } from '../utils';
import { BackupRestoreModal } from './BackupRestoreModal';
import { Button, EmptyState, InlineNotice } from './ui';

const BACKUP_FAILURE_COPY: Record<BackupHealthFailureCode, string> = {
  AUTH_FAILED: 'Zugang konnte nicht bestätigt werden',
  AUTH_FACTOR_REQUIRED: 'Ein zusätzlicher Entsperrfaktor fehlt',
  AUTH_RATE_LIMITED: 'Der Zugang ist vorübergehend begrenzt',
  CORRUPT_DATA: 'Die Sicherung konnte nicht vollständig geprüft werden',
  INVALID_INPUT: 'Die Sicherungsanfrage war ungültig',
  LOCKED: 'Kryptris war gesperrt',
  NOT_FOUND: 'Eine benötigte Sicherung fehlt',
  CANCELLED: 'Der Vorgang wurde abgebrochen',
  CONFLICT: 'Der Sicherungsstand hat sich während des Vorgangs geändert',
  FILE_TOO_LARGE: 'Die Sicherung überschreitet eine Sicherheitsgrenze',
  UNSUPPORTED_FORMAT: 'Das Sicherungsformat wird nicht unterstützt',
  UNSAFE_PATH: 'Das Sicherungsziel wurde aus Sicherheitsgründen abgelehnt',
  INTERNAL: 'Der Sicherungsvorgang konnte nicht abgeschlossen werden',
};

function backupDate(value: string | null): string {
  return value === null ? 'Noch nicht vorhanden' : formatDate(value);
}

function backupMode(automatic: boolean): string {
  return automatic ? 'Automatisch' : 'Manuell';
}

function BackupHealthDetails({ health }: { health: BackupHealthSnapshot }) {
  const latest = health.latestBackup;
  return (
    <>
      <InlineNotice
        kind={health.targetReachable ? 'success' : 'warning'}
        title={
          health.targetReachable ? 'Sicherungsziel erreichbar' : 'Sicherungsziel nicht erreichbar'
        }
      >
        {health.targetReachable
          ? 'Die zuletzt geprüfte lokale Sicherungsablage ist erreichbar.'
          : 'Richte ein Sicherungsziel ein oder verbinde den gewählten Datenträger erneut.'}
      </InlineNotice>
      {health.sameDriveWarning && (
        <InlineNotice kind="warning" title="Getrennten Speicherort verwenden">
          Das Sicherungsziel liegt auf demselben Laufwerk wie das Profil. Ein separater Datenträger
          schützt besser vor Geräteausfällen.
        </InlineNotice>
      )}
      {health.unreadableBackupCount > 0 && (
        <InlineNotice kind="warning" title="Nicht alle Sicherungen lesbar">
          {health.unreadableBackupCount === 1
            ? 'Eine vorhandene Sicherung konnte nicht als gültiges Kryptris-Backup geprüft werden.'
            : `${String(health.unreadableBackupCount)} vorhandene Sicherungen konnten nicht als gültige Kryptris-Backups geprüft werden.`}
        </InlineNotice>
      )}
      <dl className="security-center__metadata" aria-label="Zusammenfassung der Sicherungen">
        <div>
          <dt>Geprüfte Sicherungen</dt>
          <dd>{String(health.backupCount)}</dd>
        </div>
        <div>
          <dt>Gesamtgröße</dt>
          <dd>{formatBytes(health.totalSize)}</dd>
        </div>
        <div>
          <dt>Tägliche Generationen</dt>
          <dd>{String(health.generations.daily)}</dd>
        </div>
        <div>
          <dt>Wöchentliche Generationen</dt>
          <dd>{String(health.generations.weekly)}</dd>
        </div>
        <div>
          <dt>Monatliche Generationen</dt>
          <dd>{String(health.generations.monthly)}</dd>
        </div>
        <div>
          <dt>Letzte erfolgreiche Sicherung</dt>
          <dd>{backupDate(health.lastSuccessfulBackupAt)}</dd>
        </div>
        <div>
          <dt>Letzter Probelauf</dt>
          <dd>{backupDate(health.lastSemanticVerificationAt)}</dd>
        </div>
      </dl>
      {latest === null ? (
        <InlineNotice kind="info" title="Noch keine Sicherung geprüft">
          Erstelle eine verschlüsselte Sicherung, damit Kryptris den Sicherungsstand bewerten kann.
        </InlineNotice>
      ) : (
        <dl className="security-center__metadata" aria-label="Letzte geprüfte Sicherung">
          <div>
            <dt>Letzte geprüfte Sicherung</dt>
            <dd>{formatDate(latest.createdAt)}</dd>
          </div>
          <div>
            <dt>Art</dt>
            <dd>{backupMode(latest.automatic)}</dd>
          </div>
          <div>
            <dt>Tresore</dt>
            <dd>{String(latest.vaultCount)}</dd>
          </div>
          <div>
            <dt>Anhänge</dt>
            <dd>{String(latest.attachmentCount)}</dd>
          </div>
          <div>
            <dt>Größe</dt>
            <dd>{formatBytes(latest.size)}</dd>
          </div>
        </dl>
      )}
      {health.lastFailure !== null && (
        <InlineNotice kind="warning" title="Letzter fehlgeschlagener Sicherungsvorgang">
          {formatDate(health.lastFailure.occurredAt)} ·{' '}
          {BACKUP_FAILURE_COPY[health.lastFailure.code]}
        </InlineNotice>
      )}
    </>
  );
}

export function BackupView({
  state,
  notify,
  onStateChange,
}: {
  state: AppState;
  notify: Notify;
  onStateChange: (state: AppState) => void;
}) {
  const [folder, setFolder] = useState(state.settings?.backupFolder ?? null);
  const [lastBackup, setLastBackup] = useState<BackupInfo | null>(null);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [dryRunOpen, setDryRunOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<BackupHealthSnapshot | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthLiveMessage, setHealthLiveMessage] = useState('Sicherungsstatus wird geladen.');
  const healthRequestRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadHealth = useCallback(
    async (refresh = false) => {
      if (healthRequestRef.current) return;
      healthRequestRef.current = true;
      if (mountedRef.current) {
        setHealthLoading(true);
        setHealthLiveMessage(
          refresh ? 'Sicherungsstatus wird aktualisiert.' : 'Sicherungsstatus wird geladen.',
        );
      }
      try {
        const next = await window.vaulta.backup.getHealth({
          requestId: crypto.randomUUID(),
          refresh,
        });
        if (!mountedRef.current) return;
        setHealth(next);
        setHealthLiveMessage('Sicherungsstatus wurde aktualisiert.');
      } catch {
        if (!mountedRef.current) return;
        setHealthLiveMessage('Sicherungsstatus konnte nicht aktualisiert werden.');
        notify(
          'error',
          'Sicherungsstatus konnte nicht aktualisiert werden',
          'Prüfe das Sicherungsziel und versuche es erneut.',
        );
      } finally {
        healthRequestRef.current = false;
        if (mountedRef.current) setHealthLoading(false);
      }
    },
    [notify],
  );

  useEffect(() => {
    void loadHealth();
  }, [loadHealth]);

  const chooseFolder = async () => {
    try {
      const value = await window.vaulta.backup.chooseFolder();
      if (value) {
        setFolder(value);
        if (state.settings) {
          const settings = await window.vaulta.settings.update({
            settings: {
              ...state.settings,
              backupFolder: value,
            },
          });
          onStateChange({ ...state, settings });
          void loadHealth(true);
        }
      }
    } catch (error: unknown) {
      notify('error', 'Ordner konnte nicht gewählt werden', getErrorMessage(error));
    }
  };

  const createBackup = async () => {
    setBusy(true);
    try {
      const result = await window.vaulta.backup.create({ automatic: false });
      if (result) {
        setLastBackup(result);
        notify(
          'success',
          'Verschlüsseltes Backup erstellt',
          'Der Sicherungsstatus wird aktualisiert.',
        );
        void loadHealth(true);
      }
    } catch {
      notify('error', 'Backup fehlgeschlagen', 'Prüfe das Sicherungsziel und versuche es erneut.');
    } finally {
      setBusy(false);
    }
  };

  const rotation = state.settings?.backupRotation ?? { daily: 7, weekly: 4, monthly: 6 };

  return (
    <section className="tool-view" aria-labelledby="backup-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <DatabaseBackup />
          </span>
          <div>
            <p className="eyebrow">Verschlüsselt und versioniert</p>
            <h1 id="backup-title">Backups & Wiederherstellung</h1>
            <p>Sichere alle Tresore und Anhänge in einem integritätsgeschützten nativen Format.</p>
          </div>
        </div>
        <Button
          variant="primary"
          icon={<DatabaseBackup />}
          busy={busy}
          onClick={() => void createBackup()}
        >
          Jetzt sichern
        </Button>
      </header>
      <div className="dashboard-grid dashboard-grid--two">
        <section className="tool-card backup-destination">
          <header>
            <div>
              <FolderOpen />
              <h2>Sicherungsziel</h2>
            </div>
          </header>
          <div className="path-display">
            <FolderOpen />
            <span>{folder ?? 'Bei jeder Sicherung auswählen'}</span>
          </div>
          <Button onClick={() => void chooseFolder()}>Ordner wählen</Button>
          <InlineNotice kind="info">
            Ein getrennt aufbewahrter USB-Datenträger schützt auch bei Ausfall der internen
            Festplatte.
          </InlineNotice>
        </section>
        <section className="tool-card">
          <header>
            <div>
              <CalendarClock />
              <h2>Rotation</h2>
            </div>
          </header>
          <div className="rotation-stats">
            <div>
              <strong>{String(rotation.daily)}</strong>
              <span>tägliche</span>
            </div>
            <div>
              <strong>{String(rotation.weekly)}</strong>
              <span>wöchentliche</span>
            </div>
            <div>
              <strong>{String(rotation.monthly)}</strong>
              <span>monatliche</span>
            </div>
          </div>
          <p className="muted-copy">
            Automatische Sicherungen: {state.settings?.automaticBackups ? 'Aktiv' : 'Inaktiv'}.
            Änderungen sind in den Einstellungen möglich.
          </p>
        </section>
      </div>
      <section
        className="tool-card"
        aria-labelledby="backup-health-title"
        aria-busy={healthLoading}
      >
        <header>
          <div>
            <ShieldCheck />
            <div>
              <h2 id="backup-health-title">Sicherungsstatus</h2>
              <p>Lokale, pfadfreie Übersicht über Sicherungen und Probeläufe.</p>
            </div>
          </div>
          <Button icon={<RefreshCw />} busy={healthLoading} onClick={() => void loadHealth(true)}>
            Aktualisieren
          </Button>
        </header>
        <p className="sr-only" aria-live="polite" aria-atomic="true">
          {healthLiveMessage}
        </p>
        {health !== null ? (
          <BackupHealthDetails health={health} />
        ) : (
          <InlineNotice kind="info">Sicherungsstatus wird lokal geladen.</InlineNotice>
        )}
      </section>
      {lastBackup && (
        <section className="tool-card last-backup">
          <header>
            <div>
              <Check />
              <h2>Letzte Sicherung dieser Sitzung</h2>
            </div>
          </header>
          <div className="backup-facts">
            <span>
              <strong>{formatDate(lastBackup.createdAt)}</strong>Zeitpunkt
            </span>
            <span>
              <strong>{formatBytes(lastBackup.size)}</strong>Größe
            </span>
            <span>
              <strong>{String(lastBackup.vaultCount)}</strong>Tresore
            </span>
            <span>
              <strong>{String(lastBackup.attachmentCount)}</strong>Anhänge
            </span>
          </div>
        </section>
      )}
      <section className="tool-card restore-card">
        <header>
          <div>
            <Check />
            <div>
              <h2>Backup probeweise prüfen</h2>
              <p>Prüft ein ausgewähltes Backup vollständig, ohne Daten wiederherzustellen.</p>
            </div>
          </div>
          <Button icon={<ShieldCheck />} onClick={() => setDryRunOpen(true)}>
            Probelauf starten
          </Button>
        </header>
        <InlineNotice kind="info">
          Der Probelauf verwendet einen getrennten temporären Bereich und verwirft ihn nach
          Abschluss oder Abbruch. Der aktuelle Profilstand bleibt unverändert.
        </InlineNotice>
      </section>
      <section className="tool-card restore-card">
        <header>
          <div>
            <ArchiveRestore />
            <div>
              <h2>Backup wiederherstellen</h2>
              <p>Das Backup wird vollständig geprüft, bevor bestehende Tresore ersetzt werden.</p>
            </div>
          </div>
          <Button icon={<RotateCcw />} onClick={() => setRestoreOpen(true)}>
            Wiederherstellungsassistent
          </Button>
        </header>
        <InlineNotice kind="warning">
          Erstelle vor dem Wiederherstellen bei Bedarf selbst eine Sicherung des aktuellen Stands.
          Kryptris übernimmt niemals ein Backup mit ungültiger Version oder Integritätsprüfung.
        </InlineNotice>
      </section>
      <BackupRestoreModal
        open={restoreOpen}
        notify={notify}
        onClose={() => setRestoreOpen(false)}
        onRestored={onStateChange}
      />
      <BackupRestoreModal
        open={dryRunOpen}
        mode="dry-run"
        notify={notify}
        onClose={() => setDryRunOpen(false)}
        onRestored={onStateChange}
        onDryRunCompleted={(result: RestoreDryRunResult) => {
          notify(
            'success',
            'Backup probeweise geprüft',
            `${String(result.vaultCount)} Tresor${result.vaultCount === 1 ? '' : 'e'} und ${String(result.attachmentCount)} Anhang${result.attachmentCount === 1 ? '' : 'e'} wurden lokal verifiziert.`,
          );
          void loadHealth(true);
        }}
      />
    </section>
  );
}

const AUDIT_LABELS: Record<AuditEvent['type'], string> = {
  'profile-created': 'Profil erstellt',
  unlocked: 'Entsperrt',
  'unlock-failed': 'Entsperren fehlgeschlagen',
  locked: 'Gesperrt',
  'vault-created': 'Tresor erstellt',
  'vault-updated': 'Tresor geändert',
  'vault-deleted': 'Tresor gelöscht',
  'entry-created': 'Eintrag erstellt',
  'entry-updated': 'Eintrag geändert',
  'entry-moved-to-trash': 'In Papierkorb verschoben',
  'entry-restored': 'Eintrag wiederhergestellt',
  'entry-purged': 'Eintrag endgültig gelöscht',
  'entry-copied-to-vault': 'In anderen Tresor kopiert',
  'entry-moved-to-vault': 'In anderen Tresor verschoben',
  'entries-merged': 'Dubletten zusammengeführt',
  'data-quality-fixed': 'Datenqualität korrigiert',
  'trash-auto-purged': 'Papierkorb automatisch geleert',
  'attachment-added': 'Anhang hinzugefügt',
  'attachment-exported': 'Anhang exportiert',
  'private-key-exported': 'Privaten Schlüssel exportiert',
  'import-completed': 'Import abgeschlossen',
  'export-completed': 'Export abgeschlossen',
  'backup-created': 'Backup erstellt',
  'backup-restored': 'Backup wiederhergestellt',
  'backup-dry-run-completed': 'Backup probeweise geprüft',
  'import-mapping-profile-updated': 'Import-Feldzuordnung aktualisiert',
  'vault-package-exported': 'Verschlüsseltes Tresor-Paket exportiert',
  'vault-package-imported': 'Verschlüsseltes Tresor-Paket importiert',
  'settings-updated': 'Einstellungen geändert',
  'factor-added': 'Faktor hinzugefügt',
  'factor-removed': 'Faktor entfernt',
  'recovery-rotated': 'Wiederherstellungsschlüssel ersetzt',
  'recovery-used': 'Wiederherstellung verwendet',
  'recovery-readiness-succeeded': 'Recovery-Bereitschaft bestätigt',
  'recovery-readiness-failed': 'Recovery-Bereitschaft nicht bestätigt',
  'integrity-check-completed': 'Integritätsprüfung abgeschlossen',
  'breach-list-imported': 'Datenleckliste importiert',
  'breach-list-removed': 'Datenleckliste entfernt',
};

export function AuditView({ notify }: { notify: Notify }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState<'all' | AuditEvent['type']>('all');
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(true);

  const load = async (reset = false) => {
    setLoading(true);
    try {
      const values = await window.vaulta.audit.list({
        offset: reset ? 0 : events.length,
        limit: 100,
      });
      setEvents((current) => (reset ? values : [...current, ...values]));
      setHasMore(values.length === 100);
    } catch (error: unknown) {
      notify('error', 'Protokoll konnte nicht geladen werden', getErrorMessage(error));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    void window.vaulta.audit
      .list({ offset: 0, limit: 100 })
      .then((values) => {
        if (!active) return;
        setEvents(values);
        setHasMore(values.length === 100);
      })
      .catch((error: unknown) => {
        if (active)
          notify('error', 'Protokoll konnte nicht geladen werden', getErrorMessage(error));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [notify]);

  const shown = useMemo(
    () => (filter === 'all' ? events : events.filter((event) => event.type === filter)),
    [events, filter],
  );
  const eventTypes = useMemo(() => [...new Set(events.map((event) => event.type))], [events]);

  return (
    <section className="tool-view" aria-labelledby="audit-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <Activity />
          </span>
          <div>
            <p className="eyebrow">Lokal und verschlüsselt</p>
            <h1 id="audit-title">Aktivitätsprotokoll</h1>
            <p>
              Sicherheitsrelevante Ereignisse ohne Passwörter, Feldwerte oder Schlüsselmaterial.
            </p>
          </div>
        </div>
        <Button icon={<RefreshCw />} busy={loading} onClick={() => void load(true)}>
          Aktualisieren
        </Button>
      </header>
      <section className="tool-card audit-card">
        <header>
          <div>
            <History />
            <h2>Ereignisse</h2>
          </div>
          <select
            aria-label="Ereignistyp filtern"
            value={filter}
            onChange={(event) => setFilter(event.currentTarget.value as typeof filter)}
          >
            <option value="all">Alle Ereignisse</option>
            {eventTypes.map((type) => (
              <option value={type} key={type}>
                {AUDIT_LABELS[type]}
              </option>
            ))}
          </select>
        </header>
        {shown.length === 0 && !loading ? (
          <EmptyState
            title="Keine Ereignisse"
            description="Für diesen Filter liegen keine protokollierten Aktivitäten vor."
          />
        ) : (
          <div className="timeline">
            {shown.map((event) => (
              <article key={event.id}>
                <span
                  className={`timeline__dot timeline__dot--${event.type.includes('failed') ? 'danger' : event.type.includes('deleted') || event.type.includes('purged') ? 'warning' : 'normal'}`}
                >
                  <Clock3 />
                </span>
                <div>
                  <strong>{AUDIT_LABELS[event.type]}</strong>
                  <p>{event.summary}</p>
                  <small>{formatDate(event.occurredAt)}</small>
                </div>
              </article>
            ))}
          </div>
        )}
        {hasMore && (
          <footer>
            <Button busy={loading} onClick={() => void load()}>
              Weitere laden
            </Button>
          </footer>
        )}
      </section>
    </section>
  );
}
