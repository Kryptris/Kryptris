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
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

import type { AppState, AuditEvent, BackupInfo } from '../../shared/models';
import type { Notify } from '../types';
import { formatBytes, formatDate, getErrorMessage } from '../utils';
import { BackupRestoreModal } from './BackupRestoreModal';
import { Button, EmptyState, InlineNotice } from './ui';

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
  const [busy, setBusy] = useState(false);

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
        notify('success', 'Verschlüsseltes Backup erstellt', result.path);
      }
    } catch (error: unknown) {
      notify('error', 'Backup fehlgeschlagen', getErrorMessage(error));
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
          <code>{lastBackup.path}</code>
        </section>
      )}
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
  'attachment-added': 'Anhang hinzugefügt',
  'attachment-exported': 'Anhang exportiert',
  'private-key-exported': 'Privaten Schlüssel exportiert',
  'import-completed': 'Import abgeschlossen',
  'export-completed': 'Export abgeschlossen',
  'backup-created': 'Backup erstellt',
  'backup-restored': 'Backup wiederhergestellt',
  'settings-updated': 'Einstellungen geändert',
  'factor-added': 'Faktor hinzugefügt',
  'factor-removed': 'Faktor entfernt',
  'recovery-rotated': 'Wiederherstellungsschlüssel ersetzt',
  'recovery-used': 'Wiederherstellung verwendet',
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
