import {
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  Info,
  RefreshCw,
  ShieldCheck,
  WifiOff,
} from 'lucide-react';
import type { CSSProperties } from 'react';
import { useEffect } from 'react';

import type { SecurityReport } from '../../shared/models';
import { formatDate } from '../utils';
import { Button, EmptyState, LoadingState } from './ui';

export function SecurityView({
  report,
  loading,
  onEnsureReport,
  onRefresh,
  onOpenEntry,
}: {
  report: SecurityReport | null;
  loading: boolean;
  onEnsureReport: () => void;
  onRefresh: () => void;
  onOpenEntry: (entryId: string) => void;
}) {
  useEffect(() => {
    onEnsureReport();
  }, [onEnsureReport]);

  return (
    <section className="tool-view security-view" aria-labelledby="security-view-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <ShieldCheck />
          </span>
          <div>
            <p className="eyebrow">Vollständig offline</p>
            <h1 id="security-view-title">Sicherheitscheck</h1>
            <p>Schwache, wiederverwendete, alte und unvollständige Zugangsdaten erkennen.</p>
          </div>
        </div>
        <Button icon={<RefreshCw />} busy={loading} onClick={onRefresh}>
          Erneut prüfen
        </Button>
      </header>

      {loading && !report ? (
        <LoadingState label="Passwörter werden ausschließlich lokal bewertet …" />
      ) : report ? (
        <>
          <div className="security-overview">
            <div
              className="score-ring"
              style={{ '--score': `${String(report.score * 3.6)}deg` } as CSSProperties}
            >
              <strong>{String(report.score)}</strong>
              <span>von 100</span>
            </div>
            <div>
              <h2>
                {report.score >= 80
                  ? 'Dein Tresor ist gut geschützt'
                  : report.score >= 55
                    ? 'Einige Einträge brauchen Aufmerksamkeit'
                    : 'Wichtige Risiken wurden erkannt'}
              </h2>
              <p>Geprüft am {formatDate(report.generatedAt)}</p>
              <div className="severity-counts">
                <SeverityCount label="Kritisch" value={report.counts.critical} kind="critical" />
                <SeverityCount label="Warnungen" value={report.counts.warning} kind="warning" />
                <SeverityCount label="Hinweise" value={report.counts.info} kind="info" />
                <SeverityCount label="Gut" value={report.counts.good} kind="good" />
              </div>
            </div>
            <div className="offline-seal">
              <WifiOff />
              <strong>Kein Netzwerk verwendet</strong>
              <span>Passwörter, Hashes und Teil-Hashes blieben lokal.</span>
            </div>
          </div>

          <section className="tool-card findings-card">
            <header>
              <div>
                <CircleAlert />
                <h2>Konkrete Empfehlungen</h2>
              </div>
              <span>{String(report.findings.length)}</span>
            </header>
            {report.findings.length === 0 ? (
              <EmptyState
                title="Keine Risiken erkannt"
                description="Für diesen Tresor liegen derzeit keine lokalen Empfehlungen vor."
              />
            ) : (
              <div className="findings-list">
                {report.findings.map((finding) => (
                  <button
                    type="button"
                    key={finding.id}
                    className={`finding finding--${finding.severity}`}
                    onClick={() => onOpenEntry(finding.entryId)}
                  >
                    <span>
                      {finding.severity === 'critical' ? (
                        <CircleAlert />
                      ) : finding.severity === 'warning' ? (
                        <AlertTriangle />
                      ) : (
                        <Info />
                      )}
                    </span>
                    <div>
                      <strong>{finding.title}</strong>
                      <small>{finding.entryTitle}</small>
                      <p>{finding.recommendation}</p>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </section>
        </>
      ) : (
        <EmptyState
          title="Kein Bericht verfügbar"
          description="Starte den lokalen Sicherheitscheck erneut."
          action={
            <Button icon={<RefreshCw />} onClick={onRefresh}>
              Prüfung starten
            </Button>
          }
        />
      )}
    </section>
  );
}

function SeverityCount({
  label,
  value,
  kind,
}: {
  label: string;
  value: number;
  kind: 'critical' | 'warning' | 'info' | 'good';
}) {
  return (
    <div className={`severity-count severity-count--${kind}`}>
      {kind === 'good' ? (
        <CheckCircle2 />
      ) : kind === 'warning' ? (
        <AlertTriangle />
      ) : kind === 'critical' ? (
        <CircleAlert />
      ) : (
        <Info />
      )}
      <span>
        <strong>{String(value)}</strong>
        <small>{label}</small>
      </span>
    </div>
  );
}
