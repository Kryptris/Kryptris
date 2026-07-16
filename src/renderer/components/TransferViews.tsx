import {
  AlertTriangle,
  ArrowRight,
  Check,
  FileJson,
  FileSpreadsheet,
  FileUp,
  Import,
  LockKeyhole,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import type { FormEvent, ReactNode } from 'react';
import { useEffect, useState } from 'react';

import type {
  AppState,
  ExportFormat,
  ImportFormat,
  ImportMapping,
  ImportPreview,
} from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Button, EmptyState, Field, InlineNotice, PasswordInput } from './ui';

const IMPORT_FORMATS: Array<{ value: ImportFormat; label: string; description: string }> = [
  { value: 'bitwarden-json', label: 'Bitwarden', description: 'JSON-Export' },
  { value: 'onepassword-csv', label: '1Password', description: 'CSV-Export' },
  { value: 'lastpass-csv', label: 'LastPass', description: 'CSV-Export' },
  { value: 'keepass-csv', label: 'KeePass / KeePassXC', description: 'CSV-Export' },
  { value: 'protonpass-json', label: 'Proton Pass', description: 'JSON-Export' },
  { value: 'chrome-csv', label: 'Google Chrome', description: 'Passwort-CSV' },
  { value: 'edge-csv', label: 'Microsoft Edge', description: 'Passwort-CSV' },
  { value: 'firefox-csv', label: 'Mozilla Firefox', description: 'Passwort-CSV' },
  { value: 'generic-csv', label: 'Generisches CSV', description: 'Felder selbst zuordnen' },
  { value: 'generic-json', label: 'Generisches JSON', description: 'Felder selbst zuordnen' },
];

const EMPTY_MAPPING: ImportMapping = {
  title: '',
  username: '',
  password: '',
  url: '',
  note: '',
  folder: '',
  tags: '',
};

export function ImportView({
  vaultId,
  notify,
  onImported,
}: {
  vaultId: string;
  notify: Notify;
  onImported: (entryIds: string[]) => void;
}) {
  const [format, setFormat] = useState<ImportFormat>('bitwarden-json');
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [mapping, setMapping] = useState<ImportMapping>(EMPTY_MAPPING);
  const [selected, setSelected] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);

  const chooseFile = async () => {
    setBusy(true);
    try {
      const result = await window.vaulta.transfer.previewImport({ vaultId, format });
      if (result) {
        setPreview(result);
        setMapping(result.mapping ?? EMPTY_MAPPING);
        setSelected(
          result.candidates
            .filter((candidate) => candidate.selected)
            .map((candidate) => candidate.sourceIndex),
        );
      }
    } catch (error: unknown) {
      notify('error', 'Importdatei konnte nicht gelesen werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const remap = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const result = await window.vaulta.transfer.remapImport({ token: preview.token, mapping });
      setPreview(result);
      setSelected(
        result.candidates
          .filter((candidate) => candidate.selected)
          .map((candidate) => candidate.sourceIndex),
      );
      notify('success', 'Felder neu zugeordnet');
    } catch (error: unknown) {
      notify('error', 'Zuordnung fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const execute = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const result = await window.vaulta.transfer.executeImport({
        token: preview.token,
        vaultId,
        selectedRows: selected,
      });
      notify(
        'success',
        `${String(result.imported)} Einträge importiert`,
        `${String(result.skipped)} übersprungen`,
      );
      setPreview(null);
      onImported(result.entryIds);
    } catch (error: unknown) {
      notify('error', 'Import fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="tool-view transfer-view" aria-labelledby="import-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <Import />
          </span>
          <div>
            <p className="eyebrow">Assistent mit Vorschau</p>
            <h1 id="import-title">Daten importieren</h1>
            <p>Quelle auswählen, Felder prüfen und mögliche Dubletten bewusst behandeln.</p>
          </div>
        </div>
      </header>
      {!preview ? (
        <>
          <section className="tool-card">
            <header>
              <div>
                <FileUp />
                <h2>Quellformat wählen</h2>
              </div>
            </header>
            <div className="format-grid">
              {IMPORT_FORMATS.map((item) => (
                <button
                  type="button"
                  className={format === item.value ? 'is-active' : ''}
                  aria-pressed={format === item.value}
                  key={item.value}
                  onClick={() => setFormat(item.value)}
                >
                  {item.value.includes('json') ? <FileJson /> : <FileSpreadsheet />}
                  <span>
                    <strong>{item.label}</strong>
                    <small>{item.description}</small>
                  </span>
                  {format === item.value && <Check />}
                </button>
              ))}
            </div>
            <InlineNotice kind="warning" title="Quelldatei bleibt erhalten">
              Kryptris löscht Importdateien niemals automatisch. Behandle unverschlüsselte Exporte
              anschließend sicher.
            </InlineNotice>
            <Button
              variant="primary"
              icon={<FileUp />}
              busy={busy}
              onClick={() => void chooseFile()}
            >
              Datei auswählen und lokal prüfen
            </Button>
          </section>
        </>
      ) : (
        <>
          <div className="wizard-steps" aria-label="Importschritte">
            <span className="is-complete">
              <Check />
              Quelle
            </span>
            <span className="is-active">2 Vorschau</span>
            <span>3 Import</span>
          </div>
          <section className="tool-card import-summary">
            <header>
              <div>
                <FileUp />
                <div>
                  <h2>{preview.sourceName}</h2>
                  <p>
                    {String(preview.candidates.length)} erkannte Einträge ·{' '}
                    {String(preview.errors.length)} Fehler
                  </p>
                </div>
              </div>
              <Button variant="ghost" onClick={() => setPreview(null)}>
                Andere Datei
              </Button>
            </header>
          </section>
          {preview.mapping && (
            <section className="tool-card mapping-card">
              <header>
                <div>
                  <ArrowRight />
                  <h2>Felder zuordnen</h2>
                </div>
                <Button onClick={() => void remap()} busy={busy}>
                  Zuordnung anwenden
                </Button>
              </header>
              <div className="mapping-grid">
                {(Object.keys(mapping) as Array<keyof ImportMapping>).map((key) => (
                  <Field
                    label={
                      {
                        title: 'Titel',
                        username: 'Benutzername',
                        password: 'Passwort',
                        url: 'Webseite',
                        note: 'Notiz',
                        folder: 'Ordner',
                        tags: 'Tags',
                      }[key]
                    }
                    key={key}
                  >
                    <select
                      value={mapping[key]}
                      onChange={(event) =>
                        setMapping((current) => ({ ...current, [key]: event.currentTarget.value }))
                      }
                    >
                      <option value="">Nicht importieren</option>
                      {preview.detectedColumns.map((column) => (
                        <option key={column}>{column}</option>
                      ))}
                    </select>
                  </Field>
                ))}
              </div>
            </section>
          )}
          {preview.errors.length > 0 && (
            <InlineNotice
              kind="warning"
              title={`${String(preview.errors.length)} Zeilen konnten nicht gelesen werden`}
            >
              {preview.errors.slice(0, 3).map((error) => (
                <span className="notice-line" key={`${String(error.row)}-${error.message}`}>
                  Zeile {String(error.row)}: {error.message}
                </span>
              ))}
            </InlineNotice>
          )}
          <section className="tool-card import-table-card">
            <header>
              <div>
                <ShieldCheck />
                <h2>Importvorschau</h2>
              </div>
              <label className="check-row check-row--tiny">
                <input
                  type="checkbox"
                  checked={selected.length === preview.candidates.length && selected.length > 0}
                  onChange={(event) =>
                    setSelected(
                      event.currentTarget.checked
                        ? preview.candidates.map((candidate) => candidate.sourceIndex)
                        : [],
                    )
                  }
                />
                <span>Alle auswählen</span>
              </label>
            </header>
            {preview.candidates.length === 0 ? (
              <EmptyState
                title="Keine Einträge erkannt"
                description="Prüfe Format und Feldzuordnung."
              />
            ) : (
              <div className="data-table" role="table">
                <div className="data-table__head" role="row">
                  <span />
                  <span>Titel</span>
                  <span>Benutzername</span>
                  <span>Webseite</span>
                  <span>Status</span>
                </div>
                {preview.candidates.map((candidate) => (
                  <label className="data-table__row" role="row" key={candidate.sourceIndex}>
                    <input
                      type="checkbox"
                      checked={selected.includes(candidate.sourceIndex)}
                      onChange={(event) =>
                        setSelected((current) =>
                          event.currentTarget.checked
                            ? [...current, candidate.sourceIndex]
                            : current.filter((value) => value !== candidate.sourceIndex),
                        )
                      }
                    />
                    <strong>{candidate.title || 'Ohne Titel'}</strong>
                    <span>{candidate.username || '—'}</span>
                    <span>{candidate.website || '—'}</span>
                    <span>
                      {candidate.duplicateOf ? (
                        <em className="status-pill status-pill--warning">Mögliche Dublette</em>
                      ) : (
                        <em className="status-pill status-pill--good">Bereit</em>
                      )}
                      {candidate.warnings.map((warning) => (
                        <small key={warning}>{warning}</small>
                      ))}
                    </span>
                  </label>
                ))}
              </div>
            )}
            <footer className="card-actions">
              <span>
                {String(selected.length)} von {String(preview.candidates.length)} ausgewählt
              </span>
              <Button
                variant="primary"
                busy={busy}
                disabled={selected.length === 0}
                icon={<Import />}
                onClick={() => void execute()}
              >
                Auswahl verschlüsselt importieren
              </Button>
            </footer>
          </section>
        </>
      )}
    </section>
  );
}

export function ExportView({ state, notify }: { state: AppState; notify: Notify }) {
  const [format, setFormat] = useState<ExportFormat>('vaulta-backup');
  const [selectedVaults, setSelectedVaults] = useState<string[]>(
    state.vaults.map((vault) => vault.id),
  );
  const [includeAttachments, setIncludeAttachments] = useState(false);
  const [warningAccepted, setWarningAccepted] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const cleartext = format !== 'vaulta-backup';
  const canExport =
    (!cleartext || selectedVaults.length > 0) &&
    (!cleartext || (warningAccepted && confirmation === 'EXPORTIEREN' && Boolean(password)));

  useEffect(() => {
    setWarningAccepted(false);
    setConfirmation('');
    setPassword('');
  }, [format]);

  const execute = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const input = {
        format,
        vaultIds: selectedVaults,
        warningAccepted: cleartext ? warningAccepted : true,
        confirmation: cleartext ? confirmation : 'BACKUP',
        includeAttachments,
        ...(cleartext ? { masterPassword: password } : {}),
      };
      const destination = await window.vaulta.transfer.export(input);
      if (destination)
        notify(
          cleartext ? 'warning' : 'success',
          cleartext ? 'Klartextexport erstellt' : 'Verschlüsseltes Backup exportiert',
          destination,
        );
      setPassword('');
      setConfirmation('');
    } catch (error: unknown) {
      notify('error', 'Export fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="tool-view transfer-view" aria-labelledby="export-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <Upload />
          </span>
          <div>
            <p className="eyebrow">Bewusster Datentransfer</p>
            <h1 id="export-title">Daten exportieren</h1>
            <p>Das verschlüsselte Kryptris-Format ist immer die sicherste Wahl.</p>
          </div>
        </div>
      </header>
      <form className="stack" onSubmit={(event) => void execute(event)}>
        <section className="tool-card">
          <header>
            <div>
              <FileUp />
              <h2>Format</h2>
            </div>
          </header>
          <div className="export-format-grid">
            <FormatOption
              value="vaulta-backup"
              selected={format}
              title="Kryptris-Backup"
              description="Verschlüsselt, vollständig und mit Integritätsprüfung"
              icon={<LockKeyhole />}
              onSelect={setFormat}
            />
            <FormatOption
              value="json"
              selected={format}
              title="JSON"
              description="Strukturiert, aber vollständig unverschlüsselt"
              icon={<FileJson />}
              onSelect={setFormat}
            />
            <FormatOption
              value="csv"
              selected={format}
              title="CSV"
              description="Kompatibel, aber unverschlüsselt und reduziert"
              icon={<FileSpreadsheet />}
              onSelect={setFormat}
            />
          </div>
        </section>
        <section className="tool-card">
          <header>
            <div>
              <ShieldCheck />
              <h2>{cleartext ? 'Tresore und Anhänge' : 'Vollständiger Sicherungsumfang'}</h2>
            </div>
          </header>
          {cleartext ? (
            <>
              <div className="vault-check-list">
                {state.vaults.map((vault) => (
                  <label className="check-row" key={vault.id}>
                    <input
                      type="checkbox"
                      checked={selectedVaults.includes(vault.id)}
                      onChange={(event) =>
                        setSelectedVaults((current) =>
                          event.currentTarget.checked
                            ? [...current, vault.id]
                            : current.filter((id) => id !== vault.id),
                        )
                      }
                    />
                    <span>
                      <strong>{vault.name}</strong>
                      <small>{String(vault.entryCount)} Einträge</small>
                    </span>
                  </label>
                ))}
              </div>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={includeAttachments}
                  onChange={(event) => setIncludeAttachments(event.currentTarget.checked)}
                />
                <span>
                  <strong>Anhänge einschließen</strong>
                  <small>Anhänge werden separat und unverschlüsselt ausgegeben.</small>
                </span>
              </label>
            </>
          ) : (
            <InlineNotice kind="success" title="Immer vollständig">
              Ein natives Backup enthält alle Tresore, Einträge, Einstellungen, Anhänge und das
              verschlüsselte Aktivitätsprotokoll. Der Umfang ist absichtlich nicht reduzierbar,
              damit eine vollständige Wiederherstellung möglich bleibt.
            </InlineNotice>
          )}
        </section>
        {cleartext && (
          <section className="tool-card danger-zone">
            <header>
              <div>
                <AlertTriangle />
                <h2>Mehrstufige Klartextbestätigung</h2>
              </div>
            </header>
            <InlineNotice kind="error" title="Export ist nicht geschützt">
              Jede Person und jedes Programm mit Zugriff auf den Zielordner kann Passwörter und
              andere Geheimnisse lesen.
            </InlineNotice>
            <label className="check-row">
              <input
                type="checkbox"
                checked={warningAccepted}
                onChange={(event) => setWarningAccepted(event.currentTarget.checked)}
              />
              <span>
                <strong>Ich verstehe, dass die Datei unverschlüsselt ist.</strong>
              </span>
            </label>
            <Field label="Zur Bestätigung EXPORTIEREN eingeben">
              <input
                value={confirmation}
                autoComplete="off"
                onChange={(event) => setConfirmation(event.currentTarget.value.toUpperCase())}
              />
            </Field>
            <Field label="Master-Passwort">
              <PasswordInput
                value={password}
                autoComplete="current-password"
                onChange={setPassword}
              />
            </Field>
          </section>
        )}
        <div className="export-submit">
          <InlineNotice kind={cleartext ? 'warning' : 'success'}>
            {cleartext
              ? 'Wähle einen sicheren Zielordner und lösche nicht mehr benötigte Klartextkopien.'
              : 'Dieses Format bewahrt Verschlüsselung, Anhänge und Integritätsinformationen.'}
          </InlineNotice>
          <Button
            type="submit"
            variant="primary"
            icon={<Upload />}
            busy={busy}
            disabled={!canExport}
          >
            Exportziel wählen
          </Button>
        </div>
      </form>
    </section>
  );
}

function FormatOption({
  value,
  selected,
  title,
  description,
  icon,
  onSelect,
}: {
  value: ExportFormat;
  selected: ExportFormat;
  title: string;
  description: string;
  icon: ReactNode;
  onSelect: (value: ExportFormat) => void;
}) {
  return (
    <button
      type="button"
      className={selected === value ? 'is-active' : ''}
      aria-pressed={selected === value}
      onClick={() => onSelect(value)}
    >
      {icon}
      <span>
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
      {selected === value && <Check />}
    </button>
  );
}
