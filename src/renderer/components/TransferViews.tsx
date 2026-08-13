import {
  AlertTriangle,
  Archive,
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
import { useCallback, useEffect, useState } from 'react';

import type {
  AppState,
  ExportFormat,
  ImportFormat,
  ImportMapping,
  ImportMappingProfile,
  ImportPreview,
  ImportSummary,
  VaultPackagePreviewDto,
} from '../../shared/models';
import type { Notify } from '../types';
import { formatDate, getErrorMessage } from '../utils';
import { Button, EmptyState, Field, InlineNotice, PasswordInput } from './ui';

const IMPORT_FORMATS: Array<{ value: ImportFormat; label: string; description: string }> = [
  { value: 'bitwarden-json', label: 'Bitwarden', description: 'JSON-Export' },
  { value: 'onepassword-csv', label: '1Password', description: 'CSV-Export' },
  { value: 'lastpass-csv', label: 'LastPass', description: 'CSV-Export' },
  { value: 'keepass-csv', label: 'KeePass / KeePassXC', description: 'CSV-Export' },
  { value: 'protonpass-json', label: 'Proton Pass', description: 'JSON-Export' },
  { value: 'dashlane-csv', label: 'Dashlane', description: 'Credentials-CSV' },
  { value: 'nordpass-csv', label: 'NordPass', description: 'CSV-Export' },
  { value: 'roboform-csv', label: 'RoboForm', description: 'CSV-Export' },
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
  onOpenDuplicates,
  onPackageImported,
}: {
  vaultId: string;
  notify: Notify;
  onImported: (entryIds: string[], summary: ImportSummary) => void;
  onOpenDuplicates: () => void;
  onPackageImported: (vaultId: string) => void;
}) {
  const [format, setFormat] = useState<ImportFormat>('bitwarden-json');
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [mapping, setMapping] = useState<ImportMapping>(EMPTY_MAPPING);
  const [selected, setSelected] = useState<number[]>([]);
  const [busy, setBusy] = useState(false);
  const [mappingProfiles, setMappingProfiles] = useState<ImportMappingProfile[]>([]);
  const [mappingProfileName, setMappingProfileName] = useState('');
  const [selectedMappingProfileId, setSelectedMappingProfileId] = useState('');
  const [completedSummary, setCompletedSummary] = useState<ImportSummary | null>(null);
  const [packagePassword, setPackagePassword] = useState('');
  const [packagePreview, setPackagePreview] = useState<VaultPackagePreviewDto | null>(null);
  const [packageTargetName, setPackageTargetName] = useState('');
  const [packageAllowNameConflict, setPackageAllowNameConflict] = useState(false);
  const [packageBusy, setPackageBusy] = useState(false);
  const [dropActive, setDropActive] = useState(false);

  useEffect(() => {
    let active = true;
    void window.vaulta.transfer
      .listMappingProfiles()
      .then((profiles) => {
        if (active) setMappingProfiles(profiles);
      })
      .catch((error: unknown) => {
        if (active)
          notify('error', 'Feldzuordnungen konnten nicht geladen werden', getErrorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [notify]);

  const applyImportPreview = useCallback((result: ImportPreview) => {
    setPreview(result);
    setMapping(result.mapping ?? EMPTY_MAPPING);
    setSelected(
      result.candidates
        .filter((candidate) => candidate.selected)
        .map((candidate) => candidate.sourceIndex),
    );
    setCompletedSummary(null);
  }, []);

  useEffect(() => {
    return window.vaulta.transfer.onDroppedImport((drop) => {
      if (busy || preview !== null) return;
      setBusy(true);
      void window.vaulta.transfer
        .previewDroppedImport({ token: drop.token, vaultId, format, mapping })
        .then((result) => {
          if (result) applyImportPreview(result);
        })
        .catch((error: unknown) => {
          notify('error', 'Importdatei konnte nicht gelesen werden', getErrorMessage(error));
        })
        .finally(() => setBusy(false));
    });
  }, [applyImportPreview, busy, format, mapping, notify, preview, vaultId]);

  const chooseFile = async () => {
    setBusy(true);
    try {
      const result = await window.vaulta.transfer.previewImport({ vaultId, format });
      if (result) {
        applyImportPreview(result);
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
      setCompletedSummary(result.summary);
      onImported(result.entryIds, result.summary);
    } catch (error: unknown) {
      notify('error', 'Import fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const applyMappingProfile = (profileId: string) => {
    setSelectedMappingProfileId(profileId);
    const profile = mappingProfiles.find((candidate) => candidate.id === profileId);
    if (!profile) {
      setMappingProfileName('');
      return;
    }
    setMapping(profile.mapping);
    setMappingProfileName(profile.name);
  };

  const saveMappingProfile = async () => {
    const name = mappingProfileName.trim();
    if (!name) {
      notify('error', 'Name fuer Feldzuordnung fehlt', 'Gib einen Namen fuer diese Zuordnung ein.');
      return;
    }
    setBusy(true);
    try {
      const saved = await window.vaulta.transfer.saveMappingProfile({
        ...(selectedMappingProfileId ? { id: selectedMappingProfileId } : {}),
        name,
        mapping,
      });
      setMappingProfiles((current) => {
        const withoutSaved = current.filter((profile) => profile.id !== saved.id);
        return [...withoutSaved, saved].sort((left, right) =>
          left.name.localeCompare(right.name, 'de'),
        );
      });
      setSelectedMappingProfileId(saved.id);
      setMappingProfileName(saved.name);
      notify('success', 'Feldzuordnung gespeichert');
    } catch (error: unknown) {
      notify('error', 'Feldzuordnung konnte nicht gespeichert werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const removeMappingProfile = async () => {
    if (!selectedMappingProfileId) return;
    setBusy(true);
    try {
      const removed = await window.vaulta.transfer.removeMappingProfile({
        id: selectedMappingProfileId,
      });
      if (removed) {
        setMappingProfiles((current) =>
          current.filter((profile) => profile.id !== selectedMappingProfileId),
        );
        setSelectedMappingProfileId('');
        setMappingProfileName('');
        notify('success', 'Gespeicherte Feldzuordnung entfernt');
      }
    } catch (error: unknown) {
      notify('error', 'Feldzuordnung konnte nicht entfernt werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const previewPackage = async () => {
    setPackageBusy(true);
    try {
      const result = await window.vaulta.transfer.previewVaultPackage({
        exportPassword: packagePassword,
      });
      if (result) {
        setPackagePreview(result);
        setPackageTargetName(result.vaultName);
        setPackageAllowNameConflict(false);
      }
    } catch (error: unknown) {
      setPackagePreview(null);
      notify('error', 'Tresor-Paket konnte nicht geprueft werden', getErrorMessage(error));
    } finally {
      setPackageBusy(false);
    }
  };

  const importPackage = async () => {
    if (!packagePreview) return;
    setPackageBusy(true);
    try {
      const result = await window.vaulta.transfer.importVaultPackage({
        token: packagePreview.token,
        exportPassword: packagePassword,
        targetVaultName: packageTargetName,
        allowNameConflict: packageAllowNameConflict,
      });
      setPackagePassword('');
      setPackagePreview(null);
      setPackageTargetName('');
      notify(
        'success',
        'Tresor-Paket importiert',
        `${String(result.entryCount)} Eintraege und ${String(result.attachmentCount)} Anhaenge wurden lokal verschluesselt angelegt.`,
      );
      onPackageImported(result.vaultId);
    } catch (error: unknown) {
      notify('error', 'Tresor-Paket konnte nicht importiert werden', getErrorMessage(error));
    } finally {
      setPackageBusy(false);
    }
  };

  const requiresNameConflictConfirmation =
    packagePreview !== null &&
    packagePreview.nameConflict &&
    packageTargetName.trim().localeCompare(packagePreview.vaultName.trim(), 'de', {
      sensitivity: 'base',
    }) === 0;

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
          {completedSummary && (
            <section className="tool-card import-result" aria-live="polite">
              <header>
                <div>
                  <Check />
                  <div>
                    <h2>Letzter Import</h2>
                    <p>Die Zaehlwerte enthalten keine importierten Feldwerte oder Geheimnisse.</p>
                  </div>
                </div>
                {completedSummary.duplicates > 0 && (
                  <Button onClick={onOpenDuplicates}>Dubletten-Zentrale oeffnen</Button>
                )}
              </header>
              <div className="backup-facts" aria-label="Importzusammenfassung">
                <span>
                  <strong>{String(completedSummary.newEntries)}</strong>neu
                </span>
                <span>
                  <strong>{String(completedSummary.skippedEntries)}</strong>uebersprungen
                </span>
                <span>
                  <strong>{String(completedSummary.duplicates)}</strong>Dubletten
                </span>
                <span>
                  <strong>
                    {String(completedSummary.warnings + completedSummary.invalidRows)}
                  </strong>
                  Hinweise
                </span>
              </div>
            </section>
          )}
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
            <InlineNotice kind="info" title="Enpass als generisches CSV">
              Fuer Enpass gibt es kein verlaesslich dokumentiertes natives Exportlayout. Waehle
              deshalb „Generisches CSV“ und ordne die Spalten selbst zu.
            </InlineNotice>
            <div
              className={`import-drop-target${dropActive ? ' is-dragging' : ''}`}
              data-vaulta-import-drop-target
              onDragEnter={(event) => {
                if (event.dataTransfer.types.includes('Files')) setDropActive(true);
              }}
              onDragOver={(event) => {
                if (event.dataTransfer.types.includes('Files')) {
                  event.preventDefault();
                  setDropActive(true);
                }
              }}
              onDragLeave={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget as Node | null))
                  setDropActive(false);
              }}
              onDrop={(event) => {
                event.preventDefault();
                setDropActive(false);
                if (event.dataTransfer.files.length !== 1)
                  notify('error', 'Bitte genau eine Importdatei ablegen');
              }}
            >
              <div>
                <FileUp aria-hidden="true" />
                <div>
                  <strong>Datei ablegen oder auswählen</strong>
                  <p aria-live="polite">
                    Der Dateipfad bleibt im Preload und Main-Prozess; gelesen wird nur lokal.
                  </p>
                </div>
              </div>
              <Button
                variant="primary"
                icon={<FileUp />}
                busy={busy}
                onClick={() => void chooseFile()}
              >
                Datei auswählen und lokal prüfen
              </Button>
            </div>
          </section>
          <section
            className="tool-card vault-package-transfer"
            aria-labelledby="package-import-title"
          >
            <header>
              <div>
                <Archive />
                <div>
                  <h2 id="package-import-title">Kryptris-Tresor-Paket importieren</h2>
                  <p>
                    Das Paket wird lokal geprueft und als neuer Tresor mit neuen Schluesseln
                    angelegt.
                  </p>
                </div>
              </div>
            </header>
            {!packagePreview ? (
              <>
                <Field
                  label="Exportpasswort des Pakets"
                  hint="Mindestens 12 Zeichen; es wird nur fuer diese lokale Pruefung verwendet."
                >
                  <PasswordInput
                    value={packagePassword}
                    autoComplete="off"
                    onChange={setPackagePassword}
                  />
                </Field>
                <Button
                  icon={<Archive />}
                  busy={packageBusy}
                  disabled={packagePassword.length < 12}
                  onClick={() => void previewPackage()}
                >
                  Paket auswaehlen und pruefen
                </Button>
              </>
            ) : (
              <>
                <dl className="package-preview-facts">
                  <div>
                    <dt>Tresor</dt>
                    <dd>{packagePreview.vaultName}</dd>
                  </div>
                  <div>
                    <dt>Exportiert</dt>
                    <dd>{formatDate(packagePreview.createdAt)}</dd>
                  </div>
                  <div>
                    <dt>Eintraege</dt>
                    <dd>{String(packagePreview.entryCount)}</dd>
                  </div>
                  <div>
                    <dt>Anhaenge</dt>
                    <dd>{String(packagePreview.attachmentCount)}</dd>
                  </div>
                </dl>
                <Field label="Name des neuen Tresors">
                  <input
                    value={packageTargetName}
                    maxLength={100}
                    autoComplete="off"
                    onChange={(event) => {
                      setPackageTargetName(event.currentTarget.value);
                      setPackageAllowNameConflict(false);
                    }}
                  />
                </Field>
                {requiresNameConflictConfirmation && (
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={packageAllowNameConflict}
                      onChange={(event) => setPackageAllowNameConflict(event.currentTarget.checked)}
                    />
                    <span>
                      <strong>Gleichen Tresornamen bewusst erlauben</strong>
                      <small>Der bestehende Tresor wird nicht ersetzt oder zusammengefuehrt.</small>
                    </span>
                  </label>
                )}
                <InlineNotice kind="info">
                  Quelle, Pfad und alte Schluessel werden nicht uebernommen. Anhaenge werden vor der
                  Veroeffentlichung mit neuen lokalen Schluesseln verschluesselt.
                </InlineNotice>
                <footer className="card-actions">
                  <Button
                    variant="ghost"
                    disabled={packageBusy}
                    onClick={() => {
                      setPackagePreview(null);
                      setPackagePassword('');
                      setPackageTargetName('');
                    }}
                  >
                    Anderes Paket
                  </Button>
                  <Button
                    variant="primary"
                    busy={packageBusy}
                    disabled={
                      packageTargetName.trim().length === 0 ||
                      (requiresNameConflictConfirmation && !packageAllowNameConflict)
                    }
                    onClick={() => void importPackage()}
                  >
                    Als neuen Tresor importieren
                  </Button>
                </footer>
              </>
            )}
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
              <div className="mapping-profile-controls">
                <Field label="Gespeicherte Zuordnung">
                  <select
                    value={selectedMappingProfileId}
                    onChange={(event) => applyMappingProfile(event.currentTarget.value)}
                  >
                    <option value="">Neue Zuordnung</option>
                    {mappingProfiles.map((profile) => (
                      <option value={profile.id} key={profile.id}>
                        {profile.name}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Name der Zuordnung">
                  <input
                    value={mappingProfileName}
                    maxLength={80}
                    autoComplete="off"
                    onChange={(event) => setMappingProfileName(event.currentTarget.value)}
                  />
                </Field>
                <div className="mapping-profile-controls__actions">
                  <Button busy={busy} onClick={() => void saveMappingProfile()}>
                    {selectedMappingProfileId ? 'Zuordnung aktualisieren' : 'Zuordnung speichern'}
                  </Button>
                  <Button
                    variant="ghost"
                    busy={busy}
                    disabled={!selectedMappingProfileId}
                    onClick={() => void removeMappingProfile()}
                  >
                    Entfernen
                  </Button>
                </div>
              </div>
              <InlineNotice kind="info">
                Gespeichert werden nur Spaltennamen und Zuordnungen, niemals importierte Werte,
                Passwoerter oder Notizen.
              </InlineNotice>
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
      <VaultPackageExportPanel state={state} notify={notify} />
    </section>
  );
}

function VaultPackageExportPanel({ state, notify }: { state: AppState; notify: Notify }) {
  const [vaultId, setVaultId] = useState(state.vaults[0]?.id ?? '');
  const [includeAttachments, setIncludeAttachments] = useState(true);
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setVaultId((current) =>
      state.vaults.some((vault) => vault.id === current) ? current : (state.vaults[0]?.id ?? ''),
    );
  }, [state.vaults]);

  if (state.vaults.length === 0) return null;

  const exportPackage = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== confirmation) return;
    setBusy(true);
    try {
      const result = await window.vaulta.transfer.exportVaultPackage({
        vaultId,
        exportPassword: password,
        includeAttachments,
      });
      if (result) {
        notify(
          'success',
          'Verschluesseltes Tresor-Paket exportiert',
          `${String(result.entryCount)} Eintraege${result.includesAttachments ? ` und ${String(result.attachmentCount)} Anhaenge` : ''}; Pfad und Schluessel bleiben lokal.`,
        );
      }
      setPassword('');
      setConfirmation('');
    } catch (error: unknown) {
      notify('error', 'Tresor-Paket konnte nicht exportiert werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="tool-card vault-package-transfer"
      aria-labelledby="package-export-title"
      onSubmit={(event) => void exportPackage(event)}
    >
      <header>
        <div>
          <Archive />
          <div>
            <h2 id="package-export-title">Einzelnen Tresor als Paket exportieren</h2>
            <p>
              Ein portables Paket enthaelt einen Tresor, aber niemals dein Profil oder lokale Keys.
            </p>
          </div>
        </div>
      </header>
      <div className="vault-package-export-fields">
        <Field label="Tresor">
          <select value={vaultId} onChange={(event) => setVaultId(event.currentTarget.value)}>
            {state.vaults.map((vault) => (
              <option value={vault.id} key={vault.id}>
                {vault.name} ({String(vault.entryCount)} Eintraege)
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Exportpasswort"
          hint="Mindestens 12 Zeichen; verwende ein eigenstaendiges Passwort."
        >
          <PasswordInput value={password} autoComplete="off" onChange={setPassword} />
        </Field>
        <Field label="Exportpasswort wiederholen">
          <PasswordInput value={confirmation} autoComplete="off" onChange={setConfirmation} />
        </Field>
      </div>
      <label className="check-row">
        <input
          type="checkbox"
          checked={includeAttachments}
          onChange={(event) => setIncludeAttachments(event.currentTarget.checked)}
        />
        <span>
          <strong>Anhaenge einschliessen</strong>
          <small>
            Anhaenge bleiben im Paket verschluesselt und werden beim Import neu verschluesselt.
          </small>
        </span>
      </label>
      {confirmation && password !== confirmation && (
        <InlineNotice kind="error">
          Die beiden Exportpasswoerter stimmen nicht ueberein.
        </InlineNotice>
      )}
      <footer className="card-actions">
        <span>Argon2id und ein eigener zufaelliger Paketschluessel schuetzen dieses Format.</span>
        <Button
          type="submit"
          variant="primary"
          icon={<Archive />}
          busy={busy}
          disabled={!vaultId || password.length < 12 || password !== confirmation}
        >
          Paketexportziel waehlen
        </Button>
      </footer>
    </form>
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
