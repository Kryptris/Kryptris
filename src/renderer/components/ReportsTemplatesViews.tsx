import {
  BarChart3,
  Blocks,
  FileBarChart,
  FilePlus2,
  HardDrive,
  Heart,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { FormEvent } from 'react';
import { useCallback, useEffect, useState } from 'react';

import {
  ENTRY_TYPE_LABELS,
  ENTRY_TYPES,
  type CustomFieldType,
  type EntryTemplate,
  type EntryType,
  type LocalReport,
} from '../../shared/models';
import type { Notify } from '../types';
import { ENTRY_ACCENTS, formatBytes, formatDate, getErrorMessage } from '../utils';
import { Button, EmptyState, Field, IconButton, InlineNotice, LoadingState, Modal } from './ui';

export function ReportsView({
  notify,
  onOpenEntry,
}: {
  notify: Notify;
  onOpenEntry: (entryId: string) => void;
}) {
  const [report, setReport] = useState<LocalReport | null>(null);
  const [loading, setLoading] = useState(true);

  const generate = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await window.vaulta.reports.generate());
    } catch (error: unknown) {
      notify('error', 'Bericht konnte nicht erzeugt werden', getErrorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [notify]);

  useEffect(() => {
    void generate();
  }, [generate]);

  return (
    <section className="tool-view" aria-labelledby="reports-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <FileBarChart />
          </span>
          <div>
            <p className="eyebrow">Erweiterte lokale Berichte</p>
            <h1 id="reports-title">Tresorübersicht</h1>
            <p>
              Aggregierte Kennzahlen werden bei Bedarf im Arbeitsspeicher berechnet und nie
              übertragen.
            </p>
          </div>
        </div>
        <Button icon={<RefreshCw />} busy={loading} onClick={() => void generate()}>
          Neu berechnen
        </Button>
      </header>
      {loading && !report ? (
        <LoadingState label="Lokalen Bericht berechnen …" />
      ) : report ? (
        <>
          <div className="metric-grid">
            <Metric icon={<Blocks />} value={report.entryCount} label="Einträge" />
            <Metric icon={<HardDrive />} value={report.vaultCount} label="Tresore" />
            <Metric icon={<Heart />} value={report.favoriteCount} label="Favoriten" />
            <Metric icon={<Trash2 />} value={report.trashCount} label="Im Papierkorb" />
            <Metric
              icon={<HardDrive />}
              value={report.attachmentCount}
              label={`Anhänge · ${formatBytes(report.attachmentBytes)}`}
            />
            <Metric icon={<ShieldCheck />} value={report.security.score} label="Sicherheitswert" />
          </div>
          <div className="dashboard-grid dashboard-grid--two">
            <section className="tool-card type-chart">
              <header>
                <div>
                  <BarChart3 />
                  <h2>Verteilung nach Typ</h2>
                </div>
              </header>
              {ENTRY_TYPES.map((type) => {
                const value = report.typeCounts[type];
                const max = Math.max(1, ...Object.values(report.typeCounts));
                return (
                  <div className="chart-row" key={type}>
                    <span>{ENTRY_TYPE_LABELS[type]}</span>
                    <div>
                      <i
                        style={{
                          width: `${String((value / max) * 100)}%`,
                          background: ENTRY_ACCENTS[type],
                        }}
                      />
                    </div>
                    <strong>{String(value)}</strong>
                  </div>
                );
              })}
            </section>
            <section className="tool-card oldest-card">
              <header>
                <div>
                  <RefreshCw />
                  <h2>Am längsten unverändert</h2>
                </div>
              </header>
              {report.oldestEntries.length === 0 ? (
                <EmptyState
                  title="Noch keine Einträge"
                  description="Der Bericht füllt sich mit deinen Daten."
                />
              ) : (
                report.oldestEntries.map((entry) => (
                  <button type="button" key={entry.id} onClick={() => onOpenEntry(entry.id)}>
                    <span>
                      <strong>{entry.title}</strong>
                      <small>{ENTRY_TYPE_LABELS[entry.type]}</small>
                    </span>
                    <time>{formatDate(entry.updatedAt)}</time>
                  </button>
                ))
              )}
            </section>
          </div>
          <InlineNotice kind="success" title="Offline bestätigt">
            Dieser Bericht wurde ohne Netzwerkzugriff erzeugt. Stand:{' '}
            {formatDate(report.generatedAt)}
          </InlineNotice>
        </>
      ) : (
        <EmptyState
          title="Kein Bericht verfügbar"
          description="Versuche die lokale Berechnung erneut."
        />
      )}
    </section>
  );
}

function Metric({ icon, value, label }: { icon: React.ReactNode; value: number; label: string }) {
  return (
    <article className="metric-card">
      <span>{icon}</span>
      <div>
        <strong>{new Intl.NumberFormat('de-DE').format(value)}</strong>
        <small>{label}</small>
      </div>
    </article>
  );
}

interface TemplateDraft {
  id?: string;
  name: string;
  entryType: EntryType;
  fields: Array<{
    label: string;
    type: CustomFieldType;
    secret: boolean;
    defaultValue: string | number | boolean;
  }>;
}

const EMPTY_TEMPLATE: TemplateDraft = { name: '', entryType: 'custom', fields: [] };

export function TemplatesView({
  notify,
  onUseTemplate,
}: {
  notify: Notify;
  onUseTemplate: (template: EntryTemplate) => void;
}) {
  const [templates, setTemplates] = useState<EntryTemplate[]>([]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [draft, setDraft] = useState<TemplateDraft>(EMPTY_TEMPLATE);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setTemplates(await window.vaulta.templates.list());
    } catch (error: unknown) {
      notify('error', 'Vorlagen konnten nicht geladen werden', getErrorMessage(error));
    }
  }, [notify]);
  useEffect(() => {
    void load();
  }, [load]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const saved = await window.vaulta.templates.save(draft);
      setTemplates((current) =>
        [...current.filter((item) => item.id !== saved.id), saved].sort((a, b) =>
          a.name.localeCompare(b.name, 'de'),
        ),
      );
      setEditorOpen(false);
      notify('success', 'Vorlage gespeichert', saved.name);
    } catch (error: unknown) {
      notify('error', 'Vorlage konnte nicht gespeichert werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (template: EntryTemplate) => {
    try {
      await window.vaulta.templates.delete(template.id);
      setTemplates((current) => current.filter((item) => item.id !== template.id));
      notify('success', 'Vorlage gelöscht', template.name);
    } catch (error: unknown) {
      notify('error', 'Vorlage konnte nicht gelöscht werden', getErrorMessage(error));
    }
  };

  return (
    <section className="tool-view" aria-labelledby="templates-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <Blocks />
          </span>
          <div>
            <p className="eyebrow">Welle 6</p>
            <h1 id="templates-title">Eigene Vorlagen</h1>
            <p>Wiederverwendbare Feldstrukturen für häufig benötigte Einträge.</p>
          </div>
        </div>
        <Button
          variant="primary"
          icon={<Plus />}
          onClick={() => {
            setDraft(EMPTY_TEMPLATE);
            setEditorOpen(true);
          }}
        >
          Neue Vorlage
        </Button>
      </header>
      {templates.length === 0 ? (
        <EmptyState
          title="Noch keine Vorlagen"
          description="Lege eine wiederverwendbare Struktur mit eigenen Feldern an."
          action={
            <Button icon={<Plus />} onClick={() => setEditorOpen(true)}>
              Erste Vorlage erstellen
            </Button>
          }
        />
      ) : (
        <div className="template-grid">
          {templates.map((template) => (
            <article className="tool-card template-card" key={template.id}>
              <header>
                <span style={{ background: ENTRY_ACCENTS[template.entryType] }}>
                  <Blocks />
                </span>
                <div>
                  <h2>{template.name}</h2>
                  <p>
                    {ENTRY_TYPE_LABELS[template.entryType]} · {String(template.fields.length)}{' '}
                    Felder
                  </p>
                </div>
              </header>
              <ul>
                {template.fields.slice(0, 5).map((field, index) => (
                  <li key={`${field.label}-${String(index)}`}>
                    <span>{field.label}</span>
                    <small>{field.secret ? 'Geheimnis' : field.type}</small>
                  </li>
                ))}
              </ul>
              <footer>
                <Button
                  variant="primary"
                  icon={<FilePlus2 />}
                  onClick={() => onUseTemplate(template)}
                >
                  Eintrag erstellen
                </Button>
                <Button
                  onClick={() => {
                    setDraft({
                      id: template.id,
                      name: template.name,
                      entryType: template.entryType,
                      fields: structuredClone(template.fields),
                    });
                    setEditorOpen(true);
                  }}
                >
                  Bearbeiten
                </Button>
                <IconButton
                  label={`${template.name} löschen`}
                  onClick={() => void remove(template)}
                >
                  <Trash2 />
                </IconButton>
              </footer>
            </article>
          ))}
        </div>
      )}
      <Modal
        open={editorOpen}
        title={draft.id ? 'Vorlage bearbeiten' : 'Vorlage erstellen'}
        description="Vorlagen enthalten nur Feldstrukturen und Standardwerte, keine Eintragsanhänge."
        size="large"
        onClose={() => setEditorOpen(false)}
      >
        <form className="stack" onSubmit={(event) => void save(event)}>
          <div className="form-grid form-grid--two">
            <Field label="Vorlagenname">
              <input
                value={draft.name}
                onChange={(event) =>
                  setDraft((current) => ({ ...current, name: event.currentTarget.value }))
                }
              />
            </Field>
            <Field label="Basistyp">
              <select
                value={draft.entryType}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    entryType: event.currentTarget.value as EntryType,
                  }))
                }
              >
                {ENTRY_TYPES.map((type) => (
                  <option value={type} key={type}>
                    {ENTRY_TYPE_LABELS[type]}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="template-field-editor">
            <div className="subsection-heading">
              <h3>Felder</h3>
              <Button
                type="button"
                icon={<Plus />}
                onClick={() =>
                  setDraft((current) => ({
                    ...current,
                    fields: [
                      ...current.fields,
                      { label: '', type: 'text', secret: false, defaultValue: '' },
                    ],
                  }))
                }
              >
                Feld hinzufügen
              </Button>
            </div>
            {draft.fields.map((field, index) => (
              <div className="template-field-row" key={index}>
                <Field label="Bezeichnung">
                  <input
                    value={field.label}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        fields: current.fields.map((item, currentIndex) =>
                          currentIndex === index
                            ? { ...item, label: event.currentTarget.value }
                            : item,
                        ),
                      }))
                    }
                  />
                </Field>
                <Field label="Typ">
                  <select
                    value={field.type}
                    onChange={(event) => {
                      const type = event.currentTarget.value as CustomFieldType;
                      setDraft((current) => ({
                        ...current,
                        fields: current.fields.map((item, currentIndex) =>
                          currentIndex === index
                            ? {
                                ...item,
                                type,
                                secret: type === 'secret',
                                defaultValue: type === 'boolean' ? false : '',
                              }
                            : item,
                        ),
                      }));
                    }}
                  >
                    {(
                      ['text', 'secret', 'url', 'number', 'date', 'boolean'] as CustomFieldType[]
                    ).map((type) => (
                      <option key={type}>{type}</option>
                    ))}
                  </select>
                </Field>
                <IconButton
                  type="button"
                  label="Vorlagenfeld entfernen"
                  onClick={() =>
                    setDraft((current) => ({
                      ...current,
                      fields: current.fields.filter((_, currentIndex) => currentIndex !== index),
                    }))
                  }
                >
                  <Trash2 />
                </IconButton>
              </div>
            ))}
          </div>
          <div className="modal__inline-actions">
            <Button type="button" variant="ghost" onClick={() => setEditorOpen(false)}>
              Abbrechen
            </Button>
            <Button
              type="submit"
              variant="primary"
              icon={<Save />}
              busy={busy}
              disabled={!draft.name.trim()}
            >
              Vorlage speichern
            </Button>
          </div>
        </form>
      </Modal>
    </section>
  );
}
