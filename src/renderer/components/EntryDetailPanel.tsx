import {
  ArchiveRestore,
  Check,
  Copy,
  Download,
  EllipsisVertical,
  Eye,
  FileText,
  Gauge,
  Image,
  LockKeyhole,
  Pencil,
  Plus,
  RefreshCw,
  QrCode,
  ShieldCheck,
  Star,
  Trash2,
  Wifi,
  X,
} from 'lucide-react';
import type { CSSProperties } from 'react';
import { useCallback, useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';

import type {
  AppState,
  AttachmentMetadata,
  AttachmentPreview,
  EntryDetail,
  EntrySummary,
  TotpCode,
} from '../../shared/models';
import type { Notify } from '../types';
import { formatBytes, formatDate, getErrorMessage } from '../utils';
import { EntryIcon } from './EntryIcon';
import {
  Button,
  EmptyState,
  Field,
  IconButton,
  InlineNotice,
  LoadingState,
  Modal,
  PasswordConfirm,
  PasswordInput,
} from './ui';

interface EntryDetailPanelProps {
  detail: EntryDetail | null;
  summary: EntrySummary | null;
  state: AppState;
  loading: boolean;
  notify: Notify;
  onEdit: () => void;
  onToggleFavorite: () => void;
  onMoveToTrash: () => void;
  onRestore: () => void;
  onPurge: (password: string) => Promise<void>;
  onReload: () => void;
  onBack: () => void;
}

export function EntryDetailPanel({
  detail,
  summary,
  state,
  loading,
  notify,
  onEdit,
  onToggleFavorite,
  onMoveToTrash,
  onRestore,
  onPurge,
  onReload,
  onBack,
}: EntryDetailPanelProps) {
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [revealPath, setRevealPath] = useState<string | null>(null);
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [busyAttachment, setBusyAttachment] = useState<string | null>(null);
  const [preview, setPreview] = useState<{
    attachment: AttachmentMetadata;
    content: AttachmentPreview;
  } | null>(null);
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [privateKeyExportOpen, setPrivateKeyExportOpen] = useState(false);
  const [privateKeyPassword, setPrivateKeyPassword] = useState('');
  const [privateKeyConfirmation, setPrivateKeyConfirmation] = useState('');
  const [wifiQrData, setWifiQrData] = useState<string | null>(null);

  useEffect(() => {
    setRevealed({});
    setRevealPath(null);
    setPreview(null);
  }, [detail?.id]);

  useEffect(() => {
    if (Object.keys(revealed).length === 0) return;
    const timer = window.setTimeout(() => setRevealed({}), 30_000);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  const refreshTotp = useCallback(async () => {
    if (!detail || detail.type !== 'credential' || detail.deletedAt) {
      setTotp(null);
      return;
    }
    try {
      setTotp(await window.vaulta.totp.getCode({ vaultId: detail.vaultId, entryId: detail.id }));
    } catch {
      setTotp(null);
    }
  }, [detail]);

  useEffect(() => {
    void refreshTotp();
  }, [refreshTotp]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setTotp((current) => {
        if (!current) return null;
        if (current.remainingSeconds <= 1) {
          void refreshTotp();
          return current;
        }
        return { ...current, remainingSeconds: current.remainingSeconds - 1 };
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [refreshTotp]);

  if (loading)
    return (
      <section className="detail-panel">
        <LoadingState label="Eintrag wird entschlüsselt …" />
      </section>
    );
  if (!detail) {
    return (
      <section className="detail-panel detail-panel--empty">
        <EmptyState
          title="Eintrag auswählen"
          description="Wähle links einen Eintrag aus, um seine sicheren Details anzuzeigen."
        />
      </section>
    );
  }

  const reveal = async (path: string, password?: string) => {
    try {
      const input = password
        ? { vaultId: detail.vaultId, entryId: detail.id, fieldPath: path, masterPassword: password }
        : { vaultId: detail.vaultId, entryId: detail.id, fieldPath: path };
      const value = await window.vaulta.entries.reveal(input);
      setRevealed((current) => ({ ...current, [path]: value }));
      setRevealPath(null);
    } catch (error: unknown) {
      notify('error', 'Wert konnte nicht angezeigt werden', getErrorMessage(error));
    }
  };

  const copy = async (path: string, label: string) => {
    try {
      await window.vaulta.entries.copy({
        vaultId: detail.vaultId,
        entryId: detail.id,
        fieldPath: path,
      });
      notify('success', `${label} kopiert`, 'Die Zwischenablage wird automatisch geleert.');
    } catch (error: unknown) {
      notify('error', 'Kopieren fehlgeschlagen', getErrorMessage(error));
    }
  };

  const addAttachment = async () => {
    setBusyAttachment('add');
    try {
      const added = await window.vaulta.attachments.add({
        vaultId: detail.vaultId,
        entryId: detail.id,
      });
      if (added) {
        notify('success', 'Anhang verschlüsselt hinzugefügt', added.name);
        onReload();
      }
    } catch (error: unknown) {
      notify('error', 'Anhang konnte nicht hinzugefügt werden', getErrorMessage(error));
    } finally {
      setBusyAttachment(null);
    }
  };

  const removeAttachment = async (attachment: AttachmentMetadata) => {
    setBusyAttachment(attachment.id);
    try {
      await window.vaulta.attachments.remove({
        vaultId: detail.vaultId,
        entryId: detail.id,
        attachmentId: attachment.id,
      });
      notify('success', 'Anhang entfernt', attachment.name);
      onReload();
    } catch (error: unknown) {
      notify('error', 'Anhang konnte nicht entfernt werden', getErrorMessage(error));
    } finally {
      setBusyAttachment(null);
    }
  };

  const exportAttachment = async (attachment: AttachmentMetadata) => {
    setBusyAttachment(attachment.id);
    try {
      const exported = await window.vaulta.attachments.export({
        vaultId: detail.vaultId,
        entryId: detail.id,
        attachmentId: attachment.id,
      });
      if (exported)
        notify('success', 'Anhang exportiert', 'Die Zielkopie liegt unverschlüsselt vor.');
    } catch (error: unknown) {
      notify('error', 'Export fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusyAttachment(null);
    }
  };

  const previewAttachment = async (attachment: AttachmentMetadata) => {
    setBusyAttachment(attachment.id);
    try {
      const content = await window.vaulta.attachments.preview({
        vaultId: detail.vaultId,
        entryId: detail.id,
        attachmentId: attachment.id,
      });
      setPreview({ attachment, content });
    } catch (error: unknown) {
      notify('error', 'Vorschau nicht verfügbar', getErrorMessage(error));
    } finally {
      setBusyAttachment(null);
    }
  };

  const securityLabel = {
    good: 'Stark',
    info: 'Hinweise',
    warning: 'Prüfen',
    critical: 'Kritisch',
  }[summary?.securityState ?? 'info'];

  return (
    <section className="detail-panel" aria-label={`Details für ${detail.title}`}>
      <header className="detail-header">
        <IconButton label="Zurück zur Liste" className="detail-back" onClick={onBack}>
          <X />
        </IconButton>
        <EntryIcon type={detail.type} size="large" />
        <div className="detail-header__title">
          <div>
            <h1>{detail.title}</h1>
            <IconButton
              label={detail.favorite ? 'Aus Favoriten entfernen' : 'Zu Favoriten hinzufügen'}
              active={detail.favorite}
              onClick={onToggleFavorite}
            >
              <Star fill={detail.favorite ? 'currentColor' : 'none'} />
            </IconButton>
          </div>
          <small>Geändert {formatDate(detail.updatedAt)}</small>
        </div>
        <div className="detail-header__actions">
          {detail.deletedAt ? (
            <>
              <Button icon={<ArchiveRestore />} onClick={onRestore} data-testid="restore-entry-button">
                Wiederherstellen
              </Button>
              <Button
                variant="danger"
                icon={<Trash2 />}
                onClick={() => setPurgeOpen(true)}
                data-testid="purge-entry-button"
              >
                Endgültig löschen
              </Button>
            </>
          ) : (
            <>
              <Button icon={<Pencil />} onClick={onEdit} data-testid="edit-entry-button">
                Bearbeiten
              </Button>
              <Button
                variant="primary"
                icon={<Copy />}
                disabled={!detail.fields.some((field) => field.copyable)}
                onClick={() => {
                  const primary =
                    detail.fields.find((field) => field.secret && field.copyable) ??
                    detail.fields.find((field) => field.copyable);
                  if (primary) void copy(primary.path, primary.label);
                }}
              >
                Kopieren
              </Button>
              <IconButton label="In Papierkorb verschieben" onClick={onMoveToTrash}>
                <EllipsisVertical />
              </IconButton>
            </>
          )}
        </div>
      </header>

      <div className="detail-scroll">
        <div className="detail-fields">
          {detail.fields.map((field) => {
            const visibleValue = field.secret ? revealed[field.path] : field.value;
            return (
              <div className="display-field" key={field.path}>
                <span className="display-field__label">{field.label}</span>
                <div
                  className={`display-field__value ${field.kind === 'multiline' || field.kind === 'markdown' ? 'is-multiline' : ''}`}
                >
                  {field.kind === 'boolean' ? (
                    <span>{visibleValue === 'true' ? 'Ja' : 'Nein'}</span>
                  ) : field.kind === 'markdown' ? (
                    <div className="markdown-content">
                      <SafeMarkdown value={visibleValue ?? ''} />
                    </div>
                  ) : field.secret && !visibleValue ? (
                    <span className="secret-dots" aria-label="Maskierter Wert">
                      ••••••••••••••••
                    </span>
                  ) : (
                    <span>{visibleValue || '—'}</span>
                  )}
                  <span className="display-field__actions">
                    {field.secret && (
                      <IconButton
                        label={
                          visibleValue ? `${field.label} ausblenden` : `${field.label} anzeigen`
                        }
                        onClick={() => {
                          if (visibleValue) {
                            setRevealed((current) => {
                              const next = { ...current };
                              delete next[field.path];
                              return next;
                            });
                          } else if (state.settings?.requireMasterForReveal) {
                            setRevealPath(field.path);
                          } else {
                            void reveal(field.path);
                          }
                        }}
                      >
                        <Eye />
                      </IconButton>
                    )}
                    {field.copyable && (
                      <IconButton
                        label={`${field.label} kopieren`}
                        onClick={() => void copy(field.path, field.label)}
                      >
                        <Copy />
                      </IconButton>
                    )}
                  </span>
                </div>
              </div>
            );
          })}
          {totp && (
            <div className="display-field">
              <span className="display-field__label">TOTP-Code</span>
              <div className="display-field__value totp-field">
                <strong>{totp.code.replace(/(.{3})/u, '$1 ')}</strong>
                <span
                  className="totp-ring"
                  style={
                    {
                      '--totp-progress': `${String((totp.remainingSeconds / totp.period) * 360)}deg`,
                    } as CSSProperties
                  }
                  aria-label={`${String(totp.remainingSeconds)} Sekunden verbleibend`}
                >
                  {totp.remainingSeconds}
                </span>
                <IconButton
                  label="TOTP-Code kopieren"
                  onClick={() => {
                    void window.vaulta.totp
                      .copy({ vaultId: detail.vaultId, entryId: detail.id })
                      .then(() => notify('success', 'TOTP-Code kopiert'))
                      .catch((error: unknown) =>
                        notify('error', 'Kopieren fehlgeschlagen', getErrorMessage(error)),
                      );
                  }}
                >
                  <Copy />
                </IconButton>
              </div>
            </div>
          )}
          {detail.tags.length > 0 && (
            <div className="display-field display-field--tags">
              <span className="display-field__label">Tags</span>
              <div className="tag-list">
                {detail.tags.map((tag, index) => (
                  <span className={`tag tag--${String((index % 3) + 1)}`} key={tag}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {detail.note && (
          <section className="detail-note info-card">
            <header>
              <FileText />
              <h2>Notizen</h2>
            </header>
            <div className="markdown-content">
              <SafeMarkdown value={detail.note} />
            </div>
          </section>
        )}

        {detail.type === 'ssh-key' && !detail.deletedAt && (
          <section className="sensitive-action-card">
            <div>
              <LockKeyhole />
              <span>
                <strong>Privaten Schlüssel exportieren</strong>
                <small>
                  Der Export wird unverschlüsselt geschrieben und benötigt Master-Passwort plus
                  bewusste Bestätigung.
                </small>
              </span>
            </div>
            <Button
              variant="danger"
              icon={<Download />}
              onClick={() => setPrivateKeyExportOpen(true)}
            >
              Export vorbereiten
            </Button>
          </section>
        )}

        {detail.type === 'wifi' && !detail.deletedAt && (
          <section className="sensitive-action-card">
            <div>
              <Wifi />
              <span>
                <strong>WLAN-QR-Code anzeigen</strong>
                <small>
                  Der QR-Code enthält SSID und Passwort und wird ausschließlich lokal erzeugt.
                </small>
              </span>
            </div>
            <Button
              icon={<QrCode />}
              onClick={() => {
                void window.vaulta.entries
                  .wifiQr({ vaultId: detail.vaultId, entryId: detail.id })
                  .then(setWifiQrData)
                  .catch((error: unknown) =>
                    notify('error', 'QR-Code konnte nicht erzeugt werden', getErrorMessage(error)),
                  );
              }}
            >
              QR-Code anzeigen
            </Button>
          </section>
        )}

        <div className="detail-cards">
          <section className="info-card attachment-card">
            <header>
              <div>
                <FileText />
                <h2>Anhänge</h2>
              </div>
              <span>{String(detail.attachments.length)}</span>
            </header>
            <div className="attachment-list">
              {detail.attachments.map((attachment) => (
                <article key={attachment.id}>
                  <FileText />
                  <div>
                    <strong>{attachment.name}</strong>
                    <small>
                      {formatBytes(attachment.size)} · {formatDate(attachment.createdAt)}
                    </small>
                  </div>
                  {attachment.previewable && (
                    <IconButton
                      label={`${attachment.name} sicher ansehen`}
                      disabled={busyAttachment === attachment.id}
                      onClick={() => void previewAttachment(attachment)}
                    >
                      <Eye />
                    </IconButton>
                  )}
                  <IconButton
                    label={`${attachment.name} exportieren`}
                    disabled={busyAttachment === attachment.id}
                    onClick={() => void exportAttachment(attachment)}
                  >
                    <Download />
                  </IconButton>
                  <IconButton
                    label={`${attachment.name} entfernen`}
                    disabled={busyAttachment === attachment.id}
                    onClick={() => void removeAttachment(attachment)}
                  >
                    <Trash2 />
                  </IconButton>
                </article>
              ))}
              {detail.attachments.length === 0 && <p>Noch keine Anhänge.</p>}
            </div>
            {!detail.deletedAt && (
              <Button
                icon={<Plus />}
                busy={busyAttachment === 'add'}
                onClick={() => void addAttachment()}
              >
                Anhang hinzufügen
              </Button>
            )}
          </section>

          <section
            className={`info-card security-card security-card--${summary?.securityState ?? 'info'}`}
          >
            <header>
              <div>
                <ShieldCheck />
                <h2>Sicherheit</h2>
              </div>
              <span>
                <Check /> {securityLabel}
              </span>
            </header>
            <div className="security-bars" aria-label={`Sicherheitsstatus: ${securityLabel}`}>
              {[1, 2, 3, 4, 5].map((value) => (
                <span key={value} />
              ))}
            </div>
            <p>
              {summary?.securityState === 'good'
                ? 'Keine unmittelbaren lokalen Risiken für diesen Eintrag erkannt.'
                : 'Öffne den Sicherheitscheck für konkrete lokale Empfehlungen.'}
            </p>
            <Button
              variant="ghost"
              icon={<Gauge />}
              onClick={() =>
                notify('info', 'Sicherheitscheck', 'Wähle „Sicherheitscheck“ in der Navigation.')
              }
            >
              Details anzeigen
            </Button>
          </section>
        </div>

        <footer className="detail-metadata">
          <span>Erstellt {formatDate(detail.createdAt)}</span>
          <span>Zuletzt geändert {formatDate(detail.updatedAt)}</span>
          <Button variant="ghost" icon={<RefreshCw />} onClick={onReload}>
            Aktualisieren
          </Button>
        </footer>
      </div>

      <PasswordConfirm
        open={Boolean(revealPath)}
        title="Geheimnis anzeigen"
        description="Bestätige dein Master-Passwort. Der Wert wird nach 30 Sekunden wieder maskiert."
        onClose={() => setRevealPath(null)}
        onConfirm={async (password) => {
          if (revealPath) await reveal(revealPath, password);
        }}
      />
      <PasswordConfirm
        open={purgeOpen}
        title="Eintrag endgültig löschen?"
        description="Diese Aktion kann nicht rückgängig gemacht werden. Bestätige mit deinem Master-Passwort."
        confirmationLabel="Endgültig löschen"
        danger
        onClose={() => setPurgeOpen(false)}
        onConfirm={async (password) => {
          await onPurge(password);
          setPurgeOpen(false);
        }}
      />
      <Modal
        open={Boolean(preview)}
        title={preview?.attachment.name ?? 'Sichere Vorschau'}
        description="Die Vorschau existiert nur im entsperrten Arbeitsspeicher."
        size="large"
        onClose={() => setPreview(null)}
      >
        {preview?.content.kind === 'image' && (
          <div className="attachment-preview attachment-preview--image">
            <Image />
            <img src={preview.content.data} alt={preview.attachment.name} />
          </div>
        )}
        {preview?.content.kind === 'text' && (
          <pre className="attachment-preview attachment-preview--text">{preview.content.data}</pre>
        )}
        {preview?.content.kind === 'pdf' && (
          <div className="attachment-preview attachment-preview--pdf">
            <iframe title={preview.attachment.name} src={preview.content.data} sandbox="" />
          </div>
        )}
        {preview && (
          <InlineNotice kind="info">
            Vorschauen können Dateiinhalte darstellen. Öffne nur Anhänge, deren Ursprung du kennst.
          </InlineNotice>
        )}
      </Modal>
      <Modal
        open={privateKeyExportOpen}
        title="Privaten Schlüssel exportieren"
        description="Die Zieldatei ist nicht mehr durch Kryptris verschlüsselt. Verwahre sie nur so lange wie zwingend nötig."
        onClose={() => {
          setPrivateKeyExportOpen(false);
          setPrivateKeyPassword('');
          setPrivateKeyConfirmation('');
        }}
      >
        <div className="stack">
          <InlineNotice kind="error" title="Hochsensibler Klartextexport">
            Jede Person und jedes Programm mit Zugriff auf die exportierte Datei kann den privaten
            Schlüssel verwenden.
          </InlineNotice>
          <Field label="Zur Bestätigung PRIVATEN SCHLÜSSEL EXPORTIEREN eingeben">
            <input
              value={privateKeyConfirmation}
              autoComplete="off"
              onChange={(event) =>
                setPrivateKeyConfirmation(event.currentTarget.value.toUpperCase())
              }
            />
          </Field>
          <Field label="Master-Passwort">
            <PasswordInput
              value={privateKeyPassword}
              autoComplete="current-password"
              onChange={setPrivateKeyPassword}
            />
          </Field>
          <div className="modal__inline-actions">
            <Button variant="ghost" onClick={() => setPrivateKeyExportOpen(false)}>
              Abbrechen
            </Button>
            <Button
              variant="danger"
              disabled={
                privateKeyConfirmation !== 'PRIVATEN SCHLÜSSEL EXPORTIEREN' || !privateKeyPassword
              }
              onClick={() => {
                void window.vaulta.entries
                  .exportPrivateKey({
                    vaultId: detail.vaultId,
                    entryId: detail.id,
                    masterPassword: privateKeyPassword,
                    confirmation: privateKeyConfirmation,
                  })
                  .then((exported) => {
                    if (exported)
                      notify(
                        'warning',
                        'Privater Schlüssel exportiert',
                        'Die Zieldatei liegt unverschlüsselt vor.',
                      );
                    setPrivateKeyExportOpen(false);
                    setPrivateKeyPassword('');
                    setPrivateKeyConfirmation('');
                  })
                  .catch((error: unknown) =>
                    notify('error', 'Export fehlgeschlagen', getErrorMessage(error)),
                  );
              }}
            >
              Unverschlüsselt exportieren
            </Button>
          </div>
        </div>
      </Modal>
      <Modal
        open={Boolean(wifiQrData)}
        title="WLAN-QR-Code"
        description="Der QR-Code enthält das WLAN-Passwort. Zeige ihn nur Personen, die Zugang erhalten sollen."
        size="small"
        onClose={() => setWifiQrData(null)}
      >
        {wifiQrData && (
          <div className="wifi-qr">
            <img src={wifiQrData} alt={`QR-Code für ${detail.title}`} />
            <InlineNotice kind="warning">
              Schließe diese Ansicht nach dem Scannen. Screenshots können von Kryptris nicht
              vollständig verhindert werden.
            </InlineNotice>
          </div>
        )}
      </Modal>
    </section>
  );
}

function SafeMarkdown({ value }: { value: string }) {
  return (
    <ReactMarkdown
      components={{
        a: ({ children }) => <span className="markdown-link">{children}</span>,
        img: ({ alt }) => <span>[Bild entfernt: {alt ?? 'ohne Beschreibung'}]</span>,
      }}
    >
      {value}
    </ReactMarkdown>
  );
}
