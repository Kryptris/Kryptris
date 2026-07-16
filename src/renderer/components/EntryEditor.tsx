import {
  ArrowDown,
  ArrowUp,
  GripVertical,
  ImagePlus,
  Plus,
  Save,
  Sparkles,
  ScanLine,
  Trash2,
} from 'lucide-react';
import type { FormEvent, PropsWithChildren } from 'react';
import { useEffect, useState } from 'react';

import {
  ENTRY_TYPE_LABELS,
  ENTRY_TYPES,
  type CustomField,
  type CustomFieldType,
  type EntryInput,
  type EntrySummary,
  type EntryType,
  type Folder,
  type IdentityAddress,
} from '../../shared/models';
import type { Notify } from '../types';
import { createEmptyEntry, getErrorMessage, newCustomField } from '../utils';
import { EntryIcon } from './EntryIcon';
import { SecretGenerator } from './SecretGenerator';
import { Button, Field, IconButton, InlineNotice, Modal, PasswordInput } from './ui';

interface EntryEditorProps {
  open: boolean;
  vaultId: string;
  entryId?: string;
  initial?: EntryInput;
  initialType: EntryType;
  knownFolders: Folder[];
  notify: Notify;
  onClose: () => void;
  onSaved: (entry: EntrySummary) => void;
}

type EntryMutator = (entry: EntryInput) => void;

export function EntryEditor({
  open,
  vaultId,
  entryId,
  initial,
  initialType,
  knownFolders,
  notify,
  onClose,
  onSaved,
}: EntryEditorProps) {
  const [entry, setEntry] = useState<EntryInput>(() =>
    initial ? structuredClone(initial) : createEmptyEntry(initialType),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    setEntry(initial ? structuredClone(initial) : createEmptyEntry(initialType));
    setError(null);
  }, [initial, initialType, open]);

  const mutate = (mutator: EntryMutator) => {
    setEntry((current) => {
      const next = structuredClone(current);
      mutator(next);
      return next;
    });
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!entry.title.trim()) {
      setError('Gib dem Eintrag einen Titel.');
      return;
    }
    setBusy(true);
    try {
      const saved = entryId
        ? await window.vaulta.entries.update({ vaultId, entryId, entry })
        : await window.vaulta.entries.create({ vaultId, entry });
      notify(
        'success',
        entryId ? 'Eintrag aktualisiert' : 'Eintrag sicher gespeichert',
        saved.title,
      );
      onSaved(saved);
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const replaceType = (type: EntryType) => {
    const replacement = createEmptyEntry(type);
    replacement.title = entry.title;
    replacement.favorite = entry.favorite;
    replacement.folderId = entry.folderId;
    replacement.tags = [...entry.tags];
    replacement.note = entry.note;
    replacement.customFields = structuredClone(entry.customFields);
    setEntry(replacement);
  };

  return (
    <>
      <Modal
        open={open}
        title={entryId ? 'Eintrag bearbeiten' : 'Neuen Eintrag anlegen'}
        description="Geheimnisse bleiben standardmäßig maskiert und werden verschlüsselt gespeichert."
        size="wide"
        onClose={onClose}
      >
        <form className="entry-editor" onSubmit={(event) => void submit(event)}>
          {!entryId && (
            <fieldset className="type-picker">
              <legend>Eintragstyp</legend>
              <div>
                {ENTRY_TYPES.map((type) => (
                  <button
                    type="button"
                    className={entry.data.type === type ? 'is-active' : ''}
                    aria-pressed={entry.data.type === type}
                    key={type}
                    onClick={() => replaceType(type)}
                  >
                    <EntryIcon type={type} size="small" />
                    <span>{ENTRY_TYPE_LABELS[type]}</span>
                  </button>
                ))}
              </div>
            </fieldset>
          )}

          <section className="editor-section">
            <header>
              <div>
                <EntryIcon type={entry.data.type} />
                <div>
                  <h3>Allgemein</h3>
                  <p>Titel, Organisation und Favoritenstatus</p>
                </div>
              </div>
            </header>
            <div className="form-grid form-grid--two">
              <Field label="Titel">
                <input
                  value={entry.title}
                  maxLength={160}
                  autoFocus
                  onChange={(event) => {
                    const next = event.currentTarget.value;
                    mutate((draft) => void (draft.title = next));
                  }}
                />
              </Field>
              <Field
                label="Ordner"
                {...(knownFolders.length === 0
                  ? { hint: 'In diesem Tresor wurde noch kein Ordner angelegt.' }
                  : {})}
              >
                <select
                  value={entry.folderId ?? ''}
                  onChange={(event) => {
                    const next = event.currentTarget.value || null;
                    mutate((draft) => void (draft.folderId = next));
                  }}
                >
                  <option value="">Ohne Ordner</option>
                  {knownFolders.map((folder) => (
                    <option value={folder.id} key={folder.id}>
                      {folder.name}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            <Field label="Tags" hint="Mehrere Tags mit Komma trennen.">
              <input
                value={entry.tags.join(', ')}
                placeholder="z. B. Arbeit, Wichtig"
                onChange={(event) => {
                  const next = event.currentTarget.value
                    .split(',')
                    .map((tag) => tag.trim())
                    .filter(Boolean);
                  mutate((draft) => {
                    draft.tags = next;
                  });
                }}
              />
            </Field>
            <label className="check-row check-row--compact">
              <input
                type="checkbox"
                checked={entry.favorite}
                onChange={(event) => {
                  const next = event.currentTarget.checked;
                  mutate((draft) => void (draft.favorite = next));
                }}
              />
              <span>Als Favorit markieren</span>
            </label>
          </section>

          <TypeFields
            entry={entry}
            mutate={mutate}
            notify={notify}
            onOpenGenerator={() => setGeneratorOpen(true)}
          />

          <section className="editor-section">
            <header>
              <div>
                <Plus />
                <div>
                  <h3>Eigene Felder</h3>
                  <p>Text, Geheimnis, URL, Zahl, Datum oder Ein/Aus</p>
                </div>
              </div>
              <Button
                type="button"
                icon={<Plus />}
                onClick={() =>
                  mutate((draft) => {
                    draft.customFields.push(newCustomField(draft.customFields.length));
                  })
                }
              >
                Feld hinzufügen
              </Button>
            </header>
            <div className="custom-fields">
              {entry.customFields.map((field, index) => (
                <CustomFieldEditor
                  field={field}
                  key={field.id}
                  canMoveUp={index > 0}
                  canMoveDown={index < entry.customFields.length - 1}
                  onChange={(next) =>
                    mutate((draft) => {
                      draft.customFields[index] = next;
                    })
                  }
                  onRemove={() =>
                    mutate((draft) => {
                      draft.customFields.splice(index, 1);
                      draft.customFields.forEach((item, order) => void (item.order = order));
                    })
                  }
                  onMove={(direction) =>
                    mutate((draft) => {
                      const target = index + direction;
                      if (target < 0 || target >= draft.customFields.length) return;
                      const current = draft.customFields[index];
                      const replacement = draft.customFields[target];
                      if (!current || !replacement) return;
                      draft.customFields[index] = replacement;
                      draft.customFields[target] = current;
                      draft.customFields.forEach((item, order) => void (item.order = order));
                    })
                  }
                />
              ))}
              {entry.customFields.length === 0 && (
                <p className="muted-copy">Noch keine eigenen Felder.</p>
              )}
            </div>
          </section>

          <section className="editor-section">
            <header>
              <div>
                <GripVertical />
                <div>
                  <h3>Notizen</h3>
                  <p>Sichere Markdown-Teilmenge, kein ausführbares HTML</p>
                </div>
              </div>
            </header>
            <Field label="Notiz">
              <textarea
                rows={6}
                value={entry.note}
                placeholder="Zusätzliche sichere Informationen …"
                onChange={(event) => {
                  const next = event.currentTarget.value;
                  mutate((draft) => void (draft.note = next));
                }}
              />
            </Field>
          </section>

          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <div className="entry-editor__actions">
            <Button type="button" variant="ghost" onClick={onClose}>
              Abbrechen
            </Button>
            <Button type="submit" variant="primary" icon={<Save />} busy={busy}>
              {entryId ? 'Änderungen speichern' : 'Eintrag verschlüsselt speichern'}
            </Button>
          </div>
        </form>
      </Modal>
      <SecretGenerator
        open={generatorOpen}
        notify={notify}
        onClose={() => setGeneratorOpen(false)}
        onUse={(value) => {
          mutate((draft) => {
            if (draft.data.type === 'credential') draft.data.value.password = value;
          });
          setGeneratorOpen(false);
        }}
      />
    </>
  );
}

function TypeFields({
  entry,
  mutate,
  notify,
  onOpenGenerator,
}: {
  entry: EntryInput;
  mutate: (mutator: EntryMutator) => void;
  notify: Notify;
  onOpenGenerator: () => void;
}) {
  switch (entry.data.type) {
    case 'credential': {
      const value = entry.data.value;
      const importTotp = async (source: 'file' | 'screen') => {
        try {
          const configuration = await window.vaulta.totp.importQr(source);
          if (!configuration) return;
          mutate((draft) => {
            if (draft.data.type === 'credential') draft.data.value.totp = configuration;
          });
          notify('success', 'TOTP-Konfiguration lokal importiert');
        } catch (error: unknown) {
          notify('error', 'QR-Code konnte nicht importiert werden', getErrorMessage(error));
        }
      };
      return (
        <EditorSection
          title="Zugangsdaten"
          description="Anmeldung, Webseiten und optionaler TOTP-Seed"
        >
          <div className="form-grid form-grid--two">
            <TextField
              label="Benutzername oder E-Mail"
              name="username"
              value={value.username}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credential') draft.data.value.username = next;
                })
              }
            />
            <Field label="Passwort">
              <div className="field-with-button">
                <PasswordInput
                  value={value.password}
                  name="password"
                  ariaLabel="Passwort"
                  onChange={(next) =>
                    mutate((draft) => {
                      if (draft.data.type === 'credential') draft.data.value.password = next;
                    })
                  }
                />
                <Button type="button" icon={<Sparkles />} onClick={onOpenGenerator}>
                  Generator
                </Button>
              </div>
            </Field>
          </div>
          <ListField
            label="Webseiten"
            values={value.websites}
            placeholder="https://example.de"
            onChange={(values) =>
              mutate((draft) => {
                if (draft.data.type === 'credential') draft.data.value.websites = values;
              })
            }
          />
          <ListField
            label="App-Bezeichnungen"
            values={value.appNames}
            placeholder="z. B. Desktop-App"
            onChange={(values) =>
              mutate((draft) => {
                if (draft.data.type === 'credential') draft.data.value.appNames = values;
              })
            }
          />
          <label className="check-row">
            <input
              type="checkbox"
              checked={Boolean(value.totp)}
              onChange={(event) => {
                const checked = event.currentTarget.checked;
                mutate((draft) => {
                  if (draft.data.type !== 'credential') return;
                  if (checked) {
                    draft.data.value.totp = {
                      secret: '',
                      issuer: '',
                      account: '',
                      algorithm: 'SHA1',
                      digits: 6,
                      period: 30,
                    };
                  } else {
                    delete draft.data.value.totp;
                  }
                });
              }}
            />
            <span>
              <strong>TOTP-Code erzeugen</strong>
              <small>Seed bleibt verschlüsselt im Eintrag.</small>
            </span>
          </label>
          {value.totp && (
            <div className="inset-form">
              <div className="subsection-heading">
                <div>
                  <h4>TOTP-Konfiguration</h4>
                  <p>QR-Codes werden ausschließlich lokal ausgewertet.</p>
                </div>
                <div className="button-row">
                  <Button
                    type="button"
                    icon={<ImagePlus />}
                    onClick={() => void importTotp('file')}
                  >
                    Aus Bilddatei
                  </Button>
                  <Button
                    type="button"
                    icon={<ScanLine />}
                    onClick={() => void importTotp('screen')}
                  >
                    Bildschirmbereich
                  </Button>
                </div>
              </div>
              <div className="form-grid form-grid--two">
                <Field label="TOTP-Seed">
                  <PasswordInput
                    value={value.totp.secret}
                    onChange={(next) =>
                      mutate((draft) => {
                        if (draft.data.type === 'credential' && draft.data.value.totp)
                          draft.data.value.totp.secret = next.replace(/\s/gu, '').toUpperCase();
                      })
                    }
                  />
                </Field>
                <TextField
                  label="Aussteller"
                  value={value.totp.issuer}
                  onChange={(next) =>
                    mutate((draft) => {
                      if (draft.data.type === 'credential' && draft.data.value.totp)
                        draft.data.value.totp.issuer = next;
                    })
                  }
                />
                <TextField
                  label="Konto"
                  value={value.totp.account}
                  onChange={(next) =>
                    mutate((draft) => {
                      if (draft.data.type === 'credential' && draft.data.value.totp)
                        draft.data.value.totp.account = next;
                    })
                  }
                />
                <Field label="Algorithmus">
                  <select
                    value={value.totp.algorithm}
                    onChange={(event) => {
                      const next = event.currentTarget.value as 'SHA1' | 'SHA256' | 'SHA512';
                      mutate((draft) => {
                        if (draft.data.type === 'credential' && draft.data.value.totp)
                          draft.data.value.totp.algorithm = next;
                      });
                    }}
                  >
                    <option>SHA1</option>
                    <option>SHA256</option>
                    <option>SHA512</option>
                  </select>
                </Field>
                <NumberInput
                  label="Stellen"
                  min={6}
                  max={8}
                  value={value.totp.digits}
                  onChange={(next) =>
                    mutate((draft) => {
                      if (draft.data.type === 'credential' && draft.data.value.totp)
                        draft.data.value.totp.digits = next <= 6 ? 6 : 8;
                    })
                  }
                />
                <NumberInput
                  label="Zeitraum (Sekunden)"
                  min={15}
                  max={120}
                  value={value.totp.period}
                  onChange={(next) =>
                    mutate((draft) => {
                      if (draft.data.type === 'credential' && draft.data.value.totp)
                        draft.data.value.totp.period = next;
                    })
                  }
                />
              </div>
            </div>
          )}
        </EditorSection>
      );
    }
    case 'secure-note':
      return (
        <EditorSection
          title="Sichere Notiz"
          description="Formatierbarer Inhalt in sicherem Markdown"
        >
          <Field label="Inhalt">
            <textarea
              rows={12}
              value={entry.data.value.markdown}
              onChange={(event) => {
                const next = event.currentTarget.value;
                mutate((draft) => {
                  if (draft.data.type === 'secure-note') draft.data.value.markdown = next;
                });
              }}
            />
          </Field>
        </EditorSection>
      );
    case 'credit-card': {
      const value = entry.data.value;
      return (
        <EditorSection title="Kreditkarte" description="Kartendaten und Rechnungsinformationen">
          <div className="form-grid form-grid--two">
            <TextField
              label="Kartenname"
              value={value.cardName}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.cardName = next;
                })
              }
            />
            <TextField
              label="Karteninhaber"
              value={value.cardholder}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.cardholder = next;
                })
              }
            />
            <SecretField
              label="Kartennummer"
              value={value.number}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.number = next;
                })
              }
            />
            <TextField
              label="Herausgeber"
              value={value.issuer}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.issuer = next;
                })
              }
            />
            <NumberInput
              label="Ablaufmonat"
              min={1}
              max={12}
              value={value.expiryMonth}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.expiryMonth = next;
                })
              }
            />
            <NumberInput
              label="Ablaufjahr"
              min={new Date().getFullYear()}
              max={2200}
              value={value.expiryYear}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.expiryYear = next;
                })
              }
            />
            <SecretField
              label="CVC/CVV"
              value={value.cvc}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.cvc = next;
                })
              }
            />
            <SecretField
              label="PIN"
              value={value.pin}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.pin = next;
                })
              }
            />
            <TextField
              label="Kartentyp"
              value={value.cardType}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.cardType = next;
                })
              }
            />
            <TextField
              label="Service-Telefon"
              value={value.servicePhone}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.servicePhone = next;
                })
              }
            />
            <TextField
              label="Webseite"
              value={value.website}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.website = next;
                })
              }
            />
          </div>
          <Field label="Rechnungsadresse">
            <textarea
              rows={3}
              value={value.billingAddress}
              onChange={(event) => {
                const next = event.currentTarget.value;
                mutate((draft) => {
                  if (draft.data.type === 'credit-card') draft.data.value.billingAddress = next;
                });
              }}
            />
          </Field>
        </EditorSection>
      );
    }
    case 'identity': {
      const value = entry.data.value;
      return (
        <EditorSection
          title="Identität"
          description="Personen-, Kontakt- und optionale Ausweisdaten"
        >
          <div className="form-grid form-grid--three">
            <TextField
              label="Anrede"
              value={value.salutation}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.salutation = next;
                })
              }
            />
            <TextField
              label="Vorname"
              value={value.firstName}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.firstName = next;
                })
              }
            />
            <TextField
              label="Weitere Vornamen"
              value={value.middleName}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.middleName = next;
                })
              }
            />
            <TextField
              label="Nachname"
              value={value.lastName}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.lastName = next;
                })
              }
            />
            <TextField
              label="Geburtsdatum"
              type="date"
              value={value.birthDate}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.birthDate = next;
                })
              }
            />
          </div>
          <ListField
            label="E-Mail-Adressen"
            values={value.emails}
            placeholder="name@example.de"
            onChange={(values) =>
              mutate((draft) => {
                if (draft.data.type === 'identity') draft.data.value.emails = values;
              })
            }
          />
          <ListField
            label="Telefonnummern"
            values={value.phones}
            placeholder="+49 …"
            onChange={(values) =>
              mutate((draft) => {
                if (draft.data.type === 'identity') draft.data.value.phones = values;
              })
            }
          />
          <div className="form-grid form-grid--three">
            <SecretField
              label="Ausweisnummer"
              value={value.idNumber}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.idNumber = next;
                })
              }
            />
            <SecretField
              label="Reisepassnummer"
              value={value.passportNumber}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.passportNumber = next;
                })
              }
            />
            <SecretField
              label="Steuernummer"
              value={value.taxNumber}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'identity') draft.data.value.taxNumber = next;
                })
              }
            />
          </div>
          <AddressEditor
            addresses={value.addresses}
            onChange={(addresses) =>
              mutate((draft) => {
                if (draft.data.type === 'identity') draft.data.value.addresses = addresses;
              })
            }
          />
        </EditorSection>
      );
    }
    case 'wifi': {
      const value = entry.data.value;
      return (
        <EditorSection title="WLAN-Zugang" description="Netzwerkdaten und Routerzugang">
          <div className="form-grid form-grid--two">
            <TextField
              label="SSID"
              value={value.ssid}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'wifi') draft.data.value.ssid = next;
                })
              }
            />
            <Field label="Sicherheitsart">
              <select
                value={value.security}
                onChange={(event) => {
                  const next = event.currentTarget.value as typeof value.security;
                  mutate((draft) => {
                    if (draft.data.type === 'wifi') draft.data.value.security = next;
                  });
                }}
              >
                {['WPA3', 'WPA2', 'WPA', 'WEP', 'Offen', 'Andere'].map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </Field>
            <SecretField
              label="WLAN-Passwort"
              value={value.password}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'wifi') draft.data.value.password = next;
                })
              }
            />
            <TextField
              label="Router-Adresse"
              value={value.routerAddress}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'wifi') draft.data.value.routerAddress = next;
                })
              }
            />
            <TextField
              label="Router-Benutzername"
              value={value.routerUsername}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'wifi') draft.data.value.routerUsername = next;
                })
              }
            />
          </div>
          <label className="check-row check-row--compact">
            <input
              type="checkbox"
              checked={value.hidden}
              onChange={(event) => {
                const next = event.currentTarget.checked;
                mutate((draft) => {
                  if (draft.data.type === 'wifi') draft.data.value.hidden = next;
                });
              }}
            />
            <span>Verstecktes Netzwerk</span>
          </label>
        </EditorSection>
      );
    }
    case 'software-license': {
      const value = entry.data.value;
      return (
        <EditorSection title="Softwarelizenz" description="Produkt-, Lizenz- und Kaufdaten">
          <div className="form-grid form-grid--three">
            <TextField
              label="Produkt"
              value={value.product}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.product = next;
                })
              }
            />
            <TextField
              label="Hersteller"
              value={value.manufacturer}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.manufacturer = next;
                })
              }
            />
            <TextField
              label="Version"
              value={value.version}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.version = next;
                })
              }
            />
            <SecretField
              label="Lizenzschlüssel"
              value={value.licenseKey}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.licenseKey = next;
                })
              }
            />
            <TextField
              label="Lizenziert für"
              value={value.licensedTo}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.licensedTo = next;
                })
              }
            />
            <TextField
              label="Bestellnummer"
              value={value.orderNumber}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.orderNumber = next;
                })
              }
            />
            <TextField
              label="Kaufdatum"
              type="date"
              value={value.purchaseDate}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.purchaseDate = next;
                })
              }
            />
            <TextField
              label="Aktivierungsdatum"
              type="date"
              value={value.activationDate}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license')
                    draft.data.value.activationDate = next;
                })
              }
            />
            <TextField
              label="Ablaufdatum"
              type="date"
              value={value.expiryDate}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.expiryDate = next;
                })
              }
            />
            <TextField
              label="Download-Adresse"
              value={value.downloadUrl}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.downloadUrl = next;
                })
              }
            />
            <TextField
              label="Kaufpreis"
              value={value.purchasePrice}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'software-license') draft.data.value.purchasePrice = next;
                })
              }
            />
          </div>
        </EditorSection>
      );
    }
    case 'ssh-key': {
      const value = entry.data.value;
      return (
        <EditorSection
          title="SSH-Schlüssel"
          description="Verbindung und kryptografisches Schlüsselmaterial"
        >
          <InlineNotice kind="warning">
            Der private Schlüssel bleibt maskiert und erfordert für einen Export eine bewusste
            Bestätigung.
          </InlineNotice>
          <div className="form-grid form-grid--three">
            <TextField
              label="Host"
              value={value.host}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.host = next;
                })
              }
            />
            <NumberInput
              label="Port"
              min={1}
              max={65535}
              value={value.port}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.port = next;
                })
              }
            />
            <TextField
              label="Benutzername"
              value={value.username}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.username = next;
                })
              }
            />
            <TextField
              label="Schlüsseltyp"
              value={value.keyType}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.keyType = next;
                })
              }
            />
            <TextField
              label="Fingerabdruck"
              value={value.fingerprint}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.fingerprint = next;
                })
              }
            />
            <SecretField
              label="Passphrase"
              value={value.passphrase}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.passphrase = next;
                })
              }
            />
          </div>
          <Field label="Öffentlicher Schlüssel">
            <textarea
              rows={5}
              spellCheck={false}
              value={value.publicKey}
              onChange={(event) => {
                const next = event.currentTarget.value;
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.publicKey = next;
                });
              }}
            />
          </Field>
          <Field label="Privater Schlüssel">
            <PasswordTextarea
              value={value.privateKey}
              onChange={(next) =>
                mutate((draft) => {
                  if (draft.data.type === 'ssh-key') draft.data.value.privateKey = next;
                })
              }
            />
          </Field>
        </EditorSection>
      );
    }
    case 'file':
      return (
        <EditorSection
          title="Datei oder Dokument"
          description="Anhänge können nach dem ersten Speichern hinzugefügt werden"
        >
          <Field label="Beschreibung">
            <textarea
              rows={5}
              value={entry.data.value.description}
              onChange={(event) => {
                const next = event.currentTarget.value;
                mutate((draft) => {
                  if (draft.data.type === 'file') draft.data.value.description = next;
                });
              }}
            />
          </Field>
          <InlineNotice kind="info">
            Dateien werden in gestreamten, authentifizierten Chunks verschlüsselt. Das Größenlimit
            wird vor dem Hinzufügen geprüft.
          </InlineNotice>
        </EditorSection>
      );
    case 'custom':
      return (
        <EditorSection
          title="Sonstiger Eintrag"
          description="Freier Basistyp für beliebige eigene Felder"
        >
          <Field label="Beschreibung">
            <textarea
              rows={5}
              value={entry.data.value.description}
              onChange={(event) => {
                const next = event.currentTarget.value;
                mutate((draft) => {
                  if (draft.data.type === 'custom') draft.data.value.description = next;
                });
              }}
            />
          </Field>
        </EditorSection>
      );
  }
}

function EditorSection({
  title,
  description,
  children,
}: PropsWithChildren<{ title: string; description: string }>) {
  return (
    <section className="editor-section">
      <header>
        <div>
          <Sparkles />
          <div>
            <h3>{title}</h3>
            <p>{description}</p>
          </div>
        </div>
      </header>
      {children}
    </section>
  );
}

function TextField({
  label,
  name,
  value,
  type = 'text',
  onChange,
}: {
  label: string;
  name?: string;
  value: string;
  type?: string;
  onChange: (value: string) => void;
}) {
  return (
    <Field label={label}>
      <input
        type={type}
        name={name}
        value={value}
        aria-label={label}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </Field>
  );
}

function SecretField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Field label={label}>
      <PasswordInput value={value} onChange={onChange} />
    </Field>
  );
}

function NumberInput({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <Field label={label}>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </Field>
  );
}

function ListField({
  label,
  values,
  placeholder,
  onChange,
}: {
  label: string;
  values: string[];
  placeholder: string;
  onChange: (values: string[]) => void;
}) {
  return (
    <Field label={label} hint="Ein Wert pro Zeile">
      <textarea
        rows={3}
        value={values.join('\n')}
        placeholder={placeholder}
        onChange={(event) =>
          onChange(
            event.currentTarget.value
              .split('\n')
              .map((value) => value.trim())
              .filter(Boolean),
          )
        }
      />
    </Field>
  );
}

function PasswordTextarea({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="password-textarea">
      <textarea
        className={visible ? '' : 'is-masked'}
        rows={8}
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
      <Button type="button" variant="ghost" onClick={() => setVisible((current) => !current)}>
        {visible ? 'Ausblenden' : 'Bewusst anzeigen'}
      </Button>
    </div>
  );
}

function CustomFieldEditor({
  field,
  canMoveUp,
  canMoveDown,
  onChange,
  onMove,
  onRemove,
}: {
  field: CustomField;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onChange: (field: CustomField) => void;
  onMove: (direction: -1 | 1) => void;
  onRemove: () => void;
}) {
  const set = <Key extends keyof CustomField>(key: Key, value: CustomField[Key]) =>
    onChange({ ...field, [key]: value });
  const inputValue = typeof field.value === 'boolean' ? '' : String(field.value);
  return (
    <div className="custom-field-editor">
      <div
        className="field-order-controls"
        aria-label={`Reihenfolge für ${field.label || 'eigenes Feld'}`}
      >
        <IconButton
          type="button"
          label="Eigenes Feld nach oben verschieben"
          disabled={!canMoveUp}
          onClick={() => onMove(-1)}
        >
          <ArrowUp />
        </IconButton>
        <IconButton
          type="button"
          label="Eigenes Feld nach unten verschieben"
          disabled={!canMoveDown}
          onClick={() => onMove(1)}
        >
          <ArrowDown />
        </IconButton>
      </div>
      <Field label="Bezeichnung">
        <input value={field.label} onChange={(event) => set('label', event.currentTarget.value)} />
      </Field>
      <Field label="Typ">
        <select
          value={field.type}
          onChange={(event) => {
            const type = event.currentTarget.value as CustomFieldType;
            onChange({
              ...field,
              type,
              value: type === 'boolean' ? false : '',
              secret: type === 'secret',
            });
          }}
        >
          {(
            [
              ['text', 'Text'],
              ['secret', 'Geheimnis'],
              ['url', 'URL'],
              ['number', 'Zahl'],
              ['date', 'Datum'],
              ['boolean', 'Ein/Aus'],
            ] as Array<[CustomFieldType, string]>
          ).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Wert">
        {field.type === 'boolean' ? (
          <label className="switch">
            <input
              type="checkbox"
              checked={Boolean(field.value)}
              onChange={(event) => set('value', event.currentTarget.checked)}
            />
            <span />
          </label>
        ) : field.secret ? (
          <PasswordInput
            value={inputValue}
            onChange={(value) => set('value', field.type === 'number' ? Number(value) : value)}
          />
        ) : (
          <input
            type={field.type === 'number' ? 'number' : field.type === 'date' ? 'date' : 'text'}
            value={inputValue}
            onChange={(event) =>
              set(
                'value',
                field.type === 'number'
                  ? Number(event.currentTarget.value)
                  : event.currentTarget.value,
              )
            }
          />
        )}
      </Field>
      <div className="custom-field-options">
        <label className="check-row check-row--tiny">
          <input
            type="checkbox"
            checked={field.secret}
            disabled={field.type === 'secret'}
            onChange={(event) =>
              onChange({
                ...field,
                secret: event.currentTarget.checked,
                searchable: event.currentTarget.checked ? false : field.searchable,
              })
            }
          />
          <span>Maskieren</span>
        </label>
        <label className="check-row check-row--tiny">
          <input
            type="checkbox"
            checked={field.searchable}
            disabled={field.secret}
            onChange={(event) => set('searchable', event.currentTarget.checked)}
          />
          <span>Durchsuchbar</span>
        </label>
      </div>
      <IconButton type="button" label="Eigenes Feld entfernen" onClick={onRemove}>
        <Trash2 />
      </IconButton>
    </div>
  );
}

function AddressEditor({
  addresses,
  onChange,
}: {
  addresses: IdentityAddress[];
  onChange: (addresses: IdentityAddress[]) => void;
}) {
  const add = () =>
    onChange([
      ...addresses,
      {
        id: crypto.randomUUID(),
        label: 'Privat',
        street: '',
        postalCode: '',
        city: '',
        region: '',
        country: '',
      },
    ]);
  const update = (index: number, key: keyof IdentityAddress, value: string) =>
    onChange(
      addresses.map((address, current) =>
        current === index ? { ...address, [key]: value } : address,
      ),
    );
  return (
    <div className="address-editor">
      <div className="subsection-heading">
        <h4>Adressen</h4>
        <Button type="button" icon={<Plus />} onClick={add}>
          Adresse hinzufügen
        </Button>
      </div>
      {addresses.map((address, index) => (
        <div className="inset-form" key={address.id}>
          <div className="form-grid form-grid--three">
            <TextField
              label="Bezeichnung"
              value={address.label}
              onChange={(value) => update(index, 'label', value)}
            />
            <TextField
              label="Straße und Hausnummer"
              value={address.street}
              onChange={(value) => update(index, 'street', value)}
            />
            <TextField
              label="PLZ"
              value={address.postalCode}
              onChange={(value) => update(index, 'postalCode', value)}
            />
            <TextField
              label="Ort"
              value={address.city}
              onChange={(value) => update(index, 'city', value)}
            />
            <TextField
              label="Region"
              value={address.region}
              onChange={(value) => update(index, 'region', value)}
            />
            <TextField
              label="Land"
              value={address.country}
              onChange={(value) => update(index, 'country', value)}
            />
          </div>
          <Button
            type="button"
            variant="ghost"
            icon={<Trash2 />}
            onClick={() => onChange(addresses.filter((_, current) => current !== index))}
          >
            Adresse entfernen
          </Button>
        </div>
      ))}
    </div>
  );
}
