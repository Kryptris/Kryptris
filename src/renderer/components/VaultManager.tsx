import { Check, Database, Pencil, Plus, Save, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';

import type { AppState, VaultSummary } from '../../shared/models';
import type { Notify } from '../types';
import { formatDate, getErrorMessage } from '../utils';
import { Button, Field, IconButton, InlineNotice, Modal, PasswordConfirm } from './ui';

const COLORS = ['#25d2c8', '#6f5cf4', '#4f8df7', '#73d86c', '#f2b92f', '#eb7fa7', '#a780f2'];

export function VaultManager({
  open,
  state,
  notify,
  onClose,
  onStateChange,
}: {
  open: boolean;
  state: AppState;
  notify: Notify;
  onClose: () => void;
  onStateChange: (state: AppState) => void;
}) {
  const [editing, setEditing] = useState<VaultSummary | 'new' | null>(null);
  const [name, setName] = useState('');
  const [color, setColor] = useState(COLORS[0] ?? '#25d2c8');
  const [deleteVault, setDeleteVault] = useState<VaultSummary | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      setEditing(null);
      setDeleteVault(null);
    }
  }, [open]);

  const startEdit = (vault: VaultSummary | 'new') => {
    setEditing(vault);
    setName(vault === 'new' ? '' : vault.name);
    setColor(vault === 'new' ? (COLORS[0] ?? '#25d2c8') : vault.color);
  };

  const refresh = async () => onStateChange(await window.vaulta.system.getState());

  const save = async () => {
    if (!editing || !name.trim()) return;
    setBusy(true);
    try {
      if (editing === 'new') {
        await window.vaulta.vaults.create({ name: name.trim(), color });
        notify('success', 'Tresor erstellt', name.trim());
      } else {
        await window.vaulta.vaults.update({ id: editing.id, name: name.trim(), color });
        notify('success', 'Tresor aktualisiert', name.trim());
      }
      await refresh();
      setEditing(null);
    } catch (error: unknown) {
      notify('error', 'Tresor konnte nicht gespeichert werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Modal
        open={open}
        title="Tresore verwalten"
        description="Jeder Tresor besitzt eine eigene verschlüsselte Containerdatei und kryptografisch getrennte Schlüssel."
        size="large"
        onClose={onClose}
      >
        <div className="vault-manager">
          <div className="vault-manager__toolbar">
            <InlineNotice kind="info">
              Ein Profil kann mehrere getrennte Tresore enthalten, zum Beispiel Privat, Arbeit oder
              Archiv.
            </InlineNotice>
            <Button variant="primary" icon={<Plus />} onClick={() => startEdit('new')}>
              Neuer Tresor
            </Button>
          </div>
          {editing && (
            <section className="inset-form">
              <div className="form-grid form-grid--two">
                <Field label="Tresorname">
                  <input
                    value={name}
                    autoFocus
                    onChange={(event) => setName(event.currentTarget.value)}
                  />
                </Field>
                <Field label="Farbe">
                  <div className="color-picker">
                    {COLORS.map((value) => (
                      <button
                        type="button"
                        aria-label={`Farbe ${value}`}
                        aria-pressed={color === value}
                        className={color === value ? 'is-active' : ''}
                        style={{ background: value }}
                        key={value}
                        onClick={() => setColor(value)}
                      >
                        {color === value && <Check />}
                      </button>
                    ))}
                  </div>
                </Field>
              </div>
              <div className="modal__inline-actions">
                <Button variant="ghost" onClick={() => setEditing(null)}>
                  Abbrechen
                </Button>
                <Button
                  variant="primary"
                  icon={<Save />}
                  busy={busy}
                  disabled={!name.trim()}
                  onClick={() => void save()}
                >
                  Tresor speichern
                </Button>
              </div>
            </section>
          )}
          <div className="vault-manager__list">
            {state.vaults.map((vault) => (
              <article
                className={state.activeVaultId === vault.id ? 'is-active' : ''}
                key={vault.id}
              >
                <span className="vault-dot" style={{ background: vault.color }}>
                  <Database />
                </span>
                <div>
                  <strong>{vault.name}</strong>
                  <small>
                    {String(vault.entryCount)} Einträge · {String(vault.deletedCount)} im Papierkorb
                    · geändert {formatDate(vault.updatedAt)}
                  </small>
                </div>
                {state.activeVaultId === vault.id && (
                  <em className="status-pill status-pill--good">Geöffnet</em>
                )}
                <IconButton label={`${vault.name} bearbeiten`} onClick={() => startEdit(vault)}>
                  <Pencil />
                </IconButton>
                <IconButton
                  label={`${vault.name} löschen`}
                  disabled={state.vaults.length <= 1}
                  onClick={() => setDeleteVault(vault)}
                >
                  <Trash2 />
                </IconButton>
              </article>
            ))}
          </div>
        </div>
      </Modal>
      <PasswordConfirm
        open={Boolean(deleteVault)}
        title="Tresor endgültig löschen?"
        description={`Der Tresor „${deleteVault?.name ?? ''}“ und sein kryptografischer Schlüssel werden endgültig gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.`}
        danger
        confirmationLabel="Tresor endgültig löschen"
        busy={busy}
        onClose={() => setDeleteVault(null)}
        onConfirm={async (masterPassword) => {
          if (!deleteVault) return;
          setBusy(true);
          try {
            await window.vaulta.vaults.delete({ id: deleteVault.id, masterPassword });
            notify('success', 'Tresor gelöscht', deleteVault.name);
            setDeleteVault(null);
            await refresh();
          } catch (error: unknown) {
            notify('error', 'Tresor konnte nicht gelöscht werden', getErrorMessage(error));
          } finally {
            setBusy(false);
          }
        }}
      />
    </>
  );
}
