import { Check, FolderClosed, Pencil, Plus, Save, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';

import type { Folder } from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Button, EmptyState, Field, IconButton, InlineNotice, Modal } from './ui';

const COLORS = ['#25d2c8', '#6f5cf4', '#4f8df7', '#73d86c', '#f2b92f', '#eb7fa7'];

export function FolderManager({
  open,
  vaultId,
  folders,
  notify,
  onClose,
  onChanged,
}: {
  open: boolean;
  vaultId: string;
  folders: Folder[];
  notify: Notify;
  onClose: () => void;
  onChanged: () => Promise<void>;
}) {
  const [editing, setEditing] = useState<Folder | 'new' | null>(null);
  const [name, setName] = useState('');
  const [color, setColor] = useState(COLORS[0] ?? '#25d2c8');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) setEditing(null);
  }, [open]);

  const begin = (folder: Folder | 'new') => {
    setEditing(folder);
    setName(folder === 'new' ? '' : folder.name);
    setColor(folder === 'new' ? (COLORS[0] ?? '#25d2c8') : folder.color);
  };

  const save = async () => {
    if (!editing || !name.trim()) return;
    setBusy(true);
    try {
      if (editing === 'new') {
        await window.vaulta.vaults.createFolder({ vaultId, name: name.trim(), color });
        notify('success', 'Ordner erstellt', name.trim());
      } else {
        await window.vaulta.vaults.updateFolder({
          vaultId,
          id: editing.id,
          name: name.trim(),
          color,
        });
        notify('success', 'Ordner umbenannt', name.trim());
      }
      setEditing(null);
      await onChanged();
    } catch (error: unknown) {
      notify('error', 'Ordner konnte nicht gespeichert werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (folder: Folder) => {
    setBusy(true);
    try {
      await window.vaulta.vaults.deleteFolder({ vaultId, id: folder.id });
      notify('success', 'Ordner gelöscht', 'Zugeordnete Einträge bleiben im Tresor erhalten.');
      await onChanged();
    } catch (error: unknown) {
      notify('error', 'Ordner konnte nicht gelöscht werden', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Ordner verwalten"
      description="Ordner organisieren Einträge innerhalb des aktiven Tresors. Tags bleiben davon unabhängig."
      onClose={onClose}
    >
      <div className="folder-manager stack">
        <div className="folder-manager__toolbar">
          <InlineNotice kind="info">
            Ein Eintrag kann genau einem Ordner und beliebig vielen Tags zugeordnet werden.
          </InlineNotice>
          <Button variant="primary" icon={<Plus />} onClick={() => begin('new')}>
            Neuer Ordner
          </Button>
        </div>
        {editing && (
          <section className="inset-form">
            <Field label="Ordnername">
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
                    key={value}
                    style={{ background: value }}
                    className={color === value ? 'is-active' : ''}
                    aria-label={`Farbe ${value}`}
                    aria-pressed={color === value}
                    onClick={() => setColor(value)}
                  >
                    {color === value && <Check />}
                  </button>
                ))}
              </div>
            </Field>
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
                Speichern
              </Button>
            </div>
          </section>
        )}
        {folders.length === 0 ? (
          <EmptyState
            title="Noch keine Ordner"
            description="Erstelle den ersten Ordner für diesen Tresor."
          />
        ) : (
          <div className="folder-list">
            {folders.map((folder) => (
              <article key={folder.id}>
                <span style={{ background: folder.color }}>
                  <FolderClosed />
                </span>
                <strong>{folder.name}</strong>
                <IconButton label={`${folder.name} umbenennen`} onClick={() => begin(folder)}>
                  <Pencil />
                </IconButton>
                <IconButton
                  label={`${folder.name} löschen`}
                  disabled={busy}
                  onClick={() => void remove(folder)}
                >
                  <Trash2 />
                </IconButton>
              </article>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}
