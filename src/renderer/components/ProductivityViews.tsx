import {
  ArrowDown,
  ArrowUp,
  Check,
  Copy,
  FolderInput,
  Heart,
  HeartOff,
  Keyboard,
  MoveRight,
  Search,
  Tags,
  Trash2,
  Undo2,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';

import type {
  BatchEntryAction,
  Folder,
  SavedView,
  TagSummary,
  VaultSummary,
} from '../../shared/models';
import { Button, Field, IconButton, InlineNotice, Modal, PasswordInput } from './ui';

export function BatchToolbar({
  selectedCount,
  trashView,
  folders,
  vaults,
  activeVaultId,
  busy,
  onRun,
  onClear,
}: {
  selectedCount: number;
  trashView: boolean;
  folders: Folder[];
  vaults: VaultSummary[];
  activeVaultId: string;
  busy: boolean;
  onRun: (action: BatchEntryAction) => Promise<boolean>;
  onClear: () => void;
}) {
  const [tagMode, setTagMode] = useState<'tags-add' | 'tags-remove' | null>(null);
  const [tagValue, setTagValue] = useState('');
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purgePassword, setPurgePassword] = useState('');
  const [purgeCount, setPurgeCount] = useState('');
  const [transferMode, setTransferMode] = useState<'copy-to-vault' | 'move-to-vault' | null>(null);
  const [targetVaultId, setTargetVaultId] = useState('');
  const targetVaults = vaults.filter((vault) => vault.id !== activeVaultId);
  if (selectedCount === 0) return null;

  const closeTags = () => {
    setTagMode(null);
    setTagValue('');
  };

  const closePurge = () => {
    setPurgeOpen(false);
    setPurgePassword('');
    setPurgeCount('');
  };

  const closeTransfer = () => {
    setTransferMode(null);
    setTargetVaultId('');
  };

  const runTags = async () => {
    if (tagMode === null) return;
    const tags = tagValue
      .split(',')
      .map((tag) => tag.trim())
      .filter(Boolean);
    if (tags.length === 0) return;
    if (!(await onRun({ type: tagMode, tags }))) return;
    closeTags();
  };

  const purge = async () => {
    const succeeded = await onRun({
      type: 'purge',
      masterPassword: purgePassword,
      confirmationCount: Number.parseInt(purgeCount, 10),
    });
    if (!succeeded) return;
    closePurge();
  };

  const openTransfer = (mode: 'copy-to-vault' | 'move-to-vault') => {
    setTransferMode(mode);
    setTargetVaultId(targetVaults[0]?.id ?? '');
  };

  const transfer = async () => {
    if (transferMode === null || targetVaultId.length === 0) return;
    if (!(await onRun({ type: transferMode, targetVaultId }))) return;
    closeTransfer();
  };

  return (
    <>
      <section className="batch-toolbar" aria-label="Batch-Aktionen" aria-live="polite">
        <strong>{String(selectedCount)} ausgewählt</strong>
        {!trashView && (
          <>
            <Button
              icon={<Heart />}
              disabled={busy}
              onClick={() => void onRun({ type: 'favorite', value: true })}
            >
              Favorisieren
            </Button>
            <Button
              icon={<HeartOff />}
              disabled={busy}
              onClick={() => void onRun({ type: 'favorite', value: false })}
            >
              Favorit entfernen
            </Button>
            <Button icon={<Tags />} disabled={busy} onClick={() => setTagMode('tags-add')}>
              Tags hinzufügen
            </Button>
            <Button icon={<Tags />} disabled={busy} onClick={() => setTagMode('tags-remove')}>
              Tags entfernen
            </Button>
            <label className="batch-folder">
              <FolderInput aria-hidden="true" />
              <span className="sr-only">Ordner zuweisen</span>
              <select
                aria-label="Ordner für Auswahl festlegen"
                defaultValue=""
                disabled={busy}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  if (value === '') return;
                  void onRun({ type: 'folder-set', folderId: value === '__none__' ? null : value });
                  event.currentTarget.value = '';
                }}
              >
                <option value="">Ordner …</option>
                <option value="__none__">Ohne Ordner</option>
                {folders.map((folder) => (
                  <option value={folder.id} key={folder.id}>
                    {folder.name}
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
        {trashView ? (
          <>
            <Button
              icon={<Undo2 />}
              disabled={busy}
              onClick={() => void onRun({ type: 'restore' })}
            >
              Wiederherstellen
            </Button>
            <Button
              icon={<Trash2 />}
              variant="danger"
              disabled={busy}
              onClick={() => setPurgeOpen(true)}
            >
              Endgültig löschen
            </Button>
          </>
        ) : (
          <>
            <Button icon={<Trash2 />} disabled={busy} onClick={() => void onRun({ type: 'trash' })}>
              In Papierkorb
            </Button>
            {targetVaults.length > 0 && (
              <>
                <Button
                  icon={<Copy />}
                  disabled={busy}
                  onClick={() => openTransfer('copy-to-vault')}
                >
                  In Tresor kopieren
                </Button>
                <Button
                  icon={<MoveRight />}
                  disabled={busy}
                  onClick={() => openTransfer('move-to-vault')}
                >
                  In Tresor verschieben
                </Button>
              </>
            )}
          </>
        )}
        <IconButton label="Auswahl aufheben" disabled={busy} onClick={onClear}>
          <X />
        </IconButton>
      </section>

      <Modal
        open={tagMode !== null}
        title={tagMode === 'tags-add' ? 'Tags hinzufügen' : 'Tags entfernen'}
        description={`Die Aktion gilt exakt für ${String(selectedCount)} ausgewählte Einträge.`}
        size="small"
        onClose={closeTags}
        footer={
          <>
            <Button variant="ghost" onClick={closeTags}>
              Abbrechen
            </Button>
            <Button variant="primary" busy={busy} onClick={() => void runTags()}>
              Anwenden
            </Button>
          </>
        }
      >
        <Field label="Tags" hint="Mehrere Tags mit Komma trennen.">
          <input
            autoFocus
            value={tagValue}
            onChange={(event) => setTagValue(event.currentTarget.value)}
          />
        </Field>
      </Modal>

      <Modal
        open={purgeOpen}
        title="Auswahl endgültig löschen"
        description="Diese Aktion kann nicht rückgängig gemacht werden. Bestätige Master-Passwort und Anzahl."
        size="small"
        onClose={closePurge}
      >
        <div className="stack">
          <InlineNotice kind="warning">
            Es werden genau {String(selectedCount)} Einträge endgültig gelöscht.
          </InlineNotice>
          <Field label={`Anzahl eingeben (${String(selectedCount)})`}>
            <input
              inputMode="numeric"
              value={purgeCount}
              onChange={(event) => setPurgeCount(event.currentTarget.value)}
            />
          </Field>
          <Field label="Master-Passwort">
            <PasswordInput
              value={purgePassword}
              onChange={setPurgePassword}
              autoComplete="current-password"
            />
          </Field>
          <div className="modal__inline-actions">
            <Button variant="ghost" onClick={closePurge}>
              Abbrechen
            </Button>
            <Button
              variant="danger"
              busy={busy}
              disabled={purgeCount !== String(selectedCount) || purgePassword.length === 0}
              onClick={() => void purge()}
            >
              Endgültig löschen
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        open={transferMode !== null}
        title={
          transferMode === 'copy-to-vault'
            ? 'In anderen Tresor kopieren'
            : 'In anderen Tresor verschieben'
        }
        description={`Die Aktion gilt exakt für ${String(selectedCount)} ausgewählte Einträge.`}
        size="small"
        onClose={closeTransfer}
        footer={
          <>
            <Button variant="ghost" onClick={closeTransfer}>
              Abbrechen
            </Button>
            <Button
              variant="primary"
              busy={busy}
              disabled={targetVaultId.length === 0}
              onClick={() => void transfer()}
            >
              {transferMode === 'copy-to-vault' ? 'Kopieren' : 'Verschieben'}
            </Button>
          </>
        }
      >
        <Field label="Zieltresor">
          <select
            value={targetVaultId}
            onChange={(event) => setTargetVaultId(event.currentTarget.value)}
          >
            {targetVaults.map((vault) => (
              <option value={vault.id} key={vault.id}>
                {vault.name}
              </option>
            ))}
          </select>
        </Field>
      </Modal>
    </>
  );
}

export function SavedViewManager({
  open,
  views,
  onClose,
  onRename,
  onReorder,
  onDelete,
}: {
  open: boolean;
  views: SavedView[];
  onClose: () => void;
  onRename: (view: SavedView, name: string) => Promise<void>;
  onReorder: (ids: string[]) => Promise<void>;
  onDelete: (view: SavedView) => Promise<void>;
}) {
  const [names, setNames] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const close = () => {
    setNames({});
    onClose();
  };

  const move = async (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= views.length) return;
    const ids = views.map((view) => view.id);
    [ids[index], ids[target]] = [ids[target]!, ids[index]!];
    setBusy(true);
    try {
      await onReorder(ids);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Gespeicherte Ansichten verwalten"
      description="Ansichten speichern Filterdefinitionen, niemals Ergebnislisten."
      size="large"
      onClose={close}
    >
      {views.length === 0 ? (
        <p className="muted-copy">Noch keine eigene Ansicht gespeichert.</p>
      ) : (
        <div className="saved-view-manager">
          {views.map((view, index) => (
            <div key={view.id} className="saved-view-manager__row">
              <input
                aria-label={`Name von ${view.name}`}
                value={names[view.id] ?? view.name}
                onChange={(event) =>
                  setNames((current) => ({ ...current, [view.id]: event.currentTarget.value }))
                }
              />
              <IconButton
                label="Nach oben"
                disabled={busy || index === 0}
                onClick={() => void move(index, -1)}
              >
                <ArrowUp />
              </IconButton>
              <IconButton
                label="Nach unten"
                disabled={busy || index === views.length - 1}
                onClick={() => void move(index, 1)}
              >
                <ArrowDown />
              </IconButton>
              <Button
                icon={<Check />}
                disabled={busy || (names[view.id] ?? '').trim().length === 0}
                onClick={() => void onRename(view, names[view.id] ?? view.name)}
              >
                Speichern
              </Button>
              <IconButton label={`${view.name} löschen`} onClick={() => void onDelete(view)}>
                <Trash2 />
              </IconButton>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

export function TagManager({
  open,
  tags,
  onClose,
  onRename,
  onMerge,
  onDelete,
}: {
  open: boolean;
  tags: TagSummary[];
  onClose: () => void;
  onRename: (tag: TagSummary, name: string) => Promise<void>;
  onMerge: (source: TagSummary, target: TagSummary) => Promise<void>;
  onDelete: (tag: TagSummary) => Promise<void>;
}) {
  const [names, setNames] = useState<Record<string, string>>({});
  const [mergeSource, setMergeSource] = useState('');
  const [mergeTarget, setMergeTarget] = useState('');
  const effectiveSource = tags.some((tag) => tag.normalizedName === mergeSource)
    ? mergeSource
    : (tags[0]?.normalizedName ?? '');
  const effectiveTarget = tags.some((tag) => tag.normalizedName === mergeTarget)
    ? mergeTarget
    : (tags[1]?.normalizedName ?? tags[0]?.normalizedName ?? '');
  const source = tags.find((tag) => tag.normalizedName === effectiveSource);
  const target = tags.find((tag) => tag.normalizedName === effectiveTarget);
  const close = () => {
    setNames({});
    setMergeSource('');
    setMergeTarget('');
    onClose();
  };

  return (
    <Modal
      open={open}
      title="Tags verwalten"
      description="Schreibweise wird zentral normalisiert; der sichtbare Name bleibt erhalten."
      size="large"
      onClose={close}
    >
      <div className="tag-manager">
        {tags.length === 0 && (
          <p className="muted-copy">Dieser Tresor verwendet noch keine Tags.</p>
        )}
        {tags.map((tag) => (
          <div className="tag-manager__row" key={tag.normalizedName}>
            <input
              aria-label={`Tag ${tag.name} umbenennen`}
              value={names[tag.normalizedName] ?? tag.name}
              onChange={(event) =>
                setNames((current) => ({
                  ...current,
                  [tag.normalizedName]: event.currentTarget.value,
                }))
              }
            />
            <span>{String(tag.usageCount)} Einträge</span>
            <Button onClick={() => void onRename(tag, names[tag.normalizedName] ?? tag.name)}>
              Umbenennen
            </Button>
            <IconButton label={`${tag.name} löschen`} onClick={() => void onDelete(tag)}>
              <Trash2 />
            </IconButton>
          </div>
        ))}
        {tags.length >= 2 && (
          <section className="tag-merge" aria-labelledby="tag-merge-title">
            <h3 id="tag-merge-title">Tags zusammenführen</h3>
            <select
              aria-label="Quell-Tag"
              value={effectiveSource}
              onChange={(event) => setMergeSource(event.currentTarget.value)}
            >
              {tags.map((tag) => (
                <option value={tag.normalizedName} key={tag.normalizedName}>
                  {tag.name}
                </option>
              ))}
            </select>
            <span aria-hidden="true">→</span>
            <select
              aria-label="Ziel-Tag"
              value={effectiveTarget}
              onChange={(event) => setMergeTarget(event.currentTarget.value)}
            >
              {tags.map((tag) => (
                <option value={tag.normalizedName} key={tag.normalizedName}>
                  {tag.name}
                </option>
              ))}
            </select>
            <Button
              disabled={!source || !target || source.normalizedName === target.normalizedName}
              onClick={() => source && target && void onMerge(source, target)}
            >
              Zusammenführen
            </Button>
          </section>
        )}
      </div>
    </Modal>
  );
}

export interface PaletteCommand {
  id: string;
  label: string;
  keywords: string;
  run: () => void;
}

export function CommandPalette({
  open,
  commands,
  onClose,
}: {
  open: boolean;
  commands: PaletteCommand[];
  onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!open) return;
    const timer = window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [open]);
  const close = () => {
    setQuery('');
    setActiveIndex(0);
    onClose();
  };
  const normalized = query.trim().normalize('NFKC').toLocaleLowerCase('de');
  const visible = useMemo(
    () =>
      commands.filter((command) =>
        `${command.label} ${command.keywords}`
          .normalize('NFKC')
          .toLocaleLowerCase('de')
          .includes(normalized),
      ),
    [commands, normalized],
  );
  const runCommand = (command: PaletteCommand) => {
    close();
    command.run();
  };
  return (
    <Modal open={open} title="Befehlspalette" size="medium" onClose={close}>
      <label className="palette-search">
        <Search aria-hidden="true" />
        <span className="sr-only">Befehl suchen</span>
        <input
          ref={inputRef}
          role="combobox"
          value={query}
          placeholder="Navigation oder Aktion suchen"
          aria-autocomplete="list"
          aria-controls="command-palette-results"
          aria-expanded="true"
          aria-activedescendant={
            visible[activeIndex] ? `palette-command-${visible[activeIndex].id}` : undefined
          }
          onChange={(event) => {
            setQuery(event.currentTarget.value);
            setActiveIndex(0);
          }}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              setActiveIndex((current) => Math.min(current + 1, Math.max(0, visible.length - 1)));
            } else if (event.key === 'ArrowUp') {
              event.preventDefault();
              setActiveIndex((current) => Math.max(0, current - 1));
            } else if (event.key === 'Enter') {
              const command = visible[Math.min(activeIndex, visible.length - 1)];
              if (command) {
                event.preventDefault();
                runCommand(command);
              }
            }
          }}
        />
      </label>
      <div
        id="command-palette-results"
        className="palette-results"
        role="listbox"
        aria-label="Verfügbare Befehle"
      >
        {visible.map((command, index) => (
          <button
            type="button"
            role="option"
            id={`palette-command-${command.id}`}
            aria-selected={index === activeIndex}
            className={index === activeIndex ? 'is-active' : ''}
            key={command.id}
            onMouseEnter={() => setActiveIndex(index)}
            onClick={() => runCommand(command)}
          >
            {command.label}
          </button>
        ))}
        {visible.length === 0 && <p className="muted-copy">Keine passenden Befehle gefunden.</p>}
      </div>
    </Modal>
  );
}

export function ShortcutHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  const shortcuts = [
    ['Strg + K', 'Befehlspalette öffnen'],
    ['Strg + F', 'Suche fokussieren'],
    ['Strg + N', 'Neuen Eintrag erstellen'],
    ['Strg + S', 'Geöffneten Editor speichern'],
    ['Strg + L', 'Kryptris sofort sperren'],
    ['Esc', 'Dialog, Editor oder Auswahl schließen'],
    ['Strg/Klick', 'Einzelne Listeneinträge zur Auswahl hinzufügen'],
    ['Umschalt/Klick', 'Zusammenhängenden Listenbereich auswählen'],
  ];
  return (
    <Modal
      open={open}
      title="Tastaturhilfe"
      description="Alle Kürzel gelten nur im entsperrten Kryptris-Fenster."
      size="medium"
      onClose={onClose}
    >
      <div className="shortcut-list">
        {shortcuts.map(([keys, description]) => (
          <div key={keys}>
            <kbd>{keys}</kbd>
            <span>{description}</span>
          </div>
        ))}
      </div>
      <InlineNotice kind="info">
        Die Befehlspalette zeigt keine Passwörter, TOTP-Seeds oder andere maskierte Werte.
      </InlineNotice>
      <Button icon={<Keyboard />} onClick={onClose}>
        Verstanden
      </Button>
    </Modal>
  );
}
