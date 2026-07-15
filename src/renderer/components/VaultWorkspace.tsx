import { ChevronDown, LockKeyhole, Menu, Plus, Search, Settings, X } from 'lucide-react';
import type { Dispatch, SetStateAction } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type {
  AppState,
  EntryDetail,
  EntryInput,
  EntryListQuery,
  EntrySummary,
  EntryType,
  EntryView,
  Folder,
} from '../../shared/models';
import type { EntryFilters, Notify, WorkspaceSection } from '../types';
import { createEntryFromTemplate, getErrorMessage, toEntryInput } from '../utils';
import { AuditView, BackupView } from './BackupAuditViews';
import { EntryDetailPanel } from './EntryDetailPanel';
import { EntryEditor } from './EntryEditor';
import { EntryList } from './EntryList';
import { ReportsView, TemplatesView } from './ReportsTemplatesViews';
import { SecurityView } from './SecurityView';
import { SettingsView } from './SettingsView';
import { Sidebar } from './Sidebar';
import { ExportView, ImportView } from './TransferViews';
import { Brand, Button, EmptyState, IconButton, WindowControls } from './ui';
import { VaultManager } from './VaultManager';
import { FolderManager } from './FolderManager';

interface VaultWorkspaceProps {
  state: AppState;
  onStateChange: Dispatch<SetStateAction<AppState | null>>;
  notify: Notify;
}

interface EditorState {
  entryId?: string;
  input?: EntryInput;
  type: EntryType;
}

const EMPTY_FILTERS: EntryFilters = { types: [], tags: [], folderId: null, security: [] };
const ENTRY_SECTIONS: WorkspaceSection[] = ['all', 'favorites', 'recent', 'trash'];

export function VaultWorkspace({ state, onStateChange, notify }: VaultWorkspaceProps) {
  const [section, setSection] = useState<WorkspaceSection>('all');
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState<EntryFilters>(EMPTY_FILTERS);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [detail, setDetail] = useState<EntryDetail | null>(null);
  const [entriesLoading, setEntriesLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [vaultManagerOpen, setVaultManagerOpen] = useState(false);
  const [folderManagerOpen, setFolderManagerOpen] = useState(false);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const activeVault =
    state.vaults.find((vault) => vault.id === state.activeVaultId) ?? state.vaults[0] ?? null;
  const activeVaultId = activeVault?.id ?? null;
  const isEntrySection = ENTRY_SECTIONS.includes(section);
  const listView: EntryView = isEntrySection ? (section as EntryView) : 'all';

  const query = useMemo<EntryListQuery | null>(
    () =>
      activeVaultId
        ? {
            vaultId: activeVaultId,
            search,
            view: listView,
            types: filters.types,
            tags: filters.tags,
            folderId: filters.folderId,
            security: filters.security,
          }
        : null,
    [activeVaultId, filters, listView, search],
  );

  const loadFolders = useCallback(async () => {
    if (!activeVaultId) {
      setFolders([]);
      return;
    }
    try {
      setFolders(await window.vaulta.vaults.listFolders(activeVaultId));
    } catch (error: unknown) {
      notify('error', 'Ordner konnten nicht geladen werden', getErrorMessage(error));
      setFolders([]);
    }
  }, [activeVaultId, notify]);

  useEffect(() => {
    void loadFolders();
  }, [loadFolders]);

  const loadEntries = useCallback(async () => {
    if (!query) {
      setEntries([]);
      setEntriesLoading(false);
      return;
    }
    setEntriesLoading(true);
    try {
      const values = await window.vaulta.entries.list(query);
      setEntries(values);
      setSelectedEntryId((current) => {
        if (current && values.some((entry) => entry.id === current)) return current;
        return values[0]?.id ?? null;
      });
    } catch (error: unknown) {
      notify('error', 'Einträge konnten nicht geladen werden', getErrorMessage(error));
      setEntries([]);
    } finally {
      setEntriesLoading(false);
    }
  }, [notify, query]);

  useEffect(() => {
    void loadEntries();
  }, [loadEntries]);

  const loadDetail = useCallback(async () => {
    if (!activeVaultId || !selectedEntryId) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    try {
      setDetail(
        await window.vaulta.entries.getDetail({ vaultId: activeVaultId, entryId: selectedEntryId }),
      );
    } catch (error: unknown) {
      setDetail(null);
      notify('error', 'Eintrag konnte nicht geöffnet werden', getErrorMessage(error));
    } finally {
      setDetailLoading(false);
    }
  }, [activeVaultId, notify, selectedEntryId]);

  useEffect(() => {
    if (isEntrySection) void loadDetail();
  }, [isEntrySection, loadDetail]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === '/' && !isFormControl(event.target)) {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.ctrlKey && event.key.toLowerCase() === 'n') {
        event.preventDefault();
        if (activeVaultId) setEditor({ type: filters.types[0] ?? 'credential' });
      }
      if (event.ctrlKey && event.key.toLowerCase() === 'l') {
        event.preventDefault();
        void window.vaulta.system.lock();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [activeVaultId, filters.types]);

  const chooseVault = async (vaultId: string) => {
    try {
      await window.vaulta.vaults.select(vaultId);
      const next = await window.vaulta.system.getState();
      onStateChange(next);
      setSelectedEntryId(null);
      setDetail(null);
    } catch (error: unknown) {
      notify('error', 'Tresor konnte nicht gewechselt werden', getErrorMessage(error));
    }
  };

  const changeSection = (next: WorkspaceSection) => {
    setSection(next);
    setSidebarOpen(false);
    if (next !== 'all') setFilters((current) => ({ ...current, types: [] }));
  };

  const selectType = (type: EntryType) => {
    setSection('all');
    setFilters({ ...EMPTY_FILTERS, types: [type] });
    setSidebarOpen(false);
  };

  const selectedSummary = entries.find((entry) => entry.id === selectedEntryId) ?? null;
  const toggleFavorite = async (entry = selectedSummary) => {
    if (!entry || !activeVaultId) return;
    try {
      const favorite = await window.vaulta.entries.toggleFavorite({
        vaultId: activeVaultId,
        entryId: entry.id,
      });
      setEntries((current) =>
        current.map((item) => (item.id === entry.id ? { ...item, favorite } : item)),
      );
      setDetail((current) => (current?.id === entry.id ? { ...current, favorite } : current));
      notify('success', favorite ? 'Zu Favoriten hinzugefügt' : 'Aus Favoriten entfernt');
    } catch (error: unknown) {
      notify('error', 'Favorit konnte nicht geändert werden', getErrorMessage(error));
    }
  };

  const editSelected = async () => {
    if (!activeVaultId || !selectedEntryId || !detail) return;
    try {
      const model = await window.vaulta.entries.getEditModel({
        vaultId: activeVaultId,
        entryId: selectedEntryId,
      });
      setEditor({ entryId: selectedEntryId, input: toEntryInput(model), type: model.data.type });
    } catch (error: unknown) {
      notify('error', 'Bearbeitungsansicht konnte nicht geöffnet werden', getErrorMessage(error));
    }
  };

  const moveToTrash = async () => {
    if (!activeVaultId || !selectedEntryId) return;
    try {
      await window.vaulta.entries.moveToTrash({ vaultId: activeVaultId, entryId: selectedEntryId });
      notify('success', 'Eintrag in den Papierkorb verschoben');
      setSelectedEntryId(null);
      await loadEntries();
    } catch (error: unknown) {
      notify('error', 'Eintrag konnte nicht gelöscht werden', getErrorMessage(error));
    }
  };

  const restore = async () => {
    if (!activeVaultId || !selectedEntryId) return;
    try {
      await window.vaulta.entries.restore({ vaultId: activeVaultId, entryId: selectedEntryId });
      notify('success', 'Eintrag wiederhergestellt');
      setSelectedEntryId(null);
      await loadEntries();
    } catch (error: unknown) {
      notify('error', 'Wiederherstellung fehlgeschlagen', getErrorMessage(error));
    }
  };

  const purge = async (password: string) => {
    if (!activeVaultId || !selectedEntryId) return;
    await window.vaulta.entries.purge({
      vaultId: activeVaultId,
      entryId: selectedEntryId,
      masterPassword: password,
    });
    notify('success', 'Eintrag endgültig gelöscht');
    setSelectedEntryId(null);
    await loadEntries();
  };

  const openEntry = (entryId: string) => {
    setSearch('');
    setFilters(EMPTY_FILTERS);
    setSection('all');
    setSelectedEntryId(entryId);
  };

  if (!activeVault) {
    return (
      <main className="empty-workspace">
        <Brand />
        <EmptyState
          title="Noch kein Tresor"
          description="Erstelle einen lokalen Tresor, um sichere Einträge anzulegen."
          action={
            <Button variant="primary" icon={<Plus />} onClick={() => setVaultManagerOpen(true)}>
              Tresor erstellen
            </Button>
          }
        />
        <VaultManager
          open={vaultManagerOpen}
          state={state}
          notify={notify}
          onClose={() => setVaultManagerOpen(false)}
          onStateChange={onStateChange}
        />
      </main>
    );
  }

  return (
    <main
      className={`workspace ${sidebarOpen ? 'sidebar-is-open' : ''} ${selectedEntryId ? 'has-detail' : ''}`}
    >
      <header className="topbar drag-region">
        <IconButton
          label={sidebarOpen ? 'Navigation schließen' : 'Navigation öffnen'}
          className="topbar__menu no-drag"
          onClick={() => setSidebarOpen((current) => !current)}
        >
          {sidebarOpen ? <X /> : <Menu />}
        </IconButton>
        <Brand />
        <div className="vault-select no-drag">
          <LockKeyhole />
          <select
            aria-label="Aktiven Tresor wählen"
            value={activeVault.id}
            onChange={(event) => void chooseVault(event.currentTarget.value)}
          >
            {state.vaults.map((vault) => (
              <option value={vault.id} key={vault.id}>
                {vault.name}
              </option>
            ))}
          </select>
          <ChevronDown />
        </div>
        <label className="global-search no-drag">
          <Search />
          <input
            ref={searchRef}
            value={search}
            placeholder="Tresor durchsuchen"
            aria-label="Tresor durchsuchen"
            onChange={(event) => {
              setSearch(event.currentTarget.value);
              if (!isEntrySection) setSection('all');
            }}
          />
          {search && (
            <IconButton label="Suche löschen" onClick={() => setSearch('')}>
              <X />
            </IconButton>
          )}
          <kbd>/</kbd>
        </label>
        <Button
          className="topbar__new no-drag"
          variant="primary"
          icon={<Plus />}
          onClick={() => setEditor({ type: filters.types[0] ?? 'credential' })}
        >
          Neuer Eintrag
        </Button>
        <IconButton
          label="Vaulta jetzt sperren"
          className="no-drag"
          onClick={() => void window.vaulta.system.lock()}
        >
          <LockKeyhole />
        </IconButton>
        <IconButton
          label="Einstellungen öffnen"
          className="no-drag"
          active={section === 'settings'}
          onClick={() => changeSection('settings')}
        >
          <Settings />
        </IconButton>
        <WindowControls />
      </header>

      <div className={`workspace-grid ${isEntrySection ? '' : 'workspace-grid--tool'}`}>
        <Sidebar
          state={state}
          section={section}
          selectedTypes={filters.types}
          onSectionChange={changeSection}
          onTypeSelect={selectType}
          onManageFolders={() => setFolderManagerOpen(true)}
          onManageVaults={() => setVaultManagerOpen(true)}
        />
        {sidebarOpen && (
          <button
            className="sidebar-scrim"
            aria-label="Navigation schließen"
            onClick={() => setSidebarOpen(false)}
          />
        )}
        {isEntrySection ? (
          <>
            <EntryList
              section={section}
              entries={entries}
              selectedEntryId={selectedEntryId}
              filters={filters}
              loading={entriesLoading}
              knownFolders={folders}
              onFiltersChange={setFilters}
              onSelect={(entry) => setSelectedEntryId(entry.id)}
              onNew={() => setEditor({ type: filters.types[0] ?? 'credential' })}
              onToggleFavorite={(entry) => void toggleFavorite(entry)}
            />
            <EntryDetailPanel
              detail={detail}
              summary={selectedSummary}
              state={state}
              loading={detailLoading}
              notify={notify}
              onEdit={() => void editSelected()}
              onToggleFavorite={() => void toggleFavorite()}
              onMoveToTrash={() => void moveToTrash()}
              onRestore={() => void restore()}
              onPurge={purge}
              onReload={() => void Promise.all([loadEntries(), loadDetail()])}
              onBack={() => setSelectedEntryId(null)}
            />
          </>
        ) : (
          <div className="tool-host">
            {section === 'security' && (
              <SecurityView vaultId={activeVault.id} notify={notify} onOpenEntry={openEntry} />
            )}
            {section === 'backup' && (
              <BackupView state={state} notify={notify} onStateChange={onStateChange} />
            )}
            {section === 'import' && (
              <ImportView
                vaultId={activeVault.id}
                notify={notify}
                onImported={() => void loadEntries()}
              />
            )}
            {section === 'export' && <ExportView state={state} notify={notify} />}
            {section === 'audit' && <AuditView notify={notify} />}
            {section === 'settings' && (
              <SettingsView state={state} notify={notify} onStateChange={onStateChange} />
            )}
            {section === 'templates' && (
              <TemplatesView
                notify={notify}
                onUseTemplate={(template) =>
                  setEditor({
                    type: template.entryType,
                    input: createEntryFromTemplate(template),
                  })
                }
              />
            )}
            {section === 'reports' && <ReportsView notify={notify} onOpenEntry={openEntry} />}
          </div>
        )}
      </div>

      <EntryEditor
        open={Boolean(editor)}
        vaultId={activeVault.id}
        {...(editor?.entryId ? { entryId: editor.entryId } : {})}
        {...(editor?.input ? { initial: editor.input } : {})}
        initialType={editor?.type ?? 'credential'}
        knownFolders={folders}
        notify={notify}
        onClose={() => setEditor(null)}
        onSaved={(saved) => {
          setEditor(null);
          setSection('all');
          setSelectedEntryId(saved.id);
          void loadEntries();
        }}
      />
      <VaultManager
        open={vaultManagerOpen}
        state={state}
        notify={notify}
        onClose={() => setVaultManagerOpen(false)}
        onStateChange={onStateChange}
      />
      <FolderManager
        open={folderManagerOpen}
        vaultId={activeVault.id}
        folders={folders}
        notify={notify}
        onClose={() => setFolderManagerOpen(false)}
        onChanged={loadFolders}
      />
    </main>
  );
}

function isFormControl(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}
