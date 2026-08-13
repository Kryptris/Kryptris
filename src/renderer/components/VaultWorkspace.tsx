import {
  Check,
  ChevronDown,
  EyeOff,
  LockKeyhole,
  Menu,
  Plus,
  Search,
  Settings,
  X,
} from 'lucide-react';
import type { Dispatch, SetStateAction } from 'react';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';

import type {
  AppState,
  BatchEntryAction,
  EntryDetail,
  EntryInput,
  EntryListQuery,
  EntrySummary,
  EntryType,
  EntryView,
  Folder,
  LocalJobProgressEvent,
  LocalReport,
  SavedView,
  SavedViewFilters,
  SecurityReport,
  SmartViewKind,
  TagSummary,
} from '../../shared/models';
import type { EntryFilters, Notify, WorkspaceSection } from '../types';
import { createEntryFromTemplate, getErrorMessage, toEntryInput } from '../utils';
import { AuditView, BackupView } from './BackupAuditViews';
import { DataQualityViews } from './DataQualityViews';
import { EntryDetailPanel } from './EntryDetailPanel';
import { EntryEditor } from './EntryEditor';
import { EntryList } from './EntryList';
import {
  BatchToolbar,
  CommandPalette,
  type PaletteCommand,
  SavedViewManager,
  ShortcutHelp,
  TagManager,
} from './ProductivityViews';
import { ReportsView, TemplatesView } from './ReportsTemplatesViews';
import { SecurityView } from './SecurityView';
import { SettingsView, type SettingsTab } from './SettingsView';
import { Sidebar } from './Sidebar';
import { ExportView, ImportView } from './TransferViews';
import { Brand, Button, EmptyState, Field, IconButton, Modal, WindowControls } from './ui';
import { VaultManager } from './VaultManager';
import { FolderManager } from './FolderManager';
import { HelpView } from './HelpView';

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
const ENTRY_SEARCH_DEBOUNCE_MS = 200;

function sameEntryIds(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((entryId, index) => entryId === right[index]);
}

export function VaultWorkspace({ state, onStateChange, notify }: VaultWorkspaceProps) {
  const [section, setSection] = useState<WorkspaceSection>('all');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [filters, setFilters] = useState<EntryFilters>(EMPTY_FILTERS);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [selectedEntryIds, setSelectedEntryIds] = useState<string[]>([]);
  const [detail, setDetail] = useState<EntryDetail | null>(null);
  const [entriesLoading, setEntriesLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailSelectionRevision, setDetailSelectionRevision] = useState(0);
  const [pendingImportedEntryIds, setPendingImportedEntryIds] = useState<string[] | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [vaultManagerOpen, setVaultManagerOpen] = useState(false);
  const [folderManagerOpen, setFolderManagerOpen] = useState(false);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [vaultPickerOpen, setVaultPickerOpen] = useState(false);
  const [securityReports, setSecurityReports] = useState<Record<string, SecurityReport>>({});
  const [securityLoading, setSecurityLoading] = useState<Record<string, boolean>>({});
  const [localReport, setLocalReport] = useState<LocalReport | null>(null);
  const [localReportLoading, setLocalReportLoading] = useState(false);
  const [savedViews, setSavedViews] = useState<SavedView[]>([]);
  const [activeSavedViewId, setActiveSavedViewId] = useState<string | null>(null);
  const [smartView, setSmartView] = useState<SmartViewKind | null>(null);
  const [saveViewOpen, setSaveViewOpen] = useState(false);
  const [saveViewName, setSaveViewName] = useState('');
  const [savedViewManagerOpen, setSavedViewManagerOpen] = useState(false);
  const [tags, setTags] = useState<TagSummary[]>([]);
  const [tagManagerOpen, setTagManagerOpen] = useState(false);
  const [batchBusy, setBatchBusy] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutHelpOpen, setShortcutHelpOpen] = useState(false);
  const [settingsInitialTab, setSettingsInitialTab] = useState<SettingsTab>('security');
  const [qualityProgress, setQualityProgress] = useState<LocalJobProgressEvent | null>(null);
  const [securityProgressEvents, setSecurityProgressEvents] = useState<
    Record<string, LocalJobProgressEvent>
  >({});
  const searchRef = useRef<HTMLInputElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const vaultPickerRef = useRef<HTMLDivElement>(null);
  const vaultPickerTriggerRef = useRef<HTMLButtonElement>(null);
  const vaultOptionRefs = useRef(new Map<string, HTMLButtonElement>());
  const pendingVaultPickerFocusId = useRef<string | null>(null);
  const securityRequests = useRef(new Set<string>());
  const localReportRequest = useRef(false);
  const entryListRequestGeneration = useRef(0);
  const detailRequestGeneration = useRef(0);
  const selectedEntryIdRef = useRef<string | null>(null);
  const selectedEntryIdsRef = useRef<string[]>([]);
  const importedEntryIdsRef = useRef<string[]>([]);
  const activeVaultIdRef = useRef<string | null>(null);
  const isEntrySectionRef = useRef(false);

  const activeVault =
    state.vaults.find((vault) => vault.id === state.activeVaultId) ?? state.vaults[0] ?? null;
  const activeVaultId = activeVault?.id ?? null;
  const isEntrySection = ENTRY_SECTIONS.includes(section);
  selectedEntryIdRef.current = selectedEntryId;
  selectedEntryIdsRef.current = selectedEntryIds;
  activeVaultIdRef.current = activeVaultId;
  isEntrySectionRef.current = isEntrySection;
  const listView: EntryView = isEntrySection ? (section as EntryView) : 'all';
  const isOffCanvasSidebar = useOffCanvasSidebar();
  const focusMode = state.settings?.focusMode === true;

  const updateSearch = useCallback((value: string, immediate = false) => {
    entryListRequestGeneration.current += 1;
    setSearch(value);
    if (immediate) setDebouncedSearch(value);
  }, []);

  const setEntrySelection = useCallback((entryIds: string[], primaryEntryId: string | null) => {
    // Invalidate before scheduling React state so a resolved old request cannot install a
    // detail during the selection transition.
    const nextEntryIds = [...entryIds];
    detailRequestGeneration.current += 1;
    selectedEntryIdsRef.current = nextEntryIds;
    selectedEntryIdRef.current = primaryEntryId;
    setDetail(null);
    setDetailLoading(primaryEntryId !== null && isEntrySectionRef.current);
    setDetailSelectionRevision((revision) => revision + 1);
    setSelectedEntryIds(nextEntryIds);
    setSelectedEntryId(primaryEntryId);
  }, []);

  useEffect(() => {
    if (search === debouncedSearch) return;
    const timer = window.setTimeout(() => setDebouncedSearch(search), ENTRY_SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [debouncedSearch, search]);

  useEffect(
    () => () => {
      entryListRequestGeneration.current += 1;
      detailRequestGeneration.current += 1;
    },
    [],
  );

  useEffect(() => {
    if (section !== 'import') importedEntryIdsRef.current = [];
    if (section !== 'all') setPendingImportedEntryIds(null);
  }, [section]);

  const closeSidebar = useCallback((returnFocus = false) => {
    setSidebarOpen(false);
    if (returnFocus) window.setTimeout(() => menuButtonRef.current?.focus(), 0);
  }, []);

  const closeVaultPicker = useCallback((returnFocus = false) => {
    setVaultPickerOpen(false);
    if (returnFocus) window.setTimeout(() => vaultPickerTriggerRef.current?.focus(), 0);
  }, []);

  const focusVaultPickerOption = useCallback(
    (index: number) => {
      const vault = state.vaults[index];
      if (vault) vaultOptionRefs.current.get(vault.id)?.focus();
    },
    [state.vaults],
  );

  const openVaultPicker = useCallback(
    (focusVaultId?: string) => {
      pendingVaultPickerFocusId.current = focusVaultId ?? activeVaultId;
      setVaultPickerOpen(true);
    },
    [activeVaultId],
  );

  useEffect(() => {
    if (!isOffCanvasSidebar) {
      setSidebarOpen(false);
      return;
    }
    if (!sidebarOpen) return;
    const timer = window.setTimeout(() => {
      sidebarRef.current?.querySelector<HTMLElement>('button:not([disabled])')?.focus();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [isOffCanvasSidebar, sidebarOpen]);

  useEffect(() => {
    if (!vaultPickerOpen) return;
    const focusId = pendingVaultPickerFocusId.current ?? activeVaultId;
    pendingVaultPickerFocusId.current = null;
    const timer = window.setTimeout(() => {
      if (focusId) vaultOptionRefs.current.get(focusId)?.focus();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [activeVaultId, vaultPickerOpen]);

  const loadSecurityReport = useCallback(
    async (refresh = false) => {
      if (!activeVaultId || (!refresh && securityReports[activeVaultId])) return;
      if (securityRequests.current.has(activeVaultId)) return;
      securityRequests.current.add(activeVaultId);
      setSecurityLoading((current) => ({ ...current, [activeVaultId]: true }));
      try {
        const report = await window.vaulta.security.scan(activeVaultId);
        setSecurityReports((current) => ({ ...current, [activeVaultId]: report }));
        notify(
          'success',
          'Lokaler Sicherheitscheck abgeschlossen',
          'Es wurden keine Daten übertragen.',
        );
      } catch (error: unknown) {
        notify('error', 'Sicherheitscheck fehlgeschlagen', getErrorMessage(error));
      } finally {
        securityRequests.current.delete(activeVaultId);
        setSecurityLoading((current) => ({ ...current, [activeVaultId]: false }));
      }
    },
    [activeVaultId, notify, securityReports],
  );

  useEffect(() => {
    if (section === 'all') void loadSecurityReport();
  }, [loadSecurityReport, section]);

  const loadLocalReport = useCallback(
    async (refresh = false) => {
      if (!refresh && localReport !== null) return;
      if (localReportRequest.current) return;
      localReportRequest.current = true;
      setLocalReportLoading(true);
      try {
        setLocalReport(await window.vaulta.reports.generate());
      } catch (error: unknown) {
        notify('error', 'Bericht konnte nicht erzeugt werden', getErrorMessage(error));
      } finally {
        localReportRequest.current = false;
        setLocalReportLoading(false);
      }
    },
    [localReport, notify],
  );

  const query = useMemo<EntryListQuery | null>(
    () =>
      activeVaultId
        ? {
            vaultId: activeVaultId,
            search: debouncedSearch,
            view: listView,
            types: filters.types,
            tags: filters.tags,
            folderId: filters.folderId,
            security: filters.security,
            smartView,
          }
        : null,
    [activeVaultId, debouncedSearch, filters, listView, smartView],
  );

  useLayoutEffect(() => {
    entryListRequestGeneration.current += 1;
  }, [query]);

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

  useEffect(
    () =>
      window.vaulta.events.onLocalJobProgress((event) => {
        if (event.job === 'duplicates' || event.job === 'data-quality') {
          setQualityProgress(event);
          return;
        }
        if (
          event.job === 'security-center' ||
          event.job === 'integrity' ||
          event.job === 'breach-import' ||
          event.job === 'breach-scan'
        ) {
          setSecurityProgressEvents((current) => {
            const next = {
              ...current,
              [`${event.job}:${event.requestId}`]: event,
            };
            const keys = Object.keys(next);
            for (const key of keys.slice(0, Math.max(0, keys.length - 24))) delete next[key];
            return next;
          });
        }
      }),
    [],
  );

  const loadSavedViews = useCallback(async () => {
    if (!activeVaultId) {
      setSavedViews([]);
      return;
    }
    try {
      setSavedViews(await window.vaulta.productivity.listSavedViews(activeVaultId));
    } catch (error: unknown) {
      notify(
        'error',
        'Gespeicherte Ansichten konnten nicht geladen werden',
        getErrorMessage(error),
      );
      setSavedViews([]);
    }
  }, [activeVaultId, notify]);

  const loadTags = useCallback(async () => {
    if (!activeVaultId) {
      setTags([]);
      return;
    }
    try {
      setTags(await window.vaulta.productivity.listTags(activeVaultId));
    } catch (error: unknown) {
      notify('error', 'Tags konnten nicht geladen werden', getErrorMessage(error));
      setTags([]);
    }
  }, [activeVaultId, notify]);

  useEffect(() => {
    void Promise.all([loadSavedViews(), loadTags()]);
  }, [loadSavedViews, loadTags]);

  const loadEntries = useCallback(async () => {
    const requestGeneration = ++entryListRequestGeneration.current;
    const isCurrentRequest = () => requestGeneration === entryListRequestGeneration.current;
    if (!query) {
      if (!isCurrentRequest()) return;
      setEntries([]);
      if (selectedEntryIdRef.current !== null || selectedEntryIdsRef.current.length > 0) {
        setEntrySelection([], null);
      }
      setEntriesLoading(false);
      return;
    }
    if (search !== debouncedSearch) return;
    setEntriesLoading(true);
    try {
      const values = await window.vaulta.entries.list(query);
      if (!isCurrentRequest()) return;
      setEntries(values);
      const nextSelectedEntryIds = selectedEntryIdsRef.current.filter((entryId) =>
        values.some((entry) => entry.id === entryId),
      );
      const nextSelectedEntryId =
        selectedEntryIdRef.current !== null &&
        values.some((entry) => entry.id === selectedEntryIdRef.current)
          ? selectedEntryIdRef.current
          : (values[0]?.id ?? null);
      if (
        !sameEntryIds(nextSelectedEntryIds, selectedEntryIdsRef.current) ||
        nextSelectedEntryId !== selectedEntryIdRef.current
      ) {
        setEntrySelection(nextSelectedEntryIds, nextSelectedEntryId);
      }
    } catch (error: unknown) {
      if (!isCurrentRequest()) return;
      notify('error', 'Einträge konnten nicht geladen werden', getErrorMessage(error));
      setEntries([]);
      setEntrySelection([], null);
    } finally {
      if (isCurrentRequest()) setEntriesLoading(false);
    }
  }, [debouncedSearch, notify, query, search, setEntrySelection]);

  useEffect(() => {
    void loadEntries();
  }, [loadEntries]);

  const loadDetail = useCallback(async () => {
    const requestGeneration = ++detailRequestGeneration.current;
    const requestedVaultId = activeVaultId;
    const requestedEntryId = selectedEntryId;
    const isCurrentRequest = () =>
      requestGeneration === detailRequestGeneration.current &&
      activeVaultIdRef.current === requestedVaultId &&
      selectedEntryIdRef.current === requestedEntryId &&
      isEntrySectionRef.current;
    if (!requestedVaultId || !requestedEntryId || !isEntrySection) {
      setDetail(null);
      setDetailLoading(false);
      return;
    }
    setDetailLoading(true);
    try {
      const loaded = await window.vaulta.entries.getDetail({
        vaultId: requestedVaultId,
        entryId: requestedEntryId,
      });
      if (
        !isCurrentRequest() ||
        loaded.id !== requestedEntryId ||
        loaded.vaultId !== requestedVaultId
      ) {
        return;
      }
      setDetail(loaded);
    } catch (error: unknown) {
      if (!isCurrentRequest()) return;
      setDetail(null);
      notify('error', 'Eintrag konnte nicht geöffnet werden', getErrorMessage(error));
    } finally {
      if (isCurrentRequest()) setDetailLoading(false);
    }
  }, [activeVaultId, isEntrySection, notify, selectedEntryId]);

  useEffect(() => {
    if (isEntrySection) void loadDetail();
  }, [detailSelectionRevision, isEntrySection, loadDetail]);

  useEffect(() => {
    if (section !== 'all' || pendingImportedEntryIds === null) return;
    const entryIds = pendingImportedEntryIds;
    setPendingImportedEntryIds(null);
    setEntrySelection(entryIds, entryIds[0] ?? null);
    void loadEntries();
  }, [loadEntries, pendingImportedEntryIds, section, setEntrySelection]);

  // Global shortcuts must be active with the visible workspace.
  // useEffect leaves a short post-render interval without a listener.
  useLayoutEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const modifier = event.ctrlKey || event.metaKey;
      const key = event.key.toLowerCase();
      const dialogOpen =
        editor !== null ||
        vaultManagerOpen ||
        folderManagerOpen ||
        savedViewManagerOpen ||
        tagManagerOpen ||
        saveViewOpen ||
        shortcutHelpOpen;
      const renderedDialogs = Array.from(
        document.querySelectorAll<HTMLElement>('[role="dialog"][aria-modal="true"]'),
      );
      const editorForm = document.querySelector<HTMLFormElement>('form.entry-editor');
      const editorIsOnlyDialog =
        editorForm !== null &&
        renderedDialogs.length === 1 &&
        renderedDialogs[0]?.contains(editorForm) === true;
      const blockingDialogOpen = dialogOpen || renderedDialogs.length > 0;

      if (modifier && key === 'l') {
        event.preventDefault();
        void window.vaulta.system.lock();
        return;
      }
      if (modifier && key === 'k') {
        event.preventDefault();
        if (!blockingDialogOpen) setCommandPaletteOpen(true);
        return;
      }
      if (modifier && key === 's' && editor !== null) {
        event.preventDefault();
        if (editorIsOnlyDialog) editorForm.requestSubmit();
        return;
      }
      if (modifier && key === 'f' && !blockingDialogOpen && !commandPaletteOpen) {
        event.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (modifier && key === 'n' && !blockingDialogOpen && !commandPaletteOpen) {
        event.preventDefault();
        if (activeVaultId) setEditor({ type: filters.types[0] ?? 'credential' });
        return;
      }
      if (
        event.key === '/' &&
        !blockingDialogOpen &&
        !commandPaletteOpen &&
        !isFormControl(event.target)
      ) {
        event.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (event.key === 'Escape' && !blockingDialogOpen && !commandPaletteOpen) {
        if (vaultPickerOpen) {
          closeVaultPicker(true);
        } else if (isOffCanvasSidebar && sidebarOpen) {
          closeSidebar(true);
        } else if (selectedEntryId !== null) {
          setEntrySelection([], null);
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [
    activeVaultId,
    closeSidebar,
    closeVaultPicker,
    commandPaletteOpen,
    editor,
    filters.types,
    folderManagerOpen,
    isOffCanvasSidebar,
    saveViewOpen,
    savedViewManagerOpen,
    selectedEntryId,
    sidebarOpen,
    shortcutHelpOpen,
    setEntrySelection,
    tagManagerOpen,
    vaultManagerOpen,
    vaultPickerOpen,
  ]);

  useEffect(() => {
    if (!vaultPickerOpen) return;
    const close = (event: PointerEvent) => {
      if (event.target instanceof Node && !vaultPickerRef.current?.contains(event.target)) {
        closeVaultPicker(true);
      }
    };
    window.addEventListener('pointerdown', close);
    return () => {
      window.removeEventListener('pointerdown', close);
    };
  }, [closeVaultPicker, vaultPickerOpen]);

  const chooseVault = async (vaultId: string) => {
    try {
      await window.vaulta.vaults.select(vaultId);
      const next = await window.vaulta.system.getState();
      onStateChange(next);
      setEntrySelection([], null);
      setActiveSavedViewId(null);
      setSmartView(null);
      closeVaultPicker(true);
    } catch (error: unknown) {
      notify('error', 'Tresor konnte nicht gewechselt werden', getErrorMessage(error));
    }
  };

  const handleVaultPickerOptionKeyDown = (
    event: React.KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    const targetIndex =
      event.key === 'ArrowDown'
        ? Math.min(state.vaults.length - 1, index + 1)
        : event.key === 'ArrowUp'
          ? Math.max(0, index - 1)
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? state.vaults.length - 1
              : null;
    if (targetIndex !== null) {
      event.preventDefault();
      focusVaultPickerOption(targetIndex);
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      closeVaultPicker(true);
    }
  };

  const changeSection = (next: WorkspaceSection) => {
    const importedEntryIds =
      next === 'all' && section === 'import' && importedEntryIdsRef.current.length > 0
        ? [...importedEntryIdsRef.current]
        : null;
    setPendingImportedEntryIds(importedEntryIds);
    setSection(next);
    if (next === 'settings') setSettingsInitialTab('security');
    setActiveSavedViewId(null);
    setSmartView(null);
    setEntrySelection([], null);
    setSidebarOpen(false);
    if (next === 'all') {
      setFilters(EMPTY_FILTERS);
    } else {
      setFilters((current) => ({ ...current, types: [] }));
    }
  };

  const selectType = (type: EntryType) => {
    setSection('all');
    setFilters({ ...EMPTY_FILTERS, types: [type] });
    setActiveSavedViewId(null);
    setSmartView(null);
    setEntrySelection([], null);
    setSidebarOpen(false);
  };

  const selectedSummary = entries.find((entry) => entry.id === selectedEntryId) ?? null;
  // A detail request may finish after the user has already selected another entry or
  // switched vaults. Never render actions from that stale response: destructive
  // operations must only be available for the currently selected entry.
  const currentDetail =
    detail !== null && detail.id === selectedEntryId && detail.vaultId === activeVaultId
      ? detail
      : null;
  const currentDetailLoading = detailLoading;

  const isCurrentDetail = (entryId: string): boolean =>
    activeVaultId !== null &&
    activeVaultIdRef.current === activeVaultId &&
    selectedEntryIdRef.current === entryId &&
    detail?.id === entryId &&
    detail.vaultId === activeVaultId;
  const toggleFavorite = async (entry: Pick<EntrySummary, 'id'> | null = selectedSummary) => {
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

  const editSelected = async (entryId: string) => {
    if (!isCurrentDetail(entryId) || activeVaultId === null) return;
    const vaultId = activeVaultId;
    try {
      const model = await window.vaulta.entries.getEditModel({
        vaultId,
        entryId,
      });
      if (!isCurrentDetail(entryId)) return;
      setEditor({ entryId, input: toEntryInput(model), type: model.data.type });
    } catch (error: unknown) {
      notify('error', 'Bearbeitungsansicht konnte nicht geöffnet werden', getErrorMessage(error));
    }
  };

  const moveToTrash = async (entryId: string) => {
    if (!isCurrentDetail(entryId) || activeVaultId === null) return;
    const vaultId = activeVaultId;
    try {
      await window.vaulta.entries.moveToTrash({ vaultId, entryId });
      notify('success', 'Eintrag in den Papierkorb verschoben');
      if (activeVaultIdRef.current === vaultId && selectedEntryIdRef.current === entryId) {
        setEntrySelection([], null);
        await loadEntries();
      }
    } catch (error: unknown) {
      notify('error', 'Eintrag konnte nicht gelöscht werden', getErrorMessage(error));
    }
  };

  const restore = async (entryId: string) => {
    if (!isCurrentDetail(entryId) || activeVaultId === null) return;
    const vaultId = activeVaultId;
    try {
      await window.vaulta.entries.restore({ vaultId, entryId });
      notify('success', 'Eintrag wiederhergestellt');
      if (activeVaultIdRef.current === vaultId && selectedEntryIdRef.current === entryId) {
        setEntrySelection([], null);
        await loadEntries();
      }
    } catch (error: unknown) {
      notify('error', 'Wiederherstellung fehlgeschlagen', getErrorMessage(error));
    }
  };

  const purge = async (entryId: string, password: string) => {
    if (!isCurrentDetail(entryId) || activeVaultId === null) return;
    const vaultId = activeVaultId;
    await window.vaulta.entries.purge({
      vaultId,
      entryId,
      masterPassword: password,
    });
    notify('success', 'Eintrag endgültig gelöscht');
    if (activeVaultIdRef.current === vaultId && selectedEntryIdRef.current === entryId) {
      setEntrySelection([], null);
      await loadEntries();
    }
  };

  const openEntry = (entryId: string) => {
    updateSearch('', true);
    setFilters(EMPTY_FILTERS);
    setSection('all');
    setActiveSavedViewId(null);
    setSmartView(null);
    setEntrySelection([entryId], entryId);
  };

  const openEntryInVault = async (vaultId: string, entryId: string) => {
    try {
      if (vaultId !== activeVaultId) {
        await window.vaulta.vaults.select(vaultId);
        onStateChange(await window.vaulta.system.getState());
      }
      updateSearch('', true);
      setFilters(EMPTY_FILTERS);
      setSection('all');
      setActiveSavedViewId(null);
      setSmartView(null);
      setEntrySelection([entryId], entryId);
      setSidebarOpen(false);
    } catch (error: unknown) {
      notify('error', 'Eintrag konnte nicht geöffnet werden', getErrorMessage(error));
    }
  };

  const changeSelection = (entryIds: string[], primaryEntryId: string | null) => {
    setEntrySelection(entryIds, primaryEntryId);
  };

  const runBatch = async (action: BatchEntryAction): Promise<boolean> => {
    if (!activeVaultId || selectedEntryIds.length === 0 || batchBusy) return false;
    const entryIds = [...selectedEntryIds];
    setBatchBusy(true);
    try {
      const result = await window.vaulta.productivity.batch({
        vaultId: activeVaultId,
        entryIds,
        action,
      });
      notify(
        'success',
        `${String(result.affected)} ${result.affected === 1 ? 'Eintrag' : 'Einträge'} aktualisiert`,
      );
      setEntrySelection([], null);
      await Promise.all([loadEntries(), loadFolders(), loadTags(), loadSavedViews()]);
      return true;
    } catch (error: unknown) {
      notify('error', 'Batch-Aktion fehlgeschlagen', getErrorMessage(error));
      return false;
    } finally {
      setBatchBusy(false);
    }
  };

  const currentViewFilters = useMemo<SavedViewFilters>(
    () => ({
      search,
      view: listView,
      types: [...filters.types],
      tags: [...filters.tags],
      folderId: filters.folderId,
      security: [...filters.security],
      smartView,
    }),
    [filters, listView, search, smartView],
  );

  const closeSaveView = () => {
    setSaveViewOpen(false);
    setSaveViewName('');
  };

  const saveCurrentView = async () => {
    if (!activeVaultId || saveViewName.trim().length === 0) return;
    try {
      const saved = await window.vaulta.productivity.saveSavedView({
        vaultId: activeVaultId,
        name: saveViewName,
        filters: currentViewFilters,
      });
      setSavedViews((current) =>
        [...current, saved].sort((left, right) => left.order - right.order),
      );
      setActiveSavedViewId(saved.id);
      closeSaveView();
      notify('success', 'Ansicht gespeichert');
    } catch (error: unknown) {
      notify('error', 'Ansicht konnte nicht gespeichert werden', getErrorMessage(error));
    }
  };

  const applySavedView = (view: SavedView) => {
    const invalidTags = new Set(view.invalidReferences.tags);
    setSection(view.filters.view);
    updateSearch(view.filters.search, true);
    setFilters({
      types: [...view.filters.types],
      tags: view.filters.tags.filter((tag) => !invalidTags.has(tag)),
      folderId: view.invalidReferences.folder ? null : view.filters.folderId,
      security: [...view.filters.security],
    });
    setSmartView(view.filters.smartView);
    setActiveSavedViewId(view.id);
    setEntrySelection([], null);
    setSidebarOpen(false);
    if (view.invalidReferences.folder || view.invalidReferences.tags.length > 0) {
      notify(
        'warning',
        'Ansicht enthält nicht mehr verfügbare Filter',
        'Fehlende Ordner und Tags wurden für diese Anwendung übersprungen.',
      );
    }
  };

  const applySmartView = (view: SmartViewKind) => {
    setSection('all');
    updateSearch('', true);
    setFilters(EMPTY_FILTERS);
    setSmartView(view);
    setActiveSavedViewId(null);
    setEntrySelection([], null);
    setSidebarOpen(false);
  };

  const renameSavedView = async (view: SavedView, name: string) => {
    try {
      await window.vaulta.productivity.saveSavedView({
        id: view.id,
        vaultId: view.vaultId,
        name,
        filters: view.filters,
      });
      await loadSavedViews();
      notify('success', 'Ansicht umbenannt');
    } catch (error: unknown) {
      notify('error', 'Ansicht konnte nicht umbenannt werden', getErrorMessage(error));
    }
  };

  const reorderSavedViews = async (orderedIds: string[]) => {
    if (!activeVaultId) return;
    try {
      setSavedViews(
        await window.vaulta.productivity.reorderSavedViews({ vaultId: activeVaultId, orderedIds }),
      );
    } catch (error: unknown) {
      notify('error', 'Ansichten konnten nicht sortiert werden', getErrorMessage(error));
    }
  };

  const deleteSavedView = async (view: SavedView) => {
    try {
      await window.vaulta.productivity.deleteSavedView({ vaultId: view.vaultId, id: view.id });
      if (activeSavedViewId === view.id) setActiveSavedViewId(null);
      await loadSavedViews();
      notify('success', 'Ansicht gelöscht');
    } catch (error: unknown) {
      notify('error', 'Ansicht konnte nicht gelöscht werden', getErrorMessage(error));
    }
  };

  const renameTag = async (tag: TagSummary, name: string) => {
    if (!activeVaultId) return;
    try {
      const affected = await window.vaulta.productivity.renameTag({
        vaultId: activeVaultId,
        tag: tag.name,
        name,
      });
      await Promise.all([loadEntries(), loadDetail(), loadTags(), loadSavedViews()]);
      notify('success', `${String(affected)} Einträge aktualisiert`);
    } catch (error: unknown) {
      notify('error', 'Tag konnte nicht umbenannt werden', getErrorMessage(error));
    }
  };

  const mergeTags = async (source: TagSummary, target: TagSummary) => {
    if (!activeVaultId) return;
    try {
      const affected = await window.vaulta.productivity.mergeTags({
        vaultId: activeVaultId,
        sourceTags: [source.name],
        targetName: target.name,
      });
      await Promise.all([loadEntries(), loadDetail(), loadTags(), loadSavedViews()]);
      notify('success', `${String(affected)} Einträge aktualisiert`);
    } catch (error: unknown) {
      notify('error', 'Tags konnten nicht zusammengeführt werden', getErrorMessage(error));
    }
  };

  const deleteTag = async (tag: TagSummary) => {
    if (!activeVaultId) return;
    try {
      const affected = await window.vaulta.productivity.deleteTag({
        vaultId: activeVaultId,
        tag: tag.name,
      });
      await Promise.all([loadEntries(), loadDetail(), loadTags(), loadSavedViews()]);
      notify('success', `Tag aus ${String(affected)} Einträgen entfernt`);
    } catch (error: unknown) {
      notify('error', 'Tag konnte nicht gelöscht werden', getErrorMessage(error));
    }
  };

  const commands: PaletteCommand[] = [
    {
      id: 'new-entry',
      label: 'Neuen Eintrag erstellen',
      keywords: 'neu hinzufügen strg n',
      run: () => setEditor({ type: filters.types[0] ?? 'credential' }),
    },
    {
      id: 'search',
      label: 'Tresor durchsuchen',
      keywords: 'suche finden strg f',
      run: () => searchRef.current?.focus(),
    },
    {
      id: 'all',
      label: 'Alle Einträge öffnen',
      keywords: 'navigation übersicht',
      run: () => changeSection('all'),
    },
    {
      id: 'favorites',
      label: 'Favoriten öffnen',
      keywords: 'navigation favorisiert',
      run: () => changeSection('favorites'),
    },
    {
      id: 'trash',
      label: 'Papierkorb öffnen',
      keywords: 'navigation gelöscht',
      run: () => changeSection('trash'),
    },
    {
      id: 'save-view',
      label: 'Aktuelle Ansicht speichern',
      keywords: 'filter saved view lesezeichen',
      run: () => setSaveViewOpen(true),
    },
    {
      id: 'manage-tags',
      label: 'Tags verwalten',
      keywords: 'umbenennen zusammenführen löschen',
      run: () => setTagManagerOpen(true),
    },
    {
      id: 'shortcuts',
      label: 'Tastaturhilfe öffnen',
      keywords: 'shortcuts kürzel',
      run: () => setShortcutHelpOpen(true),
    },
    {
      id: 'help',
      label: 'Hilfe & Datenschutz öffnen',
      keywords: 'offline sichtschutz fokusmodus',
      run: () => changeSection('help'),
    },
    {
      id: 'lock',
      label: 'Kryptris sofort sperren',
      keywords: 'schutz strg l',
      run: () => void window.vaulta.system.lock(),
    },
  ];

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
      className={`workspace ${sidebarOpen ? 'sidebar-is-open' : ''} ${selectedEntryId ? 'has-detail' : ''} ${focusMode ? 'workspace--focus-mode' : ''}`}
    >
      <header className="topbar drag-region">
        <IconButton
          ref={menuButtonRef}
          label={sidebarOpen ? 'Navigation schließen' : 'Navigation öffnen'}
          className="topbar__menu no-drag"
          onClick={() => {
            closeVaultPicker(false);
            if (sidebarOpen) closeSidebar(false);
            else setSidebarOpen(true);
          }}
        >
          {sidebarOpen ? <X /> : <Menu />}
        </IconButton>
        <Brand />
        <div className="vault-picker no-drag" ref={vaultPickerRef}>
          <button
            ref={vaultPickerTriggerRef}
            type="button"
            className="vault-picker__trigger"
            aria-label="Aktiven Tresor wählen"
            aria-expanded={vaultPickerOpen}
            aria-haspopup="listbox"
            aria-controls="vault-picker-options"
            onClick={() => {
              if (vaultPickerOpen) closeVaultPicker(false);
              else openVaultPicker();
            }}
            onKeyDown={(event) => {
              const activeIndex = state.vaults.findIndex((vault) => vault.id === activeVault.id);
              const focusIndex =
                event.key === 'ArrowDown'
                  ? Math.min(state.vaults.length - 1, activeIndex + 1)
                  : event.key === 'ArrowUp'
                    ? Math.max(0, activeIndex - 1)
                    : event.key === 'Home'
                      ? 0
                      : event.key === 'End'
                        ? state.vaults.length - 1
                        : null;
              if (focusIndex === null) return;
              event.preventDefault();
              openVaultPicker(state.vaults[focusIndex]?.id);
            }}
          >
            <span className="vault-picker__icon" style={{ background: activeVault.color }}>
              <LockKeyhole />
            </span>
            <span className="vault-picker__current">
              <strong>{activeVault.name}</strong>
              <small>{String(activeVault.entryCount)} Einträge</small>
            </span>
            <ChevronDown className={vaultPickerOpen ? 'is-open' : ''} />
          </button>
          {vaultPickerOpen && (
            <div className="vault-picker__menu" role="dialog" aria-label="Tresor wechseln">
              <header>
                <span>Tresor wechseln</span>
                <small>{String(state.vaults.length)} verfügbar</small>
              </header>
              <div
                id="vault-picker-options"
                className="vault-picker__options"
                role="listbox"
                aria-label="Verfügbare Tresore"
              >
                {state.vaults.map((vault, index) => {
                  const selected = vault.id === activeVault.id;
                  return (
                    <button
                      ref={(element) => {
                        if (element) vaultOptionRefs.current.set(vault.id, element);
                        else vaultOptionRefs.current.delete(vault.id);
                      }}
                      type="button"
                      role="option"
                      aria-selected={selected}
                      tabIndex={selected ? 0 : -1}
                      className={selected ? 'is-active' : ''}
                      key={vault.id}
                      onClick={() => void chooseVault(vault.id)}
                      onKeyDown={(event) => handleVaultPickerOptionKeyDown(event, index)}
                    >
                      <span
                        className="vault-picker__option-icon"
                        style={{ background: vault.color }}
                      >
                        <LockKeyhole />
                      </span>
                      <span>
                        <strong>{vault.name}</strong>
                        <small>
                          {String(vault.entryCount)} Einträge · {String(vault.deletedCount)} im
                          Papierkorb
                        </small>
                      </span>
                      {selected && <Check aria-label="Aktiver Tresor" />}
                    </button>
                  );
                })}
              </div>
              <footer>
                <button
                  type="button"
                  onClick={() => {
                    closeVaultPicker(false);
                    setVaultManagerOpen(true);
                  }}
                >
                  Tresore verwalten
                </button>
              </footer>
            </div>
          )}
        </div>
        <label className="global-search no-drag">
          <Search />
          <input
            ref={searchRef}
            value={search}
            placeholder="Tresor durchsuchen"
            aria-label="Tresor durchsuchen"
            onChange={(event) => {
              updateSearch(event.currentTarget.value);
              setActiveSavedViewId(null);
              if (!isEntrySection) setSection('all');
            }}
          />
          {search && (
            <IconButton
              label="Suche löschen"
              onClick={() => {
                updateSearch('', true);
                setActiveSavedViewId(null);
              }}
            >
              <X />
            </IconButton>
          )}
          <kbd>Strg F</kbd>
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
          label="Kryptris jetzt sperren"
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

      {focusMode && (
        <div className="focus-mode-boundary" role="status">
          <EyeOff aria-hidden="true" />
          <span>
            <strong>Fokusmodus aktiv</strong>
            <small>
              Listensubtitel, Tags und Vorschau-Aktionen sind ausgeblendet. Sperre Kryptris für
              kryptografischen Schutz.
            </small>
          </span>
        </div>
      )}

      <div className={`workspace-grid ${isEntrySection ? '' : 'workspace-grid--tool'}`}>
        <Sidebar
          sidebarRef={sidebarRef}
          offCanvas={isOffCanvasSidebar && !sidebarOpen}
          onDismiss={() => closeSidebar(true)}
          state={state}
          section={section}
          selectedTypes={filters.types}
          savedViews={savedViews}
          activeSavedViewId={activeSavedViewId}
          activeSmartView={smartView}
          onSectionChange={changeSection}
          onTypeSelect={selectType}
          onSavedViewSelect={applySavedView}
          onSmartViewSelect={applySmartView}
          onSaveCurrentView={() => setSaveViewOpen(true)}
          onManageSavedViews={() => setSavedViewManagerOpen(true)}
          onManageTags={() => setTagManagerOpen(true)}
          onShowShortcuts={() => setShortcutHelpOpen(true)}
          onManageFolders={() => setFolderManagerOpen(true)}
          onManageVaults={() => setVaultManagerOpen(true)}
        />
        {isOffCanvasSidebar && sidebarOpen && (
          <button
            className="sidebar-scrim"
            aria-label="Navigation schließen"
            onClick={() => closeSidebar(true)}
          />
        )}
        {isEntrySection ? (
          <>
            <EntryList
              key={sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}
              section={section}
              entries={entries}
              primaryEntryId={selectedEntryId}
              selectedEntryIds={selectedEntryIds}
              filters={filters}
              loading={entriesLoading}
              knownFolders={folders}
              focusMode={focusMode}
              toolbar={
                <>
                  {section === 'all' && (
                    <LifecycleOverview
                      report={securityReports[activeVault.id] ?? null}
                      loading={securityLoading[activeVault.id] === true}
                      onShowRotation={() => applySmartView('rotation-due')}
                      onShowMissingTwoFactor={() => applySmartView('without-two-factor')}
                      onOpenSecurity={() => changeSection('security')}
                    />
                  )}
                  <BatchToolbar
                    selectedCount={selectedEntryIds.length}
                    trashView={section === 'trash'}
                    folders={folders}
                    vaults={state.vaults}
                    activeVaultId={activeVault.id}
                    busy={batchBusy}
                    onRun={runBatch}
                    onClear={() => changeSelection([], null)}
                  />
                </>
              }
              onFiltersChange={(next) => {
                setFilters(next);
                setActiveSavedViewId(null);
                setEntrySelection([], null);
              }}
              onSelectionChange={changeSelection}
              onNew={() => setEditor({ type: filters.types[0] ?? 'credential' })}
              onToggleFavorite={(entry) => void toggleFavorite(entry)}
            />
            <EntryDetailPanel
              detail={currentDetail}
              summary={currentDetail === null ? null : selectedSummary}
              state={state}
              loading={currentDetailLoading}
              focusMode={focusMode}
              notify={notify}
              onEdit={() => {
                if (currentDetail) void editSelected(currentDetail.id);
              }}
              onToggleFavorite={() => {
                if (currentDetail) void toggleFavorite(currentDetail);
              }}
              onMoveToTrash={() => {
                if (currentDetail) void moveToTrash(currentDetail.id);
              }}
              onRestore={() => {
                if (currentDetail) void restore(currentDetail.id);
              }}
              onPurge={(password) =>
                currentDetail ? purge(currentDetail.id, password) : Promise.resolve()
              }
              onReload={() => void Promise.all([loadEntries(), loadDetail()])}
              onBack={() => changeSelection([], null)}
            />
          </>
        ) : (
          <div className="tool-host">
            {section === 'security' && (
              <SecurityView
                progressEvents={Object.values(securityProgressEvents)}
                notify={notify}
                onScanCenter={(input) => window.vaulta.security.scanCenter(input)}
                onGetRecoveryReadiness={() => window.vaulta.security.getRecoveryReadiness()}
                onTestRecoveryReadiness={(input) =>
                  window.vaulta.security.testRecoveryReadiness(input)
                }
                onScanIntegrity={(input) => window.vaulta.security.scanIntegrity(input)}
                onSaveIntegrityReport={(input) => window.vaulta.security.saveIntegrityReport(input)}
                onGetBreachListStatus={() => window.vaulta.security.getBreachListStatus()}
                onImportBreachList={(input) => window.vaulta.security.importBreachList(input)}
                onScanBreachList={(input) => window.vaulta.security.scanBreachList(input)}
                onRemoveBreachList={() => window.vaulta.security.removeBreachList()}
                onCancel={(requestId) => window.vaulta.quality.cancelJob({ requestId })}
                onNavigate={changeSection}
                onOpenSettings={(tab) => {
                  changeSection('settings');
                  setSettingsInitialTab(tab);
                }}
                onOpenEntry={(vaultId, entryId) => void openEntryInVault(vaultId, entryId)}
              />
            )}
            {section === 'quality' && (
              <DataQualityViews
                progress={qualityProgress}
                onScanDuplicates={(request) =>
                  window.vaulta.quality.scanDuplicates({ ...request, vaultId: null })
                }
                onDescribeMerge={(request) => window.vaulta.quality.describeDuplicateMerge(request)}
                onMerge={async (request) => {
                  const result = await window.vaulta.quality.mergeDuplicates(request);
                  await Promise.all([loadEntries(), loadSavedViews()]);
                  notify(
                    'success',
                    'Dubletten zusammengeführt',
                    'Der doppelte Eintrag liegt im Papierkorb.',
                  );
                  return result;
                }}
                onTrashCandidate={async (reference) => {
                  await window.vaulta.entries.moveToTrash({
                    vaultId: reference.vaultId,
                    entryId: reference.entryId,
                    updatedAt: reference.updatedAt,
                  });
                  if (reference.vaultId === activeVault.id) await loadEntries();
                  notify('success', 'Eintrag in den Papierkorb verschoben');
                }}
                onScanDataQuality={(request) =>
                  window.vaulta.quality.scanDataQuality({
                    ...request,
                    vaultId: activeVault.id,
                  })
                }
                onPreviewFix={(findingId) =>
                  window.vaulta.quality.previewDataQualityFix({
                    vaultId: activeVault.id,
                    findingId,
                  })
                }
                onApplyFix={async (token) => {
                  const result = await window.vaulta.quality.applyDataQualityFix({ token });
                  await Promise.all([loadEntries(), loadSavedViews(), loadFolders()]);
                  notify('success', 'Datenqualitätskorrektur angewendet');
                  return result;
                }}
                onOpenFinding={(reference) => {
                  const entryId =
                    reference.kind === 'entry'
                      ? reference.entryId
                      : reference.kind === 'attachment'
                        ? reference.entryId
                        : null;
                  if (entryId !== null) openEntry(entryId);
                }}
                onCancel={(requestId) => window.vaulta.quality.cancelJob({ requestId })}
              />
            )}
            {section === 'backup' && (
              <BackupView state={state} notify={notify} onStateChange={onStateChange} />
            )}
            {section === 'import' && (
              <ImportView
                vaultId={activeVault.id}
                notify={notify}
                onImported={(entryIds) => {
                  importedEntryIdsRef.current = [...entryIds];
                }}
                onOpenDuplicates={() => changeSection('quality')}
                onPackageImported={(vaultId) => {
                  changeSection('all');
                  void chooseVault(vaultId);
                }}
              />
            )}
            {section === 'export' && <ExportView state={state} notify={notify} />}
            {section === 'audit' && <AuditView notify={notify} />}
            {section === 'help' && (
              <HelpView
                onOpenSettings={() => {
                  changeSection('settings');
                  setSettingsInitialTab('windows');
                }}
                onOpenRecovery={() => {
                  changeSection('settings');
                  setSettingsInitialTab('factors');
                }}
                onOpenBackups={() => changeSection('backup')}
              />
            )}
            {section === 'settings' && (
              <SettingsView
                state={state}
                notify={notify}
                onStateChange={onStateChange}
                initialTab={settingsInitialTab}
              />
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
            {section === 'reports' && (
              <ReportsView
                report={localReport}
                loading={localReportLoading}
                onEnsureReport={() => void loadLocalReport()}
                onRefresh={() => void loadLocalReport(true)}
                onOpenEntry={openEntry}
              />
            )}
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
          setEntrySelection([saved.id], saved.id);
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
      <Modal
        open={saveViewOpen}
        title="Aktuelle Ansicht speichern"
        description="Gespeichert wird ausschließlich die Filterdefinition, nicht die Ergebnisliste."
        size="small"
        onClose={closeSaveView}
        footer={
          <>
            <Button variant="ghost" onClick={closeSaveView}>
              Abbrechen
            </Button>
            <Button
              variant="primary"
              disabled={saveViewName.trim().length === 0}
              onClick={() => void saveCurrentView()}
            >
              Ansicht speichern
            </Button>
          </>
        }
      >
        <Field label="Name der Ansicht">
          <input
            autoFocus
            value={saveViewName}
            onChange={(event) => setSaveViewName(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                void saveCurrentView();
              }
            }}
          />
        </Field>
      </Modal>
      <SavedViewManager
        open={savedViewManagerOpen}
        views={savedViews}
        onClose={() => setSavedViewManagerOpen(false)}
        onRename={renameSavedView}
        onReorder={reorderSavedViews}
        onDelete={deleteSavedView}
      />
      <TagManager
        open={tagManagerOpen}
        tags={tags}
        onClose={() => setTagManagerOpen(false)}
        onRename={renameTag}
        onMerge={mergeTags}
        onDelete={deleteTag}
      />
      <CommandPalette
        open={commandPaletteOpen}
        commands={commands}
        onClose={() => setCommandPaletteOpen(false)}
      />
      <ShortcutHelp open={shortcutHelpOpen} onClose={() => setShortcutHelpOpen(false)} />
    </main>
  );
}

function LifecycleOverview({
  report,
  loading,
  onShowRotation,
  onShowMissingTwoFactor,
  onOpenSecurity,
}: {
  report: SecurityReport | null;
  loading: boolean;
  onShowRotation: () => void;
  onShowMissingTwoFactor: () => void;
  onOpenSecurity: () => void;
}) {
  const rotationDue =
    report?.findings.filter((finding) => finding.kind === 'rotation-due').length ?? 0;
  const expiryDue =
    report?.findings.filter((finding) => finding.kind === 'expiry-reminder-due').length ?? 0;
  const missingTwoFactor =
    report?.findings.filter((finding) => finding.kind === 'two-factor-missing').length ?? 0;

  return (
    <section className="lifecycle-overview" aria-labelledby="lifecycle-overview-title">
      <div>
        <strong id="lifecycle-overview-title">Lebenszyklus im Blick</strong>
        <span aria-live="polite">
          {loading && report === null
            ? 'Lokale Fälligkeiten werden geprüft.'
            : `${String(rotationDue)} Rotation fällig, ${String(expiryDue)} Ablaufhinweise, ${String(missingTwoFactor)} ohne markierten Zwei-Faktor-Schutz.`}
        </span>
      </div>
      <div className="lifecycle-overview__actions">
        <button type="button" onClick={onShowRotation}>
          Rotation fällig: {String(rotationDue)}
        </button>
        <button type="button" onClick={onShowMissingTwoFactor}>
          Ohne 2FA: {String(missingTwoFactor)}
        </button>
        <Button variant="ghost" onClick={onOpenSecurity}>
          Sicherheitscheck öffnen
        </Button>
      </div>
    </section>
  );
}

function useOffCanvasSidebar(): boolean {
  const query = '(max-width: 1180px)';
  const [matches, setMatches] = useState(
    () => typeof window !== 'undefined' && window.matchMedia?.(query).matches === true,
  );

  useEffect(() => {
    const media = window.matchMedia?.(query);
    if (!media) return;
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  return matches;
}

function isFormControl(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}
