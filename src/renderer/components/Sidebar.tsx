import {
  Activity,
  ArchiveRestore,
  Blocks,
  Bookmark,
  BookmarkPlus,
  CircleHelp,
  Clock3,
  Download,
  FileBarChart,
  FolderClosed,
  Heart,
  Import,
  Keyboard,
  LayoutGrid,
  ListChecks,
  LockKeyhole,
  Settings,
  ShieldCheck,
  Sparkles,
  Tags,
  Trash2,
  Upload,
} from 'lucide-react';
import type { CSSProperties, ReactNode, Ref } from 'react';
import { useEffect, useMemo, useState } from 'react';

import {
  ENTRY_TYPE_LABELS,
  ENTRY_TYPES,
  SMART_VIEW_KINDS,
  SMART_VIEW_LABELS,
} from '../../shared/models';
import type { AppState, EntryType, SavedView, SmartViewKind } from '../../shared/models';
import type { WorkspaceSection } from '../types';
import { ENTRY_ACCENTS } from '../utils';
import { EntryIcon } from './EntryIcon';
import { IconButton } from './ui';

interface SidebarProps {
  state: AppState;
  section: WorkspaceSection;
  selectedTypes: EntryType[];
  savedViews: SavedView[];
  activeSavedViewId: string | null;
  activeSmartView: SmartViewKind | null;
  onSectionChange: (section: WorkspaceSection) => void;
  onTypeSelect: (type: EntryType) => void;
  onSavedViewSelect: (view: SavedView) => void;
  onSmartViewSelect: (view: SmartViewKind) => void;
  onSaveCurrentView: () => void;
  onManageSavedViews: () => void;
  onManageTags: () => void;
  onShowShortcuts: () => void;
  onManageFolders: () => void;
  onManageVaults: () => void;
  offCanvas?: boolean;
  sidebarRef?: Ref<HTMLElement>;
  onDismiss?: () => void;
}

export function Sidebar({
  state,
  section,
  selectedTypes,
  savedViews,
  activeSavedViewId,
  activeSmartView,
  onSectionChange,
  onTypeSelect,
  onSavedViewSelect,
  onSmartViewSelect,
  onSaveCurrentView,
  onManageSavedViews,
  onManageTags,
  onShowShortcuts,
  onManageFolders,
  onManageVaults,
  offCanvas = false,
  sidebarRef,
  onDismiss,
}: SidebarProps) {
  const seconds = useAutoLockSeconds(state.autoLockAt);

  return (
    <aside
      ref={sidebarRef}
      className="sidebar"
      aria-label="Hauptnavigation"
      aria-hidden={offCanvas || undefined}
      inert={offCanvas || undefined}
      onKeyDown={(event) => {
        if (offCanvas && event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          onDismiss?.();
        }
      }}
    >
      <nav className="sidebar__scroll">
        <div className="nav-group nav-group--primary">
          <NavItem
            label="Alle Einträge"
            icon={<LayoutGrid />}
            active={
              section === 'all' &&
              selectedTypes.length === 0 &&
              activeSavedViewId === null &&
              activeSmartView === null
            }
            onClick={() => onSectionChange('all')}
          />
          <NavItem
            label="Favoriten"
            icon={<Heart />}
            active={
              section === 'favorites' && activeSavedViewId === null && activeSmartView === null
            }
            onClick={() => onSectionChange('favorites')}
          />
          <NavItem
            label="Zuletzt verwendet"
            icon={<Clock3 />}
            active={section === 'recent' && activeSavedViewId === null && activeSmartView === null}
            onClick={() => onSectionChange('recent')}
          />
          <NavItem
            label="Ordner"
            icon={<FolderClosed />}
            active={false}
            onClick={onManageFolders}
          />
          <NavItem
            label="Sicherheitszentrale"
            icon={<ShieldCheck />}
            active={section === 'security'}
            onClick={() => onSectionChange('security')}
          />
          <NavItem
            label="Datenpflege"
            icon={<ListChecks />}
            active={section === 'quality'}
            onClick={() => onSectionChange('quality')}
          />
          <NavItem
            label="Papierkorb"
            icon={<Trash2 />}
            active={section === 'trash' && activeSavedViewId === null && activeSmartView === null}
            onClick={() => onSectionChange('trash')}
          />
        </div>

        <div className="nav-heading">
          <span>Intelligente Ansichten</span>
        </div>
        <div className="nav-group nav-group--compact">
          {SMART_VIEW_KINDS.map((view) => (
            <NavItem
              key={view}
              label={SMART_VIEW_LABELS[view]}
              icon={<Sparkles />}
              active={activeSmartView === view && activeSavedViewId === null}
              onClick={() => onSmartViewSelect(view)}
            />
          ))}
        </div>

        <div className="nav-heading nav-heading--actions">
          <span>Gespeicherte Ansichten</span>
          <span className="nav-heading__actions">
            <IconButton label="Aktuelle Ansicht speichern" onClick={onSaveCurrentView}>
              <BookmarkPlus />
            </IconButton>
            <IconButton label="Gespeicherte Ansichten verwalten" onClick={onManageSavedViews}>
              <Settings />
            </IconButton>
          </span>
        </div>
        <div className="nav-group nav-group--compact saved-view-nav">
          {savedViews.length === 0 ? (
            <p>Noch keine gespeicherte Ansicht</p>
          ) : (
            savedViews.map((view) => (
              <NavItem
                key={view.id}
                label={view.name}
                icon={<Bookmark />}
                active={activeSavedViewId === view.id}
                onClick={() => onSavedViewSelect(view)}
              />
            ))
          )}
        </div>

        <div className="nav-heading">
          <span>Kategorien</span>
          <button type="button" onClick={() => onSectionChange('all')}>
            Alle
          </button>
        </div>
        <div className="category-list">
          {ENTRY_TYPES.map((type) => (
            <button
              type="button"
              key={type}
              className={selectedTypes.includes(type) && section === 'all' ? 'is-active' : ''}
              style={{ '--category-color': ENTRY_ACCENTS[type] } as CSSProperties}
              onClick={() => onTypeSelect(type)}
            >
              <EntryIcon type={type} size="small" />
              <span>{ENTRY_TYPE_LABELS[type]}</span>
            </button>
          ))}
        </div>

        <div className="nav-heading">
          <span>Werkzeuge</span>
        </div>
        <div className="nav-group nav-group--tools">
          <NavItem
            label="Backups & Wiederherstellung"
            icon={<ArchiveRestore />}
            active={section === 'backup'}
            onClick={() => onSectionChange('backup')}
          />
          <NavItem
            label="Import"
            icon={<Import />}
            active={section === 'import'}
            onClick={() => onSectionChange('import')}
          />
          <NavItem
            label="Export"
            icon={<Upload />}
            active={section === 'export'}
            onClick={() => onSectionChange('export')}
          />
          <NavItem
            label="Aktivitätsprotokoll"
            icon={<Activity />}
            active={section === 'audit'}
            onClick={() => onSectionChange('audit')}
          />
          <NavItem
            label="Eigene Vorlagen"
            icon={<Blocks />}
            active={section === 'templates'}
            onClick={() => onSectionChange('templates')}
          />
          <NavItem
            label="Lokale Berichte"
            icon={<FileBarChart />}
            active={section === 'reports'}
            onClick={() => onSectionChange('reports')}
          />
          <NavItem
            label="Tresore verwalten"
            icon={<Download />}
            active={false}
            onClick={onManageVaults}
          />
          <NavItem label="Tags verwalten" icon={<Tags />} active={false} onClick={onManageTags} />
          <NavItem
            label="Tastaturhilfe"
            icon={<Keyboard />}
            active={false}
            onClick={onShowShortcuts}
          />
          <NavItem
            label="Hilfe & Datenschutz"
            icon={<CircleHelp />}
            active={section === 'help'}
            onClick={() => onSectionChange('help')}
          />
        </div>
      </nav>

      <div className="sidebar__footer">
        <button
          type="button"
          className="auto-lock"
          onClick={() => void window.vaulta.system.lock()}
          aria-label={`Jetzt sperren. Automatische Sperre in ${formatCountdown(seconds)}`}
        >
          <span
            className="auto-lock__ring"
            style={
              {
                '--progress': `${String(
                  Math.max(
                    0,
                    Math.min(
                      360,
                      (seconds / Math.max(1, state.settings?.autoLockSeconds ?? 300)) * 360,
                    ),
                  ),
                )}deg`,
              } as CSSProperties
            }
          >
            <LockKeyhole />
          </span>
          <span>
            <small>Tresor automatisch gesperrt in</small>
            <strong>{formatCountdown(seconds)}</strong>
          </span>
        </button>
        <button
          type="button"
          className={`sidebar-settings ${section === 'settings' ? 'is-active' : ''}`}
          onClick={() => onSectionChange('settings')}
        >
          <Settings />
          Einstellungen
        </button>
      </div>
    </aside>
  );
}

function NavItem({
  label,
  icon,
  active,
  onClick,
}: {
  label: string;
  icon: ReactNode;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`nav-item ${active ? 'is-active' : ''}`}
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

function useAutoLockSeconds(autoLockAt: string | null): number {
  const calculate = useMemo(
    () => () =>
      autoLockAt ? Math.max(0, Math.ceil((Date.parse(autoLockAt) - Date.now()) / 1000)) : 0,
    [autoLockAt],
  );
  const [seconds, setSeconds] = useState(calculate);

  useEffect(() => {
    const timer = window.setInterval(() => setSeconds(calculate()), 1000);
    return () => window.clearInterval(timer);
  }, [calculate]);

  return seconds;
}

function formatCountdown(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(remaining).padStart(2, '0')}`;
}
