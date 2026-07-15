import {
  Activity,
  ArchiveRestore,
  Blocks,
  Clock3,
  Download,
  FileBarChart,
  FolderClosed,
  Heart,
  Import,
  LayoutGrid,
  LockKeyhole,
  Settings,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import type { CSSProperties, ReactNode } from 'react';
import { useEffect, useMemo, useState } from 'react';

import { ENTRY_TYPE_LABELS, ENTRY_TYPES } from '../../shared/models';
import type { AppState, EntryType } from '../../shared/models';
import type { WorkspaceSection } from '../types';
import { ENTRY_ACCENTS } from '../utils';
import { EntryIcon } from './EntryIcon';

interface SidebarProps {
  state: AppState;
  section: WorkspaceSection;
  selectedTypes: EntryType[];
  onSectionChange: (section: WorkspaceSection) => void;
  onTypeSelect: (type: EntryType) => void;
  onManageFolders: () => void;
  onManageVaults: () => void;
}

export function Sidebar({
  state,
  section,
  selectedTypes,
  onSectionChange,
  onTypeSelect,
  onManageFolders,
  onManageVaults,
}: SidebarProps) {
  const seconds = useAutoLockSeconds(state.autoLockAt);

  return (
    <aside className="sidebar" aria-label="Hauptnavigation">
      <nav className="sidebar__scroll">
        <div className="nav-group nav-group--primary">
          <NavItem
            label="Alle Einträge"
            icon={<LayoutGrid />}
            active={section === 'all' && selectedTypes.length === 0}
            onClick={() => onSectionChange('all')}
          />
          <NavItem
            label="Favoriten"
            icon={<Heart />}
            active={section === 'favorites'}
            onClick={() => onSectionChange('favorites')}
          />
          <NavItem
            label="Zuletzt verwendet"
            icon={<Clock3 />}
            active={section === 'recent'}
            onClick={() => onSectionChange('recent')}
          />
          <NavItem
            label="Ordner"
            icon={<FolderClosed />}
            active={false}
            onClick={onManageFolders}
          />
          <NavItem
            label="Sicherheitscheck"
            icon={<ShieldCheck />}
            active={section === 'security'}
            onClick={() => onSectionChange('security')}
          />
          <NavItem
            label="Papierkorb"
            icon={<Trash2 />}
            active={section === 'trash'}
            onClick={() => onSectionChange('trash')}
          />
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
