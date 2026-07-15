import {
  ArrowDownAZ,
  Check,
  ChevronDown,
  Filter,
  ListFilter,
  Plus,
  SlidersHorizontal,
  Star,
  X,
} from 'lucide-react';
import { useMemo, useState } from 'react';

import {
  ENTRY_TYPE_LABELS,
  ENTRY_TYPES,
  type EntrySummary,
  type EntryType,
  type Folder,
  type SecuritySeverity,
} from '../../shared/models';
import type { EntryFilters, WorkspaceSection } from '../types';
import { EntryIcon } from './EntryIcon';
import { Button, EmptyState, IconButton, LoadingState } from './ui';

interface EntryListProps {
  section: WorkspaceSection;
  entries: EntrySummary[];
  selectedEntryId: string | null;
  filters: EntryFilters;
  loading: boolean;
  knownFolders: Folder[];
  onFiltersChange: (filters: EntryFilters) => void;
  onSelect: (entry: EntrySummary) => void;
  onNew: () => void;
  onToggleFavorite: (entry: EntrySummary) => void;
}

type SortMode = 'title' | 'updated' | 'security';

const SECTION_TITLES: Partial<Record<WorkspaceSection, string>> = {
  all: 'Alle Einträge',
  favorites: 'Favoriten',
  recent: 'Zuletzt verwendet',
  trash: 'Papierkorb',
};

const severityOrder: Record<SecuritySeverity, number> = {
  critical: 0,
  warning: 1,
  info: 2,
  good: 3,
};

export function EntryList({
  section,
  entries,
  selectedEntryId,
  filters,
  loading,
  knownFolders,
  onFiltersChange,
  onSelect,
  onNew,
  onToggleFavorite,
}: EntryListProps) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [sort, setSort] = useState<SortMode>('updated');
  const [sortOpen, setSortOpen] = useState(false);

  const sorted = useMemo(() => {
    const values = [...entries];
    values.sort((left, right) => {
      if (sort === 'title') return left.title.localeCompare(right.title, 'de');
      if (sort === 'security') {
        return severityOrder[left.securityState] - severityOrder[right.securityState];
      }
      return Date.parse(right.updatedAt) - Date.parse(left.updatedAt);
    });
    return values;
  }, [entries, sort]);

  const knownTags = useMemo(
    () =>
      [...new Set(entries.flatMap((entry) => entry.tags))].sort((a, b) => a.localeCompare(b, 'de')),
    [entries],
  );
  const filterCount =
    filters.types.length +
    filters.tags.length +
    filters.security.length +
    (filters.folderId ? 1 : 0);

  return (
    <section className="entry-list-panel" aria-label="Eintragsliste">
      <header className="entry-list-panel__header">
        <div>
          <button className="list-title" type="button">
            {SECTION_TITLES[section] ?? 'Einträge'}
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="entry-count">{String(entries.length)}</span>
        </div>
        <div className="entry-list-panel__tools">
          <div className="popover-anchor">
            <IconButton
              label="Einträge filtern"
              active={filterCount > 0 || filtersOpen}
              aria-expanded={filtersOpen}
              onClick={() => setFiltersOpen((current) => !current)}
            >
              <SlidersHorizontal />
              {filterCount > 0 && <span className="icon-button__badge">{filterCount}</span>}
            </IconButton>
            {filtersOpen && (
              <FilterPopover
                filters={filters}
                knownTags={knownTags}
                knownFolders={knownFolders}
                onChange={onFiltersChange}
                onClose={() => setFiltersOpen(false)}
              />
            )}
          </div>
          <div className="popover-anchor">
            <IconButton
              label="Sortierung ändern"
              aria-expanded={sortOpen}
              onClick={() => setSortOpen((current) => !current)}
            >
              <ArrowDownAZ />
            </IconButton>
            {sortOpen && (
              <div className="popover-menu popover-menu--compact" role="menu">
                {(
                  [
                    ['updated', 'Zuletzt geändert'],
                    ['title', 'Titel A–Z'],
                    ['security', 'Sicherheitszustand'],
                  ] as Array<[SortMode, string]>
                ).map(([value, label]) => (
                  <button
                    type="button"
                    role="menuitemradio"
                    aria-checked={sort === value}
                    key={value}
                    onClick={() => {
                      setSort(value);
                      setSortOpen(false);
                    }}
                  >
                    {sort === value ? <Check /> : <span />}
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </header>

      {loading ? (
        <LoadingState label="Einträge werden entschlüsselt …" />
      ) : sorted.length === 0 ? (
        <EmptyState
          title={section === 'trash' ? 'Papierkorb ist leer' : 'Keine Einträge gefunden'}
          description={
            filterCount > 0
              ? 'Passe deine Filter an oder setze sie zurück.'
              : section === 'trash'
                ? 'Gelöschte Einträge erscheinen hier und können wiederhergestellt werden.'
                : 'Lege deinen ersten sicheren Eintrag in diesem Tresor an.'
          }
          action={
            section !== 'trash' && filterCount === 0 ? (
              <Button variant="primary" icon={<Plus />} onClick={onNew}>
                Neuer Eintrag
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="entry-list" role="listbox" aria-label="Tresoreinträge">
          {sorted.map((entry) => (
            <div
              className={`entry-row ${selectedEntryId === entry.id ? 'is-selected' : ''}`}
              role="option"
              aria-selected={selectedEntryId === entry.id}
              tabIndex={0}
              key={entry.id}
              onClick={() => onSelect(entry)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  onSelect(entry);
                }
              }}
            >
              <EntryIcon type={entry.type} />
              <span className="entry-row__text">
                <strong>{entry.title}</strong>
                <small>{entry.subtitle || ENTRY_TYPE_LABELS[entry.type]}</small>
                {entry.tags.length > 0 && (
                  <span className="entry-row__tags">
                    {entry.tags.slice(0, 2).map((tag) => (
                      <span key={tag}>{tag}</span>
                    ))}
                  </span>
                )}
              </span>
              <span
                className={`security-dot security-dot--${entry.securityState}`}
                title={`Sicherheitszustand: ${entry.securityState}`}
              />
              <IconButton
                label={entry.favorite ? 'Aus Favoriten entfernen' : 'Zu Favoriten hinzufügen'}
                active={entry.favorite}
                onClick={(event) => {
                  event.stopPropagation();
                  onToggleFavorite(entry);
                }}
              >
                <Star fill={entry.favorite ? 'currentColor' : 'none'} />
              </IconButton>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function FilterPopover({
  filters,
  knownTags,
  knownFolders,
  onChange,
  onClose,
}: {
  filters: EntryFilters;
  knownTags: string[];
  knownFolders: Folder[];
  onChange: (filters: EntryFilters) => void;
  onClose: () => void;
}) {
  const toggleType = (type: EntryType) => {
    onChange({
      ...filters,
      types: filters.types.includes(type)
        ? filters.types.filter((value) => value !== type)
        : [...filters.types, type],
    });
  };
  const toggleSecurity = (security: SecuritySeverity) => {
    onChange({
      ...filters,
      security: filters.security.includes(security)
        ? filters.security.filter((value) => value !== security)
        : [...filters.security, security],
    });
  };
  const toggleTag = (tag: string) => {
    onChange({
      ...filters,
      tags: filters.tags.includes(tag)
        ? filters.tags.filter((value) => value !== tag)
        : [...filters.tags, tag],
    });
  };

  return (
    <div className="filter-popover" role="dialog" aria-label="Filter">
      <header>
        <div>
          <Filter />
          <strong>Einträge filtern</strong>
        </div>
        <IconButton label="Filter schließen" onClick={onClose}>
          <X />
        </IconButton>
      </header>
      <fieldset>
        <legend>Typ</legend>
        <div className="filter-chip-grid">
          {ENTRY_TYPES.map((type) => (
            <button
              type="button"
              aria-pressed={filters.types.includes(type)}
              className={filters.types.includes(type) ? 'is-active' : ''}
              key={type}
              onClick={() => toggleType(type)}
            >
              {ENTRY_TYPE_LABELS[type]}
            </button>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Sicherheitszustand</legend>
        <div className="filter-chip-grid">
          {(
            [
              ['critical', 'Kritisch'],
              ['warning', 'Warnung'],
              ['info', 'Hinweis'],
              ['good', 'Gut'],
            ] as Array<[SecuritySeverity, string]>
          ).map(([value, label]) => (
            <button
              type="button"
              aria-pressed={filters.security.includes(value)}
              className={filters.security.includes(value) ? 'is-active' : ''}
              key={value}
              onClick={() => toggleSecurity(value)}
            >
              {label}
            </button>
          ))}
        </div>
      </fieldset>
      {knownFolders.length > 0 && (
        <fieldset>
          <legend>Ordner</legend>
          <select
            value={filters.folderId ?? ''}
            onChange={(event) =>
              onChange({ ...filters, folderId: event.currentTarget.value || null })
            }
          >
            <option value="">Alle Ordner</option>
            {knownFolders.map((folder) => (
              <option value={folder.id} key={folder.id}>
                {folder.name}
              </option>
            ))}
          </select>
        </fieldset>
      )}
      {knownTags.length > 0 && (
        <fieldset>
          <legend>Tags</legend>
          <div className="filter-chip-grid">
            {knownTags.map((tag) => (
              <button
                type="button"
                aria-pressed={filters.tags.includes(tag)}
                className={filters.tags.includes(tag) ? 'is-active' : ''}
                key={tag}
                onClick={() => toggleTag(tag)}
              >
                {tag}
              </button>
            ))}
          </div>
        </fieldset>
      )}
      <footer>
        <Button
          variant="ghost"
          icon={<ListFilter />}
          onClick={() => onChange({ types: [], tags: [], folderId: null, security: [] })}
        >
          Zurücksetzen
        </Button>
        <Button variant="primary" onClick={onClose}>
          Anwenden
        </Button>
      </footer>
    </div>
  );
}
