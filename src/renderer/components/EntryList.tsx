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
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

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
  primaryEntryId: string | null;
  selectedEntryIds: string[];
  filters: EntryFilters;
  loading: boolean;
  knownFolders: Folder[];
  focusMode: boolean;
  toolbar?: ReactNode;
  onFiltersChange: (filters: EntryFilters) => void;
  onSelectionChange: (entryIds: string[], primaryEntryId: string | null) => void;
  onNew: () => void;
  onToggleFavorite: (entry: EntrySummary) => void;
}

type SortMode = 'title' | 'updated' | 'security';

const VIRTUAL_ROW_HEIGHT = 90;
const VIRTUAL_OVERSCAN = 8;
const FALLBACK_VIEWPORT_HEIGHT = 540;

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
  primaryEntryId,
  selectedEntryIds,
  filters,
  loading,
  knownFolders,
  focusMode,
  toolbar,
  onFiltersChange,
  onSelectionChange,
  onNew,
  onToggleFavorite,
}: EntryListProps) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [sort, setSort] = useState<SortMode>('updated');
  const [sortOpen, setSortOpen] = useState(false);
  const [selectionAnchorId, setSelectionAnchorId] = useState<string | null>(null);
  const [focusedEntryId, setFocusedEntryId] = useState<string | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(FALLBACK_VIEWPORT_HEIGHT);
  const listRef = useRef<HTMLDivElement>(null);
  const rowRefs = useRef(new Map<string, HTMLDivElement>());
  const pendingFocusEntryId = useRef<string | null>(null);
  const previousPrimaryEntryId = useRef<string | null>(null);

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
  const sortedIndexById = useMemo(
    () => new Map(sorted.map((entry, index) => [entry.id, index])),
    [sorted],
  );

  const knownTags = useMemo(
    () =>
      focusMode
        ? []
        : [...new Set(entries.flatMap((entry) => entry.tags))].sort((a, b) =>
            a.localeCompare(b, 'de'),
          ),
    [entries, focusMode],
  );
  const filterCount =
    filters.types.length +
    filters.tags.length +
    filters.security.length +
    (filters.folderId ? 1 : 0);
  const selectedSet = useMemo(() => new Set(selectedEntryIds), [selectedEntryIds]);
  const allVisibleSelected =
    sorted.length > 0 && sorted.every((entry) => selectedSet.has(entry.id));
  const preferredFocusEntryId =
    focusedEntryId !== null && sortedIndexById.has(focusedEntryId)
      ? focusedEntryId
      : primaryEntryId !== null && sortedIndexById.has(primaryEntryId)
        ? primaryEntryId
        : (sorted[0]?.id ?? null);
  const maxScrollTop = Math.max(0, sorted.length * VIRTUAL_ROW_HEIGHT - viewportHeight);
  const effectiveScrollTop = Math.min(scrollTop, maxScrollTop);

  const virtualRange = useMemo(() => {
    const firstVisibleIndex = Math.min(
      Math.max(0, sorted.length - 1),
      Math.floor(effectiveScrollTop / VIRTUAL_ROW_HEIGHT),
    );
    const visibleRows = Math.ceil(viewportHeight / VIRTUAL_ROW_HEIGHT);
    const start = Math.max(0, firstVisibleIndex - VIRTUAL_OVERSCAN);
    const end = Math.min(sorted.length, firstVisibleIndex + visibleRows + VIRTUAL_OVERSCAN);
    return { start, end };
  }, [effectiveScrollTop, sorted.length, viewportHeight]);
  const preferredFocusIndex =
    preferredFocusEntryId === null ? undefined : sortedIndexById.get(preferredFocusEntryId);
  const rovingFocusEntryId =
    preferredFocusIndex !== undefined &&
    preferredFocusIndex >= virtualRange.start &&
    preferredFocusIndex < virtualRange.end
      ? preferredFocusEntryId
      : (sorted[virtualRange.start]?.id ?? null);

  const scrollEntryIntoView = useCallback(
    (index: number) => {
      const list = listRef.current;
      if (!list) return;
      const currentScrollTop = list.scrollTop;
      const currentViewportHeight = list.clientHeight || viewportHeight;
      const rowTop = index * VIRTUAL_ROW_HEIGHT;
      const rowBottom = rowTop + VIRTUAL_ROW_HEIGHT;
      const nextScrollTop =
        rowTop < currentScrollTop
          ? rowTop
          : rowBottom > currentScrollTop + currentViewportHeight
            ? rowBottom - currentViewportHeight
            : currentScrollTop;
      if (nextScrollTop === currentScrollTop) return;
      list.scrollTop = nextScrollTop;
      window.requestAnimationFrame(() => setScrollTop(nextScrollTop));
    },
    [viewportHeight],
  );

  useLayoutEffect(() => {
    const list = listRef.current;
    if (!list) return;
    const updateViewportHeight = () => {
      setViewportHeight(list.clientHeight || FALLBACK_VIEWPORT_HEIGHT);
    };
    updateViewportHeight();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateViewportHeight);
      return () => window.removeEventListener('resize', updateViewportHeight);
    }
    const observer = new ResizeObserver(updateViewportHeight);
    observer.observe(list);
    return () => observer.disconnect();
  }, [sorted.length]);

  useEffect(() => {
    const list = listRef.current;
    if (scrollTop <= maxScrollTop || !list) return;
    list.scrollTop = maxScrollTop;
  }, [maxScrollTop, scrollTop]);

  useLayoutEffect(() => {
    if (primaryEntryId === null) {
      previousPrimaryEntryId.current = null;
      return;
    }
    const index = sortedIndexById.get(primaryEntryId);
    if (
      index === undefined ||
      listRef.current === null ||
      primaryEntryId === previousPrimaryEntryId.current
    ) {
      return;
    }
    previousPrimaryEntryId.current = primaryEntryId;
    scrollEntryIntoView(index);
  }, [primaryEntryId, scrollEntryIntoView, sortedIndexById]);

  useLayoutEffect(() => {
    const entryId = pendingFocusEntryId.current;
    if (entryId === null) return;
    const row = rowRefs.current.get(entryId);
    if (!row) return;
    row.focus();
    pendingFocusEntryId.current = null;
  });

  const selectEntry = (
    entry: EntrySummary,
    options: { toggle: boolean; range: boolean } = { toggle: false, range: false },
  ) => {
    setFocusedEntryId(entry.id);
    if (options.range && selectionAnchorId !== null) {
      const anchorIndex = sortedIndexById.get(selectionAnchorId);
      const currentIndex = sortedIndexById.get(entry.id);
      if (anchorIndex !== undefined && currentIndex !== undefined) {
        const [start, end] =
          anchorIndex <= currentIndex ? [anchorIndex, currentIndex] : [currentIndex, anchorIndex];
        const rangeIds = sorted.slice(start, end + 1).map((item) => item.id);
        const next = options.toggle ? [...new Set([...selectedEntryIds, ...rangeIds])] : rangeIds;
        onSelectionChange(next, entry.id);
        return;
      }
    }
    setSelectionAnchorId(entry.id);
    if (options.toggle) {
      const next = selectedSet.has(entry.id)
        ? selectedEntryIds.filter((id) => id !== entry.id)
        : [...selectedEntryIds, entry.id];
      onSelectionChange(next, next.includes(entry.id) ? entry.id : (next[0] ?? null));
      return;
    }
    onSelectionChange([entry.id], entry.id);
  };

  const focusEntryAt = (index: number, selectRange: boolean) => {
    const target = sorted[index];
    if (target === undefined) return;
    setFocusedEntryId(target.id);
    pendingFocusEntryId.current = target.id;
    scrollEntryIntoView(index);
    if (selectRange) selectEntry(target, { toggle: false, range: true });
  };

  return (
    <section className="entry-list-panel" aria-label="Eintragsliste">
      <header className="entry-list-panel__header">
        <div>
          <button className="list-title" type="button">
            {SECTION_TITLES[section] ?? 'Einträge'}
            <ChevronDown aria-hidden="true" />
          </button>
          <span className="entry-count">{String(entries.length)}</span>
          {entries.length > 0 && (
            <button
              type="button"
              className="select-visible"
              aria-pressed={allVisibleSelected}
              onClick={() => {
                const next = allVisibleSelected ? [] : sorted.map((entry) => entry.id);
                onSelectionChange(next, next[0] ?? null);
                setSelectionAnchorId(next[0] ?? null);
              }}
            >
              {allVisibleSelected ? 'Auswahl aufheben' : 'Alle sichtbaren auswählen'}
            </button>
          )}
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

      {toolbar}

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
        <div
          ref={listRef}
          className="entry-list entry-list--virtual"
          role="listbox"
          aria-label="Tresoreinträge"
          aria-multiselectable="true"
          aria-busy={loading}
          onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        >
          <div
            className="entry-list__spacer"
            style={{ height: `${String(sorted.length * VIRTUAL_ROW_HEIGHT)}px` }}
          >
            {sorted.slice(virtualRange.start, virtualRange.end).map((entry, visibleIndex) => {
              const index = virtualRange.start + visibleIndex;
              return (
                <div
                  className={`entry-row ${primaryEntryId === entry.id ? 'is-primary' : ''} ${selectedSet.has(entry.id) ? 'is-selected' : ''}`}
                  role="option"
                  aria-selected={selectedSet.has(entry.id)}
                  aria-current={primaryEntryId === entry.id ? 'true' : undefined}
                  aria-posinset={index + 1}
                  aria-setsize={sorted.length}
                  tabIndex={rovingFocusEntryId === entry.id ? 0 : -1}
                  key={entry.id}
                  style={{ transform: `translateY(${String(index * VIRTUAL_ROW_HEIGHT)}px)` }}
                  ref={(element) => {
                    if (element === null) rowRefs.current.delete(entry.id);
                    else rowRefs.current.set(entry.id, element);
                  }}
                  onFocus={() => setFocusedEntryId(entry.id)}
                  onClick={(event) =>
                    selectEntry(entry, {
                      toggle: event.ctrlKey || event.metaKey,
                      range: event.shiftKey,
                    })
                  }
                  onKeyDown={(event) => {
                    if (event.target !== event.currentTarget) return;
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      selectEntry(entry, {
                        toggle: event.ctrlKey || event.metaKey,
                        range: event.shiftKey,
                      });
                      return;
                    }
                    const targetIndex =
                      event.key === 'ArrowDown'
                        ? Math.min(sorted.length - 1, index + 1)
                        : event.key === 'ArrowUp'
                          ? Math.max(0, index - 1)
                          : event.key === 'Home'
                            ? 0
                            : event.key === 'End'
                              ? sorted.length - 1
                              : null;
                    if (targetIndex === null) return;
                    event.preventDefault();
                    focusEntryAt(targetIndex, event.shiftKey);
                  }}
                >
                  <input
                    type="checkbox"
                    className="entry-row__select"
                    aria-label={`${entry.title} auswählen`}
                    checked={selectedSet.has(entry.id)}
                    onChange={() => selectEntry(entry, { toggle: true, range: false })}
                    onClick={(event) => event.stopPropagation()}
                  />
                  <EntryIcon type={entry.type} />
                  <span className="entry-row__text">
                    <strong>{entry.title}</strong>
                    {!focusMode && <small>{entry.subtitle || ENTRY_TYPE_LABELS[entry.type]}</small>}
                    {!focusMode && entry.tags.length > 0 && (
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
              );
            })}
          </div>
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
