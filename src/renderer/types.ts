import type { EntryType, EntryView, SecuritySeverity } from '../shared/models';

export type WorkspaceSection =
  | EntryView
  | 'security'
  | 'quality'
  | 'backup'
  | 'import'
  | 'export'
  | 'audit'
  | 'help'
  | 'settings'
  | 'templates'
  | 'reports';

export interface EntryFilters {
  types: EntryType[];
  tags: string[];
  folderId: string | null;
  security: SecuritySeverity[];
}

export interface ToastMessage {
  id: number;
  kind: 'success' | 'info' | 'warning' | 'error';
  title: string;
  message?: string;
}

export type Notify = (kind: ToastMessage['kind'], title: string, message?: string) => void;
