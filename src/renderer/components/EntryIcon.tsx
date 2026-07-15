import {
  BadgeHelp,
  CreditCard,
  FileText,
  IdCard,
  KeyRound,
  Laptop,
  NotebookPen,
  ScrollText,
  Wifi,
} from 'lucide-react';
import type { CSSProperties } from 'react';

import type { EntryType } from '../../shared/models';
import { ENTRY_ACCENTS } from '../utils';

const icons: Record<EntryType, typeof KeyRound> = {
  credential: KeyRound,
  'secure-note': NotebookPen,
  'credit-card': CreditCard,
  identity: IdCard,
  wifi: Wifi,
  'software-license': ScrollText,
  'ssh-key': Laptop,
  file: FileText,
  custom: BadgeHelp,
};

export function EntryIcon({
  type,
  size = 'medium',
}: {
  type: EntryType;
  size?: 'small' | 'medium' | 'large';
}) {
  const Icon = icons[type];
  return (
    <span
      className={`entry-icon entry-icon--${size}`}
      style={{ '--entry-accent': ENTRY_ACCENTS[type] } as CSSProperties}
      aria-hidden="true"
    >
      <Icon />
    </span>
  );
}
