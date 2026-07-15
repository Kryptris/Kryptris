import {
  AlertTriangle,
  Check,
  ChevronLeft,
  CircleAlert,
  Copy,
  Eye,
  EyeOff,
  Info,
  LoaderCircle,
  LockKeyhole,
  Maximize2,
  Minus,
  SearchX,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { ButtonHTMLAttributes, FormEvent, PropsWithChildren, ReactNode } from 'react';
import { useEffect, useId, useRef, useState } from 'react';

import type { ToastMessage } from '../types';

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  busy?: boolean;
  icon?: ReactNode;
}

export function Button({
  variant = 'secondary',
  busy = false,
  icon,
  children,
  disabled,
  className = '',
  ...props
}: ButtonProps) {
  return (
    <button
      className={`button button--${variant} ${className}`}
      disabled={disabled === true || busy}
      {...props}
    >
      {busy ? <LoaderCircle className="spin" aria-hidden="true" /> : icon}
      <span>{children}</span>
    </button>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
  active?: boolean;
}

export function IconButton({
  label,
  active = false,
  className = '',
  children,
  ...props
}: IconButtonProps) {
  return (
    <button
      className={`icon-button ${active ? 'is-active' : ''} ${className}`}
      aria-label={label}
      title={label}
      {...props}
    >
      {children}
    </button>
  );
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? 'brand--compact' : ''}`} aria-label="Vaulta">
      <span className="brand__mark" aria-hidden="true">
        <ShieldCheck />
        <LockKeyhole />
      </span>
      {!compact && <span className="brand__word">Vaulta</span>}
    </div>
  );
}

export function WindowControls() {
  return (
    <div className="window-controls no-drag" aria-label="Fenstersteuerung">
      <IconButton label="Minimieren" onClick={() => void window.vaulta.window.minimize()}>
        <Minus />
      </IconButton>
      <IconButton
        label="Maximieren oder wiederherstellen"
        onClick={() => void window.vaulta.window.toggleMaximize()}
      >
        <Maximize2 />
      </IconButton>
      <IconButton
        label="Vaulta schließen"
        className="window-controls__close"
        onClick={() => void window.vaulta.window.close()}
      >
        <X />
      </IconButton>
    </div>
  );
}

interface ModalProps extends PropsWithChildren {
  open: boolean;
  title: string;
  description?: string;
  size?: 'small' | 'medium' | 'large' | 'wide';
  onClose: () => void;
  footer?: ReactNode;
  closeLabel?: string;
}

export function Modal({
  open,
  title,
  description,
  size = 'medium',
  onClose,
  footer,
  closeLabel = 'Dialog schließen',
  children,
}: ModalProps) {
  const titleId = useId();
  const descriptionId = useId();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    panel?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
      if (event.key !== 'Tab' || !panel) return;
      const controls = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = controls[0];
      const last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first && last) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last && first) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      previouslyFocused?.focus();
    };
  }, [onClose, open]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <div
        className={`modal modal--${size}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        ref={panelRef}
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal__header">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && <p id={descriptionId}>{description}</p>}
          </div>
          <IconButton label={closeLabel} onClick={onClose}>
            <X />
          </IconButton>
        </header>
        <div className="modal__body">{children}</div>
        {footer && <footer className="modal__footer">{footer}</footer>}
      </div>
    </div>
  );
}

interface PasswordConfirmProps {
  open: boolean;
  title: string;
  description: string;
  confirmationLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onClose: () => void;
  onConfirm: (password: string) => Promise<void>;
}

export function PasswordConfirm({
  open,
  title,
  description,
  confirmationLabel = 'Bestätigen',
  danger = false,
  busy = false,
  onClose,
  onConfirm,
}: PasswordConfirmProps) {
  const [password, setPassword] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onConfirm(password).finally(() => setPassword(''));
  };

  const close = () => {
    setPassword('');
    onClose();
  };

  return (
    <Modal open={open} title={title} description={description} size="small" onClose={close}>
      <form className="stack" onSubmit={submit}>
        <Field label="Master-Passwort">
          <PasswordInput
            value={password}
            onChange={setPassword}
            autoFocus
            autoComplete="current-password"
          />
        </Field>
        <div className="modal__inline-actions">
          <Button type="button" variant="ghost" onClick={close}>
            Abbrechen
          </Button>
          <Button
            type="submit"
            variant={danger ? 'danger' : 'primary'}
            disabled={!password}
            busy={busy}
          >
            {confirmationLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

interface FieldProps extends PropsWithChildren {
  label: string;
  hint?: string;
  hintId?: string;
  htmlFor?: string;
  error?: string;
  className?: string;
}

export function Field({
  label,
  hint,
  hintId,
  htmlFor,
  error,
  className = '',
  children,
}: FieldProps) {
  return (
    <label className={`field ${error ? 'field--error' : ''} ${className}`} htmlFor={htmlFor}>
      <span className="field__label">{label}</span>
      {children}
      {hint && (
        <span className="field__hint" id={hintId}>
          {hint}
        </span>
      )}
      {error && <span className="field__error">{error}</span>}
    </label>
  );
}

interface PasswordInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
  name?: string;
  ariaLabel?: string;
  ariaDescribedBy?: string;
}

export function PasswordInput({
  value,
  onChange,
  placeholder,
  autoComplete = 'off',
  autoFocus,
  name,
  ariaLabel,
  ariaDescribedBy,
}: PasswordInputProps) {
  const [visible, setVisible] = useState(false);
  return (
    <span className="input-with-action">
      <input
        type={visible ? 'text' : 'password'}
        value={value}
        name={name}
        placeholder={placeholder}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        aria-label={ariaLabel}
        aria-describedby={ariaDescribedBy}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
      <IconButton
        type="button"
        label={visible ? 'Wert ausblenden' : 'Wert anzeigen'}
        aria-pressed={visible}
        onClick={() => setVisible((current) => !current)}
      >
        {visible ? <EyeOff /> : <Eye />}
      </IconButton>
    </span>
  );
}

export function InlineNotice({
  kind,
  title,
  children,
}: PropsWithChildren<{ kind: ToastMessage['kind']; title?: string }>) {
  const icons = {
    success: <Check />,
    info: <Info />,
    warning: <AlertTriangle />,
    error: <CircleAlert />,
  };
  return (
    <div className={`notice notice--${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span className="notice__icon">{icons[kind]}</span>
      <div>
        {title && <strong>{title}</strong>}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function LoadingState({ label = 'Vaulta wird geladen …' }: { label?: string }) {
  return (
    <div className="loading-state" role="status">
      <LoaderCircle className="spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-state__icon" aria-hidden="true">
        <SearchX />
      </span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function ToastRegion({
  messages,
  onDismiss,
}: {
  messages: ToastMessage[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="toast-region" aria-live="polite" aria-atomic="false">
      {messages.map((message) => (
        <div className={`toast toast--${message.kind}`} key={message.id} role="status">
          <div>
            <strong>{message.title}</strong>
            {message.message && <p>{message.message}</p>}
          </div>
          <IconButton label="Meldung schließen" onClick={() => onDismiss(message.id)}>
            <X />
          </IconButton>
        </div>
      ))}
    </div>
  );
}

export function CopyButton({ label, onCopy }: { label: string; onCopy: () => void }) {
  return (
    <IconButton label={label} onClick={onCopy}>
      <Copy />
    </IconButton>
  );
}

export function BackButton({ onClick, label = 'Zurück' }: { onClick: () => void; label?: string }) {
  return (
    <Button variant="ghost" icon={<ChevronLeft />} onClick={onClick}>
      {label}
    </Button>
  );
}
