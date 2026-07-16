import { startRegistration } from '@simplewebauthn/browser';
import {
  ArchiveRestore,
  Check,
  Clipboard,
  Fingerprint,
  HardDrive,
  KeyRound,
  LockKeyhole,
  Plus,
  Save,
  Settings,
  Smartphone,
  Trash2,
} from 'lucide-react';
import type { FormEvent } from 'react';
import { useEffect, useState } from 'react';

import {
  DEFAULT_SETTINGS,
  type AppState,
  type FactorStatus,
  type RecoveryRotationStarted,
  type VaultaSettings,
} from '../../shared/models';
import { isSecurityWeakeningSettingsChange } from '../../shared/settings-security';
import type { Notify } from '../types';
import { formatDate, getErrorMessage } from '../utils';
import {
  Button,
  Field,
  IconButton,
  InlineNotice,
  LoadingState,
  Modal,
  PasswordConfirm,
  PasswordInput,
} from './ui';

type SettingsTab = 'security' | 'clipboard' | 'backup' | 'factors' | 'advanced';

interface TotpSetup {
  setupId: string;
  secret: string;
  uri: string;
  qrDataUrl: string;
  explanation: string;
}

export function SettingsView({
  state,
  notify,
  onStateChange,
}: {
  state: AppState;
  notify: Notify;
  onStateChange: (state: AppState) => void;
}) {
  const [tab, setTab] = useState<SettingsTab>('security');
  const [draft, setDraft] = useState<VaultaSettings>(state.settings ?? DEFAULT_SETTINGS);
  const [savedSettings, setSavedSettings] = useState<VaultaSettings>(
    state.settings ?? DEFAULT_SETTINGS,
  );
  const [factors, setFactors] = useState<FactorStatus>(state.factorStatus);
  const [loading, setLoading] = useState(!state.settings);
  const [busy, setBusy] = useState(false);
  const [settingsPasswordOpen, setSettingsPasswordOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [totpPasswordOpen, setTotpPasswordOpen] = useState(false);
  const [totpRemoveOpen, setTotpRemoveOpen] = useState(false);
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [keySetupOpen, setKeySetupOpen] = useState(false);
  const [keyRemoveId, setKeyRemoveId] = useState<string | null>(null);
  const [recoveryPasswordOpen, setRecoveryPasswordOpen] = useState(false);
  const [recovery, setRecovery] = useState<RecoveryRotationStarted | null>(null);

  useEffect(() => {
    if (state.settings) {
      setDraft(state.settings);
      setSavedSettings(state.settings);
      return;
    }
    let active = true;
    void window.vaulta.settings
      .get()
      .then((settings) => {
        if (active) {
          setDraft(settings);
          setSavedSettings(settings);
        }
      })
      .catch((error: unknown) =>
        notify('error', 'Einstellungen konnten nicht geladen werden', getErrorMessage(error)),
      )
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [notify, state.settings]);

  const refreshFactors = async () => {
    const next = await window.vaulta.factors.status();
    setFactors(next);
    const nextState = await window.vaulta.system.getState();
    onStateChange(nextState);
  };

  const save = async (masterPassword?: string): Promise<boolean> => {
    setBusy(true);
    try {
      const settings = await window.vaulta.settings.update({
        settings: draft,
        ...(masterPassword === undefined ? {} : { masterPassword }),
      });
      setDraft(settings);
      setSavedSettings(settings);
      onStateChange({ ...state, settings });
      notify('success', 'Einstellungen gespeichert');
      return true;
    } catch (error: unknown) {
      notify('error', 'Einstellungen konnten nicht gespeichert werden', getErrorMessage(error));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const requestSave = () => {
    if (isSecurityWeakeningSettingsChange(savedSettings, draft)) {
      setSettingsPasswordOpen(true);
      return;
    }
    void save();
  };

  if (loading)
    return (
      <section className="tool-view">
        <LoadingState label="Einstellungen laden …" />
      </section>
    );

  return (
    <section className="tool-view settings-view" aria-labelledby="settings-title">
      <header className="tool-view__header">
        <div>
          <span className="tool-view__icon">
            <Settings />
          </span>
          <div>
            <p className="eyebrow">Lokal auf diesem Gerät</p>
            <h1 id="settings-title">Einstellungen</h1>
            <p>Sperrverhalten, Zwischenablage, Backups und zusätzliche Faktoren verwalten.</p>
          </div>
        </div>
        <Button variant="primary" icon={<Save />} busy={busy} onClick={requestSave}>
          Speichern
        </Button>
      </header>
      <div className="settings-layout">
        <nav className="settings-tabs" aria-label="Einstellungsbereiche">
          <SettingsTabButton
            value="security"
            current={tab}
            icon={<LockKeyhole />}
            label="Sicherheit"
            onSelect={setTab}
          />
          <SettingsTabButton
            value="clipboard"
            current={tab}
            icon={<Clipboard />}
            label="Zwischenablage"
            onSelect={setTab}
          />
          <SettingsTabButton
            value="backup"
            current={tab}
            icon={<ArchiveRestore />}
            label="Backups"
            onSelect={setTab}
          />
          <SettingsTabButton
            value="factors"
            current={tab}
            icon={<Fingerprint />}
            label="Zugang & Faktoren"
            onSelect={setTab}
          />
          <SettingsTabButton
            value="advanced"
            current={tab}
            icon={<HardDrive />}
            label="Erweitert"
            onSelect={setTab}
          />
        </nav>
        <div className="settings-content">
          {tab === 'security' && (
            <SecuritySettings
              draft={draft}
              setDraft={setDraft}
              onChangePassword={() => setChangePasswordOpen(true)}
            />
          )}
          {tab === 'clipboard' && <ClipboardSettings draft={draft} setDraft={setDraft} />}
          {tab === 'backup' && <BackupSettings draft={draft} setDraft={setDraft} notify={notify} />}
          {tab === 'factors' && (
            <FactorsSettings
              factors={factors}
              onAddTotp={() => setTotpPasswordOpen(true)}
              onRemoveTotp={() => setTotpRemoveOpen(true)}
              onAddKey={() => setKeySetupOpen(true)}
              onRemoveKey={setKeyRemoveId}
              onRotateRecovery={() => setRecoveryPasswordOpen(true)}
            />
          )}
          {tab === 'advanced' && <AdvancedSettings draft={draft} setDraft={setDraft} />}
        </div>
      </div>

      <PasswordConfirm
        open={settingsPasswordOpen}
        title="Sicherheitseinstellungen abschwächen?"
        description="Bestätige dein Master-Passwort, bevor Schutzfristen verlängert oder Schutzfunktionen deaktiviert werden."
        confirmationLabel="Einstellungen speichern"
        busy={busy}
        onClose={() => setSettingsPasswordOpen(false)}
        onConfirm={async (masterPassword) => {
          if (await save(masterPassword)) setSettingsPasswordOpen(false);
        }}
      />
      <ChangeMasterPassword
        open={changePasswordOpen}
        notify={notify}
        onClose={() => setChangePasswordOpen(false)}
      />
      <PasswordConfirm
        open={totpPasswordOpen}
        title="TOTP-Zugangssperre einrichten"
        description="Bestätige dein Master-Passwort. TOTP ist eine lokale Zusatzsperre, kein gleichwertiger kryptografischer Faktor."
        onClose={() => setTotpPasswordOpen(false)}
        onConfirm={async (masterPassword) => {
          try {
            setTotpSetup(await window.vaulta.factors.beginTotp({ masterPassword }));
            setTotpPasswordOpen(false);
          } catch (error: unknown) {
            notify('error', 'TOTP-Einrichtung fehlgeschlagen', getErrorMessage(error));
          }
        }}
      />
      <TotpSetupModal
        setup={totpSetup}
        code={totpCode}
        busy={busy}
        onCodeChange={setTotpCode}
        onClose={() => {
          setTotpSetup(null);
          setTotpCode('');
        }}
        onComplete={async () => {
          if (!totpSetup) return;
          setBusy(true);
          try {
            await window.vaulta.factors.completeTotp({
              setupId: totpSetup.setupId,
              code: totpCode.replace(/\s/gu, ''),
            });
            await refreshFactors();
            setTotpSetup(null);
            setTotpCode('');
            notify('success', 'TOTP-Zugangssperre aktiviert');
          } catch (error: unknown) {
            notify('error', 'Code konnte nicht bestätigt werden', getErrorMessage(error));
          } finally {
            setBusy(false);
          }
        }}
      />
      <PasswordConfirm
        open={totpRemoveOpen}
        title="TOTP-Zugangssperre entfernen?"
        description="Danach genügt wieder der verbleibende konfigurierte Zugang. Die Änderung wird protokolliert."
        danger
        confirmationLabel="TOTP entfernen"
        onClose={() => setTotpRemoveOpen(false)}
        onConfirm={async (masterPassword) => {
          try {
            await window.vaulta.factors.removeTotp({ masterPassword });
            await refreshFactors();
            setTotpRemoveOpen(false);
            notify('success', 'TOTP entfernt');
          } catch (error: unknown) {
            notify('error', 'TOTP konnte nicht entfernt werden', getErrorMessage(error));
          }
        }}
      />
      <SecurityKeySetup
        open={keySetupOpen}
        notify={notify}
        onClose={() => setKeySetupOpen(false)}
        onComplete={async () => {
          await refreshFactors();
          setKeySetupOpen(false);
        }}
      />
      <PasswordConfirm
        open={Boolean(keyRemoveId)}
        title="Sicherheitsschlüssel entfernen?"
        description="Stelle vorher sicher, dass mindestens ein anderer gültiger Zugang oder Wiederherstellungsschlüssel verfügbar ist."
        danger
        confirmationLabel="Schlüssel entfernen"
        onClose={() => setKeyRemoveId(null)}
        onConfirm={async (masterPassword) => {
          if (!keyRemoveId) return;
          try {
            await window.vaulta.factors.removeSecurityKey({ id: keyRemoveId, masterPassword });
            await refreshFactors();
            setKeyRemoveId(null);
            notify('success', 'Sicherheitsschlüssel entfernt');
          } catch (error: unknown) {
            notify('error', 'Schlüssel konnte nicht entfernt werden', getErrorMessage(error));
          }
        }}
      />
      <RecoveryRotateDialog
        open={recoveryPasswordOpen}
        replacing={factors.recoveryEnabled}
        onClose={() => setRecoveryPasswordOpen(false)}
        onConfirm={async (masterPassword) => {
          try {
            setRecovery(await window.vaulta.factors.rotateRecovery({ masterPassword }));
            setRecoveryPasswordOpen(false);
          } catch (error: unknown) {
            notify('error', 'Schlüssel konnte nicht vorbereitet werden', getErrorMessage(error));
          }
        }}
      />
      <RecoveryKeyModal
        key={recovery?.pendingId ?? 'no-recovery'}
        started={recovery}
        onClose={() => setRecovery(null)}
        onComplete={async (confirmation) => {
          if (!recovery) return;
          try {
            await window.vaulta.factors.completeRecoveryRotation({
              pendingId: recovery.pendingId,
              confirmation,
            });
            await refreshFactors();
            setRecovery(null);
            notify('success', 'Neuer Wiederherstellungsschlüssel aktiviert');
          } catch (error: unknown) {
            notify('error', 'Gruppenbestätigung fehlgeschlagen', getErrorMessage(error));
          }
        }}
      />
    </section>
  );
}

function SettingsTabButton({
  value,
  current,
  icon,
  label,
  onSelect,
}: {
  value: SettingsTab;
  current: SettingsTab;
  icon: React.ReactNode;
  label: string;
  onSelect: (value: SettingsTab) => void;
}) {
  return (
    <button
      type="button"
      className={current === value ? 'is-active' : ''}
      aria-current={current === value ? 'page' : undefined}
      onClick={() => onSelect(value)}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

type DraftProps = {
  draft: VaultaSettings;
  setDraft: React.Dispatch<React.SetStateAction<VaultaSettings>>;
};

function SecuritySettings({
  draft,
  setDraft,
  onChangePassword,
}: DraftProps & { onChangePassword: () => void }) {
  return (
    <section className="settings-section">
      <header>
        <LockKeyhole />
        <div>
          <h2>Automatische Sperre</h2>
          <p>
            Aktive Schlüssel werden beim Sperren soweit technisch möglich aus dem Speicher entfernt.
          </p>
        </div>
      </header>
      <Field label="Sperren nach Inaktivität">
        <select
          value={draft.autoLockSeconds}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              autoLockSeconds: Number(event.currentTarget.value),
            }))
          }
        >
          <option value={0}>Sofort beim Verlassen der App</option>
          <option value={60}>1 Minute</option>
          <option value={300}>5 Minuten (empfohlen)</option>
          <option value={600}>10 Minuten</option>
          <option value={900}>15 Minuten</option>
          <option value={1800}>30 Minuten</option>
        </select>
      </Field>
      {draft.autoLockSeconds === 0 && (
        <InlineNotice kind="info">
          „Sofort“ sperrt Kryptris, sobald die App verlassen oder minimiert wird. Während du aktiv in
          Kryptris arbeitest, bleibt der Tresor geöffnet.
        </InlineNotice>
      )}
      <div className="settings-toggle-list">
        <Toggle
          label="Beim Minimieren sperren"
          description="Empfohlen bei gemeinsam genutzten Geräten."
          checked={draft.lockOnMinimize}
          onChange={(value) => setDraft((current) => ({ ...current, lockOnMinimize: value }))}
        />
        <Toggle
          label="Bei Windows-Sitzungssperre sperren"
          description="Reagiert auf Benutzerwechsel und Win + L."
          checked={draft.lockOnSystemLock}
          onChange={(value) => setDraft((current) => ({ ...current, lockOnSystemLock: value }))}
        />
        <Toggle
          label="Bei Standby und Laptopdeckel sperren"
          description="Schützt Schlüssel bei Suspend-Ereignissen."
          checked={draft.lockOnSuspend}
          onChange={(value) => setDraft((current) => ({ ...current, lockOnSuspend: value }))}
        />
        <Toggle
          label="Master-Passwort zum Anzeigen verlangen"
          description="Kopieren bleibt möglich, ohne den Wert anzuzeigen."
          checked={draft.requireMasterForReveal}
          onChange={(value) =>
            setDraft((current) => ({ ...current, requireMasterForReveal: value }))
          }
        />
      </div>
      <div className="settings-action-row">
        <div>
          <strong>Master-Passwort ändern</strong>
          <p>Nur der Profil-Hauptschlüssel wird neu verschlüsselt.</p>
        </div>
        <Button onClick={onChangePassword}>Passwort ändern</Button>
      </div>
    </section>
  );
}

function ClipboardSettings({ draft, setDraft }: DraftProps) {
  return (
    <section className="settings-section">
      <header>
        <Clipboard />
        <div>
          <h2>Zwischenablage & Sichtschutz</h2>
          <p>
            Kryptris löscht nur Inhalte, die es selbst gesetzt hat und die noch unverändert vorliegen.
          </p>
        </div>
      </header>
      <Field label={`Zwischenablage nach ${String(draft.clipboardClearSeconds)} Sekunden leeren`}>
        <input
          type="range"
          min={5}
          max={120}
          step={5}
          value={draft.clipboardClearSeconds}
          onChange={(event) =>
            setDraft((current) => ({
              ...current,
              clipboardClearSeconds: Number(event.currentTarget.value),
            }))
          }
        />
      </Field>
      <Button icon={<Trash2 />} onClick={() => void window.vaulta.system.clearClipboard()}>
        Jetzt leeren
      </Button>
      <div className="settings-toggle-list">
        <Toggle
          label="Windows-Inhaltsschutz"
          description="Erschwert viele Bildschirmaufnahmen, kann sie aber nicht vollständig verhindern."
          checked={draft.contentProtection}
          onChange={(value) => setDraft((current) => ({ ...current, contentProtection: value }))}
        />
      </div>
      <InlineNotice kind="warning" title="Technische Grenze">
        Schadsoftware mit Benutzer- oder Administratorrechten, Kameras und ein manipuliertes
        Betriebssystem können nicht vollständig abgewehrt werden.
      </InlineNotice>
    </section>
  );
}

function BackupSettings({ draft, setDraft, notify }: DraftProps & { notify: Notify }) {
  const choose = async () => {
    try {
      const folder = await window.vaulta.backup.chooseFolder();
      if (folder) setDraft((current) => ({ ...current, backupFolder: folder }));
    } catch (error: unknown) {
      notify('error', 'Ordner konnte nicht gewählt werden', getErrorMessage(error));
    }
  };
  return (
    <section className="settings-section">
      <header>
        <ArchiveRestore />
        <div>
          <h2>Automatische Backups</h2>
          <p>Native Sicherungen bleiben vollständig verschlüsselt.</p>
        </div>
      </header>
      <Toggle
        label="Automatische Sicherungen aktivieren"
        description="Sichert nach relevanten Änderungen in den gewählten Ordner."
        checked={draft.automaticBackups}
        onChange={(value) => setDraft((current) => ({ ...current, automaticBackups: value }))}
      />
      <div className="settings-action-row">
        <div>
          <strong>Zielordner</strong>
          <p>{draft.backupFolder ?? 'Noch kein Ordner gewählt'}</p>
        </div>
        <Button onClick={() => void choose()}>Ordner wählen</Button>
      </div>
      <div className="form-grid form-grid--three">
        <NumberSetting
          label="Tägliche Stände"
          value={draft.backupRotation.daily}
          onChange={(value) =>
            setDraft((current) => ({
              ...current,
              backupRotation: { ...current.backupRotation, daily: value },
            }))
          }
        />
        <NumberSetting
          label="Wöchentliche Stände"
          value={draft.backupRotation.weekly}
          onChange={(value) =>
            setDraft((current) => ({
              ...current,
              backupRotation: { ...current.backupRotation, weekly: value },
            }))
          }
        />
        <NumberSetting
          label="Monatliche Stände"
          value={draft.backupRotation.monthly}
          onChange={(value) =>
            setDraft((current) => ({
              ...current,
              backupRotation: { ...current.backupRotation, monthly: value },
            }))
          }
        />
      </div>
    </section>
  );
}

function FactorsSettings({
  factors,
  onAddTotp,
  onRemoveTotp,
  onAddKey,
  onRemoveKey,
  onRotateRecovery,
}: {
  factors: FactorStatus;
  onAddTotp: () => void;
  onRemoveTotp: () => void;
  onAddKey: () => void;
  onRemoveKey: (id: string) => void;
  onRotateRecovery: () => void;
}) {
  return (
    <section className="settings-section">
      <header>
        <Fingerprint />
        <div>
          <h2>Zugang & zusätzliche Faktoren</h2>
          <p>
            Ein kompatibler PRF-Sicherheitsschlüssel ist stärker als die rein lokale TOTP-Sperre.
          </p>
        </div>
      </header>
      <div className="factor-list">
        <article>
          <span>
            <Smartphone />
          </span>
          <div>
            <strong>TOTP-App</strong>
            <p>
              Lokale Zusatzsperre; kein Schutz gegen eine vollständige, kontrollierte Gerätekopie.
            </p>
          </div>
          <em className={`status-pill ${factors.totpEnabled ? 'status-pill--good' : ''}`}>
            {factors.totpEnabled ? 'Aktiv' : 'Inaktiv'}
          </em>
          <Button
            variant={factors.totpEnabled ? 'danger' : 'secondary'}
            onClick={factors.totpEnabled ? onRemoveTotp : onAddTotp}
          >
            {factors.totpEnabled ? 'Entfernen' : 'Einrichten'}
          </Button>
        </article>
        <article>
          <span>
            <KeyRound />
          </span>
          <div>
            <strong>Wiederherstellungsschlüssel</strong>
            <p>Separater kryptografischer Zugang. Sicher und getrennt aufbewahren.</p>
          </div>
          <em className={`status-pill ${factors.recoveryEnabled ? 'status-pill--good' : ''}`}>
            {factors.recoveryEnabled ? 'Aktiv' : 'Nicht eingerichtet'}
          </em>
          <Button onClick={onRotateRecovery}>
            {factors.recoveryEnabled ? 'Ersetzen' : 'Einrichten'}
          </Button>
        </article>
      </div>
      <div className="subsection-heading">
        <div>
          <h3>Sicherheitsschlüssel</h3>
          <p>Registriere idealerweise mindestens zwei Schlüssel.</p>
        </div>
        <Button icon={<Plus />} onClick={onAddKey}>
          Schlüssel registrieren
        </Button>
      </div>
      {factors.securityKeys.length === 0 ? (
        <InlineNotice kind="info">
          Noch kein FIDO2-/WebAuthn-Sicherheitsschlüssel eingerichtet.
        </InlineNotice>
      ) : (
        <div className="security-key-list">
          {factors.securityKeys.map((key) => (
            <article key={key.id}>
              <Fingerprint />
              <div>
                <strong>{key.name}</strong>
                <small>Registriert {formatDate(key.createdAt)}</small>
              </div>
              <em
                className={`status-pill ${key.mode === 'prf' ? 'status-pill--good' : 'status-pill--warning'}`}
              >
                {key.mode === 'prf' ? 'Kryptografischer PRF-Modus' : 'Nur Anwesenheitsprüfung'}
              </em>
              <IconButton label={`${key.name} entfernen`} onClick={() => onRemoveKey(key.id)}>
                <Trash2 />
              </IconButton>
            </article>
          ))}
        </div>
      )}
      <InlineNotice kind="warning">
        Ein Schlüssel im Modus „Nur Anwesenheitsprüfung“ ist sichtbar schwächer und bindet keinen
        hardwarebasierten Geheimwert in die Entschlüsselung ein.
      </InlineNotice>
    </section>
  );
}

function AdvancedSettings({ draft, setDraft }: DraftProps) {
  return (
    <section className="settings-section">
      <header>
        <HardDrive />
        <div>
          <h2>Speicher & Protokoll</h2>
          <p>Grenzen für lokale Anhänge und das verschlüsselte Aktivitätsprotokoll.</p>
        </div>
      </header>
      <div className="form-grid form-grid--three">
        <NumberSetting
          label="Anhangslimit (MB)"
          value={Math.round(draft.attachmentMaxBytes / 1024 / 1024)}
          onChange={(value) =>
            setDraft((current) => ({ ...current, attachmentMaxBytes: value * 1024 * 1024 }))
          }
        />
        <NumberSetting
          label="Max. Ereignisse"
          value={draft.auditMaxEvents}
          max={50000}
          onChange={(value) => setDraft((current) => ({ ...current, auditMaxEvents: value }))}
        />
        <NumberSetting
          label="Aufbewahrung (Tage)"
          value={draft.auditRetentionDays}
          max={3650}
          onChange={(value) => setDraft((current) => ({ ...current, auditRetentionDays: value }))}
        />
      </div>
      <Toggle
        label="Reduzierte Bewegung"
        description="Deaktiviert nicht notwendige Übergänge und Animationen."
        checked={draft.reducedMotion}
        onChange={(value) => setDraft((current) => ({ ...current, reducedMotion: value }))}
      />
      <InlineNotice kind="info">
        Fachliche Metadaten, Suchindex, Aktivitätsprotokoll und Anhangsnamen bleiben verschlüsselt.
        Diagnoseprotokolle enthalten keine Tresorinhalte.
      </InlineNotice>
    </section>
  );
}

function Toggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="toggle-row">
      <span>
        <strong>{label}</strong>
        <small>{description}</small>
      </span>
      <span className="switch">
        <input
          type="checkbox"
          checked={checked}
          onChange={(event) => onChange(event.currentTarget.checked)}
        />
        <i />
      </span>
    </label>
  );
}

function NumberSetting({
  label,
  value,
  min = 0,
  max = 1000,
  onChange,
}: {
  label: string;
  value: number;
  min?: number;
  max?: number;
  onChange: (value: number) => void;
}) {
  return (
    <Field label={label}>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </Field>
  );
}

function ChangeMasterPassword({
  open,
  notify,
  onClose,
}: {
  open: boolean;
  notify: Notify;
  onClose: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (newPassword !== confirmation) {
      setError('Die neuen Passwörter stimmen nicht überein.');
      return;
    }
    if (newPassword.length < 12) {
      setError('Das neue Passwort muss mindestens 12 Zeichen enthalten.');
      return;
    }
    setBusy(true);
    try {
      await window.vaulta.auth.changeMasterPassword({ currentPassword, newPassword });
      notify('success', 'Master-Passwort geändert');
      onClose();
      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      title="Master-Passwort ändern"
      description="Der Profil-Hauptschlüssel wird mit dem neuen Passwort neu verschlüsselt; Tresorinhalte müssen nicht komplett neu geschrieben werden."
      onClose={onClose}
    >
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <Field label="Aktuelles Master-Passwort">
          <PasswordInput
            value={currentPassword}
            autoComplete="current-password"
            onChange={setCurrentPassword}
          />
        </Field>
        <Field label="Neues Master-Passwort">
          <PasswordInput
            value={newPassword}
            autoComplete="new-password"
            onChange={setNewPassword}
          />
        </Field>
        <Field label="Neues Passwort wiederholen">
          <PasswordInput
            value={confirmation}
            autoComplete="new-password"
            onChange={setConfirmation}
          />
        </Field>
        {error && <InlineNotice kind="error">{error}</InlineNotice>}
        <div className="modal__inline-actions">
          <Button type="button" variant="ghost" onClick={onClose}>
            Abbrechen
          </Button>
          <Button
            type="submit"
            variant="primary"
            busy={busy}
            disabled={!currentPassword || !newPassword || !confirmation}
          >
            Passwort ändern
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function TotpSetupModal({
  setup,
  code,
  busy,
  onCodeChange,
  onClose,
  onComplete,
}: {
  setup: TotpSetup | null;
  code: string;
  busy: boolean;
  onCodeChange: (value: string) => void;
  onClose: () => void;
  onComplete: () => Promise<void>;
}) {
  return (
    <Modal
      open={Boolean(setup)}
      title="TOTP-App verbinden"
      description="Scanne den QR-Code ausschließlich mit deiner gewünschten Authenticator-App."
      onClose={onClose}
    >
      {setup && (
        <div className="stack totp-setup">
          <img src={setup.qrDataUrl} alt="QR-Code für TOTP-Einrichtung" />
          <Field label="Alternativer Einrichtungsschlüssel">
            <code>{setup.secret}</code>
          </Field>
          <InlineNotice kind="warning">{setup.explanation}</InlineNotice>
          <Field label="Aktuellen Code zur Bestätigung">
            <input
              className="totp-input"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(event) => onCodeChange(event.currentTarget.value.replace(/\D/gu, ''))}
            />
          </Field>
          <Button
            variant="primary"
            busy={busy}
            disabled={code.length < 6}
            onClick={() => void onComplete()}
          >
            TOTP bestätigen
          </Button>
        </div>
      )}
    </Modal>
  );
}

function SecurityKeySetup({
  open,
  notify,
  onClose,
  onComplete,
}: {
  open: boolean;
  notify: Notify;
  onClose: () => void;
  onComplete: () => Promise<void>;
}) {
  const [name, setName] = useState('Mein Sicherheitsschlüssel');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const register = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    let saltBytes: Uint8Array | null = null;
    let resultBytes: Uint8Array | null = null;
    try {
      const begun = await window.vaulta.factors.beginSecurityKey({
        name: name.trim(),
        masterPassword: password,
      });
      saltBytes = decodeBase64Url(begun.prfSalt);
      const prfSaltBuffer = saltBytes.slice().buffer;
      const options = addPrfExtension(begun.options, prfSaltBuffer);
      const response = await startRegistration({ optionsJSON: options as never });
      const extracted = extractPrfResult(response);
      let prfResult: string | undefined;
      if (typeof extracted === 'string') prfResult = extracted;
      else if (extracted) {
        resultBytes = new Uint8Array(extracted);
        prfResult = encodeBase64Url(resultBytes);
      }
      const input = prfResult
        ? { challengeId: begun.challengeId, response, prfResult }
        : { challengeId: begun.challengeId, response };
      const completed = await window.vaulta.factors.completeSecurityKey(input);
      if (!completed.verified) throw new Error('Die WebAuthn-Antwort wurde nicht bestätigt.');
      notify(
        completed.mode === 'prf' ? 'success' : 'warning',
        completed.mode === 'prf'
          ? 'Sicherheitsschlüssel kryptografisch registriert'
          : 'Schlüssel nur als Anwesenheitsprüfung registriert',
        completed.warning ?? undefined,
      );
      setPassword('');
      await onComplete();
    } catch (error: unknown) {
      notify('error', 'Registrierung fehlgeschlagen', getErrorMessage(error));
    } finally {
      saltBytes?.fill(0);
      resultBytes?.fill(0);
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      title="Sicherheitsschlüssel registrieren"
      description="Kryptris versucht den hardwaregebundenen PRF-/hmac-secret-Modus zu verwenden."
      onClose={onClose}
    >
      <form className="stack" onSubmit={(event) => void register(event)}>
        <Field label="Anzeigename">
          <input value={name} onChange={(event) => setName(event.currentTarget.value)} />
        </Field>
        <Field label="Master-Passwort">
          <PasswordInput value={password} autoComplete="current-password" onChange={setPassword} />
        </Field>
        <InlineNotice kind="info">
          Windows öffnet nach dem Start eine native WebAuthn-Abfrage. Berühre oder entsperre dort
          deinen Schlüssel.
        </InlineNotice>
        <div className="modal__inline-actions">
          <Button type="button" variant="ghost" onClick={onClose}>
            Abbrechen
          </Button>
          <Button
            type="submit"
            variant="primary"
            icon={<Fingerprint />}
            busy={busy}
            disabled={!name.trim() || !password}
          >
            Registrierung starten
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function RecoveryRotateDialog({
  open,
  replacing,
  onClose,
  onConfirm,
}: {
  open: boolean;
  replacing: boolean;
  onClose: () => void;
  onConfirm: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const phrase = replacing ? 'ERSETZEN' : 'ERSTELLEN';
  const close = () => {
    setPassword('');
    setConfirmation('');
    onClose();
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await onConfirm(password);
      setPassword('');
      setConfirmation('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open={open}
      title={
        replacing ? 'Wiederherstellungsschlüssel ersetzen' : 'Wiederherstellungsschlüssel erstellen'
      }
      description="Nach dem Master-Passwort wird der neue Schlüssel einmal angezeigt. Aktiviert wird er erst nach einer zweiten Gruppenbestätigung."
      onClose={close}
    >
      <form className="stack" onSubmit={(event) => void submit(event)}>
        {replacing && (
          <InlineNotice kind="warning" title="Der bisherige Schlüssel bleibt vorerst gültig">
            Erst die anschließende korrekte Gruppenbestätigung aktiviert den neuen Schlüssel und
            macht den alten ungültig.
          </InlineNotice>
        )}
        <Field label={`Zur Bestätigung ${phrase} eingeben`}>
          <input
            value={confirmation}
            autoComplete="off"
            onChange={(event) => setConfirmation(event.currentTarget.value.toUpperCase())}
          />
        </Field>
        <Field label="Master-Passwort">
          <PasswordInput value={password} autoComplete="current-password" onChange={setPassword} />
        </Field>
        <div className="modal__inline-actions">
          <Button type="button" variant="ghost" onClick={close}>
            Abbrechen
          </Button>
          <Button
            type="submit"
            variant="primary"
            busy={busy}
            disabled={confirmation !== phrase || !password}
          >
            {replacing ? 'Neuen Schlüssel anzeigen' : 'Schlüssel erstellen'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function RecoveryKeyModal({
  started,
  onClose,
  onComplete,
}: {
  started: RecoveryRotationStarted | null;
  onClose: () => void;
  onComplete: (confirmation: Record<string, string>) => Promise<void>;
}) {
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const recovery = started?.recovery ?? null;
  const complete = async () => {
    if (!recovery) return;
    setBusy(true);
    try {
      await onComplete(answers);
    } finally {
      setBusy(false);
    }
  };
  const missing =
    recovery?.confirmationIndexes.some((index) => !answers[String(index)]?.trim()) ?? true;
  return (
    <Modal
      open={Boolean(started)}
      title="Neuen Wiederherstellungsschlüssel sichern"
      description="Der alte Schlüssel bleibt gültig, bis du die ausgewählten Gruppen korrekt bestätigst."
      size="large"
      onClose={onClose}
    >
      {recovery && (
        <div className="stack">
          <InlineNotice kind="warning">
            Drucke den Schlüssel aus oder schreibe ihn vollständig ab und verwahre ihn getrennt vom
            Gerät. Nach erfolgreicher Bestätigung wird der alte Schlüssel ungültig.
          </InlineNotice>
          <div className="recovery-key">
            {recovery.groups.map((group, index) => (
              <span key={`${group}-${String(index)}`}>
                <small>{String(index + 1).padStart(2, '0')}</small>
                {group}
              </span>
            ))}
          </div>
          <div className="recovery-confirm">
            <h3>Ausgewählte Gruppen bestätigen</h3>
            <div className="form-grid form-grid--three">
              {recovery.confirmationIndexes.map((index) => (
                <Field label={`Gruppe ${String(index + 1)}`} key={index}>
                  <input
                    value={answers[String(index)] ?? ''}
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(event) =>
                      setAnswers((current) => ({
                        ...current,
                        [String(index)]: event.currentTarget.value.trim().toUpperCase(),
                      }))
                    }
                  />
                </Field>
              ))}
            </div>
          </div>
          <div className="modal__inline-actions">
            <Button variant="ghost" onClick={onClose}>
              Abbrechen und alten Schlüssel behalten
            </Button>
            <Button
              variant="primary"
              icon={<Check />}
              busy={busy}
              disabled={missing}
              onClick={() => void complete()}
            >
              Gruppen bestätigen und aktivieren
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
function addPrfExtension(options: unknown, first: ArrayBuffer): unknown {
  if (!isRecord(options)) throw new Error('Ungültige WebAuthn-Optionen.');
  const extensions = isRecord(options.extensions) ? options.extensions : {};
  return { ...options, extensions: { ...extensions, prf: { eval: { first } } } };
}
function extractPrfResult(response: unknown): string | ArrayBuffer | null {
  if (!isRecord(response) || !isRecord(response.clientExtensionResults)) return null;
  const prf = response.clientExtensionResults.prf;
  if (!isRecord(prf) || !isRecord(prf.results)) return null;
  const first = prf.results.first;
  return typeof first === 'string' || first instanceof ArrayBuffer ? first : null;
}
function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/gu, '+').replace(/_/gu, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return window.btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
}
