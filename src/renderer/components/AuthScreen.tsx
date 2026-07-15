import { startAuthentication } from '@simplewebauthn/browser';
import {
  ArchiveRestore,
  ArrowRight,
  Check,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Printer,
  RotateCcw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import type { Dispatch, FormEvent, SetStateAction } from 'react';
import { useEffect, useMemo, useState } from 'react';

import type { AppState, RecoverySetup, UnlockResult } from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Brand, Button, Field, InlineNotice, PasswordInput, WindowControls } from './ui';
import { BackupRestoreModal } from './BackupRestoreModal';

interface AuthScreenProps {
  state: AppState;
  onStateChange: Dispatch<SetStateAction<AppState | null>>;
  notify: Notify;
}

type UnlockStage = 'password' | 'totp' | 'security-key' | 'recovery';

interface PendingSetup {
  pendingId: string;
  recovery: RecoverySetup;
}

export function AuthScreen({ state, onStateChange, notify }: AuthScreenProps) {
  return (
    <main className="auth-shell">
      <header className="auth-titlebar drag-region">
        <Brand />
        <WindowControls />
      </header>
      <div className="auth-glow auth-glow--teal" />
      <div className="auth-glow auth-glow--violet" />
      <div className="auth-content">
        {state.hasProfile ? (
          <UnlockFlow state={state} onStateChange={onStateChange} notify={notify} />
        ) : (
          <SetupFlow onStateChange={onStateChange} notify={notify} />
        )}
      </div>
      <footer className="auth-footer">
        <span>Vollständig offline</span>
        <span aria-hidden="true">•</span>
        <span>Version {state.version}</span>
      </footer>
    </main>
  );
}

function SetupFlow({ onStateChange, notify }: Pick<AuthScreenProps, 'onStateChange' | 'notify'>) {
  const [vaultName, setVaultName] = useState('Privat');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [enableRecovery, setEnableRecovery] = useState(true);
  const [pending, setPending] = useState<PendingSetup | null>(null);
  const [groupAnswers, setGroupAnswers] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [restoreOpen, setRestoreOpen] = useState(false);

  useEffect(
    () =>
      window.vaulta.events.onLocked(() => {
        setVaultName('Privat');
        setPassword('');
        setConfirmation('');
        setEnableRecovery(true);
        setPending(null);
        setGroupAnswers({});
        setBusy(false);
        setError(null);
        setRestoreOpen(false);
      }),
    [],
  );

  const score = useMemo(() => {
    let value = 0;
    if (password.length >= 12) value++;
    if (password.length >= 18) value++;
    if (/[a-z]/u.test(password) && /[A-Z]/u.test(password)) value++;
    if (/\d/u.test(password) || /[^\p{L}\p{N}]/u.test(password)) value++;
    return value;
  }, [password]);

  const begin = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (password !== confirmation) {
      setError('Die beiden Passwörter stimmen nicht überein.');
      return;
    }
    if (password.length < 12) {
      setError('Verwende mindestens 12 Zeichen für dein Master-Passwort.');
      return;
    }
    setBusy(true);
    try {
      const started = await window.vaulta.setup.begin({
        masterPassword: password,
        vaultName: vaultName.trim(),
        enableRecovery,
      });
      setPassword('');
      setConfirmation('');
      if (started.recovery) {
        setPending({ pendingId: started.pendingId, recovery: started.recovery });
      } else {
        const nextState = await window.vaulta.setup.complete({
          pendingId: started.pendingId,
          confirmation: {},
        });
        onStateChange(nextState);
        notify('success', 'Vaulta ist bereit', 'Dein erster Tresor wurde sicher angelegt.');
      }
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const complete = async (event: FormEvent) => {
    event.preventDefault();
    if (!pending) return;
    const missing = pending.recovery.confirmationIndexes.some(
      (index) => !groupAnswers[String(index)]?.trim(),
    );
    if (missing) {
      setError('Bestätige alle angeforderten Gruppen des Wiederherstellungsschlüssels.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const nextState = await window.vaulta.setup.complete({
        pendingId: pending.pendingId,
        confirmation: groupAnswers,
      });
      onStateChange(nextState);
      notify('success', 'Vaulta ist bereit', 'Wiederherstellungsschlüssel bestätigt.');
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  if (pending) {
    return (
      <section className="auth-card auth-card--recovery" aria-labelledby="setup-recovery-title">
        <div className="auth-card__icon auth-card__icon--success">
          <KeyRound />
        </div>
        <p className="eyebrow">Einmalige Anzeige</p>
        <h1 id="setup-recovery-title">Wiederherstellungsschlüssel sichern</h1>
        <p className="auth-card__lead">
          Dieser Schlüssel ist der einzige zweite Zugang zu deinen Daten. Vaulta speichert ihn
          niemals im Klartext.
        </p>
        <InlineNotice kind="warning" title="Jetzt sicher aufbewahren">
          Drucke den Schlüssel aus oder schreibe ihn vollständig ab. Ein Foto auf demselben Gerät
          ist kein verlässliches Backup.
        </InlineNotice>
        <div className="recovery-key" aria-label="Wiederherstellungsschlüssel">
          {pending.recovery.groups.map((group, index) => (
            <span key={`${group}-${String(index)}`}>
              <small>{String(index + 1).padStart(2, '0')}</small>
              {group}
            </span>
          ))}
        </div>
        <Button type="button" icon={<Printer />} onClick={() => window.print()}>
          Schlüssel drucken
        </Button>
        <form className="stack recovery-confirm" onSubmit={(event) => void complete(event)}>
          <h2>Ausgewählte Gruppen bestätigen</h2>
          <div className="form-grid form-grid--three">
            {pending.recovery.confirmationIndexes.map((index) => (
              <Field label={`Gruppe ${String(index + 1)}`} key={index}>
                <input
                  value={groupAnswers[String(index)] ?? ''}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) =>
                    setGroupAnswers((current) => ({
                      ...current,
                      [String(index)]: event.currentTarget.value.trim().toUpperCase(),
                    }))
                  }
                />
              </Field>
            ))}
          </div>
          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <Button type="submit" variant="primary" busy={busy} icon={<Check />}>
            Schlüssel bestätigen und Vaulta öffnen
          </Button>
        </form>
      </section>
    );
  }

  return (
    <section className="auth-card auth-card--setup" aria-labelledby="setup-title">
      <div className="auth-card__icon">
        <Sparkles />
      </div>
      <p className="eyebrow">Willkommen bei Vaulta</p>
      <h1 id="setup-title">Dein sicherer, lokaler Tresor</h1>
      <p className="auth-card__lead">
        Richte ein lokales Profil ein. Deine Daten verlassen dieses Gerät nicht.
      </p>
      <form
        className="stack setup-form"
        aria-label="Vaulta-Profil einrichten"
        onSubmit={(event) => void begin(event)}
      >
        <Field label="Name des ersten Tresors">
          <input
            value={vaultName}
            maxLength={64}
            autoFocus
            onChange={(event) => setVaultName(event.currentTarget.value)}
          />
        </Field>
        <div className="setup-form__password">
          <Field
            label="Master-Passwort"
            hint="Mindestens 12 Zeichen. Eine lange Passphrase ist leichter zu merken."
            hintId="setup-master-password-hint"
          >
            <PasswordInput
              value={password}
              autoComplete="new-password"
              ariaLabel="Master-Passwort"
              ariaDescribedBy="setup-master-password-hint"
              onChange={setPassword}
            />
          </Field>
          <div className="password-meter" aria-label={`Passwortstärke ${String(score)} von 4`}>
            {[1, 2, 3, 4].map((part) => (
              <span className={part <= score ? 'is-filled' : ''} key={part} />
            ))}
          </div>
        </div>
        <Field label="Master-Passwort wiederholen">
          <PasswordInput
            value={confirmation}
            autoComplete="new-password"
            ariaLabel="Master-Passwort wiederholen"
            onChange={setConfirmation}
          />
        </Field>
        <label className="check-row">
          <input
            type="checkbox"
            checked={enableRecovery}
            onChange={(event) => setEnableRecovery(event.currentTarget.checked)}
          />
          <span>
            <strong>Wiederherstellungsschlüssel erzeugen</strong>
            <small>Empfohlen. Er wird nur einmal vollständig angezeigt.</small>
          </span>
        </label>
        <InlineNotice kind="info">
          Ohne Master-Passwort oder Wiederherstellungsschlüssel können deine Daten nicht
          wiederhergestellt werden. Es gibt keine Hintertür.
        </InlineNotice>
        {error && <InlineNotice kind="error">{error}</InlineNotice>}
        <Button
          type="submit"
          variant="primary"
          busy={busy}
          disabled={!vaultName.trim() || !password || !confirmation}
          icon={<ArrowRight />}
        >
          Profil sicher einrichten
        </Button>
        <div className="auth-alternative">
          <span>Du hast bereits ein verschlüsseltes Backup?</span>
          <Button
            type="button"
            variant="ghost"
            icon={<ArchiveRestore />}
            onClick={() => setRestoreOpen(true)}
          >
            Backup wiederherstellen
          </Button>
        </div>
      </form>
      <BackupRestoreModal
        open={restoreOpen}
        freshProfile
        notify={notify}
        onClose={() => setRestoreOpen(false)}
        onRestored={onStateChange}
      />
    </section>
  );
}

function UnlockFlow({ state, onStateChange, notify }: AuthScreenProps) {
  const [stage, setStage] = useState<UnlockStage>('password');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordConfirmation, setNewPasswordConfirmation] = useState('');
  const [securityResult, setSecurityResult] = useState<UnlockResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshState = async () => {
    onStateChange(await window.vaulta.system.getState());
    setPassword('');
    setTotpCode('');
  };

  const handleUnlockResult = async (result: UnlockResult) => {
    if (result.status === 'unlocked') {
      await refreshState();
      notify('success', 'Tresor entsperrt');
      return;
    }
    if (result.status === 'totp-required') {
      setStage('totp');
      return;
    }
    setSecurityResult(result);
    setStage('security-key');
    await authenticateSecurityKey(result);
  };

  const unlock = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await window.vaulta.auth.unlock({ masterPassword: password });
      await handleUnlockResult(result);
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const verifyTotp = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await window.vaulta.auth.unlock({
        masterPassword: password,
        totpCode: totpCode.replace(/\s/gu, ''),
      });
      await handleUnlockResult(result);
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  const authenticateSecurityKey = async (result = securityResult) => {
    if (!result?.securityKeyOptions || !result.challengeId) return;
    setBusy(true);
    setError(null);
    let saltBytes: Uint8Array | null = null;
    let resultBytes: Uint8Array | null = null;
    try {
      const payload = result.securityKeyOptions;
      let options: unknown = payload;
      if (isRecord(payload) && 'options' in payload) {
        options = payload.options;
        if (typeof payload.prfSalt === 'string') {
          saltBytes = decodeBase64Url(payload.prfSalt);
          options = addPrfExtension(options, saltBytes.slice().buffer);
        }
      }
      const response = await startAuthentication({
        optionsJSON: options as never,
      });
      const extracted = extractPrfResult(response);
      let prfResult: string | undefined;
      if (typeof extracted === 'string') {
        prfResult = extracted;
      } else if (extracted) {
        resultBytes = new Uint8Array(extracted);
        prfResult = encodeBase64Url(resultBytes);
      }
      const input = prfResult
        ? { challengeId: result.challengeId, response, prfResult }
        : { challengeId: result.challengeId, response };
      const verified = await window.vaulta.auth.completeSecurityKey(input);
      if (!verified.verified || !verified.unlocked) {
        throw new Error('Der Sicherheitsschlüssel konnte nicht bestätigt werden.');
      }
      await refreshState();
      notify('success', 'Sicherheitsschlüssel bestätigt');
    } catch (caught: unknown) {
      const message = getErrorMessage(caught);
      await window.vaulta.auth
        .cancelSecurityKey({ challengeId: result.challengeId })
        .catch(() => undefined);
      setSecurityResult(null);
      setPassword('');
      setTotpCode('');
      setStage('password');
      setError(message);
    } finally {
      saltBytes?.fill(0);
      resultBytes?.fill(0);
      setBusy(false);
    }
  };

  const cancelSecurityKey = async () => {
    const challengeId = securityResult?.challengeId;
    if (challengeId !== undefined) {
      await window.vaulta.auth.cancelSecurityKey({ challengeId }).catch(() => undefined);
    }
    setSecurityResult(null);
    setPassword('');
    setTotpCode('');
    setError(null);
    setStage('password');
  };

  const recover = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (newPassword !== newPasswordConfirmation) {
      setError('Die neuen Passwörter stimmen nicht überein.');
      return;
    }
    if (newPassword.length < 12) {
      setError('Das neue Master-Passwort muss mindestens 12 Zeichen enthalten.');
      return;
    }
    setBusy(true);
    try {
      const nextState = await window.vaulta.auth.recover({
        recoveryKey: recoveryKey.trim(),
        newMasterPassword: newPassword,
      });
      onStateChange(nextState);
      notify(
        'warning',
        'Wiederherstellung abgeschlossen',
        'Richte zusätzliche Faktoren erneut ein.',
      );
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="auth-card auth-card--unlock" aria-labelledby="unlock-title">
      <div className="auth-card__icon">
        {stage === 'security-key' ? <Fingerprint /> : <LockKeyhole />}
      </div>
      <p className="eyebrow">Lokal verschlüsselt</p>
      <h1 id="unlock-title">
        {stage === 'password' && 'Willkommen zurück'}
        {stage === 'totp' && 'Zusätzlichen Code eingeben'}
        {stage === 'security-key' && 'Sicherheitsschlüssel verwenden'}
        {stage === 'recovery' && 'Profil wiederherstellen'}
      </h1>
      <p className="auth-card__lead">
        {stage === 'password' && 'Entsperre Vaulta mit deinem Master-Passwort.'}
        {stage === 'totp' && 'Öffne deine TOTP-App und bestätige den aktuellen Code.'}
        {stage === 'security-key' &&
          'Verbinde deinen registrierten Schlüssel und bestätige die Windows-Abfrage.'}
        {stage === 'recovery' &&
          'Der Wiederherstellungsschlüssel ersetzt das bisherige Master-Passwort und entfernt zusätzliche Faktoren.'}
      </p>

      {stage === 'password' && (
        <form className="stack" onSubmit={(event) => void unlock(event)}>
          <Field label="Master-Passwort">
            <PasswordInput
              value={password}
              autoFocus
              autoComplete="current-password"
              onChange={setPassword}
            />
          </Field>
          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <Button type="submit" variant="primary" busy={busy} disabled={!password}>
            Vaulta entsperren
          </Button>
          {state.factorStatus.recoveryEnabled && (
            <Button type="button" variant="ghost" onClick={() => setStage('recovery')}>
              Wiederherstellungsschlüssel verwenden
            </Button>
          )}
        </form>
      )}

      {stage === 'totp' && (
        <form className="stack" onSubmit={(event) => void verifyTotp(event)}>
          <Field label="6- oder 8-stelliger TOTP-Code">
            <input
              className="totp-input"
              inputMode="numeric"
              pattern="[0-9 ]*"
              autoComplete="one-time-code"
              autoFocus
              maxLength={9}
              value={totpCode}
              onChange={(event) => setTotpCode(event.currentTarget.value.replace(/[^0-9 ]/gu, ''))}
            />
          </Field>
          <InlineNotice kind="info" title="Lokale Zusatzsperre">
            TOTP schützt vor beiläufigem Zugriff, ist bei einer vollständigen Gerätekopie aber kein
            gleichwertiger kryptografischer Faktor.
          </InlineNotice>
          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <Button type="submit" variant="primary" busy={busy} disabled={totpCode.length < 6}>
            Code bestätigen
          </Button>
          <Button type="button" variant="ghost" onClick={() => setStage('password')}>
            Zurück
          </Button>
        </form>
      )}

      {stage === 'security-key' && (
        <div className="stack">
          <div className="security-key-illustration" aria-hidden="true">
            <Fingerprint />
            <span />
            <ShieldCheck />
          </div>
          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <Button
            type="button"
            variant="primary"
            busy={busy}
            icon={<RotateCcw />}
            onClick={() => void authenticateSecurityKey()}
          >
            Erneut versuchen
          </Button>
          <Button type="button" variant="ghost" onClick={() => void cancelSecurityKey()}>
            Zurück
          </Button>
        </div>
      )}

      {stage === 'recovery' && (
        <form className="stack" onSubmit={(event) => void recover(event)}>
          <InlineNotice kind="warning" title="Sicherheitsfaktoren werden zurückgesetzt">
            Nach erfolgreicher Wiederherstellung musst du TOTP und Sicherheitsschlüssel erneut
            einrichten.
          </InlineNotice>
          <Field label="Wiederherstellungsschlüssel">
            <textarea
              rows={3}
              value={recoveryKey}
              spellCheck={false}
              autoFocus
              onChange={(event) => setRecoveryKey(event.currentTarget.value.toUpperCase())}
            />
          </Field>
          <Field label="Neues Master-Passwort">
            <PasswordInput
              value={newPassword}
              autoComplete="new-password"
              onChange={setNewPassword}
            />
          </Field>
          <Field label="Neues Master-Passwort wiederholen">
            <PasswordInput
              value={newPasswordConfirmation}
              autoComplete="new-password"
              onChange={setNewPasswordConfirmation}
            />
          </Field>
          {error && <InlineNotice kind="error">{error}</InlineNotice>}
          <Button
            type="submit"
            variant="primary"
            busy={busy}
            disabled={!recoveryKey || !newPassword || !newPasswordConfirmation}
          >
            Wiederherstellen und neues Passwort setzen
          </Button>
          <Button type="button" variant="ghost" onClick={() => setStage('password')}>
            Zurück zur Anmeldung
          </Button>
        </form>
      )}
    </section>
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
