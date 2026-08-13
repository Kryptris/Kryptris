import { KeyRound, LockKeyhole } from 'lucide-react';
import type { FormEvent } from 'react';
import { useEffect, useRef, useState } from 'react';

import type { AppState, LocalJobProgressEvent, RestoreDryRunResult } from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Button, Field, InlineNotice, Modal, PasswordInput } from './ui';

interface BackupRestoreModalProps {
  open: boolean;
  freshProfile?: boolean;
  mode?: 'restore' | 'dry-run';
  notify: Notify;
  onClose: () => void;
  onRestored: (state: AppState) => void;
  onDryRunCompleted?: (result: RestoreDryRunResult) => void;
}

export function BackupRestoreModal({
  open,
  freshProfile = false,
  mode = 'restore',
  notify,
  onClose,
  onRestored,
  onDryRunCompleted,
}: BackupRestoreModalProps) {
  const isDryRun = mode === 'dry-run';
  const [credentialType, setCredentialType] = useState<'master' | 'recovery'>('master');
  const [credential, setCredential] = useState('');
  const [newMasterPassword, setNewMasterPassword] = useState('');
  const [newMasterPasswordConfirmation, setNewMasterPasswordConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
  const [dryRunProgress, setDryRunProgress] = useState<LocalJobProgressEvent | null>(null);
  const [liveMessage, setLiveMessage] = useState('');
  const activeRequestIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (activeRequestId === null) return;
    return window.vaulta.events.onLocalJobProgress((event) => {
      if (event.job !== 'backup-dry-run' || event.requestId !== activeRequestId) return;
      setDryRunProgress(event);
      setLiveMessage(dryRunProgressCopy(event));
    });
  }, [activeRequestId]);

  useEffect(
    () => () => {
      const requestId = activeRequestIdRef.current;
      if (requestId !== null) {
        void window.vaulta.quality.cancelJob({ requestId }).catch(() => undefined);
      }
    },
    [],
  );

  const clearForm = () => {
    setCredential('');
    setNewMasterPassword('');
    setNewMasterPasswordConfirmation('');
    setError(null);
    setDryRunProgress(null);
    setLiveMessage('');
  };

  const cancelDryRun = async () => {
    const requestId = activeRequestIdRef.current;
    if (requestId === null || cancelling) return;
    setCancelling(true);
    setLiveMessage('Abbruch des Backup-Probelaufs wird angefordert.');
    try {
      const accepted = await window.vaulta.quality.cancelJob({ requestId });
      setLiveMessage(
        accepted
          ? 'Abbruch des Backup-Probelaufs wurde angefordert.'
          : 'Der Backup-Probelauf war bereits abgeschlossen oder beendet.',
      );
    } catch {
      setError('Der Backup-Probelauf konnte nicht abgebrochen werden. Versuche es erneut.');
      setLiveMessage('Der Backup-Probelauf konnte nicht abgebrochen werden.');
      setCancelling(false);
    }
  };

  const close = () => {
    if (busy) {
      if (isDryRun) void cancelDryRun();
      return;
    }
    clearForm();
    onClose();
  };

  const restore = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    if (credentialType === 'recovery' && newMasterPassword !== newMasterPasswordConfirmation) {
      setError('Die beiden neuen Master-Passwörter stimmen nicht überein.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const restored = await window.vaulta.backup.restore({
        credential: { type: credentialType, value: credential },
        ...(credentialType === 'recovery' ? { newMasterPassword } : {}),
      });
      if (restored) {
        onRestored(restored);
        notify(
          'success',
          'Backup vollständig wiederhergestellt',
          credentialType === 'master'
            ? 'Entsperre das wiederhergestellte Profil mit seinem Master-Passwort.'
            : 'Das Profil verwendet jetzt dein neues Master-Passwort.',
        );
        setNewMasterPassword('');
        setNewMasterPasswordConfirmation('');
        onClose();
      }
    } catch (caught: unknown) {
      setError(getErrorMessage(caught));
    } finally {
      setBusy(false);
      setCredential('');
    }
  };

  const dryRun = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || !credential || activeRequestIdRef.current !== null) return;
    const requestId = crypto.randomUUID();
    activeRequestIdRef.current = requestId;
    setActiveRequestId(requestId);
    setBusy(true);
    setCancelling(false);
    setError(null);
    setDryRunProgress(null);
    setLiveMessage('Backup-Probelauf wurde gestartet.');
    try {
      const result = await window.vaulta.backup.dryRun({
        requestId,
        credential: { type: credentialType, value: credential },
      });
      if (result !== null) {
        onDryRunCompleted?.(result);
        clearForm();
        onClose();
      } else {
        setLiveMessage('Die Dateiauswahl für den Backup-Probelauf wurde abgebrochen.');
      }
    } catch {
      setError(
        'Der Backup-Probelauf konnte nicht abgeschlossen werden. Der aktuelle Profilstand blieb unverändert.',
      );
      setLiveMessage('Der Backup-Probelauf konnte nicht abgeschlossen werden.');
    } finally {
      activeRequestIdRef.current = null;
      setActiveRequestId(null);
      setBusy(false);
      setCancelling(false);
      setDryRunProgress(null);
      setCredential('');
    }
  };

  const progressText = cancelling
    ? 'Abbruch wird angefordert'
    : dryRunProgress === null
      ? 'Lokaler Probelauf wird vorbereitet'
      : dryRunProgressCopy(dryRunProgress);
  const progressTotal = Math.max(1, dryRunProgress?.total ?? 2);
  const progressCompleted = Math.min(progressTotal, Math.max(0, dryRunProgress?.completed ?? 0));

  return (
    <Modal
      open={open}
      title={
        isDryRun
          ? 'Verschlüsseltes Backup probeweise prüfen'
          : 'Verschlüsseltes Backup wiederherstellen'
      }
      description={
        isDryRun
          ? 'Wähle eine .vaulta-backup-Datei. Sie wird in einem getrennten temporären Bereich vollständig geprüft, ohne den aktuellen Profilstand zu verändern.'
          : freshProfile
            ? 'Stelle auf diesem frischen System ein vollständiges Kryptris-Profil aus einer .vaulta-backup-Datei wieder her.'
            : 'Wähle eine .vaulta-backup-Datei. Version und Integrität werden vollständig geprüft, bevor Daten ersetzt werden.'
      }
      onClose={close}
    >
      <form
        className="stack"
        onSubmit={(event) => void (isDryRun ? dryRun(event) : restore(event))}
      >
        <div className="segmented-control">
          <button
            type="button"
            className={credentialType === 'master' ? 'is-active' : ''}
            onClick={() => setCredentialType('master')}
          >
            <LockKeyhole />
            Master-Passwort
          </button>
          <button
            type="button"
            className={credentialType === 'recovery' ? 'is-active' : ''}
            onClick={() => setCredentialType('recovery')}
          >
            <KeyRound />
            Wiederherstellungsschlüssel
          </button>
        </div>
        <Field
          label={
            credentialType === 'master'
              ? isDryRun
                ? 'Master-Passwort des Backups für den Probelauf'
                : 'Master-Passwort des Backups'
              : 'Wiederherstellungsschlüssel'
          }
        >
          {credentialType === 'master' ? (
            <PasswordInput
              value={credential}
              autoComplete="current-password"
              onChange={setCredential}
            />
          ) : (
            <textarea
              rows={3}
              value={credential}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setCredential(event.currentTarget.value.toUpperCase())}
            />
          )}
        </Field>
        {!isDryRun && credentialType === 'recovery' && (
          <>
            <Field label="Neues Master-Passwort" hint="Mindestens 12 Zeichen">
              <PasswordInput
                value={newMasterPassword}
                autoComplete="new-password"
                onChange={setNewMasterPassword}
              />
            </Field>
            <Field label="Neues Master-Passwort wiederholen">
              <PasswordInput
                value={newMasterPasswordConfirmation}
                autoComplete="new-password"
                onChange={setNewMasterPasswordConfirmation}
              />
            </Field>
          </>
        )}
        <InlineNotice kind="info">
          {isDryRun
            ? 'Nach der Dateiauswahl wird das Backup in einem getrennten Bereich entschlüsselt und semantisch geprüft. Es werden keine Tresore, Anhänge oder Profile wiederhergestellt.'
            : 'Nach der Dateiauswahl wird das Backup in einem getrennten Bereich entschlüsselt und geprüft. Bei Abbruch oder Fehler bleiben bestehende Daten unverändert.'}
        </InlineNotice>
        {isDryRun && busy && (
          <section className="backup-dry-run-progress" aria-label="Status des Backup-Probelaufs">
            <div>
              <strong>Backup-Probelauf läuft</strong>
              <span>{progressText}</span>
            </div>
            <progress
              max={progressTotal}
              value={progressCompleted}
              aria-label={`Backup-Probelauf: ${progressText}`}
              aria-valuetext={`${String(progressCompleted)} von ${String(progressTotal)} Schritten abgeschlossen`}
            />
          </section>
        )}
        {isDryRun && (
          <p className="sr-only" aria-live="polite" aria-atomic="true">
            {liveMessage}
          </p>
        )}
        {error && <InlineNotice kind="error">{error}</InlineNotice>}
        <div className="modal__inline-actions">
          <Button
            type="button"
            variant="ghost"
            busy={isDryRun && cancelling}
            disabled={busy && !isDryRun}
            onClick={() => {
              if (isDryRun && busy) {
                void cancelDryRun();
                return;
              }
              close();
            }}
          >
            {isDryRun && busy ? 'Probelauf abbrechen' : 'Abbrechen'}
          </Button>
          <Button
            type="submit"
            variant="primary"
            busy={busy}
            disabled={
              !credential ||
              (!isDryRun &&
                credentialType === 'recovery' &&
                (newMasterPassword.length < 12 || !newMasterPasswordConfirmation))
            }
          >
            {isDryRun ? 'Backup auswählen und probeweise prüfen' : 'Backup auswählen und prüfen'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function dryRunProgressCopy(progress: LocalJobProgressEvent): string {
  const phase = {
    entschluesseln: 'Backup wird in einem getrennten Bereich entschlüsselt',
    'semantisch-pruefen': 'Profil, Tresore, Anhänge und Protokoll werden geprüft',
    abgeschlossen: 'Backup-Probelauf wurde abgeschlossen',
  }[progress.phase];
  return phase ?? 'Lokaler Backup-Probelauf läuft';
}
