import { KeyRound, LockKeyhole } from 'lucide-react';
import type { FormEvent } from 'react';
import { useState } from 'react';

import type { AppState } from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Button, Field, InlineNotice, Modal, PasswordInput } from './ui';

interface BackupRestoreModalProps {
  open: boolean;
  freshProfile?: boolean;
  notify: Notify;
  onClose: () => void;
  onRestored: (state: AppState) => void;
}

export function BackupRestoreModal({
  open,
  freshProfile = false,
  notify,
  onClose,
  onRestored,
}: BackupRestoreModalProps) {
  const [credentialType, setCredentialType] = useState<'master' | 'recovery'>('master');
  const [credential, setCredential] = useState('');
  const [newMasterPassword, setNewMasterPassword] = useState('');
  const [newMasterPasswordConfirmation, setNewMasterPasswordConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    if (busy) return;
    setCredential('');
    setNewMasterPassword('');
    setNewMasterPasswordConfirmation('');
    setError(null);
    onClose();
  };

  const restore = async (event: FormEvent) => {
    event.preventDefault();
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

  return (
    <Modal
      open={open}
      title="Verschlüsseltes Backup wiederherstellen"
      description={
        freshProfile
          ? 'Stelle auf diesem frischen System ein vollständiges Vaulta-Profil aus einer .vaulta-backup-Datei wieder her.'
          : 'Wähle eine .vaulta-backup-Datei. Version und Integrität werden vollständig geprüft, bevor Daten ersetzt werden.'
      }
      onClose={close}
    >
      <form className="stack" onSubmit={(event) => void restore(event)}>
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
              ? 'Master-Passwort des Backups'
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
        {credentialType === 'recovery' && (
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
          Nach der Dateiauswahl wird das Backup in einem getrennten Bereich entschlüsselt und
          geprüft. Bei Abbruch oder Fehler bleiben bestehende Daten unverändert.
        </InlineNotice>
        {error && <InlineNotice kind="error">{error}</InlineNotice>}
        <div className="modal__inline-actions">
          <Button type="button" variant="ghost" disabled={busy} onClick={close}>
            Abbrechen
          </Button>
          <Button
            type="submit"
            variant="primary"
            busy={busy}
            disabled={
              !credential ||
              (credentialType === 'recovery' &&
                (newMasterPassword.length < 12 || !newMasterPasswordConfirmation))
            }
          >
            Backup auswählen und prüfen
          </Button>
        </div>
      </form>
    </Modal>
  );
}
