import { EyeOff, KeyRound, LockKeyhole } from 'lucide-react';
import { useState } from 'react';

import { Button, InlineNotice, Modal } from './ui';

export function OnboardingModal({
  open,
  onComplete,
}: {
  open: boolean;
  onComplete: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);

  const complete = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await onComplete();
    } catch {
      // App reports the protected settings-write error; keep this modal open for a retry.
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Willkommen bei Kryptris"
      description="Dein Tresor bleibt auf diesem Gerät. Diese kurze Einführung ist optional."
      size="medium"
      onClose={() => void complete()}
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={() => void complete()}>
            Einführung überspringen
          </Button>
          <Button variant="primary" busy={busy} onClick={() => void complete()}>
            Loslegen
          </Button>
        </>
      }
    >
      <ol className="onboarding-steps">
        <li>
          <LockKeyhole aria-hidden="true" />
          <span>
            <strong>Sperre hat Vorrang</strong>
            <small>Strg + L sperrt sofort und beendet geheime Ansichten.</small>
          </span>
        </li>
        <li>
          <KeyRound aria-hidden="true" />
          <span>
            <strong>Wiederherstellung vorbereiten</strong>
            <small>Bewahre einen Wiederherstellungsschlüssel getrennt vom Gerät auf.</small>
          </span>
        </li>
        <li>
          <EyeOff aria-hidden="true" />
          <span>
            <strong>Sichtschutz bewusst wählen</strong>
            <small>
              Fokusmodus und Inhaltsschutz reduzieren Sichtbarkeit, ersetzen aber keine Sperre.
            </small>
          </span>
        </li>
      </ol>
      <InlineNotice kind="info">
        Du kannst diese Hinweise später unter „Hilfe & Datenschutz“ und die Optionen unter „Windows
        & Sichtschutz“ erneut aufrufen.
      </InlineNotice>
    </Modal>
  );
}
