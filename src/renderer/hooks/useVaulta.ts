import { useCallback, useEffect, useRef, useState } from 'react';

import type { AppState } from '../../shared/models';
import type { Notify, ToastMessage } from '../types';
import { getErrorMessage } from '../utils';

export function useVaultaState() {
  const [state, setState] = useState<AppState | null>(null);
  const [fatalError, setFatalError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void window.vaulta.system
      .getState()
      .then((nextState) => {
        if (active) setState(nextState);
      })
      .catch((error: unknown) => {
        if (active) setFatalError(getErrorMessage(error));
      });

    const removeLocked = window.vaulta.events.onLocked(() => {
      setState((current) => (current ? { ...current, locked: true } : current));
    });
    const removeChanged = window.vaulta.events.onStateChanged(setState);

    return () => {
      active = false;
      removeLocked();
      removeChanged();
    };
  }, []);

  return { state, setState, fatalError };
}

export function useToasts() {
  const [messages, setMessages] = useState<ToastMessage[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setMessages((current) => current.filter((message) => message.id !== id));
  }, []);

  const notify: Notify = useCallback((kind, title, message) => {
    const id = nextId.current++;
    const next: ToastMessage = message ? { id, kind, title, message } : { id, kind, title };
    setMessages((current) => [...current.slice(-3), next]);
    window.setTimeout(() => {
      setMessages((current) => current.filter((item) => item.id !== id));
    }, 4200);
  }, []);

  useEffect(
    () =>
      window.vaulta.events.onClipboardCleared(() => {
        notify('info', 'Zwischenablage geleert', 'Der von Kryptris kopierte Wert wurde entfernt.');
      }),
    [notify],
  );

  useEffect(
    () =>
      window.vaulta.events.onBackgroundWarning((message) => {
        notify('warning', 'Hintergrundaktion fehlgeschlagen', message);
      }),
    [notify],
  );

  return { messages, notify, dismiss };
}
