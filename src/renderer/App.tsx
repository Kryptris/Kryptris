import { AlertTriangle, RotateCcw } from 'lucide-react';
import { useEffect } from 'react';

import { AuthScreen } from './components/AuthScreen';
import { OnboardingModal } from './components/OnboardingModal';
import { Button, LoadingState, ToastRegion } from './components/ui';
import { VaultWorkspace } from './components/VaultWorkspace';
import { useToasts, useVaultaState } from './hooks/useVaulta';
import { getErrorMessage } from './utils';

export function App() {
  const { state, setState, fatalError } = useVaultaState();
  const { messages, notify, dismiss } = useToasts();

  useEffect(() => {
    if (state?.settings?.reducedMotion) {
      document.documentElement.dataset.reducedMotion = 'true';
    } else {
      delete document.documentElement.dataset.reducedMotion;
    }
    return () => {
      delete document.documentElement.dataset.reducedMotion;
    };
  }, [state?.settings?.reducedMotion]);

  if (fatalError) {
    return (
      <main className="fatal-screen">
        <span className="fatal-screen__icon" aria-hidden="true">
          <AlertTriangle />
        </span>
        <h1>Kryptris konnte nicht gestartet werden</h1>
        <p>{fatalError}</p>
        <Button icon={<RotateCcw />} variant="primary" onClick={() => window.location.reload()}>
          Erneut versuchen
        </Button>
      </main>
    );
  }

  if (!state) {
    return <LoadingState />;
  }

  const completeOnboarding = async () => {
    if (!state.settings) return;
    try {
      const settings = await window.vaulta.settings.update({
        settings: { ...state.settings, onboardingCompleted: true },
      });
      setState((current) => (current ? { ...current, settings } : current));
    } catch (error: unknown) {
      notify('error', 'Einführung konnte nicht abgeschlossen werden', getErrorMessage(error));
      throw error;
    }
  };

  return (
    <>
      {!state.hasProfile || state.locked ? (
        <AuthScreen state={state} onStateChange={setState} notify={notify} />
      ) : (
        <VaultWorkspace state={state} onStateChange={setState} notify={notify} />
      )}
      <OnboardingModal
        open={state.hasProfile && !state.locked && state.settings?.onboardingCompleted === false}
        onComplete={completeOnboarding}
      />
      <ToastRegion messages={messages} onDismiss={dismiss} />
    </>
  );
}
