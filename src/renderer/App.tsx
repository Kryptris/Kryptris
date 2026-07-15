import { AlertTriangle, RotateCcw } from 'lucide-react';

import { AuthScreen } from './components/AuthScreen';
import { Button, LoadingState, ToastRegion } from './components/ui';
import { VaultWorkspace } from './components/VaultWorkspace';
import { useToasts, useVaultaState } from './hooks/useVaulta';

export function App() {
  const { state, setState, fatalError } = useVaultaState();
  const { messages, notify, dismiss } = useToasts();

  if (fatalError) {
    return (
      <main className="fatal-screen">
        <span className="fatal-screen__icon" aria-hidden="true">
          <AlertTriangle />
        </span>
        <h1>Vaulta konnte nicht gestartet werden</h1>
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

  return (
    <>
      {!state.hasProfile || state.locked ? (
        <AuthScreen state={state} onStateChange={setState} notify={notify} />
      ) : (
        <VaultWorkspace state={state} onStateChange={setState} notify={notify} />
      )}
      <ToastRegion messages={messages} onDismiss={dismiss} />
    </>
  );
}
