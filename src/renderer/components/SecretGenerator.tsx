import { Check, RefreshCw, WandSparkles } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import type { GeneratedSecret, PasswordGeneratorOptions } from '../../shared/models';
import type { Notify } from '../types';
import { getErrorMessage } from '../utils';
import { Button, Field, InlineNotice, Modal } from './ui';

const DEFAULT_GENERATOR_OPTIONS: PasswordGeneratorOptions = {
  mode: 'password',
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeSimilar: true,
  excludedCharacters: '',
  requiredCharacters: '',
  minimumUppercase: 1,
  minimumLowercase: 1,
  minimumNumbers: 1,
  minimumSymbols: 1,
  wordCount: 5,
  separator: '-',
  capitalizeWords: false,
  includeNumber: true,
};

interface SecretGeneratorProps {
  open: boolean;
  notify: Notify;
  onClose: () => void;
  onUse: (value: string) => void;
}

export function SecretGenerator({ open, notify, onClose, onUse }: SecretGeneratorProps) {
  const [options, setOptions] = useState<PasswordGeneratorOptions>(DEFAULT_GENERATOR_OPTIONS);
  const [result, setResult] = useState<GeneratedSecret | null>(null);
  const [busy, setBusy] = useState(false);

  const generate = useCallback(async () => {
    setBusy(true);
    try {
      setResult(await window.vaulta.generator.generate(options));
    } catch (error: unknown) {
      notify('error', 'Generierung fehlgeschlagen', getErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }, [notify, options]);

  useEffect(() => {
    if (open && !result) void generate();
  }, [generate, open, result]);

  return (
    <Modal
      open={open}
      title="Passwort- und Passphrasengenerator"
      description="Die Zufallswerte werden lokal über den kryptografisch sicheren Systemgenerator erzeugt."
      size="large"
      onClose={onClose}
    >
      <div className="generator-layout">
        <div className="generator-result">
          <WandSparkles />
          <code>{result?.value ?? 'Wird sicher erzeugt …'}</code>
          {result && (
            <div className="generator-score">
              <span style={{ width: `${String(Math.max(8, result.score * 20))}%` }} />
              <strong>{result.label}</strong>
              <small>Geschätzte Knackzeit: {result.crackTime}</small>
            </div>
          )}
        </div>

        <div className="segmented-control" role="group" aria-label="Generatorart">
          <button
            type="button"
            className={options.mode === 'password' ? 'is-active' : ''}
            aria-pressed={options.mode === 'password'}
            onClick={() => setOptions((current) => ({ ...current, mode: 'password' }))}
          >
            Passwort
          </button>
          <button
            type="button"
            className={options.mode === 'passphrase' ? 'is-active' : ''}
            aria-pressed={options.mode === 'passphrase'}
            onClick={() => setOptions((current) => ({ ...current, mode: 'passphrase' }))}
          >
            Passphrase
          </button>
        </div>

        {options.mode === 'password' ? (
          <div className="stack">
            <Field label={`Länge: ${String(options.length)}`}>
              <input
                type="range"
                min={8}
                max={128}
                value={options.length}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    length: Number(event.currentTarget.value),
                  }))
                }
              />
            </Field>
            <div className="generator-checks">
              {(
                [
                  ['uppercase', 'Großbuchstaben'],
                  ['lowercase', 'Kleinbuchstaben'],
                  ['numbers', 'Zahlen'],
                  ['symbols', 'Sonderzeichen'],
                  ['excludeSimilar', 'Ähnliche Zeichen vermeiden'],
                ] as const
              ).map(([key, label]) => (
                <label className="check-row check-row--compact" key={key}>
                  <input
                    type="checkbox"
                    checked={options[key]}
                    onChange={(event) =>
                      setOptions((current) => ({ ...current, [key]: event.currentTarget.checked }))
                    }
                  />
                  <span>{label}</span>
                </label>
              ))}
            </div>
            <div className="form-grid form-grid--two">
              <Field label="Zeichen ausschließen">
                <input
                  value={options.excludedCharacters}
                  onChange={(event) =>
                    setOptions((current) => ({
                      ...current,
                      excludedCharacters: event.currentTarget.value,
                    }))
                  }
                />
              </Field>
              <Field label="Zwingend enthalten">
                <input
                  value={options.requiredCharacters}
                  onChange={(event) =>
                    setOptions((current) => ({
                      ...current,
                      requiredCharacters: event.currentTarget.value,
                    }))
                  }
                />
              </Field>
            </div>
            <div className="form-grid form-grid--four">
              <NumberField
                label="Min. A–Z"
                value={options.minimumUppercase}
                onChange={(value) =>
                  setOptions((current) => ({ ...current, minimumUppercase: value }))
                }
              />
              <NumberField
                label="Min. a–z"
                value={options.minimumLowercase}
                onChange={(value) =>
                  setOptions((current) => ({ ...current, minimumLowercase: value }))
                }
              />
              <NumberField
                label="Min. Zahlen"
                value={options.minimumNumbers}
                onChange={(value) =>
                  setOptions((current) => ({ ...current, minimumNumbers: value }))
                }
              />
              <NumberField
                label="Min. Symbole"
                value={options.minimumSymbols}
                onChange={(value) =>
                  setOptions((current) => ({ ...current, minimumSymbols: value }))
                }
              />
            </div>
          </div>
        ) : (
          <div className="stack">
            <Field label={`Wortanzahl: ${String(options.wordCount)}`}>
              <input
                type="range"
                min={3}
                max={12}
                value={options.wordCount}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    wordCount: Number(event.currentTarget.value),
                  }))
                }
              />
            </Field>
            <Field label="Trennzeichen">
              <input
                value={options.separator}
                maxLength={4}
                onChange={(event) =>
                  setOptions((current) => ({ ...current, separator: event.currentTarget.value }))
                }
              />
            </Field>
            <label className="check-row check-row--compact">
              <input
                type="checkbox"
                checked={options.capitalizeWords}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    capitalizeWords: event.currentTarget.checked,
                  }))
                }
              />
              <span>Wörter großschreiben</span>
            </label>
            <label className="check-row check-row--compact">
              <input
                type="checkbox"
                checked={options.includeNumber}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    includeNumber: event.currentTarget.checked,
                  }))
                }
              />
              <span>Zahl ergänzen</span>
            </label>
          </div>
        )}

        <InlineNotice kind="info">
          Der generierte Wert wird erst gespeichert, wenn du ihn übernimmst und den Eintrag
          sicherst.
        </InlineNotice>
        <div className="modal__inline-actions">
          <Button icon={<RefreshCw />} busy={busy} onClick={() => void generate()}>
            Neu erzeugen
          </Button>
          <Button
            variant="primary"
            icon={<Check />}
            disabled={!result}
            onClick={() => {
              if (result) onUse(result.value);
            }}
          >
            Wert übernehmen
          </Button>
        </div>
      </div>
    </Modal>
  );
}

function NumberField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <Field label={label}>
      <input
        type="number"
        min={0}
        max={20}
        value={value}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
      />
    </Field>
  );
}
