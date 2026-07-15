import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as common from '@zxcvbn-ts/language-common';
import * as german from '@zxcvbn-ts/language-de';

export interface PasswordStrength {
  score: number;
  label: string;
  crackTime: string;
}

const evaluator = new ZxcvbnFactory({
  translations: german.translations,
  graphs: common.adjacencyGraphs,
  dictionary: {
    ...common.dictionary,
    ...german.dictionary,
  },
});

export function evaluatePassword(password: string, userInputs: string[] = []): PasswordStrength {
  const result = evaluator.check(
    password,
    userInputs.filter((value) => value.trim().length > 0),
  );
  const labels = ['Sehr schwach', 'Schwach', 'Ausreichend', 'Stark', 'Sehr stark'] as const;

  return {
    score: result.score,
    label: labels[result.score] ?? 'Unbekannt',
    crackTime: result.crackTimes.offlineSlowHashingXPerSecond.display,
  };
}
