import { describe, expect, it } from 'vitest';

import { PasswordGeneratorService } from '../../src/main/services/password-generator-service';
import type { PasswordGeneratorOptions } from '../../src/shared/models';

const defaults: PasswordGeneratorOptions = {
  mode: 'password',
  length: 32,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeSimilar: true,
  excludedCharacters: 'x',
  requiredCharacters: '!?',
  minimumUppercase: 3,
  minimumLowercase: 3,
  minimumNumbers: 3,
  minimumSymbols: 3,
  wordCount: 6,
  separator: '-',
  capitalizeWords: false,
  includeNumber: false,
};

describe('PasswordGeneratorService', () => {
  const service = new PasswordGeneratorService();

  it('erfuellt Laenge, Ausschluesse, Pflichtzeichen und Mindestanzahlen', () => {
    const generated = service.generate(defaults);
    expect(generated.value).toHaveLength(32);
    expect(generated.value).toContain('!');
    expect(generated.value).toContain('?');
    expect(generated.value).not.toMatch(/[Il1O0ox]/u);
    expect(generated.value.match(/[A-Z]/gu)?.length ?? 0).toBeGreaterThanOrEqual(3);
    expect(generated.value.match(/[a-z]/gu)?.length ?? 0).toBeGreaterThanOrEqual(3);
    expect(generated.value.match(/[0-9]/gu)?.length ?? 0).toBeGreaterThanOrEqual(3);
    expect(generated.score).toBeGreaterThanOrEqual(0);
  });

  it('erzeugt lokale Passphrasen mit optionaler Zahl', () => {
    const generated = service.generate({
      ...defaults,
      mode: 'passphrase',
      wordCount: 5,
      capitalizeWords: true,
      includeNumber: true,
    });
    const words = generated.value.split('-');
    expect(words).toHaveLength(5);
    expect(words.every((word) => /^\p{Lu}/u.test(word))).toBe(true);
    expect(generated.value).toMatch(/\d{2}/u);
  });

  it('weist widerspruechliche Regeln zurueck', () => {
    expect(() =>
      service.generate({ ...defaults, excludedCharacters: '!', requiredCharacters: '!' }),
    ).toThrow(/ausgeschlossen/u);
  });
});
