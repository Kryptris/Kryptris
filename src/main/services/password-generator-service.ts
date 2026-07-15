import { randomInt } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import type { GeneratedSecret, PasswordGeneratorOptions } from '../../shared/models';
import { GERMAN_PASSPHRASE_WORDS } from './german-word-list';
import { evaluatePassword } from './password-strength';

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!#$%&()*+,-./:;<=>?@[]^_{|}~';
const SIMILAR_CHARACTERS = new Set(Array.from('Il1O0o|'));

interface CharacterClass {
  enabled: boolean;
  minimum: number;
  characters: string;
  name: string;
}

export class PasswordGeneratorService {
  public generate(options: PasswordGeneratorOptions): GeneratedSecret {
    const value =
      options.mode === 'password'
        ? this.generatePassword(options)
        : this.generatePassphrase(options);
    const strength = evaluatePassword(value);

    return { value, ...strength };
  }

  private generatePassword(options: PasswordGeneratorOptions): string {
    if (!Number.isInteger(options.length) || options.length < 4 || options.length > 256) {
      throw invalid('Die Passwortlaenge muss zwischen 4 und 256 Zeichen liegen.');
    }

    const excluded = new Set(Array.from(options.excludedCharacters));
    if (options.excludeSimilar) {
      for (const character of SIMILAR_CHARACTERS) excluded.add(character);
    }

    const required = [...new Set(Array.from(options.requiredCharacters))];
    const conflicting = required.find((character) => excluded.has(character));
    if (conflicting !== undefined) {
      throw invalid('Ein zwingend erforderliches Zeichen wurde zugleich ausgeschlossen.');
    }

    const classes: CharacterClass[] = [
      {
        enabled: options.uppercase,
        minimum: options.minimumUppercase,
        characters: filterCharacters(UPPERCASE, excluded),
        name: 'Grossbuchstaben',
      },
      {
        enabled: options.lowercase,
        minimum: options.minimumLowercase,
        characters: filterCharacters(LOWERCASE, excluded),
        name: 'Kleinbuchstaben',
      },
      {
        enabled: options.numbers,
        minimum: options.minimumNumbers,
        characters: filterCharacters(NUMBERS, excluded),
        name: 'Zahlen',
      },
      {
        enabled: options.symbols,
        minimum: options.minimumSymbols,
        characters: filterCharacters(SYMBOLS, excluded),
        name: 'Sonderzeichen',
      },
    ];

    for (const characterClass of classes) {
      if (!Number.isInteger(characterClass.minimum) || characterClass.minimum < 0) {
        throw invalid(`Die Mindestanzahl fuer ${characterClass.name} ist ungueltig.`);
      }
      if (!characterClass.enabled && characterClass.minimum > 0) {
        throw invalid(`${characterClass.name} sind deaktiviert, haben aber eine Mindestanzahl.`);
      }
      if (characterClass.enabled && characterClass.characters.length === 0) {
        throw invalid(`Alle verfuegbaren ${characterClass.name} wurden ausgeschlossen.`);
      }
    }

    const enabledClasses = classes.filter((characterClass) => characterClass.enabled);
    const combinedPool = enabledClasses.map((characterClass) => characterClass.characters).join('');
    const fillPool = combinedPool.length > 0 ? combinedPool : required.join('');
    if (fillPool.length === 0) {
      throw invalid('Aktiviere mindestens eine Zeichengruppe oder gib erforderliche Zeichen an.');
    }

    const result = [...required];
    for (const characterClass of enabledClasses) {
      const alreadyPresent = result.filter((character) =>
        characterClass.characters.includes(character),
      ).length;
      for (let index = alreadyPresent; index < characterClass.minimum; index += 1) {
        result.push(randomCharacter(characterClass.characters));
      }
    }

    if (result.length > options.length) {
      throw invalid('Laenge, Mindestanzahlen und zwingende Zeichen passen nicht zusammen.');
    }
    while (result.length < options.length) result.push(randomCharacter(fillPool));

    return shuffle(result).join('');
  }

  private generatePassphrase(options: PasswordGeneratorOptions): string {
    if (!Number.isInteger(options.wordCount) || options.wordCount < 3 || options.wordCount > 20) {
      throw invalid('Eine Passphrase muss aus 3 bis 20 Woertern bestehen.');
    }
    if (options.separator.length > 16 || /[\r\n\0]/u.test(options.separator)) {
      throw invalid('Das Trennzeichen ist zu lang oder enthaelt Steuerzeichen.');
    }

    const available = Array.from(GERMAN_PASSPHRASE_WORDS);
    const words: string[] = [];
    for (let index = 0; index < options.wordCount; index += 1) {
      const selectedIndex = randomInt(available.length);
      const selected = available.splice(selectedIndex, 1)[0];
      if (selected === undefined) throw new Error('Die lokale Wortliste ist unvollstaendig.');
      words.push(options.capitalizeWords ? capitalize(selected) : selected);
    }

    if (options.includeNumber) {
      const wordIndex = randomInt(words.length);
      words[wordIndex] = `${words[wordIndex] ?? ''}${randomInt(10, 100)}`;
    }
    return words.join(options.separator);
  }
}

function filterCharacters(characters: string, excluded: ReadonlySet<string>): string {
  return Array.from(characters)
    .filter((character) => !excluded.has(character))
    .join('');
}

function randomCharacter(characters: string): string {
  const values = Array.from(characters);
  const value = values[randomInt(values.length)];
  if (value === undefined) throw new Error('Leere Zeichenauswahl.');
  return value;
}

function shuffle(values: string[]): string[] {
  for (let index = values.length - 1; index > 0; index -= 1) {
    const target = randomInt(index + 1);
    [values[index], values[target]] = [values[target] ?? '', values[index] ?? ''];
  }
  return values;
}

function capitalize(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
