import { randomUUID } from 'node:crypto';

import { VaultaError } from '../../shared/errors';
import {
  ENTRY_TYPES,
  type CustomField,
  type EntryInput,
  type EntryTemplate,
} from '../../shared/models';
import { emptyEntryInput } from './entry-utils';

export type EntryTemplateInput = Omit<EntryTemplate, 'id' | 'createdAt' | 'updatedAt'> & {
  id?: string;
};

export class TemplateService {
  private readonly templates = new Map<string, EntryTemplate>();

  public constructor(initial: readonly EntryTemplate[] = []) {
    for (const template of initial) this.templates.set(template.id, structuredClone(template));
  }

  public list(): EntryTemplate[] {
    return [...this.templates.values()]
      .sort((left, right) => left.name.localeCompare(right.name, 'de'))
      .map((template) => structuredClone(template));
  }

  public save(input: EntryTemplateInput): EntryTemplate {
    validateTemplate(input);
    const now = new Date().toISOString();
    const existing = input.id === undefined ? undefined : this.templates.get(input.id);
    if (input.id !== undefined && existing === undefined) {
      throw new VaultaError('NOT_FOUND', 'Die Vorlage wurde nicht gefunden.');
    }
    const template: EntryTemplate = {
      id: input.id ?? randomUUID(),
      name: input.name.trim(),
      entryType: input.entryType,
      fields: input.fields.map((field) => ({ ...field, label: field.label.trim() })),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.templates.set(template.id, structuredClone(template));
    return structuredClone(template);
  }

  public delete(id: string): void {
    if (!this.templates.delete(id)) {
      throw new VaultaError('NOT_FOUND', 'Die Vorlage wurde nicht gefunden.');
    }
  }

  public apply(templateId: string, base: Partial<EntryInput> = {}): EntryInput {
    const template = this.templates.get(templateId);
    if (template === undefined)
      throw new VaultaError('NOT_FOUND', 'Die Vorlage wurde nicht gefunden.');
    if (base.data !== undefined && base.data.type !== template.entryType) {
      throw invalid('Die Ausgangsdaten passen nicht zum Eintragstyp der Vorlage.');
    }
    const empty = emptyEntryInput(template.entryType, template.name);
    const customFields: CustomField[] = template.fields.map((field, index) => {
      const secret = field.secret || field.type === 'secret';
      return {
        id: randomUUID(),
        label: field.label,
        type: field.type,
        value: field.defaultValue,
        secret,
        searchable: !secret,
        order: index,
      };
    });

    const result: EntryInput = {
      ...empty,
      ...base,
      title: base.title ?? empty.title,
      folderId: base.folderId ?? empty.folderId,
      tags: base.tags === undefined ? empty.tags : [...base.tags],
      favorite: base.favorite ?? empty.favorite,
      note: base.note ?? empty.note,
      customFields: [
        ...customFields,
        ...(base.customFields === undefined ? [] : structuredClone(base.customFields)),
      ],
      data: base.data === undefined ? empty.data : structuredClone(base.data),
    };
    if (base.id === undefined) delete result.id;
    return result;
  }

  public snapshot(): EntryTemplate[] {
    return this.list();
  }
}

function validateTemplate(input: EntryTemplateInput): void {
  const name = input.name.trim();
  if (name.length < 1 || name.length > 80) {
    throw invalid('Der Vorlagenname muss zwischen 1 und 80 Zeichen lang sein.');
  }
  if (!ENTRY_TYPES.includes(input.entryType))
    throw invalid('Der Eintragstyp der Vorlage ist ungueltig.');
  if (input.fields.length > 100)
    throw invalid('Eine Vorlage darf hoechstens 100 Felder enthalten.');

  const labels = new Set<string>();
  for (const field of input.fields) {
    const label = field.label.trim();
    if (label.length < 1 || label.length > 80) throw invalid('Eine Feldbezeichnung ist ungueltig.');
    const normalized = label.toLocaleLowerCase('de');
    if (labels.has(normalized)) throw invalid('Feldbezeichnungen muessen eindeutig sein.');
    labels.add(normalized);
    if (field.type === 'boolean' && typeof field.defaultValue !== 'boolean') {
      throw invalid(`Das Feld „${label}“ benoetigt einen Ein/Aus-Standardwert.`);
    }
    if (field.type === 'number' && typeof field.defaultValue !== 'number') {
      throw invalid(`Das Feld „${label}“ benoetigt einen numerischen Standardwert.`);
    }
    if (
      field.type !== 'boolean' &&
      field.type !== 'number' &&
      typeof field.defaultValue !== 'string'
    ) {
      throw invalid(`Der Standardwert fuer „${label}“ ist ungueltig.`);
    }
  }
}

function invalid(message: string): VaultaError {
  return new VaultaError('INVALID_INPUT', message);
}
