import { describe, expect, it } from 'vitest';

import { TemplateService } from '../../src/main/services/template-service';

describe('TemplateService', () => {
  it('speichert, listet und wendet wiederverwendbare Vorlagen an', () => {
    const service = new TemplateService();
    const saved = service.save({
      name: 'Serverzugang',
      entryType: 'ssh-key',
      fields: [
        { label: 'Umgebung', type: 'text', secret: false, defaultValue: 'Produktion' },
        { label: 'Notfall-PIN', type: 'secret', secret: true, defaultValue: '' },
      ],
    });
    const applied = service.apply(saved.id, { title: 'Server Nord' });

    expect(service.list()).toHaveLength(1);
    expect(applied.title).toBe('Server Nord');
    expect(applied.data.type).toBe('ssh-key');
    expect(applied.customFields).toHaveLength(2);
    expect(applied.customFields[1]).toMatchObject({ secret: true, searchable: false });
  });

  it('liefert defensive Kopien und loescht gezielt', () => {
    const service = new TemplateService();
    const saved = service.save({ name: 'Notiz', entryType: 'secure-note', fields: [] });
    const snapshot = service.snapshot();
    snapshot[0]!.name = 'Manipuliert';
    expect(service.list()[0]?.name).toBe('Notiz');
    service.delete(saved.id);
    expect(service.list()).toEqual([]);
  });

  it('weist doppelte Feldnamen zurueck', () => {
    const service = new TemplateService();
    expect(() =>
      service.save({
        name: 'Doppelt',
        entryType: 'custom',
        fields: [
          { label: 'Code', type: 'text', secret: false, defaultValue: '' },
          { label: 'code', type: 'secret', secret: true, defaultValue: '' },
        ],
      }),
    ).toThrow(/eindeutig/u);
  });
});
