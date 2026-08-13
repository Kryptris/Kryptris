import { describe, expect, it, vi } from 'vitest';

import { KRYPTRIS_TRAY_ICON_DATA_URL, createKryptrisTrayIcon } from '../../src/main/tray-icon';

describe('Kryptris-Tray-Symbol', () => {
  it('liefert eine eingebettete lokale SVG-Datenquelle ohne Netzwerk-URL', () => {
    expect(KRYPTRIS_TRAY_ICON_DATA_URL).toMatch(/^data:image\/svg\+xml;base64,/u);
    const encoded = KRYPTRIS_TRAY_ICON_DATA_URL.split(',', 2)[1];
    expect(encoded).toBeDefined();
    const svg = Buffer.from(encoded ?? '', 'base64').toString('utf8');
    expect(svg).toContain('<svg');
    expect(svg).toContain('Kryptris');
    expect(svg).not.toMatch(/^https?:/u);
  });

  it('verwendet die eingebettete Quelle und verweigert ein unsichtbares Tray-Symbol', () => {
    const createFromDataURL = vi.fn(() => ({ isEmpty: () => false }));

    const icon = createKryptrisTrayIcon({ createFromDataURL });

    expect(icon.isEmpty()).toBe(false);
    expect(createFromDataURL).toHaveBeenCalledWith(KRYPTRIS_TRAY_ICON_DATA_URL);
    expect(() =>
      createKryptrisTrayIcon({ createFromDataURL: () => ({ isEmpty: () => true }) }),
    ).toThrow(/Tray-Symbol/i);
  });
});
