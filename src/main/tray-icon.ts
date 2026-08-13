const KRYPTRIS_TRAY_ICON_SVG = String.raw`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" role="img" aria-label="Kryptris"><defs><linearGradient id="background" x1="128" y1="96" x2="896" y2="928" gradientUnits="userSpaceOnUse"><stop stop-color="#111A35"/><stop offset="1" stop-color="#090E20"/></linearGradient><linearGradient id="shield" x1="250" y1="178" x2="780" y2="846" gradientUnits="userSpaceOnUse"><stop stop-color="#32D8C5"/><stop offset="0.56" stop-color="#5FA8FF"/><stop offset="1" stop-color="#9A6CFF"/></linearGradient><filter id="glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="28"/></filter></defs><rect width="1024" height="1024" rx="224" fill="url(#background)"/><path d="M512 132 804 246v225c0 199-119 344-292 421C339 815 220 670 220 471V246Z" fill="#31D7C5" opacity="0.2" filter="url(#glow)"/><path d="M512 146 790 254v214c0 187-111 323-278 399-167-76-278-212-278-399V254Z" fill="url(#shield)"/><path d="M512 232 708 309v158c0 131-72 231-196 297-124-66-196-166-196-297V309Z" fill="#0B1126"/><path d="M414 473v-54c0-58 42-105 98-105s98 47 98 105v54" fill="none" stroke="url(#shield)" stroke-linecap="round" stroke-width="48"/><rect x="372" y="451" width="280" height="214" rx="52" fill="url(#shield)"/><circle cx="512" cy="548" r="31" fill="#0B1126"/><path d="M512 575v38" stroke="#0B1126" stroke-linecap="round" stroke-width="30"/></svg>`;

/** Embedded local copy of build/icon.svg so packaged tray startup has no file-system dependency. */
export const KRYPTRIS_TRAY_ICON_DATA_URL = `data:image/svg+xml;base64,${Buffer.from(
  KRYPTRIS_TRAY_ICON_SVG,
  'utf8',
).toString('base64')}`;

export interface TrayIconImage {
  isEmpty(): boolean;
}

export interface NativeImageFactory<T extends TrayIconImage> {
  createFromDataURL(dataUrl: string): T;
}

/** Refuse to create an invisible tray item if Electron cannot decode the bundled local icon. */
export function createKryptrisTrayIcon<T extends TrayIconImage>(factory: NativeImageFactory<T>): T {
  const icon = factory.createFromDataURL(KRYPTRIS_TRAY_ICON_DATA_URL);
  if (icon.isEmpty())
    throw new Error('Das lokale Kryptris-Tray-Symbol konnte nicht geladen werden.');
  return icon;
}
