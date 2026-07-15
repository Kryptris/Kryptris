# ADR 0004: Electron-Prozess- und IPC-Grenze

- Status: angenommen
- Datum: 14. Juli 2026
- Bezug: Welle 0 und 5

## Entscheidung

Der React-Renderer ist eine nicht vertrauenswürdige Darstellungsschicht. Er erhält weder Node.js noch `ipcRenderer`, Schlüssel, generische Systemfunktionen oder frei nutzbare Dateioperationen. Pfade gelangen nur nach einer nativen Auswahl zur Anzeige in den Renderer und werden im Main-Prozess niemals ungeprüft als Schreibziel übernommen. Der Preload exponiert ausschließlich die in `src/shared/ipc.ts` fest benannte API.

Da Electron-Sandbox-Preloads keine lokalen CommonJS-Abhängigkeiten laden dürfen, wird der Preload
separat zu genau einer Datei gebündelt. Der Build bricht ab, wenn das Ergebnis neben `electron` einen
weiteren Laufzeitimport enthält oder die Vaulta-API in einer isolierten Sandbox-Ausführung nicht
exponiert werden kann.

Jeder IPC-Handler:

- prüft Sender-Frame und exakte lokale Origin,
- validiert ein strikt begrenztes Schema,
- ruft genau eine fachliche Operation auf,
- serialisiert Fehler ohne Stack/Details,
- liefert Geheimnisse nur bei bewusster Reveal-Aktion; Copy bleibt vollständig im Main-Prozess.

BrowserWindow nutzt `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, deaktivierte Navigation/Popups und Content Protection. Berechtigungen sind standardmäßig verweigert. Remote-Requests, Remote-Ressourcen, `webview`, `eval`, `new Function` und unvalidierte externe Links sind verboten. Produktions-CSP: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'` plus restriktive Basis-/Frame-/Objektregeln.

Packaging setzt Electron-Fuses: kein `RunAsNode`, keine `NODE_OPTIONS`/CLI-Inspect-Argumente, ASAR-Integritätsprüfung und ausschließliches Laden aus ASAR.

## Geheimnisfluss

- Listen liefern nur Entry-Summaries.
- Details enthalten maskierte Secret-Felder ohne Wert.
- Reveal erfordert eine konkrete Feld-ID und optional erneute Master-Prüfung.
- Copy schreibt im Main-Prozess und bestätigt nur den Erfolg.
- Bearbeiten ist eine bewusste Aktion und darf das konkret bearbeitete Entry-Modell kurzzeitig an den Renderer liefern.
- Sperren sendet ein Ereignis, verwirft den Rendererzustand und räumt Schlüssel/Zwischenablage.

## Externe Links

Vaulta exponiert keine Shell- oder Link-Bridge. Websites bleiben als Text kopierbar; Links in Markdown werden nicht anklickbar dargestellt. Navigation, Popups und externe Requests bleiben vollständig blockiert.
