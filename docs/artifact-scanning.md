# Artefakt- und Canary-Scan

`npm run security:scan-artifacts` prüft die erzeugten `dist`- und `release`-Bäume
vor einer Veröffentlichung auf die festgelegten Canary-Geheimnisse. Geprüft werden
Dateipfade sowie Inhalte in UTF-8, UTF-16LE und UTF-16BE.

Der Scan behandelt Container inhaltlich:

- ZIP, JAR und NUPKG werden ohne Schreiben auf die Platte rekursiv gestreamt.
- ASAR-Header werden begrenzt geparst; gepackte Dateien und darin liegende Archive
  werden rekursiv geprüft.
- Ein NSIS-Installer ist selbst kein verlässlich direkt lesbares ZIP. Deshalb wird
  die rohe Setup-EXE geprüft und zusätzlich werden die beiden exakt im selben
  electron-builder-Lauf erzeugten Bäume `win-unpacked` und
  `win-arm64-unpacked` rekursiv geprüft. Fehlen diese reproduzierbaren
  Staging-Bäume, schlägt der Scan des NSIS-Installers geschlossen fehl.
- Der Windows-Release-Workflow installiert zusätzlich genau den erzeugten NSIS-Installer still in
  ein isoliertes Benutzerziel und scannt den tatsächlich extrahierten Installationsbaum. Erst danach
  wird ausschließlich eine markierte Kopie für den Playwright-Inspector angepasst; die
  Release-EXE bleibt unverändert.

Symbolische Verknüpfungen, verschlüsselte oder unsichere Archiveinträge sowie
Traversal-Pfade werden abgelehnt. Grenzen für Datei- und Headergröße,
Eintragszahl, Kompressionsrate, gesamte entpackte Datenmenge und
Verschachtelungstiefe verhindern, dass der Release-Check selbst zur
Zip-Bomb-Senke wird.

Die fokussierten Tests liegen in `tests/unit/artifact-scanner.test.ts`. Sie decken
komprimierte Canary-Inhalte, verschachtelte ASARs, Pfad-Canaries, das
NSIS-Staging, Symlinks, hohe Kompressionsraten und harte Größenlimits ab.

`npm run security:check-fuses` prüft parallel die gehärteten Electron-Fuses beider Architekturen.
Der Release-Workflow verifiziert dieselben Fuses nochmals an der unveränderten installierten EXE,
deinstalliert Vaulta anschließend still und prüft über ein Sentinel, dass lokale Nutzerdaten gemäß
Produktentscheidung erhalten bleiben.
