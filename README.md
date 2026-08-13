# Kryptris

Kryptris ist ein lokaler, deutschsprachiger Passwort-Manager für Windows 10/11. Er arbeitet ohne Konto, Cloud oder externe Dienste und speichert alle fachlichen Daten verschlüsselt im lokalen Benutzerprofil. Das Produkt folgt dem verbindlichen [Konzept](docs/concept.md) und dem visuellen [UI-Prototyp](docs/assets/vaulta-ui-prototype.png).

## Funktionsumfang

- ein lokales Profil mit mehreren kryptografisch getrennten Tresoren
- Zugangsdaten, sichere Notizen, Kreditkarten, Identitäten, WLAN, Lizenzen, SSH-Schlüssel, Dateien und freie Einträge
- eigene Felder, Ordner, Tags, Favoriten, Papierkorb und Volltextsuche
- Passwort-/Passphrasengenerator, Offline-TOTP und lokaler Sicherheitscheck
- authentifiziert verschlüsselte Anhänge mit sicherem Dateigrößenlimit
- Wiederherstellungsschlüssel, verschlüsselte Backups, Rotation und Restore-Prüfung
- Import aus Bitwarden, 1Password, LastPass, KeePass, Proton Pass und Browser-CSV sowie generischem CSV/JSON
- stark bestätigte Klartext-Exporte und verschlüsseltes Aktivitätsprotokoll
- optionale TOTP-Sperre und FIDO2/WebAuthn-Sicherheitsschlüssel mit sichtbarer PRF-/Anwesenheits-Klassifizierung
- wiederverwendbare Vorlagen und erweiterte lokale Berichte
- Mehrfachauswahl, atomare Batch-/Cross-Vault-Aktionen, gespeicherte Ansichten, zentrale
  Tagverwaltung und lokale Befehlspalette
- lokale Dubletten-Zentrale mit feldweisem Merge, Lebenszyklus-/Rotationshinweise und
  Datenqualitätsprüfung mit bestätigten Korrekturvorschauen
- optionale, standardmäßig deaktivierte Papierkorbfrist ohne Nachholen geschlossener Zeiträume
- Sicherheitszentrale mit Recovery-Bereitschaftstest, vollständiger redigierter Integritätsprüfung
  und einer optional importierbaren, strikt lokalen Datenleckliste ohne Online-Abfrage
- Backup-Gesundheitscenter mit redigiertem Status, Generationenübersicht, Warnung bei gleichem
  Laufwerk und isoliertem, abbrechbarem Restore-Probelauf
- portables, separat mit Argon2id und einem zufälligen Paket-Schlüssel verschlüsseltes Tresor-Paket
  mit optionalen Anhängen, Vorschau und atomarem Import
- Import für Dashlane, NordPass und RoboForm mit inhaltsbasierter Formaterkennung, wiederverwendbaren
  CSV-Feldzuordnungen, Importzusammenfassung und sicherem Drag-and-drop
- optionale Windows-Integration mit lokalem Tray-Status, reversiblen Autostart-Einstellungen und
  Sperren vor dem Ausblenden beim Schließen
- ausschließlich lokale, allgemeine Erinnerungen für Rotation, Abläufe und Backup-Prüfungen; sie
  enthalten keine Tresor-, Eintrags- oder Geheimwerte
- Fokusmodus, lokale Hilfe und überspringbares Onboarding sowie tastatur- und Screenreader-taugliche
  Bedienpfade
- virtualisierte Eintragsliste für große Tresore, entprellte Suche und Schutz vor veralteten
  Listenantworten
- NSIS-Installer und portable ZIP-Ausgabe

## Sicherheitsmodell in Kürze

Das Master-Passwort wird mit Argon2id (mindestens 256 MiB Arbeitsspeicher im Produktprofil) abgeleitet. Es schützt einen zufälligen 256-Bit-Profil-Gate-Key; daraus werden getrennte Schlüssel abgeleitet. Tresore und Profilmetadaten nutzen AES-256-GCM, Anhänge authentifizierte AES-GCM-Chunks. Container werden erst verifiziert und dann transaktional ausgetauscht. Kryptografische Schlüssel bleiben im Main-Prozess und werden beim Sperren überschrieben, soweit JavaScript/Node dies zulässt.

Der Renderer läuft mit `contextIsolation`, ohne Node-Integration, im Chromium-Sandboxprozess. Seine API besteht aus einer festen, schema-validierten IPC-Allowlist. Datei-, Zwischenablage- und Kryptografieoperationen liegen im Main-Prozess. Die Oberfläche wird produktiv von einem ausschließlich an `127.0.0.1` gebundenen statischen Server ausgeliefert; dadurch steht für FIDO2 eine von Chromium akzeptierte lokale WebAuthn-Origin bereit. Es gibt keine Daten-API und keine Verbindung zu externen Netzen. Details: [ADR 0004](docs/architecture/adr-0004-electron-boundary.md) und [ADR 0005](docs/architecture/adr-0005-local-webauthn-origin.md).

Kryptris schützt Daten auf einer ausgeschalteten oder gesperrten Festplatte und erkennt manipulierte Container. Es kann ein bereits kompromittiertes Windows, Administrator-Schadsoftware, Keylogger, manipulierte Zwischenablagen oder Kameras nicht zuverlässig beherrschen. Ohne Master- oder gültigen Wiederherstellungsschlüssel existiert keine Hintertür.

## Entwicklung

Voraussetzungen: Windows 10/11, Node.js 24 und Corepack.

```powershell
$env:COREPACK_HOME = Join-Path (Get-Location) '.corepack'
corepack pnpm install --frozen-lockfile --store-dir .pnpm-store
corepack pnpm dev
```

Die Paketauflösung ist in `pnpm-lock.yaml` festgeschrieben. pnpm führt nur explizit freigegebene Installationsskripte aus.

## Prüfen und bauen

```powershell
corepack pnpm verify
corepack pnpm test:e2e
corepack pnpm benchmark:performance -- --output docs\performance-benchmark-YYYY-MM-DD.json
corepack pnpm audit:prod
corepack pnpm licenses:prod
corepack pnpm make
corepack pnpm security:check-fuses
corepack pnpm security:scan-artifacts
```

`pnpm test:e2e` testet immer den unmittelbar zuvor gebauten Workspace. Der Windows-Release-Workflow
startet den separaten Paket-Test direkt über Playwright mit `VAULTA_E2E_MODE=packaged` und
`VAULTA_E2E_EXECUTABLE`, damit eine bereits installierte und für E2E vorbereitete EXE geprüft werden
kann.

`pnpm benchmark:performance` erzeugt ausschließlich synthetische Daten mit 1.000, 5.000 und 10.000
Einträgen und misst nur Main-Prozess-Pfade. Der Benchmark misst weder IPC-/Structured-Clone-Kosten
noch React-/Chromium-Rendering, den ersten sichtbaren UI-Feedback-Zeitpunkt oder Renderer-Frames.
Diese UI-Ziele bleiben deshalb ein separater manueller/extern messbarer Abnahmenachweis. Der bislang
aufgezeichnete Einzellauf ist in [Leistungsnachweis Welle 12](docs/performance-benchmark.md) und als
[Rohdatensatz](docs/performance-benchmark-2026-08-13.json) dokumentiert.

`pnpm make` erzeugt unter `release/` einen NSIS-Installer und portable ZIPs für x64 und ARM64. Die erste Ausgabe ist gemäß Produktentscheidung nicht codesigniert; Windows SmartScreen kann warnen. Updates und Deinstallation löschen `%APPDATA%\Vaulta` niemals automatisch, damit bestehende Daten erhalten bleiben.

## Datenablage

```text
%APPDATA%/Vaulta/
  profile.json
  vaults/<vault-id>.vaulta
  attachments/<vault-id>/<attachment-id>.vatt
  audit.vaulta
  backups/
  security/offline-breach-v1.kbi # optionaler, binärer Offline-Datenleckindex; nie Teil eines Backups
  migration-backups/ # bytegenaue, manifestgeschützte Vorab-Snapshots
  .vaulta-migration-transaction/ # nur während einer atomaren Migration
  .vaulta-multi-file-transaction/ # nur während eines fachlichen Mehrdatei-Commits
```

Die Datei `profile.json` enthält nur technische KDF-, Format- und Faktorparameter sowie
verschlüsselte geschützte Metadaten. Tresornamen, Titel, Tags, Dateinamen, Auditereignisse und alle
fachlichen Werte bleiben verschlüsselt. Ein Migrationsjournal enthält ausschließlich technische
relative Pfade, Größen und Prüfsummen; seine Rollback-Sidecars bestehen aus den bereits
verschlüsselten Originaldateien.

Der Sicherungsstatus und gespeicherte CSV-Feldzuordnungen nutzen ausschließlich diesen bestehenden
geschützten Metadatenpfad. Sie legen keinen zweiten Speicherort an und enthalten weder Importwerte
noch Pfade, Dateinamen oder Fehlermeldungstexte. Das portable Paketformat ist dagegen eine bewusst
separate, verschlüsselte Exportdatei; Details stehen in [ADR 0007](docs/architecture/adr-0007-portable-vault-package.md).

Die Windows-Einstellungen, lokale Erinnerungs-Opt-ins, der Fokusmodus und der Onboarding-Marker liegen
ebenfalls ausschließlich in den geschützten Profileinstellungen. Tray, Erinnerungstimer und
revisionsgebundene Listen-/Sicherheitscaches bleiben flüchtig und werden beim Sperren verworfen; es
entsteht kein zusätzlicher Klartext-Speicherpfad.

Für Enpass gibt es absichtlich keinen geratenen Herstellerparser: Ohne ein belastbar dokumentiertes,
anonymisiert testbares natives Exportlayout wird dessen CSV über die generische Feldzuordnung
importiert. Die Dateiendung oder ein Herstellername reicht nie zur Formaterkennung.

Weitere Nachweise:

- [Erweiterungsroadmap ab Version 1.1](docs/extensions.md)
- [Portables Tresor-Paket](docs/architecture/adr-0007-portable-vault-package.md)
- [Bedrohungsmodell](docs/architecture/adr-0001-threat-model.md)
- [Schlüsselhierarchie](docs/architecture/adr-0002-key-hierarchy.md)
- [Containerformat](docs/architecture/adr-0003-container-format.md)
- [Datenmigrationen und Format-Baseline](docs/data-migrations.md)
- [Leistungsnachweis Welle 12](docs/performance-benchmark.md)
- [Security-Testmatrix](docs/security-test-matrix.md)
- [Manueller Sicherheitsreview](docs/security-review.md)
- [Produktabnahme und Wellennachweise](docs/acceptance.md)
- [Passkey-Untersuchung](docs/passkey-research.md)

## Datenschutz

Kryptris enthält keine Telemetrie, Werbung, Crash-Uploads, Remote-Schriften, Remote-Bilder oder
Online-Datenleckabfragen. Eine optionale, vom Benutzer lokal importierte Datenleckliste wird weder
hochgeladen noch abgefragt; Passwort-Hashes verlassen den Prozess nicht. Diagnosemeldungen enthalten
keine Feldwerte. Websites bleiben kopierbar; Links in Markdown werden ausschließlich als nicht
anklickbarer Text dargestellt.
