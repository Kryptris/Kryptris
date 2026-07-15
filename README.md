# Vaulta

Vaulta ist ein lokaler, deutschsprachiger Passwort-Manager für Windows 10/11. Er arbeitet ohne Konto, Cloud oder externe Dienste und speichert alle fachlichen Daten verschlüsselt im lokalen Benutzerprofil. Das Produkt folgt dem verbindlichen [Konzept](docs/concept.md) und dem visuellen [UI-Prototyp](docs/assets/vaulta-ui-prototype.png).

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
- NSIS-Installer und portable ZIP-Ausgabe

## Sicherheitsmodell in Kürze

Das Master-Passwort wird mit Argon2id (mindestens 256 MiB Arbeitsspeicher im Produktprofil) abgeleitet. Es schützt einen zufälligen 256-Bit-Profil-Gate-Key; daraus werden getrennte Schlüssel abgeleitet. Tresore und Profilmetadaten nutzen AES-256-GCM, Anhänge authentifizierte AES-GCM-Chunks. Container werden erst verifiziert und dann transaktional ausgetauscht. Kryptografische Schlüssel bleiben im Main-Prozess und werden beim Sperren überschrieben, soweit JavaScript/Node dies zulässt.

Der Renderer läuft mit `contextIsolation`, ohne Node-Integration, im Chromium-Sandboxprozess. Seine API besteht aus einer festen, schema-validierten IPC-Allowlist. Datei-, Zwischenablage- und Kryptografieoperationen liegen im Main-Prozess. Die Oberfläche wird produktiv von einem ausschließlich an `127.0.0.1` gebundenen statischen Server ausgeliefert; dadurch steht für FIDO2 eine von Chromium akzeptierte lokale WebAuthn-Origin bereit. Es gibt keine Daten-API und keine Verbindung zu externen Netzen. Details: [ADR 0004](docs/architecture/adr-0004-electron-boundary.md) und [ADR 0005](docs/architecture/adr-0005-local-webauthn-origin.md).

Vaulta schützt Daten auf einer ausgeschalteten oder gesperrten Festplatte und erkennt manipulierte Container. Es kann ein bereits kompromittiertes Windows, Administrator-Schadsoftware, Keylogger, manipulierte Zwischenablagen oder Kameras nicht zuverlässig beherrschen. Ohne Master- oder gültigen Wiederherstellungsschlüssel existiert keine Hintertür.

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

`pnpm make` erzeugt unter `release/` einen NSIS-Installer und portable ZIPs für x64 und ARM64. Die erste Ausgabe ist gemäß Produktentscheidung nicht codesigniert; Windows SmartScreen kann warnen. Updates und Deinstallation löschen `%APPDATA%\Vaulta` niemals automatisch.

## Datenablage

```text
%APPDATA%/Vaulta/
  profile.json
  vaults/<vault-id>.vaulta
  attachments/<vault-id>/<attachment-id>.vatt
  audit.vaulta
  backups/
  migration-backups/ # bytegenaue, manifestgeschützte Vorab-Snapshots
  .vaulta-migration-transaction/ # nur während einer atomaren Migration
```

Die Datei `profile.json` enthält nur technische KDF-, Format- und Faktorparameter sowie
verschlüsselte geschützte Metadaten. Tresornamen, Titel, Tags, Dateinamen, Auditereignisse und alle
fachlichen Werte bleiben verschlüsselt. Ein Migrationsjournal enthält ausschließlich technische
relative Pfade, Größen und Prüfsummen; seine Rollback-Sidecars bestehen aus den bereits
verschlüsselten Originaldateien.

Weitere Nachweise:

- [Bedrohungsmodell](docs/architecture/adr-0001-threat-model.md)
- [Schlüsselhierarchie](docs/architecture/adr-0002-key-hierarchy.md)
- [Containerformat](docs/architecture/adr-0003-container-format.md)
- [Datenmigrationen und Format-Baseline](docs/data-migrations.md)
- [Security-Testmatrix](docs/security-test-matrix.md)
- [Manueller Sicherheitsreview](docs/security-review.md)
- [Produktabnahme Welle 0–6](docs/acceptance.md)
- [Passkey-Untersuchung](docs/passkey-research.md)

## Datenschutz

Vaulta enthält keine Telemetrie, Werbung, Crash-Uploads, Remote-Schriften, Remote-Bilder oder Datenleckabfragen. Diagnosemeldungen enthalten keine Feldwerte. Websites bleiben kopierbar; Links in Markdown werden ausschließlich als nicht anklickbarer Text dargestellt.
