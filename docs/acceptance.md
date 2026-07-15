# Produktabnahme Vaulta – Welle 0 bis 6

Stand: 15. Juli 2026

Dieses Dokument bildet die verbindlichen Wellen, Produktentscheidungen und produktweiten Kriterien
aus `docs/concept.md` auf Implementierung und reproduzierbare Nachweise ab. Es trennt den fertigen
Produktstand bewusst von Prüfungen, die nur auf GitHub Actions, frischen Windows-Profilen oder echter
FIDO2-Hardware ausgeführt werden können.

## Welle 0 – Sicherheitsfundament und Prototyp

**Bestanden.** Electron/React/TypeScript/pnpm, Windows-CI, fünf ADRs, Argon2id/HKDF/AES-GCM,
manipulationsgeschützte Container, strikt typisierte IPC-Schemas und der deutsche
teal-violette Drei-Spalten-Workspace sind umgesetzt. Renderer-Isolation, Sender-/Origin-Prüfung und
fehlender direkter Node-/Dateizugriff werden automatisiert geprüft.

## Welle 1 – Nutzbarer lokaler Tresor

**Bestanden.** Setup und Master-Passwort, mehrere kryptografisch getrennte Tresore, Zugangsdaten und
sichere Notizen, CRUD/Papierkorb, Suche, Ordner, Tags, Favoriten, Generator, Auto-Lock, Maskierung,
Main-Prozess-Clipboard sowie transaktionale Writes und Recovery sind vollständig angebunden.

## Welle 2 – Datentypen und Anhänge

**Bestanden.** Alle neun vereinbarten Eintragstypen, freie Felder, chunkverschlüsselte Anhänge,
Größenlimit, Preview-Allowlist und Offline-TOTP funktionieren im gemeinsamen import-/exportneutralen
Datenmodell. Roundtrip-, Manipulations- und 100-MB-Grenztests sind enthalten.

## Welle 3 – Wiederherstellung und Datensicherheit

**Bestanden.** Einmaliger gruppierter Recovery-Key, natives verschlüsseltes Backup, Rotation,
vollständige semantische Restore-Prüfung, verschlüsseltes redigiertes Audit und eine crash-sichere
Mehrdatei-Migrationsinfrastruktur sind umgesetzt. Backup- und Migrations-Commits prüfen unmittelbar
vor dem Austausch nochmals Live-Dateisatz und Hashes; nicht terminale Migrationen werden bytegenau
zurückgerollt. Details: [Format-Baseline](data-migrations.md).

## Welle 4 – Import, Export und Sicherheitscheck

**Bestanden.** Bitwarden, 1Password, LastPass, KeePass, Proton Pass, Browser-CSV sowie generisches
CSV/JSON werden mit Vorschau, Auswahl, Feldzuordnung, Fehlern und Dubletten verarbeitet. Klartext
JSON/CSV verlangt Warnung, Bestätigungsphrase, Zielwahl und Master-Passwort. Der vollständig lokale
Check deckt schwache, wiederverwendete, alte, unvollständige und SSH-bezogene Befunde ab.

## Welle 5 – Faktoren und Härtung

**Bestanden.** WebAuthn-Signaturprüfung, echter PRF-Wrap, sichtbarer Presence-Fallback, lokale
TOTP-Sperre mit ehrlicher Einschränkung, Content Protection, gehärtete Electron-Fuses,
CSP-/Navigation-/Permission-Härtung, Security-Matrix, NSIS und beide portablen ZIPs sind umgesetzt.
Faktor-Wrap und öffentliche/geschützte Metadaten werden atomar in einer Profilgeneration geändert.

## Welle 6 – Zukunftsfunktionen

**Bestanden.** Die [Passkey-Untersuchung](passkey-research.md) begründet das V1-No-Go,
wiederverwendbare Vorlagen und erweiterte lokale Berichte sind verschlüsselt umgesetzt. Der Release
bleibt wie festgelegt unsigniert; SmartScreen-Hinweis und späterer Signaturpfad sind dokumentiert.

## Festgelegte Produktentscheidungen

Alle Entscheidungen aus Abschnitt 16 des Konzepts sind eingehalten: Vaulta ist eine deutsche,
gehärtete Windows-Electron-App im ruhigen Dunkelmodus, arbeitet ohne Konto, Cloud, Telemetrie oder
Funktionsnetzwerk, nutzt ein Profil mit mehreren Tresoren und das Master-Passwort als Primärzugang.
Recovery ist optional und einmalig, FIDO2-PRF wird kryptografisch und Presence/TOTP nur als lokale
Sperre klassifiziert. Es gibt keine Historie früherer Feldwerte. Native Backups sind verschlüsselt,
Klartext-Exporte stark bestätigt, Datenleckprüfungen bewusst nicht enthalten und die Verteilung
besteht aus einem unsignierten NSIS-Installer plus x64-/ARM64-ZIP.

## Produktweite Abnahmekriterien

| Kriterium                                     | Status                                        | Nachweis                                                                                  |
| --------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Wellen 0–5 abgeschlossen                      | bestanden                                     | obige Zuordnung; 36 Testdateien/171 Tests                                                 |
| zusätzlich Welle 6 umgesetzt                  | bestanden                                     | Passkey-Research, Vorlagen, lokale Berichte                                               |
| Installation/Nutzung ohne Netzwerk            | lokal teilweise bestanden; Windows-Gate offen | stiller NSIS-Install/Uninstall bestanden; vollständiger Packaged-E2E läuft in Actions     |
| keine Entschlüsselung ohne Master/Recovery    | bestanden                                     | KDF-/Wrap-/Recovery-/Manipulations- und Verlustszenarien                                  |
| keine sensiblen Daten in Logs/Temp/Artefakten | bestanden                                     | Audit-Redaction, Canary-Tests; 29.557 Release- und 7.367 Installationsdateien gescannt    |
| Backup/Restore auf frischem Windows-Ziel      | Integration bestanden; Windows-Gate offen     | Fresh-root-Service-Suite grün; Electron-/Win10-/Win11-Gate vor Tag                        |
| Typen, Anhänge, TOTP, Import/Export/Check     | bestanden                                     | Unit-, Property-, Integrations-, UI- und E2E-Suiten                                       |
| manueller Review ohne kritische Befunde       | bestanden                                     | [Sicherheitsreview](security-review.md), keine offenen kritischen/hohen/mittleren Befunde |
| Installer und ZIP über Actions reproduzierbar | Workflow abnahmebereit; Taglauf offen         | getrennte Read-only-Build-/Write-Publish-Jobs, Tag-/Hash-/Payload-Gates                   |

## Ausgeführter Abschlussnachweis

- `npm run verify`: Prettier, ESLint, drei Typechecks, 36/36 Testdateien und 171/171 Tests grün.
- `npm run test:e2e`: Produktionsbundle und visueller Drei-Spalten-Smoke-Test grün. Der echte
  Electron-Test wird in der Codex-Desktop-Sandbox bewusst übersprungen; Windows Actions führt ihn
  sowohl gegen den Source-Build als auch gegen eine isolierte Kopie der installierten App aus.
- `npm run audit:prod`: keine bekannte Schwachstelle. Lizenz-Allowlist: 154 Produktionspakete,
  ausschließlich 0BSD, Apache-2.0, BSD-3-Clause, ISC und MIT.
- `npm run make`: `Vaulta-1.0.0-Setup.exe`, `Vaulta-1.0.0-x64.zip` und
  `Vaulta-1.0.0-arm64.zip` aus dem finalen Quellstand erzeugt.
- x64-/ARM64-Fuses grün; Release-Canary-Scan über 29.557 Dateien grün.
- echter NSIS-Installer still installiert; installierte EXE/Fuses und 7.367 Payload-Dateien grün;
  stille Deinstallation entfernte die App und erhielt das Nutzerdaten-Sentinel.
- SHA-256-Prüfsummen liegen in `release/SHA256SUMS.txt`; Authenticode ist erwartungsgemäß
  `NotSigned`.

## Verbindliche externe Release-Gates

Die Implementierung und der lokale Release-Kandidat sind abgeschlossen. Die strenge
„produktionsbereit“-Definition aus dem Konzept verlangt vor einem öffentlichen Tag zusätzlich:

1. einen erfolgreichen Lauf von `.github/workflows/windows-release.yml` auf dem Release-Tag;
2. vollständige Offline-Nutzung und Fresh-Restore auf frischen Windows-10- und
   Windows-11-Benutzerprofilen;
3. Sitzungssperre, Standby und optionale Minimize-Sperre auf echtem Windows;
4. Registrierung/Unlock/Verlustpfade mit einem realen FIDO2-Key für PRF und Presence;
5. einen ARM64-Runtime-Smoke-Test auf echter ARM64-Hardware.

Diese Punkte benötigen externe Runner, Betriebssystemprofile oder Hardware. Sie sind keine offenen
Implementierungsbefunde, bleiben aber bis zum Nachweis tag-sperrend.
