# Vaulta Security-Testmatrix

Stand: 15. Juli 2026

Diese Matrix ist Bestandteil der Abnahme. Automatisierte Fälle laufen in CI;
Hardware-/Windows-Integrationsfälle werden vor einem öffentlichen Tag auf frischen Windows-10- und
Windows-11-Benutzerprofilen wiederholt.

| Bereich        | Fall                                                   | Erwartung                                                        | Nachweis                                 |
| -------------- | ------------------------------------------------------ | ---------------------------------------------------------------- | ---------------------------------------- |
| KDF            | Argon2id-Vektor und Parametergrenzen                   | identisches Ergebnis; Produktprofil nie unter 256 MiB            | Unit-Test `key-derivation`               |
| Umschlag       | falsches Master-Passwort                               | kein Profil-Key; generischer Fehler; Rate-Limit                  | Integration `profile-service`            |
| Recovery       | korrekter/falscher Key, Prüfsumme                      | nur korrekter Key öffnet; neues Master erforderlich              | Integration `profile-recovery`           |
| Recovery       | Nutzung bei aktivem TOTP/FIDO                          | Faktoren und Public-Daten entfernt; kein stilles Beibehalten     | Integration `factor-loss`                |
| Container      | Roundtrip aller Datentypen                             | bitgetreue fachliche Daten                                       | Integration `vault-container`            |
| Container      | Header/Ciphertext/Tag manipuliert                      | `CORRUPT_DATA`, keine Teilantwort                                | Unit `encrypted-container`               |
| Container      | Absturz vor/nach Rename                                | letzter bestätigter Stand oder prüfbarer `.previous`-Stand       | Integration `atomic-write`               |
| Migration      | Absturz nach erstem von mehreren Writes                | bytegenauer Gesamtrollback; kein gemischter Versionsstand        | Integration `persistent-migration`       |
| Anhänge        | Chunk vertauscht/entfernt/angehängt                    | Entschlüsselung/Export scheitert; kein Zielklartext              | Integration `attachment-service`         |
| Anhänge        | 100-MB-Limit/konfiguriertes Limit                      | Import vor Schreiben abgelehnt                                   | Unit/Integration `attachment-limit`      |
| Pfade          | Traversal, UNC, absoluter Rendererpfad                 | Schema-/Path-Safety-Ablehnung                                    | Property-Test `path-safety`              |
| Backup-Pfad    | frei gesetzter oder veralteter Rendererpfad            | nur unmittelbar nativ autorisierter lokaler Ordner akzeptiert    | Unit/Integration Settings                |
| Restore-Pfad   | Symlink/Junction und ambiger Crash-Marker              | fail-closed; Rollback bleibt bis authentifizierter Gesamtprüfung | Integration `backup-service`             |
| Sperren        | fünf Minuten Inaktivität                               | Schlüssel, Index, Detailzustand und Pending-Faktoren verworfen   | Unit `auto-lock`; E2E                    |
| Windows        | Sitzungssperre/Standby/Minimize-Option                 | sofortige Sperre gemäß Einstellung                               | manueller Windows-Smoke-Test             |
| Clipboard      | unveränderter Vaulta-Inhalt                            | nach 5–120 s geleert                                             | Unit `clipboard-service`                 |
| Clipboard      | danach anderer Inhalt kopiert                          | fremder Inhalt bleibt erhalten                                   | Unit `clipboard-service`                 |
| Renderer       | Node-/Dateizugriff                                     | `process`, `require`, direkte Pfade nicht verfügbar              | E2E `renderer-isolation`                 |
| IPC            | unbekannter Kanal/falscher Sender/übergroße Daten      | abgelehnt, kein Stack/Secret                                     | Unit `ipc-guard`                         |
| Einstellungen  | Schutzfunktion abschwächen                             | gültiges Master-Passwort nötig; parallele Updates serialisiert   | Integration Controller                   |
| CSP/Navigation | Remote-Request, Popup, Navigation                      | vollständig blockiert; keine Shell-/Link-Bridge                  | E2E `navigation-policy`                  |
| TOTP Entry     | RFC-Testvektoren SHA-1/256/512                         | erwartete Codes                                                  | Unit `totp-service`                      |
| TOTP Gate      | Verlust/Fehler                                         | kein Unlock; Recovery setzt Faktor zurück                        | Integration `factor-loss`                |
| WebAuthn       | Signatur/Challenge/Origin/RP-ID/Counter manipuliert    | abgelehnt und ggf. Profil erneut gesperrt                        | Unit mit virtuellen Antworten            |
| WebAuthn       | PRF vorhanden                                          | Master alleine kann Profil-Key nicht öffnen                      | Integration `factor-wrap`                |
| WebAuthn       | PRF fehlt                                              | nur Presence-Modus mit sichtbarer Warnung                        | UI-/Service-Test                         |
| Faktor-State   | Crash/Parallelität beim Hinzufügen oder Entfernen      | Wrap, Public- und Protected-State atomar in einer Generation     | Integration `profile-factor-transaction` |
| Import         | alle benannten Formate                                 | Vorschau, Mapping, Fehler und Dubletten nachvollziehbar          | Fixture-/Property-Tests                  |
| Import         | Formeln/HTML/überlange Felder                          | neutralisiert/abgelehnt; keine Ausführung                        | Property-/UI-Test                        |
| Export         | Klartext ohne Passwort/2 Bestätigungen                 | abgelehnt                                                        | Integration/UI-Test                      |
| Backup         | manipulierte Datei/Manifest                            | vor Restore abgelehnt                                            | Integration `backup-service`             |
| Backup         | frisches Zielprofil                                    | vollständig nur mit Master oder Recovery                         | E2E `fresh-restore`                      |
| Audit          | Aktionen mit Canary-Secrets                            | nur feste Zusammenfassungen/IDs gespeichert                      | Integration `audit-redaction`            |
| Artefakte      | Canary-Suche in `dist`/Installer/ZIP/Installationsbaum | keine Treffer                                                    | `security:scan-artifacts`; NSIS-Gate     |
| Packaging      | x64/ARM64-Fuses und NSIS-Deinstallation                | gehärtete Bits; App entfernt, Nutzerdaten bleiben erhalten       | Fuse-Check; Sentinel-Smoke-Test          |
| Offline        | keine externe Datenverbindung                          | Setup, CRUD, TOTP, Backup, Import/Export funktionieren           | Packaged-E2E in Windows Actions          |

## Automatisierter Abschlussstand

- Der Quelllauf besteht Prettier, ESLint, alle drei TypeScript-Konfigurationen sowie 36 Testdateien
  mit 171 Tests.
- Der Browser-E2E lädt das echte Produktionsbundle und bestätigt den prototypnahen
  Drei-Spalten-Workspace. Der vollständige Electron-E2E deckt Setup, Minimize-Sperre, CRUD,
  Papierkorb, Import, Klartextexport, Backup, Navigation/Requests und Fresh-Root-Restore ab.
- Der vollständige Electron-E2E wird lokal in der Codex-Desktop-Sandbox absichtlich übersprungen.
  Der Windows-Workflow führt ihn gegen den Source-Build und gegen eine isolierte Inspector-Kopie der
  tatsächlich installierten Anwendung aus; die Release-EXE selbst bleibt gehärtet.
- Produktionsaudit und Lizenz-Allowlist sind grün. Der lokale Release-Scan prüfte 29.557 Dateien,
  der Scan des still installierten NSIS-Payloads weitere 7.367 Dateien ohne Canary-Treffer.
- Die Fuses beider Architekturen, der echte NSIS-Install/Uninstall und der Erhalt lokaler Nutzerdaten
  sind lokal grün.

Vor einem öffentlichen Tag bleiben die realen Windows-/Hardware-Zeilen verbindlich: frische
Win10-/Win11-Profile ohne Netzwerk, Fresh Restore, Sitzungssperre/Standby/Minimize, physischer
FIDO2-Key mit PRF und Presence sowie ARM64-Hardware. Der aktuelle lokale Lauf ersetzt diese
Plattformnachweise nicht.

## Verlustszenarien

| Master    | TOTP      | FIDO PRF  | Recovery  | Ergebnis                                        |
| --------- | --------- | --------- | --------- | ----------------------------------------------- |
| vorhanden | vorhanden | vorhanden | beliebig  | alle konfigurierten Faktoren erforderlich       |
| vorhanden | verloren  | vorhanden | vorhanden | Recovery, neues Master, Faktoren neu einrichten |
| vorhanden | vorhanden | verloren  | vorhanden | zweiter PRF-Key oder Recovery                   |
| verloren  | beliebig  | beliebig  | vorhanden | Recovery, neues Master, Faktoren neu einrichten |
| verloren  | beliebig  | beliebig  | verloren  | Daten endgültig verloren; keine Umgehung        |

Presence-only-FIDO und TOTP sind lokale Sperren. Bei einer vollständig manipulierbaren Gerätekopie gelten sie ausdrücklich nicht als Ersatz für Master/Recovery oder einen PRF-Wrap.
