# Produktabnahme Kryptris – Welle 0 bis 12

Stand: 13. August 2026

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

## Welle 7 – Produktivität und Organisation

**Bestanden.** Die Eintragsliste unterstützt explizite Strg-/Umschalt-Mehrfachauswahl und alle
definierten Batch-Aktionen. Endgültiges Löschen verlangt Master-Passwort und Anzahl; Tresorwechsel
schreiben Einträge und Anhänge unter neuen IDs und Zielschlüsseln. Ein crash-fester
Mehrdatei-Koordinator hält Quell- und Zielcontainer samt Anhängen bei Fehler, Abbruch und Neustart
atomar. Gespeicherte Ansichten liegen in geschützten Profilmetadaten, intelligente Ansichten und
zentrale Tag-Normalisierung sind aktiv. Befehlspalette, lokale Hilfe, Fokus-/Escape-Regeln und die
festgelegten Kürzel sind per Renderer-Tests abgedeckt. Nachweis: 42 Testdateien/217 Tests sowie Build
und drei lokale E2E-Smokes grün; echter Electron-E2E sandboxbedingt übersprungen.

Beim Re-Audit am 26. Juli wurde zusätzlich bestätigt, dass die redigierten Auditdatensätze der
schreibenden Batch-, Cross-Vault- und Purge-Flows innerhalb derselben Mehrdatei-Transaktion
committed werden. Der kombinierte Welle-8-Nachweis unten enthält sämtliche Welle-7-Tests.

## Welle 8 – Datenqualität, Dubletten und Lebenszyklus

**Bestanden.** Import und Datenpflege verwenden denselben Main-only-Dublettendienst mit
normalisierten, HMAC-abgeleiteten Vergleichsmerkmalen. Globale und tresorbezogene Scans sind
revisionsgebunden, koalesziert, fortschrittsfähig und abbrechbar. Die UI begründet Kandidaten,
ermöglicht getrenntes Behalten, optimistisch abgesichertes Verschieben in den Papierkorb sowie
feld- und sammlungsweisen Merge. Merge und Attachment-Neuverschlüsselung werden authentifiziert
verifiziert und gemeinsam mit dem redigierten Audit atomar committed.

Lebenszyklusfelder für Rotation, lokale 2FA-Klassifizierung und Ablaufhinweise werden als
VaultDocument V2 gespeichert; die Vorwärtsmigration V1 → V2 besitzt Snapshot, Mehrdatei-Rollback,
V1-/V2-Fixtures, Idempotenz-, Future-Version- und Abbruchtests. Der lokale Datenqualitätsreport gibt
nur technische Referenzen und Befundcodes aus. Korrekturen verlangen eine Vorschau und ein
kurzlebiges, einmalig verwendbares Main-only-Token. Die optionale Papierkorbfrist steht
standardmäßig auf „nie“, verlangt eine sichtbare Backup-Bestätigung und läuft nur während einer
durchgehend entsperrten Frist ohne Nachholen.

Nachweis des Welle-8-Gates: `corepack pnpm verify` mit 57 Testdateien/307 Tests, Produktionsbundle,
der echte Electron-Flow für Setup, CRUD, Navigation-Härtung und Fresh-Restore sowie vier visuelle
Chromium-Smoke-Flows einschließlich Datenpflege, kleinem Fenster und 200-%-Skalierung.

## Welle 9 – Sicherheitszentrale und lokale Vorsorge

**Bestanden.** Die Sicherheitszentrale bündelt acht klar als lokale Indikatoren bezeichnete Kacheln
für Zugangsdaten, Datenqualität, Faktoren, Backup, Recovery, KDF, Integrität und die optionale
Offline-Datenleckliste. Der Recovery-Bereitschaftstest entschlüsselt ausschließlich den Profil-Gate-
Key im Main-Prozess, speichert nur Zeitpunkt und Erfolg und drosselt Fehlversuche auch dann, wenn
der nachfolgende Status-/Audit-Commit fehlschlägt.

Die vollständige Integritätsprüfung liest Profil, Tresore, Audit, Attachment-Chunks und fachliche
Referenzen frisch vom Datenträger, gibt bei großen Referenzmengen an den Event-Loop ab und wird durch
Lock oder Abbruch sofort invalidiert. Redigierte Befunde überleben bewusst einen beschädigten Profil-
oder Auditcontainer, obwohl ihr optionaler Status dann nicht persistiert werden kann. Bei
erfolgreichem Commit sind Status und Audit atomar; eine gemeinsame Writer-Sperre über alle Tresore,
Profil und Audit schließt das Race zwischen Endprüfung und Commit. Der Cache wird auf die durch den
eigenen Commit erzeugte Revision umgebunden. Der kurzlebige Berichtsexport verweigert direkte und
kanonisch aufgelöste Junction-/Symlink-Pfade unter dem Datenordner.

Die Datenleckfunktion bleibt optional und vollständig offline. Sie akzeptiert nur das dokumentierte
binäre `sha1-count-v1`-Eingabeformat, prüft Struktur, Sortierung, Prüfsumme und Größenlimits,
speichert keinen Passwort-Hash in UI, Audit oder Bericht und lässt Scan, Import und Entfernen nicht
parallel gegeneinander laufen. Index, Profilmanifest und Audit werden atomar installiert bzw.
entfernt; der Index wird weder gesichert noch restauriert und muss nach einem Restore erneut
importiert werden.

Nachweis des Welle-9-Gates: `corepack pnpm verify` mit 72 Testdateien/390 Tests und
`corepack pnpm test:e2e` mit Produktionsbuild sowie 6/6 Playwright-Flows (ein echter Electron-Flow,
fünf visuelle Chromium-Smokes einschließlich Sicherheitszentrale bei 200-%-Skalierung).

## Welle 10 – Backup, Restore und Transfer

**Bestanden.** Das Main-only-Backup-Gesundheitscenter authentifiziert berücksichtigte Backups vor
der Statusberechnung und zeigt nur Zielerreichbarkeit, Größen-/Generationenwerte,
Tresor-/Anhangszahlen, Zeitpunkte und technische Fehlercodes. Es speichert keine Pfade,
Backupnamen oder ursprünglichen Fehlermeldungen und warnt bei einem Sicherungsziel auf demselben
Laufwerk. Die Berechnung ist revisionsgebunden, koalesziert und beim Sperren invalidiert.

Der Restore-Probelauf ist ein einzelner, abbrechbarer Main-Prozess-Job. Er entschlüsselt nur in einen
eigenen temporären Arbeitsbereich, prüft Header, Manifest und semantischen Zustand und entfernt den
Bereich bei Erfolg, Fehler, Abbruch oder Sperre. Der Staging-Baum und seine Verzeichnishierarchie
werden gegen Symlinks/Junctions und Pfadwechsel geprüft; die Staging-Profile, Vaults und Audits
laufen dabei im reinen Leseprüfmodus.

Das portable `.kryptris-vault`-Paket hat einen eigenen zufälligen 256-Bit-Paket-Schlüssel, ein
separates Argon2id-Exportpasswort, AES-256-GCM-Records und ein verschlüsseltes, versioniertes
Manifest. Vorschau und Namenskonfliktprüfung erfolgen vor dem Import. Der Import prüft die
Paketidentität erneut, remappt alle technischen IDs, verschlüsselt optionale Anhänge unter dem
frischen Zielschlüssel und committet Profil-Registry, Vault, Anhänge und Audit gemeinsam. Das
Anhangs-Staging ist eine Main-only-Capability mit kanonischen Verzeichnis- und Dateiidentitäten;
Schreib-, Transaktionslese- und nichtrekursive Bereinigungspfade verweigern direkte oder später
eingehängte Symlink-/Junction-Aliasse. Temporäre Anhangsbuffer werden auf jedem Erfolgs-, Fehler-
und Bereinigungspfad überschrieben. Nach dem bestätigten Commit bleibt das Importergebnis auch bei
einem konkurrierenden Lock oder einer nichtkritischen UI-/Bereinigungsstörung erfolgreich; neue
entschlüsselte Caches werden dann nicht publiziert.

Dashlane-, NordPass- und RoboForm-CSV werden nur anhand dokumentierter Inhalts-Signaturen erkannt
und gegen anonymisierte Fixtures geprüft. Enpass bleibt absichtlich beim generischen CSV-Mapper, da
kein belastbar dokumentiertes natives Layout als sichere Grundlage vorliegt. CSV-Zuordnungsprofile
enthalten nur Namen und Spaltenselektoren, nicht importierte Werte. Drag-and-drop verwendet einen
preload-eigenen, kurzlebigen Einmal-Token; der Renderer kann keinen Dateipfad an die Main-Operation
geben. Der Main-Prozess liest die Datei descriptor-gebunden und verweigert ausgetauschte, symbolisch
verlinkte, zu große oder während des Lesens veränderte Quellen. Die Importzusammenfassung umfasst neue,
übersprungene, doppelte, warnende und fehlerhafte Zeilen; nach dem Import sind die betroffenen
Einträge für die Dubletten-Zentrale verfügbar.

Der Nachweis umfasst gezielte Unit- und Integrationssuiten für Sicherungsstatus, Restore-Probelauf,
Paketformat/-Import, Mapping-Snapshots, Hersteller-Fixtures und den sicheren Quelldateileser sowie
IPC-/Preload- und Renderer-Tests für den Drop-Token. Das Welle-10-Gate bestand mit
`corepack pnpm verify` (81 Testdateien/443 Tests) und `corepack pnpm test:e2e` (Produktionsbuild,
6/6 Playwright-Flows: ein echter Electron-Flow und fünf visuelle Chromium-Smokes).

## Welle 11 – Windows-Integration, Bedienbarkeit und Barrierefreiheit

**Implementiert; die releaseweite Gesamtabnahme wird mit Welle 12 geführt.** Geschützte
Profileinstellungen steuern Minimize-to-Tray, Close-to-Tray, den reversiblen Windows-Autostart und
den minimierten Start. Ein minimierter Windows-Start öffnet keinen entschlüsselten Tresor. Das
Main-Prozess-Tray enthält ausschließlich den Status „gesperrt“ oder „entsperrt“ sowie die Aktionen
„Öffnen“, „Jetzt sperren“ und „Beenden“; es kennt keine Tresor-, Eintrags- oder Geheimdaten. Beim
Schließen in den Infobereich sperrt Kryptris vor dem Verbergen.

Die optionalen lokalen Erinnerungen lesen nur im entsperrten Zustand technische Fälligkeitszählungen
und zeigen einen allgemeinen lokalen Hinweis ohne Titel, Tresorname, Pfad oder Geheimwert. Beim Klick
wird vor dem Öffnen gesperrt; Sperren, Dispose und eine geänderte Erinnerungspräferenz invalidieren
Timer und späte Ergebnisse.

Fokusmodus reduziert Listensubtitel, Tags und Vorschauaktionen und wird ausdrücklich nicht als
kryptografischer Schutz beschrieben. Die UI ergänzt lokale Hilfe, überspringbares Onboarding,
semantische Navigation, sichtbare Fokuszustände, Live-Regionen und eine Einstellung für reduzierte
Bewegung. Unit- und Renderer-Tests decken Tray-/Reminder-Policy, Settings, Onboarding sowie
Tastatur-/Fokuspfade ab; die finale manuelle 200-%-Windows-Prüfung bleibt Teil der Release-Gates.

## Welle 12 – Leistung, Wartbarkeit und Release-Qualität

**Implementiert mit bewusst getrennten Abnahmegrenzen.** Der echte Controller-Entsperrtest startet
mit zwei V1-Tresoren, erhält einen verschlüsselten Anhang und TOTP-Faktordaten, prüft Idempotenz und
rollt einen zwischen zwei Vault-Ersetzungen unterbrochenen Commit beim nächsten Start zurück. Eine
Zukunftsversion wird vor Snapshot und Write abgelehnt. V1-/V2-Fixtures sowie Klartext-Canaries in
Journal und Rollback-Sidecars sind Teil des Nachweises.

Die Eintragsliste verwendet ein virtualisiertes, tastaturbedienbares Fenster statt tausender
gleichzeitiger DOM-Zeilen. Die Suche wird 200 ms entprellt, und eine Renderer-Anfragengeneration
verwirft veraltete Antworten. Main-Prozess-Listen arbeiten mit Autorisierungscheckpoints und
revisionsgebunden koaleszierten Sicherheitsreports; Sperren leert Caches und Pending-Reports, sodass
eine verspätete Auswertung keine neue geheime Anzeige publizieren kann.

Der Artefaktscanner behandelt zusätzlich bekannte Cache-, Bericht-, Restore-/Import-Staging- und
Transaktionspfade sowie verschachtelte ZIP-/ASAR-Inhalte fail-closed. Die einzige bewusst enge
Ausnahme ist ein exakt strukturvalidierter `KRYBRCH1`-Header des öffentlichen Offline-
Datenleckindexes in einem Rollback-Sidecar; sie akzeptiert keine beliebigen Klartextdateien und keine
Fachwerte.

Der [Leistungsnachweis](performance-benchmark.md) dokumentiert einen einzelnen, rein synthetischen
Main-Prozess-Lauf auf einem AMD Ryzen 5 7600X mit Node.js v24.14.0. Bei 10.000 Einträgen wurden
9.968,047 ms für die kalte Liste, 30,710 ms für eine Suche mit warmem Sicherheitsreport,
9.875,643 ms für den vollständigen Sicherheitscheck und 153,253 ms für den vollständigen
Dublettenscan aufgezeichnet. Die Messung umfasst weder Renderer-Frames noch den Zeitpunkt des ersten
sichtbaren UI-Feedbacks, IPC-/Structured-Clone-Kosten oder echte 200-%-Windows-Skalierung. Die
Roadmap-Ziele „unter 200 ms bis zum ersten sinnvollen UI-Feedback“ und „kein blockierter
Renderer-Frame über 100 ms“ sind daher ausdrücklich **nicht als bestanden markiert**.

Der aktuelle Quelltest `corepack pnpm verify` bestand mit 87 Testdateien und 487 Tests. Das
Produktions-Dependency-Audit war ohne Befund, die Lizenz-Allowlist akzeptierte 154
Produktionspakete und der aktuelle `dist`-Artefaktscan fand in 143 Dateien keine bekannte Canary.
`corepack pnpm test:e2e` bestand mit 7/7 Flows: einem echten Electron-Flow und sechs visuellen
Chromium-Smokes. Der finale `make`-Lauf erzeugte x64- und ARM64-NSIS-Installer sowie ZIPs mit
`buildUniversalInstaller: false` und `SHA256SUMS.txt`; beide unpacked EXEs bestanden die Fuse-Prüfung.
Der Release-Scan fand in 29.682 Dateien keine Canary. Der installierte x64-NSIS-Payload bestand
Fuse- und Scan-Prüfung in 7.420 Dateien, der packaged Electron-CRUD-/Restore-Flow gegen eine
isolierte Kopie bestand 1/1, und die stille Deinstallation erhielt das Userdata-Sentinel.

## Festgelegte Produktentscheidungen

Alle Entscheidungen aus Abschnitt 16 des Konzepts sind eingehalten: Vaulta ist eine deutsche,
gehärtete Windows-Electron-App im ruhigen Dunkelmodus, arbeitet ohne Konto, Cloud, Telemetrie oder
Funktionsnetzwerk, nutzt ein Profil mit mehreren Tresoren und das Master-Passwort als Primärzugang.
Recovery ist optional und einmalig, FIDO2-PRF wird kryptografisch und Presence/TOTP nur als lokale
Sperre klassifiziert. Es gibt keine Historie früherer Feldwerte. Native Backups sind verschlüsselt,
Klartext-Exporte stark bestätigt; Datenleckprüfungen erfolgen ausschließlich gegen eine optional
vom Benutzer lokal importierte Liste ohne Online-Abfrage. Die Verteilung besteht aus einem
unsignierten NSIS-Installer plus x64-/ARM64-ZIP.

Welle 13 ist ausdrücklich nicht implementiert. Es wurden weder Browser-Erweiterung, Autofill oder
Auto-Type noch Windows-Passkey-Provider, Cloud, Teams oder Teilen ergänzt.

## Produktweite Abnahmekriterien

| Kriterium                                     | Status                                         | Nachweis                                                                                    |
| --------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Wellen 0–10 abgeschlossen                     | bestanden                                      | obige Zuordnung; Welle 10 mit 81 Testdateien/443 Tests und 6/6 E2E-Flows                    |
| Welle 11 implementiert                        | lokal bestanden; externe Windows-Gates offen   | Tray-/Reminder-/Settings-/Renderer-Tests, 7/7 Workspace-E2E                                 |
| Welle 12 implementiert                        | lokal bestanden; Renderer-/externe Gates offen | 87/87 Testdateien, 487/487 Tests; Audit/Lizenzen, 7/7 E2E, Paket/Fuse/Canary, siehe unten   |
| Welle 13                                      | nicht implementiert                            | bewusstes Entscheidungstor; kein Browser-, Auto-Type-, Passkey-Provider- oder Cloud-Code    |
| zusätzlich Welle 6 umgesetzt                  | bestanden                                      | Passkey-Research, Vorlagen, lokale Berichte                                                 |
| Installation/Nutzung ohne Netzwerk            | lokal bestanden; Windows-Gate offen            | packaged CRUD-/Restore 1/1, stiller NSIS-Uninstall mit erhaltenem Userdata-Sentinel         |
| keine Entschlüsselung ohne Master/Recovery    | bestanden                                      | KDF-/Wrap-/Recovery-/Manipulations- und Verlustszenarien                                    |
| keine sensiblen Daten in Logs/Temp/Artefakten | lokal bestanden; externe Reproduktion offen    | Audit-Redaction, Canary-Tests; Release 29.682 und installierter Payload 7.420 Dateien clean |
| Backup/Restore auf frischem Windows-Ziel      | Integration bestanden; Windows-Gate offen      | Fresh-root-Service-Suite grün; Electron-/Win10-/Win11-Gate vor Tag                          |
| Typen, Anhänge, TOTP, Import/Export/Check     | bestanden                                      | Unit-, Property-, Integrations-, UI- und E2E-Suiten                                         |
| manueller Review ohne kritische Befunde       | bestanden                                      | [Sicherheitsreview](security-review.md), keine offenen kritischen/hohen/mittleren Befunde   |
| Installer und ZIP über Actions reproduzierbar | Workflow abnahmebereit; Taglauf offen          | getrennte Read-only-Build-/Write-Publish-Jobs, Tag-/Hash-/Payload-Gates                     |

## Ausgeführter Nachweis des aktuellen Welle-12-Quellstands

- `corepack pnpm verify`: Prettier, ESLint, drei Typechecks, 87/87 Testdateien und 487/487 Tests
  grün.
- `corepack pnpm benchmark:performance -- --output docs\performance-benchmark-2026-08-13.json`:
  ein synthetischer Main-Prozess-Lauf mit 1.000, 5.000 und 10.000 Einträgen; Umfang und exakte Werte
  stehen im [Leistungsnachweis](performance-benchmark.md). Er ist kein Renderer-Frame-Nachweis.
- `corepack pnpm audit:prod`: ohne Produktionsbefund; `corepack pnpm licenses:prod`: 154 erlaubte
  Produktionspakete.
- `corepack pnpm test:e2e`: 7/7 Flows grün: ein echter Electron-Flow und sechs visuelle
  Chromium-Smokes.
- `corepack pnpm make`: x64- und ARM64-NSIS-Installer sowie ZIPs bei
  `buildUniversalInstaller: false`, einschließlich `SHA256SUMS.txt`.
- Beide unpacked EXEs bestanden die Fuse-Prüfung. `corepack pnpm security:scan-artifacts release`
  fand in 29.682 Dateien keine bekannte Canary.
- Der installierte x64-NSIS-Payload bestand Fuse- und Artefaktscan in 7.420 Dateien. Der isolierte
  packaged Electron-CRUD-/Restore-Flow bestand 1/1; die stille Deinstallation erhielt das
  Userdata-Sentinel.

## Verbindliche externe Release-Gates

Der vollständig abgenommene lokale Release-Kandidat umfasst Wellen 0–12. Die strenge
„produktionsbereit“-Definition aus dem Konzept verlangt vor einem öffentlichen Tag zusätzlich:

1. einen erfolgreichen Lauf von `.github/workflows/windows-release.yml` auf dem Release-Tag;
2. vollständige Offline-Nutzung und Fresh-Restore auf frischen Windows-10- und
   Windows-11-Benutzerprofilen;
3. Sitzungssperre, Standby und optionale Minimize-Sperre auf echtem Windows;
4. Registrierung/Unlock/Verlustpfade mit einem realen FIDO2-Key für PRF und Presence;
5. einen ARM64-Runtime-Smoke-Test auf echter ARM64-Hardware.

Diese Punkte benötigen externe Runner, Betriebssystemprofile oder Hardware. Sie sind keine offenen
Implementierungsbefunde, bleiben aber bis zum Nachweis tag-sperrend.
