# Manueller Sicherheitsreview

Stand: 13. August 2026
Scope: Architektur und Quellcode einschließlich Welle 12; finale Paketnachweise werden aus diesem Quellstand getrennt geführt

## Review-Checkliste

- [x] Main-/Preload-/Renderer-Trennung und Senderprüfung vollständig inspiziert
- [x] keine generische IPC-, Datei-, Shell- oder Netzwerkbrücke im Preload
- [x] `contextIsolation`, Sandbox, CSP, Navigation, Popups und Berechtigungen restriktiv
- [x] KDF-/HKDF-/AES-GCM-Verwendung und Domänentrennung geprüft
- [x] Nonce-Eindeutigkeit, AAD und Container-/Chunk-Manipulationstests geprüft
- [x] Schlüssel-/Pending-State wird bei allen Sperrpfaden verworfen
- [x] Recovery erzwingt ein neues Master-Passwort und entfernt Zusatzfaktoren
- [x] TOTP-/Presence-Modus wird nicht als zusätzlicher kryptografischer Schutz beworben
- [x] alle Importer begrenzen Größe/Felder und führen kein HTML oder Formeln aus
- [x] Markdown ohne Raw-HTML; Vorschauen ausschließlich per Allowlist
- [x] Datei- und Backup-Pfade gegen Traversal, Symlinks und ungeprüfte Rendererwerte abgesichert
- [x] Exporte verlangen Master-Passwort, Warnung, Ziel- und zweite Bestätigung
- [x] Logs, Audit und Fehlerpfade enthalten keine Feldwerte oder Schlüsselmaterialien
- [x] Dubletten- und Datenqualitätsscans sind revisionsgebunden, koalesziert und beim Sperren
      invalidiert
- [x] Merge, Korrektur und automatische Papierkorb-Leerung committen Fachzustand und redigiertes
      Audit atomar
- [x] Korrekturvorschauen verwenden kurzlebige, einmalige Main-only-Token und aktuelle Revisionen
- [x] VaultDocument V1 → V2 besitzt Snapshot, Rollback, Future-Version- und Klartext-Canary-Tests
- [x] automatische Papierkorbfristen sind standardmäßig deaktiviert und werden nie nachgeholt
- [x] Recovery-Bereitschaftstest verarbeitet Schlüssel nur im Main-Prozess, drosselt Fehlversuche
      und persistiert keine Schlüsselanteile
- [x] Integritäts- und Datenleckscans sind revisionsgebunden, abbrechbar und bei Lock vollständig
      ungültig; ihre Berichte, Fortschritte und Audits sind redigiert
- [x] Integritätsstatus, Datenleckmanifest/-index und Audit werden bei Erfolg atomar aktualisiert
- [x] Klartextberichte sowie Datenleck-Staging verwerfen direkte, symbolische und Junction-Aliaspfade
      in den Datenordner
- [x] Backup-Gesundheitswerte enthalten nur technische Status-/Zeitwerte und Fehlercodes, nie Pfade,
      Backupnamen oder ursprüngliche Fehlermeldungen
- [x] Restore-Probeläufe sind einzeln, abbrechbar, beim Sperren invalidiert und bereinigen einen
      descriptor-gebundenen, gegen Symlinks/Junctions geprüften Leseprüf-Staging-Baum
- [x] Portable Tresor-Pakete verwenden einen unabhängigen zufälligen Paket-Schlüssel, Argon2id und
      AES-GCM; Manifest, Dokument und Anhänge werden vor dem atomaren Import vollständig geprüft
- [x] Paket-Anhangs-Staging ist an eine Main-only-Verzeichnis-Capability mit kanonischen
      Verzeichnis-/Dateiidentitäten gebunden; Schreiben, Transaktionslesen und Bereinigen brechen
      bei Symlink-/Junction-/TOCTOU-Wechseln geschlossen ab
- [x] Herstellerimporte erkennen dokumentierte Inhalte statt Dateinamen; Enpass fällt kontrolliert auf
      den generischen Mapper zurück, statt ein unbestätigtes Layout zu erraten
- [x] Drag-and-drop-Pfade bleiben im Preload hinter kurzlebigen Einmal-Tokens; der descriptor-gebundene
      Main-Leser erkennt Symlinks, Größenüberschreitungen und TOCTOU-Austausch
- [x] Tray und lokale Erinnerungen verarbeiten nur Sperrstatus beziehungsweise allgemeine lokale
      Hinweise; Klicks sperren vor dem Öffnen, Reminder werden beim Sperren verworfen
- [x] große Listen verwenden Main-only-Autorisierungscheckpoints, revisionsgebundene koaleszierte
      Sicherheitsreports und verwerfen Pending-/Cache-State beim Sperren
- [x] der echte Controller-Entsperrtest deckt V1 → V2 für mehrere Tresore, Anhang, TOTP, Idempotenz,
      Future-Version und unterbrochenen Commit ab; Journal und Sidecars bestehen Klartext-Canaries
- [x] Artefaktscanner prüft Caches, Berichte, Restore-/Import-Staging, Transaktionsartefakte und
      ZIP-/ASAR-Inhalte; `KRYBRCH1` ist nur mit exaktem öffentlichen Indexheader zulässig
- [x] Produktions-Dependency-Audit aus dem aktuellen Welle-12-Quellstand (`pnpm audit --prod` ohne
      Befund)
- [x] Lizenz-Allowlist aus dem aktuellen Welle-12-Quellstand (154 erlaubte Produktionspakete)
- [x] Artefaktscan des aktuellen `dist`-Baums (143 Dateien, keine bekannte Canary)
- [x] Workspace-Electron-E2E (1 echter Electron-Flow plus sechs visuelle Smokes, 7/7 grün)
- [x] finaler Installer-/ZIP-Rebuild für x64 und ARM64 mit `buildUniversalInstaller: false` und
      `SHA256SUMS.txt`; beide unpacked EXEs bestanden die Fuse-Prüfung
- [x] Canary-Scan des finalen Release-Baums (29.682 Dateien) sowie Fuse- und Payload-Scan der
      installierten x64-NSIS-Kopie (7.420 Dateien) ohne Befund
- [x] isolierter packaged Electron-CRUD-/Restore-Flow (1/1) und stille NSIS-Deinstallation mit
      erhaltenem Userdata-Sentinel

## Befundklassen

- kritisch: Entschlüsselung, Codeausführung oder Secret-Leak ohne gültigen Zugang
- hoch: Faktor-/Integritätsumgehung oder dauerhafter Klartextrest
- mittel: begrenzte Metadatenoffenlegung, DoS oder unsichere Voreinstellung
- niedrig: Härtungs-/Dokumentationsabweichung ohne unmittelbaren Secretzugriff

## Behobene Befunde

| Schwere | Befund                                                                                                                                                      | Behebung/Nachweis                                                                                                                                                                                                             |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hoch    | Der Renderer konnte beliebige externe Ziele über eine Shell-Brücke öffnen.                                                                                  | Brücke vollständig aus IPC, Preload und Renderer entfernt; Webseiten bleiben nur kopierbar, Markdown-Links sind nicht interaktiv.                                                                                             |
| hoch    | Setup-Geheimnisse konnten zwischen Recovery-Anzeige und Bestätigung in einem unklaren Pending-Zustand verbleiben.                                           | Eine Auth-Epoch umfasst nun den gesamten Setup-Vorgang; Timeout, Sperren, Suspend und Dispose verwerfen Pending-State und Schlüssel.                                                                                          |
| hoch    | Faktor-Metadaten, PRF-Wrap und geschützter Faktor-State wurden in mehreren Schreibvorgängen geändert.                                                       | Ein serialisierter Compare-and-swap-Commit schreibt alle Faktoränderungen atomar in genau einer Profilgeneration; Crash- und Paralleltests decken Registrierung und Entfernung ab.                                            |
| hoch    | Backup-/Migrationsfolgen konnten bei Absturz oder wechselndem Live-Zustand inkonsistent werden.                                                             | Live-Datei-/Hash-Prüfung, authentifizierte Gesamtvalidierung und ein persistentes Transaktionsjournal mit bytegenauem Rollback wurden ergänzt.                                                                                |
| mittel  | Ein kompromittierter Renderer konnte einen frei gewählten Backup-Ordner übergeben.                                                                          | Nur unmittelbar zuvor nativ ausgewählte, lokale Windows-Pfade werden sitzungsgebunden akzeptiert; UNC, Device- und relative Pfade werden abgelehnt.                                                                           |
| mittel  | Sicherheitsrelevante Einstellungen konnten ohne erneute Master-Bestätigung abgeschwächt werden.                                                             | Jede definierte Abschwächung verlangt die Verifikation des aktuellen Master-Passworts; parallele Updates sind serialisiert.                                                                                                   |
| mittel  | Renderer-Aktivität konnte den Auto-Lock künstlich verlängern.                                                                                               | Vertrauenswürdige Aktivität stammt ausschließlich aus Main-Prozess-Eingabeereignissen; indirekte Renderer-Resetpfade wurden entfernt.                                                                                         |
| mittel  | Restore-Ziele konnten über Symlinks oder Junctions umgeleitet werden.                                                                                       | Restore akzeptiert nur reale Verzeichnisse und verwirft Symlinks/Junctions vor dem Schreiben.                                                                                                                                 |
| niedrig | Temporäre Clipboard-Vergleichsbuffer wurden nicht explizit überschrieben.                                                                                   | Buffer werden in einem `finally`-Pfad genullt.                                                                                                                                                                                |
| hoch    | Cross-Vault- und Attachment-Purge-Aktionen hätten mit einzelnen Dateioperationen Teilzustände hinterlassen können.                                          | Ein gemeinsames technisches Journal, verschlüsselte Rollback-Sidecars, CAS-Prüfungen und Startup-Recovery committen Vaults und Anhänge gemeinsam.                                                                             |
| mittel  | Ein paralleles Sperren konnte den gerade geleerten Saved-View-Cache über einen asynchronen Rollback wiederherstellen.                                       | Rollback stellt einen Snapshot nur bei weiterhin gültiger Auth-Epoch wieder her; Lock/Dispose behalten andernfalls den autoritativen leeren Zustand.                                                                          |
| hoch    | Dubletten-Merge, Datenqualitätskorrektur oder Retention hätten Fachzustand ohne zugehöriges Audit committen können.                                         | Der Auditdatensatz wird vorbereitet, verschlüsselt und als Ziel derselben Mehrdatei-Transaktion geschrieben; Fehler und Sperren rollen sämtliche Ziele zurück.                                                                |
| mittel  | Teure Scans oder Korrekturvorschauen hätten nach Sperren beziehungsweise auf veralteter Revision weiterwirken können.                                       | Main-only-Jobkoordinator, Auth-Epoch, Revisionstoken und Einmal-Vorschautoken verwerfen laufende oder veraltete Arbeit; Lock leert Jobs, Caches und Pending-State.                                                            |
| hoch    | Ein fehlgeschlagener Recovery-Test hätte bei einem nachfolgenden Persistenzfehler nicht zuverlässig zur Drosselung gezählt.                                 | Der kryptografische Fehlversuch wird vor dem optionalen Status-/Audit-Commit als Fehlversuch registriert; Key-Buffer werden in jedem Pfad gelöscht.                                                                           |
| hoch    | Ein beschädigtes Profil oder Audit hätte einen bereits redigierten Integritätsbefund durch den anschließenden Statuscommit unterdrücken können.             | Der Scanner liefert den redigierten Report und ein Main-only-Exporttoken auch bei nicht persistierbarem Status; nur Lock, Abbruch, Auth- und Revisionsfehler werden weitergereicht.                                           |
| hoch    | Eine Vault-Mutation konnte nach der letzten Integritätsrevision und vor dem Status-/Audit-Commit einen veralteten Status veröffentlichen.                   | Alle betroffenen Vault-Writer sowie Profil und Audit werden für die kurze Endprüfung und den atomaren Commit gemeinsam gehalten; der Cache wird auf die resultierende Generation umgebunden.                                  |
| hoch    | Ein Klartextbericht hätte über eine Junction oder einen Symlink in den Datenordner geschrieben und dort eine Datei ersetzen können.                         | Der finale Writer kanonisiert den vorhandenen Pfadpräfix vor `mkdir`, Ersetzen oder Öffnen und verweigert geschützte Wurzeln; Sentinel-Tests decken direkten und Aliaspfad ab.                                                |
| mittel  | Offline-Datenleckscan, -import und -entfernung konnten um dieselbe Indexgeneration konkurrieren.                                                            | Ein serialisierter Main-only-Executor bricht den Scan vor Mutation ab, wartet auf dessen Ende und serialisiert danach neue Scans; Index, Manifest und Audit committen oder rollen gemeinsam zurück.                           |
| hoch    | Ein Restore-Probelauf hätte nach einem Pfadwechsel im temporären Staging-Baum über eine Junction/Symlink lesen oder schreiben können.                       | Die temporäre Wurzel und jede Verzeichnishierarchie werden identitäts- und kanonisch geprüft; Ausgabedateien sind exklusiv und ohne Follow geöffnet, der nachgelagerte Prüfflow ist strikt schreibfrei.                       |
| mittel  | Ein Import konnte zwischen Pfadprüfung und `readFile` gegen eine ausgetauschte Quelldatei laufen.                                                           | Der Main-Prozess liest nur über einen geprüften Read-only-Descriptor, vergleicht Pfad- und Handle-Identität vor/nach dem Lesen und prüft währenddessen die Auth-Epoch.                                                        |
| mittel  | Ein Renderer hätte einen Drag-and-drop-Dateipfad in eine Importoperation einschleusen können.                                                               | Nur der Preload löst den nativen Drop-Pfad auf und mintet einen kurzlebigen Einmal-Token; an Main gelangt ausschließlich der hinterlegte Pfad, Tokens verfallen und werden bei Lock gelöscht.                                 |
| mittel  | Ein Paketimport konnte nach erfolgreichem Commit wegen Sperren oder einer nachgelagerten Cache-, UI- oder Aufräumstörung als fehlgeschlagen erscheinen.     | Der bestätigte Commit wird vor jeder Nacharbeit autoritativ; Caches werden nur bei frischer Auth-Epoch veröffentlicht, sonst verworfen. Warnungen, Buffer-Dispose und Staging-Bereinigung bleiben redigiert und best-effort.  |
| mittel  | Paket-Anhangs-Staging konnte durch einen späten Junction-/Symlink-Wechsel außerhalb des Arbeitsbereichs schreiben oder passende externe Dateien bereinigen. | Controller-Capability, `realpath`-/dev/ino-Prüfungen, `O_NOFOLLOW`, Handle-/Pfadvergleich und nichtrekursiver Cleanup prüfen vor jedem Schritt erneut; Sentinel-Tests decken direkte und späte Aliaswechsel ab.               |
| mittel  | Tray-Status oder lokale Erinnerung hätten Tresor-, Eintrags- oder Geheimmetadaten außerhalb des Fensters anzeigen können.                                   | Die Main-only-Dienste behalten nur Sperrstatus beziehungsweise technische Fälligkeitszählungen. Menü und Benachrichtigung sind generisch; Aktivierung sperrt vor dem Öffnen und Sperren invalidiert Timer/Resultate.          |
| mittel  | Eine verspätete große Listen- oder Sicherheitsauswertung hätte nach Sperren eine Cachegeneration oder Anzeige reaktivieren können.                          | `EntryViewService.listAsync()` prüft Main-only-Autorisierung in Batches, koalesziert nur dieselbe Revision und leert Pending-/Cache-Maps bei Lock; der Renderer verwirft zusätzlich Antworten einer alten Anfragengeneration. |
| hoch    | Ein neuer Laufzeit-, Staging- oder Rollbackpfad hätte geheimen Klartext in ein Releaseartefakt übernehmen können.                                           | Der Scanner verweigert Klartextfelder und unbekannte Runtime-Artefakte, rekursiv auch in ZIP/ASAR. Nur ein exakt geprüfter `KRYBRCH1`-Header eines öffentlichen SHA-1-Index ist als Rollbackbyte zulässig.                    |

## Abschlussbefund

Im geprüften Welle-12-Codepfad besteht **kein offener kritischer, hoher oder mittlerer
Sicherheitsbefund aus dem Quellreview**. `corepack pnpm verify` bestand mit Prettier, ESLint, allen
drei TypeScript-Konfigurationen sowie 87 Testdateien/487 Tests. `pnpm audit --prod` ergab keinen
Befund, die Lizenz-Allowlist akzeptierte 154 Produktionspakete und der aktuelle `dist`-Scan fand in
143 Dateien keine bekannte Canary. Der zusätzliche Controller-Migrationstest und die Scanner-Tests
sind Teil dieses Verify-Laufs.

Der [aufgezeichnete Leistungsnachweis](performance-benchmark.md) misst ausschließlich Main-Prozess-
Pfade. Er bestätigt keine Renderer-Frame-Dauer, keinen Zeitpunkt des ersten sichtbaren UI-Feedbacks,
keine IPC-/Structured-Clone-Kosten und keine Bedienung bei 200-%-Skalierung. Diese UI-Ziele bleiben
daher ausdrücklich nicht als bestanden markiert, obwohl die lokalen Electron-, Paket-, Fuse- und
Payload-Gates bestanden haben.

Node bietet keine descriptor-relative `openat`-/`unlinkat`-API. Die Paket-Staging-Implementierung
schreibt deshalb erst nach der Prüfung des geöffneten Handles und verwendet für die Bereinigung
nichtrekursive, unmittelbar erneuerte Topologie- und Identitätsprüfungen. Ein gleicher Benutzer,
der genau zwischen letzter Prüfung und einer Betriebssystemoperation Dateisystemobjekte austauscht,
kann die Verfügbarkeit stören; ohne gültigen Zugang entsteht daraus weder Klartext noch ein
entschlüsselter Rest. Diese Plattformgrenze ersetzt keine Prüfung auf einem gehärteten Windows-Testsystem.

Der aktuelle Welle-12-Paketlauf erzeugte x64- und ARM64-NSIS-Installer sowie ZIPs mit
`buildUniversalInstaller: false` und `SHA256SUMS.txt`. Beide unpacked EXEs bestanden die Fuse-Prüfung;
der Release-Scan umfasste 29.682 Dateien ohne bekannte Canary. Eine isolierte installierte x64-
NSIS-Kopie bestand Fuse- und Payload-Scan in 7.420 Dateien sowie den packaged Electron-
CRUD-/Restore-Flow (1/1). Die stille Deinstallation erhielt das Userdata-Sentinel. Installer und EXEs
bleiben entsprechend der festgelegten Produktentscheidung bewusst unsigniert.

Vor einem öffentlichen Tag müssen zusätzlich die GitHub-Release-Strecke und die manuellen
Windows-/Hardware-Fälle aus der [Security-Testmatrix](security-test-matrix.md) auf frischen
Windows-10-/Windows-11-Benutzerprofilen bestehen. Dazu gehören insbesondere vollständige
Offline-Nutzung, frischer Backup-Restore, Sitzungssperre/Standby sowie ein realer
FIDO2-PRF-/Presence-Test. Die fehlende Codesignatur ist eine festgelegte Produktentscheidung und muss
mit der dokumentierten SmartScreen-Warnung beibehalten werden.
