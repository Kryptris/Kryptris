# Kryptris – Erweiterungsplan ab Version 1.1

**Status:** Umsetzungsorientierte Roadmap
**Stand:** 26. Juli 2026
**Ausgangsbasis:** Abgenommener Funktionsstand aus `docs/acceptance.md`
**Ziel:** Kryptris im bestehenden Offline- und Sicherheitsmodell spürbar produktiver,
übersichtlicher und langfristig wartbarer machen.

## 1. Zweck dieses Dokuments

Dieses Dokument ist kein loses Ideenboard. Es beschreibt eine ausführbare Erweiterungsroadmap mit
Reihenfolge, fachlichen Anforderungen, technischen Leitplanken und Abnahmekriterien. Eine
Implementierung darf die vorhandenen Sicherheitszusagen nicht stillschweigend abschwächen.

Die Wellen werden nacheinander umgesetzt. Nach jeder Welle müssen Formatierung, Linting, Typechecks
und Tests wieder grün sein. Änderungen am persistenten Datenmodell benötigen vor dem ersten Writer
eine vorwärtsgerichtete Migration über die vorhandene Snapshot-/Rollback-Infrastruktur.

## 2. Bestehende Basis – nicht erneut implementieren

Kryptris besitzt bereits:

- ein lokales Profil mit mehreren kryptografisch getrennten Tresoren;
- neun Eintragstypen, freie Felder, Ordner, Tags, Favoriten, Papierkorb und Volltextsuche;
- Offline-TOTP, Generator, verschlüsselte Anhänge und sichere Vorschauen;
- Recovery-Key, verschlüsselte Backups, Rotation und semantisch geprüften Restore;
- Import mit Vorschau/Dublettenhinweis sowie abgesicherten Export;
- lokalen Sicherheitscheck, Auditprotokoll, Vorlagen und lokale Berichte;
- optionale TOTP- und FIDO2/WebAuthn-Sperren;
- gehärtete Electron-Grenzen, strikt validierte IPC-Kanäle und Windows-Pakete.

Neue Funktionen sollen vorhandene Services, Komponenten und IPC-Muster erweitern. Es dürfen keine
parallelen Speicher-, Kryptografie- oder Renderer-Dateizugriffe entstehen.

## 3. Verbindliche Produkt- und Sicherheitsleitplanken

1. **Offline bleibt Standard und Zusage.** Keine Telemetrie, Cloud, Remote-Schriften, externen
   Bilder, Datenleckabfragen oder stillen Update-Anfragen.
2. **Geheimnisse bleiben im Main-Prozess.** Der Renderer erhält nur die für die konkrete Anzeige
   oder Aktion benötigten Daten. Datei- und Clipboard-Zugriffe laufen weiterhin über validierte IPC.
3. **Keine alten Geheimnisse speichern.** Diese Roadmap führt keine Passwort- oder Feldwerthistorie
   ein. Für Rotation werden nur Zeitpunkte und Status gespeichert.
4. **Keine unsicheren Komfort-Abkürzungen.** Aus gesperrtem Zustand sind weder Suche noch Kopieren,
   Auto-Type oder Vorschauen erreichbar.
5. **Explizite Aktualisierung teurer Auswertungen.** Sicherheitscheck und lokaler Report werden nur
   bei Änderung der zugrunde liegenden Revision oder durch eine sichtbare Aktualisieren-Aktion neu
   berechnet.
6. **Crash-sichere Persistenz.** Mehrere betroffene Dateien werden weiterhin atomar und mit
   Rollback behandelt. Ein Fehler darf keinen teilweise migrierten Zustand hinterlassen.
7. **Keine sensiblen Diagnosewerte.** Logs, Fehler, Audittexte, Testsnapshots und Artefakte dürfen
   keine Passwörter, TOTP-Seeds, privaten Schlüssel, Recovery-Keys oder entschlüsselten Anhänge
   enthalten.
8. **Deutsch und barrierearm.** Neue sichtbare Texte sind deutsch, konsistent benannt und per
   Tastatur erreichbar. Icons erhalten zugängliche Namen oder sind korrekt dekorativ.

## 4. Prioritäten

| Priorität | Welle                              | Nutzen                             | Risiko/Aufwand  |
| --------- | ---------------------------------- | ---------------------------------- | --------------- |
| P0        | 7 – Produktivität                  | Sehr hoher täglicher Nutzen        | Mittel          |
| P0        | 8 – Datenqualität                  | Weniger Dubletten und Pflegefehler | Mittel bis hoch |
| P1        | 9 – Sicherheitszentrale            | Bessere lokale Vorsorge            | Mittel          |
| P1        | 10 – Backup und Transfer           | Höhere Wiederherstellbarkeit       | Mittel bis hoch |
| P1        | 11 – Windows und Bedienung         | Mehr Komfort ohne Cloud            | Mittel          |
| P2        | 12 – Leistung und Qualität         | Zukunftssicherheit großer Tresore  | Mittel          |
| Gate      | 13 – optionale Plattformfunktionen | Hoher möglicher Nutzen             | Sehr hoch       |

## 5. Welle 7 – Produktivität und Organisation

> **Umgesetzt am 21. Juli und beim Wiederaufnahmestand am 26. Juli 2026 erneut auditiert.**
> Mehrfachauswahl, atomare Batch- und Cross-Vault-Aktionen, verschlüsselte gespeicherte Ansichten,
> intelligente Ansichten, transaktionale Tagverwaltung sowie Befehlspalette und lokale Tastaturhilfe
> sind implementiert. Auditdatensätze der schreibenden Batch-, Cross-Vault- und Purge-Flows werden
> zusammen mit den fachlichen Dateien committed. Der kombinierte Nachweis nach Welle 8 umfasst
> 57 Testdateien mit 307 Tests.

### 7.1 Mehrfachauswahl und Batch-Aktionen

Die Eintragsliste erhält eine sichtbare Mehrfachauswahl. Unterstützt werden Maus, `Strg`-/
`Umschalt`-Auswahl und eine Aktion „Alle sichtbaren auswählen“. Batch-Aktionen gelten nur für die
aktuell explizit ausgewählten IDs, niemals implizit für eine später veränderte Suchmenge.

Aktionen:

- Favorit setzen oder entfernen;
- Tags hinzufügen oder entfernen;
- Ordner zuweisen oder Ordnerzuordnung lösen;
- in den Papierkorb verschieben;
- aus dem Papierkorb wiederherstellen;
- endgültig löschen, nur mit Master-Passwort und klarer Anzahl-Bestätigung;
- in einen anderen Tresor kopieren oder verschieben.

Tresorübergreifende Aktionen müssen Eintrag und Anhänge vollständig neu unter dem Zielschlüssel
schreiben. „Verschieben“ löscht die Quelle erst, nachdem Zielcontainer und Zielanhänge erfolgreich
verifiziert und committed wurden. Bei Fehler bleibt die Quelle unverändert erhalten.

**Abnahme:** Batch-Aktionen sind atomar, respektieren Filter und Papierkorbstatus und besitzen Tests
für Teilerfolg, Abbruch, falsches Master-Passwort und Attachment-Rollback.

### 7.2 Gespeicherte Ansichten

Benutzer können eine aktuelle Kombination aus Suche, Typen, Tags, Ordner, Sicherheitsstatus und
Ansicht als benannte „Gespeicherte Ansicht“ sichern. Gespeichert werden nur Filterdefinitionen, keine
Ergebnislisten. Ansichten liegen verschlüsselt in den Profilmetadaten und erscheinen in der Sidebar.

Mitgelieferte intelligente Ansichten:

- „Kürzlich geändert“;
- „Ohne Ordner“;
- „Ohne Tags“;
- „Rotation fällig“;
- „Ohne Zwei-Faktor-Schutz“, soweit lokal anhand des Eintrags erkennbar;
- „Mit Anhängen“.

**Abnahme:** Umbenennen, Sortieren und Löschen funktionieren; ungültige Verweise auf gelöschte
Ordner/Tags werden verständlich behandelt.

### 7.3 Tag-Verwaltung

Eine zentrale Tag-Ansicht zeigt Nutzungshäufigkeit und erlaubt Umbenennen, Zusammenführen und
Löschen. Änderungen wirken transaktional auf alle betroffenen Einträge. Groß-/Kleinschreibung und
Whitespace werden über eine zentrale Normalisierung behandelt, während der sichtbare Name erhalten
bleibt.

### 7.4 Tastaturbedienung und Befehlspalette

Innerhalb des **entsperrten** Fensters wird eine Befehlspalette ergänzt, standardmäßig über
`Strg+K`. Sie kann Navigation und ungefährliche Aktionen auslösen, aber keine maskierten Werte in
Suchergebnissen anzeigen. Weitere lokale Kürzel:

- `Strg+N`: neuer Eintrag;
- `Strg+F`: Suche fokussieren;
- `Strg+S`: Editor speichern;
- `Esc`: Dialog/Editor schließen oder Auswahl verlassen;
- `Strg+L`: sofort sperren.

Kürzel dürfen nicht mit Eingaben kollidieren und werden in einer Hilfeansicht dokumentiert. Es gibt
in dieser Welle keine globalen Betriebssystem-Hotkeys.

## 6. Welle 8 – Datenqualität, Dubletten und Lebenszyklus

> **Umgesetzt am 26. Juli 2026.** Die gemeinsame Dublettenerkennung wird von Import und
> Datenpflege genutzt; Scan, Vergleich, feldweiser Merge, Attachment-Revalidierung und Löschen sind
> revisionsgebunden, abbrechbar und transaktional. Lebenszyklusmetadaten, Startübersicht,
> Datenqualitätsprüfung mit Einmal-Vorschautoken sowie optionale Papierkorbfristen sind vollständig
> über Main-Prozess, validierte IPC-Allowlist und deutsche, tastaturbedienbare Renderer-Flows
> angebunden. Die neuen persistenten Lebenszyklusfelder werden gesammelt über die getestete
> VaultDocument-Migration V1 → V2 eingeführt. `corepack pnpm verify` ist mit 57 Testdateien und
> 307 Tests grün; Produktionsbundle, der echte Electron-Flow sowie vier Chromium-Smoke-Flows
> einschließlich kleinem Fenster und 200-%-Skalierung sind grün.

### 8.1 Dubletten-Zentrale

Die bisherige Dublettenerkennung beim Import wird zu einem wiederverwendbaren lokalen Service
ausgebaut. Er erkennt mögliche Dubletten anhand normalisierter, typspezifischer Merkmale, zum
Beispiel Titel, Benutzername, Host und Website. Geheimnisse werden nur im entsperrten Arbeitsspeicher
verglichen; persistierte Hilfsindizes enthalten keine ungeschützten Werte.

Die UI zeigt Kandidatenpaare mit einer nachvollziehbaren Begründung. Der Benutzer kann:

- Einträge getrennt behalten;
- einen Eintrag löschen;
- pro Feld auswählen, welcher Wert übernommen wird;
- Tags, Notizen, Websites, eigene Felder und Anhänge zusammenführen.

Anhänge werden anhand ihrer bereits vorhandenen SHA-256-Metadaten erkannt, aber vor einer
Zusammenführung über den authentifizierten Inhaltspfad verifiziert. Zusammenführen ist eine
transaktionale Operation und erzeugt ein redigiertes Auditereignis.

### 8.2 Rotation und Ablaufdaten ohne Geheimnishistorie

Zugangsdaten erhalten optionale Metadaten:

- gewünschtes Rotationsintervall in Tagen;
- nächstes Rotationsdatum;
- Rotation bewusst ausgenommen;
- letzter lokal bestätigter 2FA-Status: unbekannt, aktiv oder nicht aktiv;
- optionale Erinnerung für Lizenz-, Karten- und Dokumentabläufe.

Beim Ändern eines relevanten Geheimnisses wird `secretChangedAt` weiterhin aktualisiert. Alte Werte
werden nicht aufbewahrt. Überfällige Einträge erscheinen in Sicherheitscheck, gespeicherten Ansichten
und der Startübersicht.

### 8.3 Datenqualitätsprüfung

Eine lokale Prüfung meldet zusätzlich:

- ungültige oder offensichtlich fehlerhafte URLs;
- identische oder nahezu identische Websites in einem Eintrag;
- leere Titel und Platzhaltertitel aus Importen;
- abgelaufene Kreditkarten oder Lizenzen;
- TOTP-Konfigurationen mit ungewöhnlichen Parametern;
- Anhänge mit nicht mehr passender Metadaten-/Dateizuordnung;
- verwaiste Ordner- oder Ansichtsreferenzen.

Automatische Korrekturen benötigen immer eine Vorschau. Fachliche Werte dürfen nicht ohne
Bestätigung verändert werden.

### 8.4 Papierkorb-Regeln

Optional kann der Papierkorb Einträge nach einer einstellbaren Frist automatisch endgültig löschen.
Standard ist „nie“. Vor Aktivierung werden Auswirkung und Backup-Abhängigkeit erklärt. Eine
automatische Leerung läuft nur entsperrt, schreibt ein Auditereignis und wird nicht nachgeholt, wenn
Kryptris geschlossen war.

## 7. Welle 9 – Sicherheitszentrale und lokale Vorsorge

> **Umgesetzt am 27. Juli 2026.** Sicherheitscheck, Datenqualität, Faktoren, Backup, Recovery,
> KDF, Integrität und die optionale Offline-Datenleckliste werden als acht lokale Kacheln
> zusammengeführt. Der Recovery-Test prüft ausschließlich den Gate-Key im Main-Prozess und drosselt
> Fehlversuche. Integritäts- und Datenleckscans sind abbrechbar, fortschrittsfähig,
> revisionsgebunden und werden beim Sperren verworfen. Integritätsberichte sind redigiert und gegen
> direkte sowie Junction-/Symlink-Aliasziele des Datenordners geschützt. Der Offline-Index ist
> strikt binär validiert, nie Teil eines Backups und erzeugt weder Netzverkehr noch persistierte
> Passwort-Hashes. `corepack pnpm verify` bestand mit 72 Testdateien/390 Tests; der Produktionsbuild
> und sechs Playwright-Flows einschließlich echten Electron- und 200-%-Smoke-Tests sind grün.

### 9.1 Einheitliches Sicherheits-Dashboard

Sicherheitscheck, Datenqualität, Faktorstatus, Backupzustand und Recovery-Vorsorge werden in einer
Übersicht zusammengeführt. Der Score darf nicht suggerieren, dass ein kompromittiertes Windows
beherrscht wird. Jede Kachel zeigt Ursache, konkrete nächste Aktion und Zeitpunkt der letzten
Berechnung.

Neue lokale Befunde:

- Master-Passwort/KDF-Parameter entsprechen nicht mehr der aktuellen Produktempfehlung;
- kein getesteter Recovery-Key beziehungsweise Bestätigung zu lange her;
- automatische Backups deaktiviert oder letztes erfolgreiches Backup zu alt;
- Rotation überfällig;
- Zugangsdaten ohne lokal markierten 2FA-Schutz;
- Integritätsprüfung von Tresor oder Anhängen fehlgeschlagen.

### 9.2 Recovery-Bereitschaftstest

Der Benutzer kann in einem geführten Dialog nachweisen, dass der Recovery-Key noch lesbar vorliegt.
Der Test entschlüsselt nur den Profil-Gate-Key im Speicher und verändert weder Master-Passwort noch
Faktoren. Gespeichert werden ausschließlich Zeitpunkt und Erfolg, niemals Teile des Keys.

Fehlversuche werden gedrosselt und redigiert auditiert. Der Dialog erklärt klar, dass ein Test kein
Ersatz für ein echtes Backup ist.

### 9.3 Vollständige Integritätsprüfung

Eine manuell gestartete Prüfung validiert alle Container, Attachment-Chunks, Manifestbeziehungen und
fachlichen Referenzen, ohne Inhalte zu exportieren. Sie ist abbrechbar, zeigt Fortschritt und erzeugt
einen lokal speicherbaren **redigierten** Bericht. Dateinamen, Titel und Hashes geschützter Inhalte
werden nicht in den Bericht geschrieben.

### 9.4 Optional importierbare Offline-Datenleckliste

Kryptris führt keine Online-Abfrage ein. Optional darf der Benutzer eine lokal bereitgestellte,
vorberechnete Hashliste importieren. Der Importer akzeptiert ausschließlich dokumentierte Formate,
prüft Größe und Struktur, speichert die Liste außerhalb der Tresore und versieht sie mit Quelle,
Datum und lokal berechneter Prüfsumme.

Passwörter werden lokal gehasht und nur im Prozess verglichen. Es werden keine Passwort-Hashes in
Audit, Report oder UI ausgegeben. Die Funktion ist vollständig optional; ohne Liste bleibt das
bisherige Verhalten bestehen.

## 8. Welle 10 – Backup, Restore und Transfer

> **Umgesetzt am 9. August 2026.** Das Backup-Gesundheitscenter, der isolierte Restore-Probelauf,
> das in ADR 0007 beschriebene portable Tresor-Paket sowie die erweiterten Importwege sind im
> Main-Prozess, über die validierte IPC-Kette und in den deutschen Renderer-Flows vorhanden. Der
> Nachweis umfasst `corepack pnpm verify` mit 81 Testdateien/443 Tests und `corepack pnpm test:e2e`
> mit Produktionsbuild sowie 6/6 Playwright-Flows.

### 10.1 Backup-Gesundheitscenter

Die vorhandenen verschlüsselten Backups erhalten eine verständliche Statusansicht. Sie authentifiziert
vor der Zählung jedes berücksichtigte Backup und gibt nur redigierte, pfadfreie Werte an den Renderer:

- letzter Erfolg und letzter Fehler;
- Zielordner erreichbar/nicht erreichbar;
- vorhandene Generationen nach täglich/wöchentlich/monatlich;
- Größe und Anzahl enthaltenen Tresore/Anhänge;
- Zeitpunkt der letzten erfolgreichen semantischen Verifikation;
- sichtbare Warnung, wenn Backups nur auf demselben Datenträger liegen.

Fehler werden angezeigt, ohne Pfade oder Inhalte unnötig in Logs zu schreiben. Automatische Backups
werden koalesziert, damit eine Serie schneller Änderungen keine parallelen Backups startet.

### 10.2 Restore-Probelauf

Vor einem echten Restore kann ein Backup vollständig in einem isolierten temporären Arbeitsbereich
entschlüsselt und semantisch geprüft werden. Der Probelauf verändert das aktive Profil nicht. Der
temporäre Bereich wird über den vorhandenen Cleartext-/Canary-Ansatz kontrolliert bereinigt; bei
Abbruch oder Fehler darf kein entschlüsselter Rest verbleiben. Der Staging-Baum wird vor und während
der Prüfung gegen Symlinks/Junctions und ausgetauschte Pfade geprüft; schreibende Staging-Services
laufen im reinen Leseprüfmodus.

### 10.3 Verschlüsseltes Tresor-Paket

Neben dem vollständigen nativen Backup wird ein einzelner Tresor als portables, verschlüsseltes
Kryptris-Paket exportierbar. Das Paket erhält einen eigenen zufälligen Schlüssel, geschützt durch ein
separates Exportpasswort mit Argon2id. Es enthält optional Anhänge und ein versioniertes Manifest.
Der Import unterstützt Vorschau, Namenskonflikte und vollständige Integritätsprüfung.

Das ausschließlich Main-seitige Anhangs-Staging ist eine kurzlebige Controller-Capability. Seine
Security-, Staging- und Jobverzeichnisse sowie jede Quelle werden vor Schreiben, Transaktionslesen
und nichtrekursiver Bereinigung kanonisch und über Dateisystemidentitäten geprüft. Ein bestätigter
Mehrdatei-Commit bleibt auch bei nachträglichem Sperren oder einer Bereinigungsstörung das
autoritativ erfolgreiche Importergebnis; entschlüsselte Buffer und Caches werden trotzdem sofort
verworfen.

Dieses Format ist kein Klartextexport und darf nicht den aktiven Profil- oder Tresorschlüssel direkt
übernehmen. Format und Schlüsselhierarchie werden vor Implementierung in einem ADR dokumentiert.

### 10.4 Verbesserter Import

- zusätzliche Importer für Dashlane-, NordPass- und RoboForm-Exporte mit inhaltsbasierter
  Spaltensignatur und anonymisierten Fixtures; Enpass wird bewusst ausschließlich als generisches
  CSV mit Feldzuordnung verarbeitet, weil kein belastbar dokumentiertes, anonymisiert testbares
  natives Layout vorliegt;
- Drag-and-drop als Komfortweg: Der Preload mintet einen kurzlebigen Einmal-Token für den nativen
  Pfad; der Renderer erhält oder übergibt den Pfad nie;
- wiederverwendbare Feldzuordnungsprofile für generisches CSV;
- Zusammenfassung nach Import: neu, übersprungen, Dubletten, Warnungen und fehlerhafte Zeilen;
- direkter Übergang aus dem Importer in die Dubletten-Zentrale.

Exporter und Importer dürfen nie Formate anhand des Dateinamens allein vertrauen. Der Main-Prozess
liest Importquellen descriptor-gebunden, begrenzt die Größe und verifiziert Dateiidentität vor,
während und nach dem Einlesen, damit ein Pfadwechsel nicht zu einem anderen Importinhalt führt.

## 9. Welle 11 – Windows-Integration, Bedienbarkeit und Barrierefreiheit

> **Implementiert und im Gesamt-Verify vom 13. August 2026 abgedeckt.** Die geschützten
> Profileinstellungen steuern minimieren/schließen in den Infobereich, reversiblen Windows-Autostart
> und einen minimierten, weiterhin gesperrten Autostart. Das Main-Prozess-Tray zeigt nur den
> Sperrstatus sowie „Öffnen“, „Jetzt sperren“ und „Beenden“; beim Schließen in den Infobereich wird
> vor dem Ausblenden gesperrt. Lokale Erinnerungen arbeiten nur entsperrt, sind beim Sperren
> ungültig und erzeugen ausschließlich einen allgemeinen Hinweis. Fokusmodus, lokale Hilfe,
> überspringbares Onboarding, semantische Navigation, sichtbare Fokuszustände, Live-Regionen und
> reduzierte Bewegung sind im Renderer ergänzt. Der Quelltestnachweis umfasst `corepack pnpm verify`
> mit 87 Testdateien und 487 Tests; der finale Electron-/Paketnachweis wird im Welle-12-Release-Gate
> getrennt geführt.

### 11.1 Tray und Startverhalten

Optionale Einstellungen:

- in den Infobereich minimieren;
- beim Schließen in den Infobereich wechseln;
- mit Windows starten;
- beim Start minimiert und **gesperrt** öffnen;
- sichtbare Tray-Aktion „Jetzt sperren“ und Status „gesperrt/entsperrt“.

Das Tray-Menü zeigt niemals Tresornamen, Einträge oder Geheimnisse. Änderungen am Autostart müssen
reversibel sein und dürfen keine Administratorrechte voraussetzen.

### 11.2 Lokale Erinnerungen

Windows-Benachrichtigungen können optional auf fällige Rotation, Abläufe oder veraltete Backups
hinweisen. Benachrichtigungstexte enthalten standardmäßig weder Eintragstitel noch Tresornamen. Ein
Klick öffnet Kryptris nur; Details erscheinen erst nach Entsperren.

### 11.3 Fokusmodus gegen Schulterblick

Ein optionaler Fokusmodus reduziert sichtbare Metadaten, maskiert Listensubtitel und blendet
Vorschauen aus. Er ist kein kryptografischer Schutz und wird so bezeichnet. Sperren bleibt jederzeit
die sichere Aktion.

### 11.4 Barrierefreiheit und responsive Oberfläche

- vollständige Tastaturreihenfolge für Navigation, Liste, Detail und Dialoge;
- sichtbare Fokuszustände und verständliche Screenreader-Namen;
- Statusänderungen über geeignete Live-Regionen statt nur über Farbe;
- Kontrastprüfung für normalen Text, Sekundärtext, Befunde und deaktivierte Controls;
- Unterstützung von 200 % Windows-Skalierung und kleineren Fenstern ohne verdeckte Aktionen;
- reduzierte Bewegung konsequent in allen neuen Animationen beachten;
- keine Information ausschließlich durch Icon oder Farbe vermitteln.

### 11.5 Onboarding und Hilfe

Eine lokale Hilfe erklärt Recovery, Backups, Faktoren, Exportgefahren, Tastenkürzel und die Grenzen
des Sicherheitsmodells. Beim ersten Start gibt es eine kurze, überspringbare Einführung. Inhalte
werden mit der Anwendung ausgeliefert und laden keine Webseiten.

## 10. Welle 12 – Leistung, Wartbarkeit und Release-Qualität

> **Implementierungs- und lokaler Nachweis vom 13. August 2026.** Die V1→V2-Migration ist über den
> echten Controller-Entsperrpfad für mehrere Tresore, Anhang und TOTP-Faktor abgedeckt, einschließlich
> Idempotenz, unterbrochenem Commit, Future-Version-Ablehnung vor Write sowie Klartext-Canaries in
> Journal und Sidecars. Die Liste ist virtualisiert; Suche wird 200 ms entprellt und eine
> Anfragengeneration verwirft veraltete Antworten. Revisionsgebundene Main-Prozess-Sicherheitsreports
> werden koalesziert und beim Sperren mitsamt laufenden Anfragen invalidiert. Der Artefaktscanner
> prüft zusätzlich Caches, Berichte, temporäre Staging-/Transaktionspfade sowie ZIP-/ASAR-Inhalte;
> die einzige eng geprüfte Ausnahme ist ein exakt strukturvalidierter `KRYBRCH1`-Header des
> öffentlichen Offline-Datenleckindexes, niemals beliebiger Klartext. `corepack pnpm verify` ist mit
> 87 Testdateien und 487 Tests grün; Produktionsaudit und Lizenz-Allowlist sind lokal grün, der
> `dist`-Artefaktscan fand in 143 Dateien keine Canary-Werte. `corepack pnpm test:e2e` bestand mit
> 7/7 Flows (echter Electron-Flow und sechs visuelle Smokes). Der finale `make`-Lauf erzeugte x64-
> und ARM64-NSIS-Installer sowie ZIPs mit `buildUniversalInstaller: false` und
> `SHA256SUMS.txt`; beide unpacked EXEs bestanden die Fuse-Prüfung. Der Release-Scan fand in 29.682
> Dateien keine Canary, der installierte x64-NSIS-Payload bestand Fuse- und Scan-Prüfung in 7.420
> Dateien, der isolierte packaged CRUD-/Restore-Flow bestand 1/1 und die stille Deinstallation erhielt
> das Userdata-Sentinel. Der aufgezeichnete Benchmark ist ein einzelner Main-Prozess-Lauf; er beweist
> ausdrücklich weder Renderer-Frames noch den Zeitpunkt des ersten sichtbaren UI-Feedbacks. Diese
> beiden Zielwerte sowie frische Windows-10-/Windows-11-, Hardware-, Codesignatur- und CI-Nachweise
> bleiben als externe Abnahmegates offen.

### 12.1 Große Tresore

Kryptris erhält reproduzierbare Benchmarks mit synthetischen, nicht sensiblen Daten für 1.000,
5.000 und 10.000 Einträge. Zielwerte auf einem dokumentierten Referenzsystem:

- Wechsel zwischen normalen Ansichten: unter 200 ms bis zum ersten sinnvollen UI-Feedback;
- Eingabe in die Suche: kein blockierter Renderer-Frame über 100 ms;
- Eintragsliste: virtualisiert, ohne tausende gleichzeitige DOM-Knoten;
- Sicherheitscheck und Dublettenscan: abbrechbar, mit Fortschritt und ohne doppelte Parallelberechnung;
- Sperren: unmittelbar priorisiert, auch während laufender Auswertungen.

Caches bleiben ausschließlich im entsperrten Zustand, revisionsgebunden und werden beim Sperren
vollständig invalidiert.

### 12.2 Datenformat Version 2

Alle neuen persistenten Felder werden gesammelt in einer dokumentierten Formatversion eingeführt,
statt mehrere unkoordinierte Writer-Migrationen zu erzeugen. Erforderlich sind:

- Ergänzung von `docs/data-migrations.md`;
- Migration V1 → V2 mit Vorab-Snapshot und Rollback;
- Idempotenztests, Downgrade-Ablehnung und Future-Version-Test;
- Fixture für V1 und V2;
- Test mit mehreren Tresoren, Anhängen, Faktoren und unterbrochenem Commit;
- keinerlei Klartext in Journal oder Sidecars.

### 12.3 Testausbau

- Unit-Tests für jeden neuen Service und jedes Schema;
- Property-Tests für Batch-Selektion, Tag-Normalisierung, Merge und Importmapping;
- Integrationsfälle für Cross-Vault-Move, Restore-Probelauf und V2-Migration;
- Renderer-Tests für Tastaturbedienung, Fokus und Dialogabbrüche;
- Electron-E2E für einen vollständigen neuen Hauptflow pro Welle;
- visuelle Smoke-Tests für Desktop, kleines Fenster und 200-%-Skalierung;
- Artifact-Scan um neue Cache-, Bericht- und Temporärpfade erweitern.

### 12.4 Release und Dokumentation

- `CHANGELOG.md` nach Keep-a-Changelog-Prinzip;
- sichtbare Versions-/Migrationshinweise ohne Marketing- oder Netzwerkzugriff;
- aktualisierte README, Acceptance-Matrix, Security-Review und relevante ADRs;
- Windows-Release weiterhin mit SHA-256-Prüfsummen;
- Code Signing als empfohlenes externes Release-Gate dokumentieren, aber nicht vortäuschen;
- keine automatische Online-Aktualisierung in dieser Roadmap.

## 11. Welle 13 – bewusste Entscheidungstore, nicht automatisch implementieren

> **Nicht implementiert.** Welle 13 bleibt ein Entscheidungstor. Diese Roadmap ergänzt weder
> Browser-Erweiterung, Autofill/Auto-Type, Windows-Passkey-Provider noch Cloud, Teams oder Teilen.

Die folgenden Ideen sind attraktiv, verändern aber Bedrohungsmodell, Plattformumfang oder
Produktabgrenzung erheblich. Sie dürfen **nicht** zusammen mit Welle 7–12 beiläufig umgesetzt werden.

### 13.1 Browser-Erweiterung und Autofill

Erfordert einen authentifizierten Native-Messaging-Kanal, Browser-spezifische Pakete, Phishing-
Schutz, Origin-Matching, gesonderte Releases und einen eigenen Security-Review. Vorher sind Konzept,
Threat Model, Prototyp und klare Entscheidung des Produktverantwortlichen nötig.

### 13.2 Windows-Hello-/Passkey-Provider

Die No-Go-Kriterien aus `docs/passkey-research.md` bleiben verbindlich. Produktive Arbeit beginnt
erst mit signierter nativer Komponente, geklärter Recovery/Portabilität und Hardware-/Browser-Matrix.

### 13.3 Cloud-Sync, Teams und Teilen

Diese Funktionen widersprechen der aktuellen Offline-/Einbenutzer-Abgrenzung und würden Konto,
Konfliktauflösung, Geräteschlüssel, Serverbetrieb, Missbrauchsschutz und Datenschutzprozesse
erfordern. Sie benötigen ein separates Produktkonzept und werden hier nicht implementiert.

### 13.4 Globale Auto-Type-Hotkeys

Globale Hotkeys und simulierte Tastatureingaben erhöhen das Risiko, Geheimnisse in das falsche
Fenster zu schreiben. Ein späterer Prototyp müsste Zielfensterbindung, Abbruch, Zwischenablagefreiheit,
Sperrzustand und Windows-Berechtigungen untersuchen.

## 12. Technische Umsetzungsreihenfolge pro Welle

Für jede Welle gilt:

1. aktuellen Quellstand, Tests, ADRs und Persistenzpfade vollständig prüfen;
2. Datenmodell/Schema und notwendige Migration zuerst entwerfen;
3. Main-Prozess-Service mit kleinen, testbaren Operationen implementieren;
4. IPC-Konstante, Zod-Schema, Handler, Preload-API und Mock-Coverage gemeinsam ergänzen;
5. Renderer-State im passenden Workspace-Elternteil halten und vorhandene UI-Bausteine nutzen;
6. Fehler-, Abbruch-, Sperr- und Rollbackpfade testen;
7. teure Berechnungen revisionsbasiert cachen und beim Sperren invalidieren;
8. Dokumentation und Abnahmematrix aktualisieren;
9. `corepack pnpm verify` ausführen;
10. betroffene E2E-, Build- und Security-Prüfungen ausführen und nicht ausführbare externe Gates
    ehrlich dokumentieren.

## 13. Definition of Done für die Gesamterweiterung

Welle 7–12 gelten erst als abgeschlossen, wenn:

- alle Anforderungen entweder umgesetzt oder mit konkreter Begründung als bewusste Abweichung im
  Dokument markiert sind;
- keine P0/P1-Fehler und keine kritischen, hohen oder mittleren Security-Befunde offen sind;
- alte V1-Profile verlustfrei migrieren und ein unterbrochener Migrationslauf sauber zurückrollt;
- Sperren alle neuen Caches, Aufgaben und geheimen UI-Zustände beendet;
- Batch-, Merge-, Cross-Vault- und Restore-Operationen atomar sind;
- `corepack pnpm verify` grün ist;
- relevante Electron-E2E-, Paket-, Fuse-, Lizenz- und Artifact-Scans grün sind;
- README, Acceptance, Datenmigrationen, Security-Review und neue ADRs den realen Stand abbilden;
- offene Hardware-/Windows-/Signaturprüfungen ausdrücklich als externe Gates benannt sind;
- Welle 13 ohne separate Freigabe unberührt bleibt.

## 14. Empfohlener Zuschnitt für Releases

- **1.1:** Welle 7 – Mehrfachauswahl, Ansichten, Tags und Tastaturbedienung
- **1.2:** Welle 8 – Dubletten, Merge, Rotation und Datenqualität
- **1.3:** Welle 9 – Sicherheitszentrale, Recovery-Test und Integritätsprüfung
- **1.4:** Welle 10 – Backup-Gesundheit, Restore-Probelauf und Transfer
- **1.5:** Welle 11 – Tray, Erinnerungen, Fokusmodus und Barrierefreiheit
- **2.0:** Welle 12 – Format V2, große Tresore und vollständige Qualitätsgates

Diese Aufteilung ist eine technische Reihenfolge, kein Zwang zu öffentlichen Zwischenreleases. Eine
einzige Implementierungssitzung soll trotzdem nach jeder Welle einen grünen, lauffähigen Zustand
herstellen, bevor sie weiterarbeitet.

## 15. Nicht-Ziele dieser Roadmap

- keine Cloud und kein Konto;
- keine Telemetrie oder Crash-Uploads;
- keine Online-Datenleckprüfung;
- keine alte Passwort-/Feldwerthistorie;
- keine Browser-Erweiterung oder Auto-Type ohne eigene Freigabe;
- kein produktiver Passkey-Provider;
- keine automatische Online-Aktualisierung;
- keine unverschlüsselten Such-, Icon-, Bericht- oder Metadaten-Caches;
- keine kosmetische Komplettneugestaltung zulasten der bestehenden Informationsarchitektur.
