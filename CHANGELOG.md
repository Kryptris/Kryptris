# Changelog

Alle wesentlichen Änderungen an Kryptris werden in dieser Datei dokumentiert.

Das Format folgt [Keep a Changelog](https://keepachangelog.com/de/1.1.0/). Eine öffentliche
Versionierung wird erst mit einem ausdrücklich freigegebenen Release vorgenommen.

## [Unreleased]

### Hinzugefügt

- Mehrfachauswahl mit atomaren Batch-, Cross-Vault- und Attachment-Aktionen.
- Verschlüsselte gespeicherte Ansichten, intelligente Ansichten, zentrale Tagverwaltung,
  Befehlspalette und lokale Tastaturhilfe.
- Lokale Dubletten-Zentrale mit begründeten Kandidaten, feldweisem Merge und authentifizierter
  Attachment-Revalidierung.
- Lebenszyklusmetadaten für Rotation, lokale 2FA-Klassifizierung und Ablaufhinweise samt
  Startübersicht.
- Abbrechbare, revisionsgebundene Datenqualitätsprüfung mit bestätigten Einmal-Vorschautoken.
- Optionale Papierkorbfristen, standardmäßig „nie“, mit sichtbarer Backup-Bestätigung.
- VaultDocument-Format V2 mit Vorwärtsmigration, V1-/V2-Fixtures, Snapshot, Rollback und
  Future-Version-Ablehnung.
- Crash-fester Mehrdatei-Koordinator für fachliche Transaktionen.
- Sicherheitszentrale mit acht lokalen Kacheln für Zugangsdaten, Datenqualität, Faktoren, Backups,
  Recovery, KDF, Integrität und die optionale Offline-Datenleckliste.
- Recovery-Bereitschaftstest mit gedrosselten Fehlversuchen, ohne Speicherung von Key-Material.
- Abbrechbare vollständige Integritätsprüfung mit redigiertem Main-only-Exporttoken.
- Optionaler, strikt strukturvalidierter Offline-Datenleckindex mit lokalem Passwortvergleich.
- Backup-Gesundheitscenter mit pfadfreiem Status, Generationenübersicht, Laufwerkswarnung und
  Zeitstempel für erfolgreiche semantische Restore-Probeläufe.
- Isolierter, abbrechbarer Restore-Probelauf mit kontrolliert bereinigtem Staging-Bereich.
- Portables `.kryptris-vault`-Paket mit eigenem Exportpasswort, Vorschau, Namenskonfliktprüfung,
  optionalen Anhängen und atomarem Zielimport.
- Inhaltsbasierte Dashlane-, NordPass- und RoboForm-Importer, wiederverwendbare CSV-Feldzuordnungen,
  Importzusammenfassung und sicherer Drag-and-drop-Import.
- Optionale Windows-Integration mit lokalem Sperrstatus im Tray, reversiblen Autostart-Einstellungen
  und Sperren vor dem Ausblenden beim Schließen.
- Optionale, allgemeine lokale Erinnerungen für Rotation, Ablaufdaten und Backup-Prüfungen sowie
  Fokusmodus, lokale Hilfe und überspringbares Onboarding.
- Virtualisierte Eintragsliste, 200-ms-Suchentprellung und Schutz vor veralteten Listenantworten für
  große Tresore.
- Reproduzierbarer Main-Prozess-Leistungsbenchmark mit ausschließlich synthetischen 1.000-, 5.000-
  und 10.000-Eintragsdaten samt maschinenlesbarem Rohdatensatz.
- Controller-Integrationstest für die echte V1→V2-Migration mehrerer Tresore mit Anhang, TOTP,
  Idempotenz, Future-Version-Ablehnung und unterbrochenem Commit.

### Geändert

- Import und Datenpflege verwenden dieselbe normalisierte, Main-only-Dublettenerkennung.
- Schreibende Batch-, Cross-Vault-, Purge-, Merge-, Datenqualitäts- und Retention-Flows committen
  den redigierten Auditdatensatz atomar mit dem fachlichen Zustand.
- Integritätsstatus und Offline-Datenleckmanifest werden mit ihrem Audit atomar committed; der
  Datenleckindex wird gemeinsam installiert oder entfernt.
- Enpass wird absichtlich nur über den generischen CSV-Mapper verarbeitet, weil kein belastbar
  dokumentiertes und anonymisiert testbares natives Exportlayout vorliegt.
- Der Release-Artefaktscanner prüft zusätzlich Laufzeit-Caches, Berichte, Restore-/Import-Staging,
  Transaktionsartefakte und verschachtelte ZIP-/ASAR-Inhalte.

### Sicherheit

- Laufende lokale Auswertungen und revisionsgebundene Caches werden beim Sperren verworfen.
- Weder Migrationsjournal noch Rollback-Sidecars enthalten entschlüsselte Fachwerte.
- Automatische Korrekturen sind ohne gültige Vorschau, aktuelle Revision und einmalig verwendbares
  Main-only-Token nicht ausführbar.
- Integritätscache, laufende Scans, Recovery-Pending-State und Datenleckbefunde werden beim Sperren
  vollständig invalidiert. Redigierte Berichte können weder direkt noch über Junction-/Symlink-Aliase
  in den Kryptris-Datenordner schreiben.
- Backup-Probeläufe prüfen ihre temporäre Hierarchie gegen Link-/Pfadwechsel, führen nach dem
  Entschlüsseln nur schreibfreie Validierung aus und bereinigen bei Abbruch oder Fehler.
- Paketimport remappt IDs und committet Registry, Vault, Anhänge und Audit zusammen; Paket- und
  Staging-Buffer werden auf allen Exit-Pfaden überschrieben.
- Paketimporte behandeln den bestätigten Mehrdatei-Commit auch bei einem unmittelbar folgenden Lock
  oder einer nichtkritischen Nacharbeit als autoritativ und veröffentlichen dann keine neuen
  entschlüsselten Caches.
- Paket-Anhangs-Staging prüft seine controller-eigene Verzeichnis- und Dateiidentität vor Schreiben,
  Transaktionslesen und nichtrekursiver Bereinigung; Symlink-/Junction-/TOCTOU-Wechsel werden
  geschlossen abgewiesen.
- Drag-and-drop-Dateipfade verbleiben im Preload hinter kurzlebigen Einmal-Tokens. Importquellen
  werden im Main-Prozess descriptor-gebunden eingelesen und bei TOCTOU-Austausch verworfen.
- Tray und Benachrichtigungen zeigen ausschließlich Sperrstatus beziehungsweise allgemeine lokale
  Hinweise. Ihre Aktivierung sperrt vor dem Öffnen; Sperren invalidiert Timer und späte Ergebnisse.
- Große Listen prüfen Main-only-Autorisierung in Batches; revisionsgebundene Sicherheitsreports und
  laufende Auswertungen werden beim Sperren nicht wiederverwendbar verworfen.
- Der Artefaktscanner akzeptiert in Rollback-Sidecars nur einen exakt strukturvalidierten
  `KRYBRCH1`-Header des öffentlichen Offline-Datenleckindexes, niemals beliebigen Klartext oder
  Fachwerte.
