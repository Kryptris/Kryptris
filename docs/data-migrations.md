# Datenmigrationen und Format-Baseline

Stand: 15. Juli 2026

## Verbindliche Baseline

Vaulta 1.0 beginnt mit Formatversion 1. Es existiert weder im Konzept noch in einer ausgelieferten
Anwendung eine semantisch definierte Formatversion 0. Deshalb enthält der Produktcode bewusst keine
vermutende oder verlustbehaftete `v0 → v1`-Konvertierung.

| Persistenter Bereich           | Aktuelle Version | Durchsetzender Parser             |
| ------------------------------ | ---------------- | --------------------------------- |
| `profile.json`                 | 1                | `parseStoredProfileHeader`        |
| äußerer `.vaulta`-Container    | 1                | `EncryptedContainerCodec`         |
| entschlüsselter Tresor-Payload | 1                | `parseVaultDocument`              |
| entschlüsseltes Audit-Dokument | 1                | `parseAuditDocument`              |
| `.vatt`-Header und -Footer     | 1                | Attachment-Header-/Footer-Prüfung |
| natives `.vaulta-backup`       | 1                | ausschließlich `BackupService`    |

Die Migrationsinfrastruktur verändert native Backups nicht. Der Backup-Parser prüft deren eigene
Version und Integrität beim Inspect/Restore weiterhin fail-closed.

## Start- und Migrationsreihenfolge

1. Noch vor dem ersten Profil- oder Root-Zugriff stellt `BackupService.recoverInterruptedRestore()`
   einen eindeutig bestimmbaren, unterbrochenen Restore-Zustand fertig oder zurück.
2. `PersistentMigrationService.inspect()` liest nur die technischen Versionsheader der Live-Daten.
   Eine unbekannte Zukunftsversion oder ein älteres Format ohne lückenlosen Pfad wird ohne Änderung
   mit `UNSUPPORTED_FORMAT` abgelehnt.
3. Erst nach vollständiger Authentifizierung darf `PersistentMigrationService.migrate()` eine
   registrierte Vorwärtskette vorbereiten.
4. Alle Transformationen werden zunächst im Speicher erzeugt und als aktuelle Zielversion validiert.
5. Vor dem ersten persistenten Write entsteht unter `migration-backups/` ein vollständiger
   bytegenauer Snapshot aller erkannten Live-Artefakte.
6. Vor dem ersten Austausch schreibt Vaulta unter `.vaulta-migration-transaction/` für jede
   betroffene Datei eine bytegenaue, fsyncte Rollback-Sidecar und danach ein dauerhaftes Journal.
7. Erst nachdem Snapshot, Rollback-Sidecars, Quellzustand und Journal verifiziert sind, werden die
   migrierten Dateien über den transaktionalen `AtomicFileWriter` ersetzt. Ein terminaler Marker
   wird erst nach der Hashprüfung aller installierten Ziele geschrieben.

Tresor-, Audit- und Attachment-Dateien bleiben im Snapshot und in den Rollback-Sidecars exakt in
ihrem bereits verschlüsselten On-Disk-Format. `profile.json` enthält ausschließlich technische
Header und bereits verschlüsselte geschützte Metadaten. Das authentifiziert verschlüsselte
Snapshot-Manifest enthält die vollständige Sicherungszuordnung. Für die lokale Crash-Recovery stehen
technische relative Pfade, Größen und SHA-256-Werte zusätzlich im kurzlebigen Journal; entschlüsselte
Feldwerte oder Schlüssel werden dort nie abgelegt. Ein unvollständiger Snapshot gibt keinen Write
frei.

## Regeln für eine zukünftige Migration

Eine neue Migration muss:

- genau eine Version vorwärts führen, beispielsweise `1 → 2`;
- alle fachlichen Felder erhalten oder eine ausdrücklich beschlossene Semantik dokumentieren;
- wiederholbar sein: bereits aktuelle Dateien bleiben byte- und schreibseitig unangetastet;
- ihre Zielversion selbst setzen und mit dem echten Zielparser validierbar sein;
- als `ForwardMigrationStep` am zuständigen persistenten Adapter registriert werden;
- mindestens je eine Quell- und Ziel-Fixture sowie Tests für Datenvollständigkeit, Wiederholung,
  Snapshot-vor-Write und manipulierte Eingaben enthalten;
- die alte Version noch so weit lesbar halten, dass Vaulta authentifizieren und den geschützten
  Snapshot erzeugen kann.

Versionssprünge, Rückwärtsmigrationen und unbekannte Zukunftsversionen sind konstruktiv gesperrt.
Fehlt nach einem Absturz der terminale Commit-Marker, stellt der nächste Start sämtliche betroffenen
Dateien anhand des vor dem ersten Write dauerhaft installierten Journals bytegenau aus den
Rollback-Sidecars wieder her. Eine teilweise Migration wird niemals anhand einzelner Versionswerte
fortgesetzt. Bei einem terminal markierten Commit oder Rollback werden alle Zielhashes erneut
geprüft, bevor das Transaktionsverzeichnis aufgeräumt wird. Der unveränderte, verschlüsselte
Vorab-Snapshot bleibt für eine kontrollierte Wiederherstellung erhalten.

## Aktuelle Testfixtures

`tests/fixtures/migrations/` dokumentiert die v1-Headerbaseline für Profil, Container und Anhänge.
Die Dispatcher-Fixtures sind ausdrücklich ein Testformat und keine behauptete historische
Vaulta-Version. Sie prüfen die Infrastruktur für eine lückenlose mehrstufige Vorwärtskette, ohne eine
nicht spezifizierte Produktmigration zu erfinden.
