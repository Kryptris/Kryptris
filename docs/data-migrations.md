# Datenmigrationen und Format-Baseline

Stand: 13. August 2026

## Verbindliche Baseline

Vaulta 1.0 beginnt mit Formatversion 1. Es existiert weder im Konzept noch in einer ausgelieferten
Anwendung eine semantisch definierte Formatversion 0. Deshalb enthält der Produktcode bewusst keine
vermutende oder verlustbehaftete `v0 → v1`-Konvertierung.

| Persistenter Bereich              | Aktuelle Version | Durchsetzender Parser                |
| --------------------------------- | ---------------- | ------------------------------------ |
| `profile.json`                    | 1                | `parseStoredProfileHeader`           |
| äußerer `.vaulta`-Container       | 1                | `EncryptedContainerCodec`            |
| entschlüsselter Tresor-Payload    | 2                | `parseVaultDocument`                 |
| entschlüsseltes Audit-Dokument    | 1                | `parseAuditDocument`                 |
| `.vatt`-Header und -Footer        | 1                | Attachment-Header-/Footer-Prüfung    |
| natives `.vaulta-backup`          | 1                | ausschließlich `BackupService`       |
| portables `.kryptris-vault`-Paket | 1                | ausschließlich `VaultPackageService` |

Die Migrationsinfrastruktur verändert native Backups oder portable Tresor-Pakete nicht. Beide
Parser prüfen ihre eigene Version und Integrität weiterhin fail-closed. Das Paketformat ist kein
Profil- oder VaultDocument-Migrationsschritt und übernimmt weder Profil- noch Tresorschlüssel.

## VaultDocument V1 → V2

VaultDocument V2 führt die Lebenszyklusmetadaten aus Welle 8 gesammelt ein. Jeder Eintrag erhält
genau ein `lifecycle`-Objekt mit den Feldern `rotationIntervalDays`, `nextRotationDate`,
`rotationExcluded`, `twoFactorStatus` und `expiryReminderDate`. Bei der Migration werden dafür die
neutralen Werte `null`, `null`, `false`, `unknown` und `null` gesetzt. Bestehende Fachwerte,
Tresormetadaten, Anhänge, Faktorinformationen und verschlüsselte Containerparameter bleiben
unverändert; alte geheime Werte werden weder erzeugt noch gespeichert.

Der eingebettete Adapter `createVaultDocumentEmbeddedMigrationAdapter()` registriert genau den
Vorwärtsschritt 1 → 2. Er entschlüsselt erst nach vollständiger Autorisierung, transformiert im
Main-Prozess, validiert mit dem echten V2-Parser und verschlüsselt wieder unter dem vorhandenen
Tresorschlüssel. Sämtliche betroffenen Tresore werden gemeinsam über die bestehende
Snapshot-/Journal-/Rollback-Infrastruktur committed. Bereits aktuelle V2-Dateien werden weder
erneut geschrieben noch erneut gesichert. Format 3 oder höher wird vor Snapshot und Write als
`UNSUPPORTED_FORMAT` abgelehnt; eine Rückwärtsmigration wird nicht angeboten.

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

## Regeln für eine weitere Migration

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

`tests/fixtures/migrations/vault-document-v1.json` und `vault-document-v2.json` dokumentieren die
fachliche Quell- und Zielstruktur der produktiven Tresor-Payload-Migration.
`tests/integration/vaulta-controller-v2-migration.test.ts` startet zusätzlich den tatsächlichen
Controller-Entsperrpfad auf zwei V1-Tresoren. Die Suite erhält einen verschlüsselten Anhang und die
öffentlichen sowie geschützten TOTP-Faktordaten, prüft den zweiten Unlock als schreibfreie
Idempotenz, lehnt eine verschlüsselte Zukunftsversion vor Snapshot und Write ab und rollt einen
zwischen zwei Vault-Ersetzungen unterbrochenen Commit beim nächsten Controller-Start bytegenau zurück.
Die für diesen Integrationstest reduzierten Argon2id-Parameter sind ausdrücklich test-only; der
Produktpfad behält seine eigenen KDF-Untergrenzen. Canary-Werte aus synthetischem Titel und Passwort
dürfen weder im Journal noch in Rollback-Sidecars erscheinen.

Die übrigen v1-Header- und Dispatcher-Fixtures bleiben ausdrücklich Testformate für Profil,
Container, Anhänge und lückenlose mehrstufige Vorwärtsketten; sie behaupten keine nicht
spezifizierte historische Produktversion.

## Generische Mehrdatei-Transaktionen ab Welle 7

Cross-Vault-Move, Cross-Vault-Copy, Batch-Purge, Dubletten-Merge, automatische Papierkorb-Leerung und
bestätigte Datenqualitätskorrekturen verwenden unabhängig von der semantischen Migrationspipeline
den in [ADR-0006](architecture/adr-0006-multi-file-transactions.md) festgelegten
Mehrdatei-Koordinator. Fachlicher Zustand und redigierter Auditdatensatz gehören dabei zum selben
Commit. Sein kurzlebiges Journal enthält nur relative Zielpfade, Aktion, Größen und SHA-256-Werte.
Rollback-Sidecars sind bytegenaue Kopien bereits verschlüsselter Live-Dateien.
Verschlüsselte Staging-Anhänge werden gestreamt und ihre Quellidentität, Größe und Prüfsumme vor und
während des Commits erneut geprüft; der absolute Staging-Pfad wird nicht journalisiert.

Beim Start wird ein fehlender terminaler Marker als Rollback behandelt. Ein vorhandener Commit- oder
Rollback-Marker wird gegen Journal und installierte Dateigenerationen geprüft, bevor technische
Artefakte entfernt werden. Erst danach laufen Restore- und Format-Migrations-Recovery. Diese
Infrastruktur ändert keine Formatversion und ersetzt nicht den Snapshot-vor-Write-Pfad einer
fachlichen V1→V2-Migration.

## Geschützte Zusatzmetadaten ab Welle 9

Welle 9 ergänzt keine weitere VaultDocument- oder Containerformatversion. Die ausschließlich
technischen Zustände `recovery-readiness`, `integrity-status` und das Manifest
`offline-breach-list` liegen als schema-validierte, AES-GCM-geschützte Profilmetadaten in
`profile.json`. Sie werden durch die bestehenden Profil- und Audit-Writer beziehungsweise beim
Datenleckimport über dieselbe Mehrdatei-Transaktion aktualisiert. Die Werte enthalten weder
Recovery-Key-Teile, Passwortwerte noch Passwort-Hashes; gespeichert werden nur Zeitpunkte,
Ergebniszustände und technische Größen-/Prüfsummenangaben.

Der optionale Datenleckindex `security/offline-breach-v1.kbi` ist ein separates binäres,
versioniertes Hilfsartefakt. Er wird vor dem Profilmanifest atomar validiert und gemeinsam mit
Profilmetadaten und redigiertem Audit committed. Der Index gehört bewusst nicht zu nativen Backups,
Snapshots oder Restore-Zielen: Nach einem Restore ist die Liste daher nicht konfiguriert bzw. muss
aus der ursprünglichen lokalen Quelle erneut importiert werden. Unterbrochene Transaktionen rollen
Index, Manifest und Audit gemeinsam zurück; Journal und Sidecars enthalten weiterhin nur
verschlüsselte Originalbytes und technische Prüfsummen.

## Geschützte Zusatzmetadaten und Transferformat ab Welle 10

Welle 10 führt keine weitere VaultDocument-, Container- oder native Backupformatversion ein. Der
redigierte Sicherungsstatus `backup-health-v1` liegt als schema-validierte, AES-GCM-geschützte
Profilmetadaten vor. Er enthält ausschließlich Zeitpunkte sowie einen technischen Fehlercode; weder
Sicherungsordner, Dateinamen noch ursprüngliche Fehlermeldungen werden gespeichert. Der
Restore-Probelauf verwendet einen kontrolliert bereinigten, nur temporären Staging-Bereich und
schreibt keinen Migrations- oder Klartextzustand in das Profil.

Gespeicherte CSV-Feldzuordnungen liegen als versioniertes Snapshot `import-mapping-profiles-v1` in
demselben geschützten Metadatenpfad. Ein Profil enthält nur technische ID, Anzeigename, Zeitstempel
und Spaltenselektoren. Importierte Feldwerte, Vorschauen und Quellpfade werden nie darin
gespeichert. Änderungen werden zusammen mit einem redigierten Auditdatensatz über den bestehenden
Mehrdatei-Commit aktualisiert; ein fehlgeschlagener Commit stellt den vorherigen Snapshot wieder her.

Das portable Format `kryptris-vault-package` Version 1 (`.kryptris-vault`) ist in
[ADR-0007](architecture/adr-0007-portable-vault-package.md) spezifiziert. Header, versioniertes
Manifest, Vault-Dokument und optionale Anhänge sind durch den separaten Paket-Schlüssel und
AES-256-GCM-Records authentifiziert; der Paket-Schlüssel wird ausschließlich mit dem separaten
Argon2id-Exportpasswort geschützt. Ein Import remappt technische IDs, verschlüsselt Anhänge unter
einem frischen Ziel-Tresorschlüssel und committet Profil-Registry, Vault, Anhänge und Audit in einer
Mehrdatei-Transaktion. Journal und Staging enthalten keine fachlichen Klartextwerte.
