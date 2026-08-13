# ADR-0007: Portables verschlüsseltes Tresor-Paket

- Status: akzeptiert
- Datum: 9. August 2026
- Bezug: Welle 10

## Kontext

Ein natives Kryptris-Backup enthält das vollständige Profil samt Zugangskonfiguration und ist für
eine vollständige Wiederherstellung vorgesehen. Für den kontrollierten Transfer eines einzelnen
Tresors wird ein separates Paket benötigt. Dieses darf weder den Profil-Hauptschlüssel noch den
aktiven Tresorschlüssel oder die Schlüsselumschläge des Quellsystems wiederverwenden.

## Entscheidung

Ein Paket ist ein versionierter, ausschließlich verschlüsselter Main-Process-Container mit der
Endung `.kryptris-vault`. Es enthält genau einen exportierten Tresor, optional dessen Anhänge und
ein verschlüsseltes Manifest. Der unverschlüsselte technische Header beschränkt sich auf Magic,
Formatversion, KDF-Parameter, Salt, Nonce, Algorithmuskennung und einen authentifizierten
Schlüsselumschlag. Tresorname, IDs, Eintrags- oder Anhangszahlen, Dateinamen und Hashes befinden
sich nie im Header.

Für jeden Export erzeugt Kryptris einen neuen zufälligen 256-Bit-Paketschlüssel. Ein separates
Exportpasswort wird mit Argon2id und einem frischen 128-Bit-Salt abgeleitet; die gespeicherten
Parameter erfüllen mindestens die Produktuntergrenzen. Der abgeleitete Schlüssel umschließt den
Paketschlüssel mit AES-256-GCM und paket- sowie versionsgebundener AAD. Der Paketschlüssel
verschlüsselt die serialisierten Tresordaten, Anhänge und das Manifest ebenfalls mit AES-256-GCM
und domänenseparierter AAD.

Beim Import wird zuerst das Paket vollständig authentifiziert und in einem Main-only-Staging
validiert. Das Manifest bindet Formatversion, jedes Payload-Element, Größe und SHA-256. Erst nach
vollständiger Prüfung, Namenskonfliktentscheidung und neuer lokaler Schlüsselableitung wird ein
neuer Tresor mit neuer lokaler ID, neuem zufälligen Seed und neu verschlüsselten Anhängen in einer
Mehrdatei-Transaktion installiert. Die Quell-ID, der Quell-Tresorschlüssel und alle Quell-
Attachment-Wraps werden nie übernommen. Abbruch, Authentifizierungsfehler und Schreibfehler
löschen Staging-Daten kontrolliert und hinterlassen keinen sichtbaren Teilzustand.

Für einen kurzen historischen Zwischenstand vor vollständiger Welle 8 gilt nach dieser
Authentifizierung eine eng begrenzte Kompatibilitätsregel: Ein als V2 markierter Payload darf nur
dann im Speicher ergänzt werden, wenn eine strikte V1-Projektion aller übrigen Felder gültig ist
und mindestens ein Eintrag den gesamten `lifecycle`-Block vermisst. Nur diese fehlenden neutralen
Werte werden ergänzt; vorhandene oder partielle Lifecycle-Werte bleiben unverändert und müssen die
strikte V2-Validierung bestehen. Das Paket auf Datenträger wird dabei nie geschrieben oder
normalisiert.

Die Vorschau entschlüsselt keine Daten im Renderer. Sie erhält ausschließlich redigierte,
authentifizierte Metadaten wie Anzahl der Einträge und Anhänge sowie einen Namenskonfliktstatus.
Passwörter, Inhalte, Dateinamen, technische Quellpfade und Schlüssel verbleiben im Main-Prozess.

## Konsequenzen

- Pakete sind mit einem eigenen Passwort transportierbar, aber kein Ersatz für vollständige
  Profilbackups oder Recovery-Zugang.
- Ein vergessenes Exportpasswort kann nicht über den Quellprofilzugang wiederhergestellt werden.
- Der Import kostet eine vollständige Neuverschlüsselung; das verhindert Schlüsselkopplung zwischen
  Systemen und stellt einen atomaren Zielzustand sicher.
- Die Paketversion wird strikt geprüft. Zukunftsversionen und unbekannte Algorithmen werden vor
  jeder Entschlüsselung abgelehnt.

## Verworfene Alternativen

- **Direktes Kopieren eines `.vaulta`-Containers:** würde Quell-ID und Schlüsselbeziehung in das
  Ziel übernehmen und kann keinen eigenständigen Exportpasswortzugang herstellen.
- **Paket mit Profil-Hauptschlüssel verschlüsseln:** bindet den Transfer an das Quellprofil und
  verletzt die Trennung von Backup und Portabilität.
- **Klartext-ZIP mit Passwortschutz:** lässt sich nicht mit dem Containerbedrohungsmodell und der
  Restdatenregel vereinbaren.
