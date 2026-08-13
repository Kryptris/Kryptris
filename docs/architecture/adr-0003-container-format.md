# ADR 0003: Versionierte Container und atomare Writes

- Status: angenommen
- Datum: 14. Juli 2026
- Bezug: Welle 0–3, 8 und 12

## Tresorcontainer

Ein `.vaulta`-Container besteht aus einem minimalen technischen Header und einem AES-256-GCM-Payload. Der Header enthält Magic, Formatversion, Container-/Tresor-ID, HKDF-Salt, Generation, Algorithmus, Nonce und Auth-Tag. Tresorname, Typen, Titel, Tags, Ordner und Einträge stehen ausschließlich im verschlüsselten Payload. Der kanonisch serialisierte Header ohne Tag ist AAD.

Unbekannte Versionen oder Algorithmen werden abgelehnt. Vor einer Migration entsteht ein authentifiziertes Backup. Migrationen sind nur vorwärtsgerichtet.

Der äußere `.vaulta`-Container bleibt in Version 1. Die entschlüsselte, im Container liegende
`VaultDocument`-Payload ist dagegen seit Welle 8 in Version 2: Sie bündelt ausschließlich die
Lebenszyklusmetadaten eines Eintrags in einem `lifecycle`-Objekt. Der registrierte Main-Prozess-
Schritt 1 → 2 validiert zuerst mit dem V2-Parser, erstellt über die vorhandene
Snapshot-/Rollback-Infrastruktur einen Vorab-Snapshot und ersetzt alle betroffenen Tresore erst
anschließend atomar. Bereits aktuelle V2-Payloads werden nicht geschrieben; eine Version 3 oder höher
wird vor Snapshot und Write abgelehnt. Der Controller-Integrationstest deckt mehrere Tresore, einen
Anhang, einen TOTP-Faktor, unterbrochenen Commit und Klartext-Canaries in Journal/Sidecars ab.

## Anhänge

Anhänge nutzen ein binäres Chunkformat:

1. Magic/Version, technische IDs, Chunkgröße und umschlagverschlüsselter zufälliger Dateischlüssel
2. fortlaufende Chunks mit Index, Klartextlänge, frischem 96-Bit-Nonce, Ciphertext und GCM-Tag
3. authentifizierter Abschlussdatensatz mit Chunkanzahl, Gesamtgröße und SHA-256

Index, erwartete Reihenfolge, Dateigröße, letztes-Chunk-Markierung und Attachment-ID sind AAD. Fehlende, doppelte, vertauschte oder angehängte Chunks brechen die Entschlüsselung ab. Der Klartext wird direkt aus/zu Streams verarbeitet; Export schreibt zunächst eine temporäre verschlüsselte/zu verifizierende Zieldatei und benennt sie erst nach Erfolg um.

## Transaktionaler Austausch

1. neuen verschlüsselten Stand im selben Verzeichnis mit zufälligem `.tmp`-Namen schreiben
2. Datei synchronisieren
3. den vollständigen neuen Container erneut öffnen und authentifiziert prüfen
4. bestehenden Stand in `.previous` umbenennen
5. neuen Stand atomar auf den Zielnamen umbenennen
6. `.previous` erst nach erfolgreichem Austausch entfernen

Beim Start gilt ausschließlich ein vollständig prüfbarer Zielstand. Fehlt er nach einem Absturz, darf ein prüfbarer `.previous`-Stand wiederhergestellt werden; ein ungeprüfter `.tmp`-Stand wird nie automatisch übernommen. Tempdateien enthalten nur Ciphertext.

## Löschung

Gelöschte Einträge werden beim nächsten Containerstand nicht mehr geschrieben. Anhänge besitzen eigene Schlüssel und werden durch Schlüssel-/Dateientfernung kryptografisch gelöscht. Physisches Überschreiben auf SSDs wird nicht versprochen.
