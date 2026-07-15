# ADR 0001: Bedrohungsmodell

- Status: angenommen
- Datum: 14. Juli 2026
- Bezug: Welle 0

## Entscheidung

Vaulta priorisiert den Schutz ruhender lokaler Daten. Ein Angreifer darf `profile.json`, Tresorcontainer, Anhänge, Backups und temporäre Schreibstände vollständig kopieren und verändern können, ohne Inhalte zu lesen oder unbemerkt zu manipulieren. Das Master-Passwort oder der Wiederherstellungsschlüssel bleibt für eine erfolgreiche Entschlüsselung zwingend.

## Im Modell

- Diebstahl/Kopie einer ausgeschalteten oder gesperrten Festplatte
- anderer lokaler Benutzer ohne Kontrolle über den entsperrten Vaulta-Prozess
- Offline-Brute-Force gegen kopierte Dateien
- Änderung, Kürzung, Vertauschung oder Wiederholung von Container-/Anhangsdaten
- Absturz oder Stromausfall während eines Schreibvorgangs
- kompromittierter Renderer durch einen UI-/Markdown-/Importfehler
- unbeabsichtigte Offenlegung über Logs, Dateinamen, Zwischenablage oder Tempdateien
- Verlust von Master-Passwort, TOTP-Gerät oder Sicherheitsschlüssel

## Außerhalb des garantierbaren Modells

- Schadsoftware mit Zugriff auf den bereits entsperrten Benutzerprozess
- Administrator-/Kernel-Kompromittierung, DLL-Injektion oder manipuliertes Betriebssystem
- Keylogger, Kamera, physisches Abfilmen oder kompromittierte Zwischenablage
- forensisch garantiertes Überschreiben freier SSD-Blöcke
- Verfügbarkeit bei Verlust sowohl des Master- als auch des Wiederherstellungsschlüssels

Vaulta reduziert diese Risiken durch kurze Klartextlebensdauer, Sperren bei Sitzungswechsel/Standby, Content Protection, Prozessisolation und kryptografisches Löschen. Die UI benennt die Grenzen sichtbar.

## Sicherheitsinvarianten

1. Kein fachlicher Inhalt liegt absichtlich unverschlüsselt auf dem Datenträger.
2. Jeder verschlüsselte Gegenstand/Chunk erhält einen frischen Nonce; Nonces werden nie mit demselben Schlüssel wiederverwendet.
3. Headerwerte, Reihenfolge und Chunkabschluss sind authentifiziert.
4. Renderer und Importdaten bestimmen niemals ungeprüfte Dateipfade.
5. Kopieraktionen geben den Geheimwert nicht als IPC-Antwort zurück.
6. Sperren nullt aktive `Buffer`, verwirft Suchindex, Pending-Faktoren und entschlüsselte Dokumente.
7. Fehlermeldungen und Auditereignisse enthalten IDs/Aktionstypen, aber keine Feldwerte.
8. Recovery entfernt alle Zusatzfaktoren und erzwingt ein neues Master-Passwort.

## Restrisiko

JavaScript-Strings sind unveränderlich und können nicht zuverlässig überschrieben werden. Geheimnisse werden deshalb bevorzugt als `Buffer` verarbeitet und nicht länger gehalten als erforderlich; eine absolute Speicherbereinigung kann Electron/Node nicht garantieren.
