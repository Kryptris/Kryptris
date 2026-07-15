# ADR 0002: Schlüsselhierarchie

- Status: angenommen
- Datum: 14. Juli 2026
- Bezug: Welle 0, 3 und 5

## Entscheidung

Vaulta nutzt eine Umschlagverschlüsselung. Beim Setup entstehen zufällig:

- Profil-Gate-Key: 256 Bit
- Profil-Hauptschlüssel: 256 Bit
- Recovery-Schlüssel: 256 Bit plus Prüfsumme
- pro Tresor ein zufälliges HKDF-Salt
- pro Anhang ein zufälliger Dateischlüssel

Das Master-Passwort wird mit Argon2id und einem 128-Bit-Salt verarbeitet. Produktparameter beginnen bei 262.144 KiB, werden auf ungefähr eine Sekunde kalibriert und samt Formatversion gespeichert. Der abgeleitete Schlüssel verschlüsselt nur den stabilen Profil-Gate-Key. Der Profil-Gate-Key schützt den Profil-Hauptschlüssel. Ein Passwortwechsel muss daher weder Tresore noch PRF-Wraps neu verschlüsseln.

## Ableitungen

HKDF-SHA-256 erzeugt domänenseparierte Schlüssel:

```text
Profil-Hauptschlüssel
  +-- "vaulta/profile-metadata/v1" -> geschützte Profilmetadaten
  +-- "vaulta/audit/v1"            -> Aktivitätsprotokoll
  +-- "vaulta/search/v1"           -> flüchtiger Suchindexkontext
  +-- "vaulta/vault/v1" + Salt     -> jeweiliger Tresorschlüssel

Tresorschlüssel
  +-- "vaulta/attachment-wrap/v1"  -> Umschlag der Dateischlüssel
```

Info-Strings, Profil-/Tresor-ID und Formatversion werden als AAD gebunden.

## Zusätzliche Zugänge

- Recovery: Ein separater HKDF-Schlüssel aus 256 zufälligen Bits schützt eine zweite Kopie des Profil-Gate-/Hauptschlüsselzugangs. Der Klartext wird nicht gespeichert.
- FIDO2 PRF: `HKDF(Profil-Gate-Key, WebAuthn-PRF-Ergebnis, keyId)` bildet einen echten zusätzlichen Wrap. Sobald mindestens ein PRF-Schlüssel verpflichtend ist, existiert kein Master-only-Wrap des Profil-Hauptschlüssels.
- FIDO2 ohne PRF: Nur verifizierte Anwesenheit nach Master-Unlock; sichtbar als schwächer markiert.
- TOTP: Seed liegt in geschützten Profilmetadaten. Es ist eine lokale Sperre und kein gleichwertiger kryptografischer Faktor.

Mindestens zwei PRF-fähige Sicherheitsschlüssel werden empfohlen. Recovery ist der einzige vorgesehene Weg, wenn alle verpflichtenden Schlüssel verloren sind.

## Speicherlebensdauer

Entschlüsselte Schlüssel liegen nur im Main-Prozess in überschreibbaren `Buffer`-Objekten. `lock()`, Prozessende, Windows-Sitzungssperre und Standby überschreiben sie und verwerfen abgeleitete Zustände. Ein Garbage-Collector kann frühere interne Kopien nicht absolut ausschließen; APIs vermeiden unnötige Konvertierung in Strings.
