# ADR 0005: Lokale WebAuthn-Origin

- Status: angenommen mit dokumentiertem Restrisiko
- Datum: 14. Juli 2026
- Bezug: Welle 5

## Problem

Chromium gestattet WebAuthn nicht für `file:` und behandelt Electron-Custom-Schemes trotz `secure`-Markierung nicht zuverlässig als zulässige Relying-Party-Origin. Vaulta benötigt eine vollständig offline nutzbare Windows-FIDO2-Abfrage ohne Cloud oder langlebigen Hintergrunddienst.

## Entscheidung

Der Main-Prozess startet für die Lebensdauer des Fensters einen minimalen statischen HTTP-Server auf
einem zufälligen Port, gebunden ausschließlich an die IPv4- und IPv6-Loopback-Adressen `127.0.0.1`
und `::1`. Das Fenster lädt `http://localhost:<port>`. Dadurch bleibt die Origin auf allen
Windows-Resolverkonfigurationen erreichbar, ohne den Server an eine externe Schnittstelle zu binden.
Der Server:

- akzeptiert nur `GET`/`HEAD` und einen exakten `localhost:<port>`-Host,
- liefert nur gebündelte Rendererdateien aus einem festen Root aus,
- besitzt keine Daten-, Upload-, IPC- oder Diagnose-Endpunkte,
- lehnt Traversal, Dotfiles und unbekannte Methoden ab,
- sendet CSP, COOP, CORP, Permissions Policy, `nosniff`, `DENY` und `no-store`,
- wird beim App-Ende geschlossen.

Loopback funktioniert ohne Internetadapter oder DNS-Dienst und überträgt keine Daten außerhalb des Rechners. `localhost` ist die WebAuthn-RP-ID. Credentials sind nicht auffindbar (`residentKey: discouraged`); ihre IDs und PRF-Salts liegen im authentifizierten technischen Profilheader. Challenges sind zufällig, kurzlebig und einmalig. Assertions werden im Main-Prozess samt Origin, RP-ID, Signatur und Counter verifiziert.

## PRF und Fallback

Wenn der Authenticator die PRF-Erweiterung liefert, geht das 32-Byte-Ergebnis in einen zusätzlichen kryptografischen Key-Wrap ein. Fehlt PRF, bleibt nur eine verifizierte Anwesenheitsprüfung nach Master-Unlock; die UI kennzeichnet sie ausdrücklich als schwächer. Sobald ein PRF-Wrap verpflichtend ist, kann ein Presence-only-Key ihn nicht umgehen.

## Restrisiko

WebAuthn bindet Credentials an `localhost`, nicht an einen Port. Ein bösartiger lokaler Prozess könnte ebenfalls eine `localhost`-Origin betreiben. Er kennt bei nicht auffindbaren Credentials jedoch weder Credential-ID noch den authentifizierten PRF-Salt aus einem gesperrten Profil; jede Benutzung erfordert außerdem Benutzerinteraktion. Dieses Restrisiko liegt innerhalb der offen benannten Grenze für bereits aktive lokale Schadsoftware. Eine spätere native Bindung an die Windows-WebAuthn-API kann die Loopback-Origin ersetzen, benötigt aber eine gepflegte, reproduzierbar gebaute Native-Komponente.
