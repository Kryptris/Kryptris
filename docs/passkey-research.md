# Welle 6: Untersuchung einer lokalen Passkey-Integration

Stand: 14. Juli 2026

## Ergebnis

Vaulta speichert in Version 1 keine Passkeys. Diese Entscheidung bleibt richtig: Eine bloße Ablage privater Passkey-Daten wäre ohne Provider-Integration unbrauchbar und würde das Sicherheitsmodell unnötig erweitern.

## Bewertete Wege

### Windows WebAuthn Plugin Authenticator

Windows 11 stellt APIs bereit, mit denen ein Drittanbieter als nativer Passkey-Provider registriert werden kann. Das ist der fachlich passendste Zukunftsweg: Browser und Apps würden Vaulta über den Windows-WebAuthn-Stack auswählen. Er benötigt jedoch eine signierte native Komponente, Windows-spezifische Registrierung/Lifecycle-Behandlung, sichere Freigabe aus dem entsperrten Main-Prozess und einen separaten Security-Review. Für einen zunächst unsignierten V1-Build ist das nicht vertretbar.

### Browser-Erweiterung

Eine Erweiterung könnte WebAuthn-/Credential-Flows vermitteln, widerspricht aber der V1-Abgrenzung, vergrößert Update-/Supply-Chain-Fläche und benötigt einen authentifizierten Native-Messaging-Kanal. Sie wird nicht eingeführt.

### Export/Import portabler Passkeys

Standardisierte, sicher portable Passkey-Formate und Provider-Unterstützung sind nicht ausreichend interoperabel, um einen belastbaren lokalen Workflow zu versprechen. Private Schlüssel dürfen nicht als gewöhnliche benutzerdefinierte Felder behandelt werden.

## Architekturvorbereitung

- `EntryType` und Containerformat sind versioniert und können später einen Passkey-Deskriptor aufnehmen.
- Kryptografische Objekt-/Attachment-Schlüssel erlauben getrennte Providerdaten.
- Die IPC-Allowlist kann um wenige Provideroperationen erweitert werden, ohne Node-Rechte im Renderer.
- Der Forschungszweig muss zuerst ein Windows-Native-POC, Hardware-/Browser-Matrix, Signaturbudget und Recovery-/Portabilitätskonzept liefern.

## Go/No-Go-Kriterien

Eine produktive Umsetzung beginnt erst, wenn:

1. ein gepflegter Windows-Providerpfad ohne Admin-Dauerrecht verfügbar ist,
2. Code Signing und sichere Updates finanziert sind,
3. Credential-Backup/Recovery ohne Hintertür fachlich gelöst ist,
4. Chrome, Edge, Firefox sowie Windows Hello/roaming Keys getestet sind,
5. ein unabhängiger Review keine kritischen Befunde enthält.

Bis dahin bleibt Vaulta Passwort-/TOTP-/SSH-Manager und optionaler FIDO2-Entsperr-Client, aber kein Passkey-Provider.
