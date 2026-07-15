# Manueller Sicherheitsreview

Stand: 15. Juli 2026  
Scope: Architektur, Quellcode und lokal erzeugter Release-Kandidat von Vaulta 1.0

## Review-Checkliste

- [x] Main-/Preload-/Renderer-Trennung und Senderprüfung vollständig inspiziert
- [x] keine generische IPC-, Datei-, Shell- oder Netzwerkbrücke im Preload
- [x] `contextIsolation`, Sandbox, CSP, Navigation, Popups und Berechtigungen restriktiv
- [x] KDF-/HKDF-/AES-GCM-Verwendung und Domänentrennung geprüft
- [x] Nonce-Eindeutigkeit, AAD und Container-/Chunk-Manipulationstests geprüft
- [x] Schlüssel-/Pending-State wird bei allen Sperrpfaden verworfen
- [x] Recovery erzwingt ein neues Master-Passwort und entfernt Zusatzfaktoren
- [x] TOTP-/Presence-Modus wird nicht als zusätzlicher kryptografischer Schutz beworben
- [x] alle Importer begrenzen Größe/Felder und führen kein HTML oder Formeln aus
- [x] Markdown ohne Raw-HTML; Vorschauen ausschließlich per Allowlist
- [x] Datei- und Backup-Pfade gegen Traversal, Symlinks und ungeprüfte Rendererwerte abgesichert
- [x] Exporte verlangen Master-Passwort, Warnung, Ziel- und zweite Bestätigung
- [x] Logs, Audit und Fehlerpfade enthalten keine Feldwerte oder Schlüsselmaterialien
- [x] Produktions-Dependency-Audit ohne bekannte Schwachstelle; Lizenz-Allowlist bestanden
- [x] finaler Installer/ZIP-Rebuild, Fuse-Prüfung und SHA-256-Prüfsummen
- [x] Canary-Scan von finalem Build, Installer, ZIP und installiertem NSIS-Payload

## Befundklassen

- kritisch: Entschlüsselung, Codeausführung oder Secret-Leak ohne gültigen Zugang
- hoch: Faktor-/Integritätsumgehung oder dauerhafter Klartextrest
- mittel: begrenzte Metadatenoffenlegung, DoS oder unsichere Voreinstellung
- niedrig: Härtungs-/Dokumentationsabweichung ohne unmittelbaren Secretzugriff

## Behobene Befunde

| Schwere | Befund                                                                                                            | Behebung/Nachweis                                                                                                                                                                  |
| ------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hoch    | Der Renderer konnte beliebige externe Ziele über eine Shell-Brücke öffnen.                                        | Brücke vollständig aus IPC, Preload und Renderer entfernt; Webseiten bleiben nur kopierbar, Markdown-Links sind nicht interaktiv.                                                  |
| hoch    | Setup-Geheimnisse konnten zwischen Recovery-Anzeige und Bestätigung in einem unklaren Pending-Zustand verbleiben. | Eine Auth-Epoch umfasst nun den gesamten Setup-Vorgang; Timeout, Sperren, Suspend und Dispose verwerfen Pending-State und Schlüssel.                                               |
| hoch    | Faktor-Metadaten, PRF-Wrap und geschützter Faktor-State wurden in mehreren Schreibvorgängen geändert.             | Ein serialisierter Compare-and-swap-Commit schreibt alle Faktoränderungen atomar in genau einer Profilgeneration; Crash- und Paralleltests decken Registrierung und Entfernung ab. |
| hoch    | Backup-/Migrationsfolgen konnten bei Absturz oder wechselndem Live-Zustand inkonsistent werden.                   | Live-Datei-/Hash-Prüfung, authentifizierte Gesamtvalidierung und ein persistentes Transaktionsjournal mit bytegenauem Rollback wurden ergänzt.                                     |
| mittel  | Ein kompromittierter Renderer konnte einen frei gewählten Backup-Ordner übergeben.                                | Nur unmittelbar zuvor nativ ausgewählte, lokale Windows-Pfade werden sitzungsgebunden akzeptiert; UNC, Device- und relative Pfade werden abgelehnt.                                |
| mittel  | Sicherheitsrelevante Einstellungen konnten ohne erneute Master-Bestätigung abgeschwächt werden.                   | Jede definierte Abschwächung verlangt die Verifikation des aktuellen Master-Passworts; parallele Updates sind serialisiert.                                                        |
| mittel  | Renderer-Aktivität konnte den Auto-Lock künstlich verlängern.                                                     | Vertrauenswürdige Aktivität stammt ausschließlich aus Main-Prozess-Eingabeereignissen; indirekte Renderer-Resetpfade wurden entfernt.                                              |
| mittel  | Restore-Ziele konnten über Symlinks oder Junctions umgeleitet werden.                                             | Restore akzeptiert nur reale Verzeichnisse und verwirft Symlinks/Junctions vor dem Schreiben.                                                                                      |
| niedrig | Temporäre Clipboard-Vergleichsbuffer wurden nicht explizit überschrieben.                                         | Buffer werden in einem `finally`-Pfad genullt.                                                                                                                                     |

## Abschlussbefund

Im geprüften Quellstand besteht **kein offener kritischer, hoher oder mittlerer Sicherheitsbefund**.
Der vollständige Quelllauf ist grün: Prettier, ESLint, alle drei TypeScript-Konfigurationen sowie 36
Testdateien mit 171 Tests. Der Produktionsaudit meldet keine bekannte Schwachstelle; die Allowlist
akzeptiert 154 Produktionspakete ausschließlich unter 0BSD, Apache-2.0, BSD-3-Clause, ISC oder MIT.

Der aktuelle lokale Rebuild erzeugte genau den NSIS-Installer und die portablen x64-/ARM64-ZIPs.
Beide gepackten EXEs bestehen die Fuse-Prüfung. Der Roh-/Container-Scan fand in 29.557 geprüften
Dateien kein Canary-Geheimnis; die stille Testinstallation bestand zusätzlich Fuse- und Payload-Scan
über 7.367 Dateien. Die stille Deinstallation entfernte die Anwendung und erhielt das isolierte
Nutzerdaten-Sentinel. Die drei SHA-256-Werte stehen in `release/SHA256SUMS.txt`. Installer und EXEs
bleiben entsprechend der festgelegten Produktentscheidung bewusst unsigniert.

Vor einem öffentlichen Tag müssen zusätzlich die GitHub-Release-Strecke und die manuellen
Windows-/Hardware-Fälle aus der [Security-Testmatrix](security-test-matrix.md) auf frischen
Windows-10-/Windows-11-Benutzerprofilen bestehen. Dazu gehören insbesondere vollständige
Offline-Nutzung, frischer Backup-Restore, Sitzungssperre/Standby sowie ein realer
FIDO2-PRF-/Presence-Test. Die fehlende Codesignatur ist eine festgelegte Produktentscheidung und muss
mit der dokumentierten SmartScreen-Warnung beibehalten werden.
