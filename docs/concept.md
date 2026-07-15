# Vaulta – Konzept für einen lokalen Passwort-Manager

**Status:** Fachliches und technisches Ausgangskonzept  
**Version:** 1.0  
**Stand:** 14. Juli 2026  
**Zielplattform:** Windows 10/11, Desktop  
**Arbeitstitel:** Vaulta

## 1. Kurzfassung

Vaulta ist ein moderner, deutschsprachiger Passwort-Manager für genau eine Person. Die Anwendung arbeitet vollständig offline, benötigt weder Konto noch Server und speichert sämtliche Tresordaten ausschließlich lokal und verschlüsselt. Sie verwaltet mehrere getrennte Tresore sowie Zugangsdaten, sichere Notizen, Kreditkarten, Identitäten, WLAN-Zugänge, Softwarelizenzen, SSH-Schlüssel, Dateien und frei definierbare sonstige Einträge.

Das Master-Passwort ist der primäre Zugang. Optional können ein FIDO2-Sicherheitsschlüssel und eine TOTP-App als zusätzliche Sperren eingerichtet werden. Ein einmalig erzeugter Wiederherstellungsschlüssel kann als zweiter kryptografischer Zugang dienen. Ohne Master-Passwort oder Wiederherstellungsschlüssel gibt es bewusst keine Wiederherstellung und keine Hintertür.

Die Anwendung wird mit Electron, Node.js und TypeScript umgesetzt. Electron ist für diesen Zweck vertretbar, wenn der Renderer strikt isoliert bleibt, keine Node-Rechte erhält und alle Datei-, Schlüssel- und Kryptografieoperationen in einem kleinen privilegierten Kern stattfinden. Ein dunkles, eigenständiges Design orientiert sich bei Bedienkomfort und Informationsdichte an Proton Pass, ohne dessen Oberfläche zu kopieren.

## 2. Ziele und Abgrenzung

### 2.1 Ziele

- produktiver Einsatz auf einem einzelnen Windows-Gerät
- lokale Ende-zu-Ende-Verschlüsselung ohne externen Dienst
- mehrere logisch und kryptografisch getrennte Tresore
- komfortable Verwaltung aller üblichen Geheimnis- und Dokumenttypen
- starke Offline-Sicherheitsanalyse für Passwörter
- sichere Anhänge, TOTP-Erzeugung und Passwortgenerator
- verständliche Backups, Importe und bewusst abgesicherte Exporte
- moderne, vollständig deutsche Dunkelmodus-Oberfläche
- automatisierte Tests und reproduzierbare Windows-Builds über GitHub Actions

### 2.2 Nicht Bestandteil

- Cloud-Synchronisierung oder eigener Server
- Mehrbenutzerbetrieb, Rollen, Teams oder Teilen von Einträgen
- Browser-Erweiterung und automatisches Ausfüllen im Browser
- Online-Prüfung gegen bekannte Datenlecks
- Master-Passwort-Zurücksetzung durch einen Betreiber
- Notfallzugriff durch andere Personen
- unbemerkte Telemetrie, Werbung oder externe Analyse-Dienste

### 2.3 Sicherheitsgrenzen

Vaulta schützt insbesondere gegen den Diebstahl der ausgeschalteten oder gesperrten Festplatte, das Kopieren der Tresordateien, neugierige lokale Benutzer und eine nachträgliche Analyse lokaler Daten. Gegen bereits aktive Schadsoftware mit Benutzer- oder Administratorrechten, Keylogger, manipulierte Betriebssysteme, kompromittierte Zwischenablagen oder Bildschirmkameras kann eine Desktop-Anwendung keinen vollständigen Schutz garantieren. Diese Grenze wird in der Anwendung und Dokumentation offen benannt.

## 3. Benutzer- und Nutzungskonzept

Es existiert genau ein lokales Profil. Dieses Profil besitzt mehrere Tresore, beispielsweise „Privat“, „Arbeit“ oder „Archiv“. Ein Tresor kann jederzeit erstellt, umbenannt, exportiert, gesichert oder gelöscht werden. Es gibt keine Rollen und keine Freigaben.

Der normale Ablauf lautet:

1. Vaulta startet mit einer neutralen Entsperransicht.
2. Der Benutzer gibt das Master-Passwort ein.
3. Falls aktiviert, wird zusätzlich der Sicherheitsschlüssel oder TOTP-Code verlangt.
4. Der zuletzt verwendete Tresor wird geöffnet.
5. Nach fünf Minuten Inaktivität sperrt sich Vaulta standardmäßig automatisch.
6. Sperren, Programmende oder Windows-Sitzungssperre entfernen aktive Schlüssel aus dem Speicher, soweit technisch möglich.

Die Zeit bis zur Sperre ist einstellbar. Empfohlene Auswahlwerte sind sofort, 1, 5, 10, 15 und 30 Minuten. Optional sperrt Vaulta außerdem beim Minimieren, beim Wechsel des Windows-Benutzers, bei Standby und beim Schließen des Laptopdeckels.

## 4. Informationsarchitektur und Oberfläche

### 4.1 Hauptfenster

Das Hauptfenster nutzt eine Drei-Spalten-Struktur:

- **Navigation links:** Tresorauswahl, Alle Einträge, Favoriten, Kategorien, Sicherheitscheck und Papierkorb
- **Liste in der Mitte:** Suchergebnisse und Einträge mit Typ, Titel, Untertitel und Favoritenstatus
- **Detailansicht rechts:** Felder, Aktionen, TOTP-Code, Anhänge und Sicherheitsbewertung

Oben befinden sich eine globale Suche, „Neuer Eintrag“, die manuelle Sperre und Einstellungen. Geheimnisse sind standardmäßig maskiert. Kopieren erfolgt über eindeutige Schaltflächen; erfolgreiche Kopiervorgänge werden knapp bestätigt.

### 4.2 Weitere Ansichten

- Entsperren und Ersteinrichtung
- Wiederherstellung mit Wiederherstellungsschlüssel
- Eintrag erstellen und bearbeiten
- Passwort- und Passphrasengenerator
- Sicherheitscheck
- Import-Assistent mit Vorschau und Dublettenprüfung
- Export- und Backup-Assistent mit Sicherheitswarnungen
- Tresorverwaltung
- Einstellungen für Sicherheit, Zwischenablage, Darstellung und Backups
- verschlüsseltes Aktivitätsprotokoll
- Papierkorb mit Wiederherstellen und endgültigem Löschen

### 4.3 Suche, Organisation und Bedienung

- Volltextsuche über Titel, Benutzernamen, URLs, Tags und ausgewählte benutzerdefinierte Felder
- Filter nach Typ, Favorit, Tag, Ordner und Sicherheitszustand
- frei definierbare Ordner, Tags und Farben
- Favoriten und zuletzt verwendete Einträge
- Tastaturnavigation innerhalb der App
- globale Betriebssystem-Tastenkürzel sind zunächst nicht vorgesehen, damit keine Geheimnisse aus dem gesperrten Zustand erreichbar werden
- Suchindex existiert nur verschlüsselt auf der Festplatte und wird nach dem Entsperren im Speicher aufgebaut

## 5. Eintragstypen und Datenmodell

Jeder Eintrag besitzt mindestens ID, Tresor-ID, Typ, Titel, Ordner, Tags, Favoritenstatus, Notiz, benutzerdefinierte Felder, Anhänge sowie Erstellungs- und Änderungszeitpunkt. Zeitstempel sind keine Passwort-Historie; frühere Feldwerte werden nicht gespeichert.

### 5.1 Zugangsdaten

- Titel
- Benutzername oder E-Mail-Adresse
- Passwort
- eine oder mehrere Webseiten beziehungsweise App-Bezeichner
- optionaler TOTP-Seed mit aktuellem Einmalcode
- Notizen, Tags, Ordner und Anhänge
- eigene Felder als Text, Geheimnis, URL, Zahl, Datum oder Ein/Aus-Wert

### 5.2 Sichere Notizen

- Titel
- formatierbarer Text auf Basis einer sicheren Markdown-Teilmenge
- Tags, Ordner, eigene Felder und Anhänge
- keine ungefilterte HTML-Ausführung

### 5.3 Kreditkarten

- Kartenname, Karteninhaber und Kartennummer
- Ablaufdatum, CVC/CVV und optionale PIN
- Herausgeber, Kartentyp und Rechnungsadresse
- Service-Telefonnummer, Webseite und Notizen

### 5.4 Identitäten und Adressen

- Name, Geburtsdatum und optionale Anrede
- E-Mail-Adressen und Telefonnummern
- Privat-, Arbeits- und frei definierbare Adressen
- optionale Ausweis-, Reisepass- oder Steuerdaten
- Notizen und Dokumentanhänge

### 5.5 WLAN-Zugänge

- Anzeigename und SSID
- Passwort
- Sicherheitsart, beispielsweise WPA2 oder WPA3
- verstecktes Netzwerk
- Router-Adresse sowie optionaler Router-Benutzername
- Notizen und QR-Code-Anzeige für kompatible Geräte

### 5.6 Softwarelizenzen

- Produkt, Hersteller und Version
- Lizenzschlüssel und Lizenznehmer
- Kauf-, Aktivierungs- und Ablaufdatum
- Bestellnummer, Download-Adresse und Kaufpreis
- Beleg als Anhang

### 5.7 SSH-Schlüssel

- Anzeigename, Host, Port und Benutzername
- Schlüsseltyp und Fingerabdruck
- öffentlicher und privater Schlüssel
- optionale Passphrase
- privater Schlüssel bleibt standardmäßig maskiert und erfordert eine bewusste Exportbestätigung

### 5.8 Dateien und Dokumente

- Titel, Beschreibung, Tags und Ordner
- ein oder mehrere verschlüsselte Anhänge
- in Version 1 ein konfigurierbares Größenlimit mit einem sicheren Standard von 100 MB pro Datei
- Vorschauen nur für ausgewählte ungefährliche Formate und ausschließlich nach dem Entsperren

### 5.9 Sonstige Einträge

Ein leerer Basistyp erlaubt beliebig viele eigene Felder. Feldreihenfolge, Bezeichnung, Datentyp und Maskierung sind frei definierbar. Eigene wiederverwendbare Vorlagen sind für eine spätere Welle vorgesehen.

## 6. Kernfunktionen

### 6.1 Passwort- und Passphrasengenerator

- konfigurierbare Länge
- Großbuchstaben, Kleinbuchstaben, Zahlen und Sonderzeichen
- ausgeschlossene oder zwingend enthaltene Zeichen
- Vermeidung ähnlich aussehender Zeichen
- frei definierbare Regeln und Mindestanzahlen
- Passphrasen mit Wortanzahl, Trennzeichen, Großschreibung und optionalen Zahlen
- lokale Zufallsquelle über den kryptografisch sicheren Generator des Betriebssystems
- Stärkeanzeige vor dem Übernehmen

### 6.2 Lokaler Sicherheitscheck

- schwache und leicht erratbare Passwörter
- mehrfach verwendete Passwörter
- alte Passwörter anhand des letzten Änderungsdatums
- leere oder unvollständige Zugangsdaten
- ungeschützte private Schlüssel oder sensible Felder
- lokale Bewertung mit einer etablierten Offline-Bibliothek und eigenen Regeln
- keine Übertragung von Passwörtern, Hashes oder Teil-Hashes ins Internet

### 6.3 TOTP-Verwaltung

Vaulta kann TOTP-Seeds in Einträgen verschlüsselt speichern, aktuelle Codes offline erzeugen, verbleibende Zeit anzeigen und Codes kontrolliert kopieren. QR-Import erfolgt lokal über Bilddatei oder Bildschirmaufnahme nur nach ausdrücklicher Aktion. Die Kamera wird nicht benötigt.

### 6.4 Passkeys

Passkeys werden in der Architektur berücksichtigt, aber nicht in die erste produktive Version aufgenommen. Ohne Browser-Erweiterung oder tiefe Windows-WebAuthn-Integration wäre eine reine Speicherung wenig nützlich. Eine spätere Forschungswelle klärt, ob Vaulta als lokaler Passkey-Provider sicher und mit vertretbarem Aufwand umsetzbar ist.

### 6.5 Zwischenablage und Sichtschutz

- Geheimnisse werden über den Main-Prozess kopiert
- automatische Leerung nach standardmäßig 30 Sekunden, einstellbar von 5 bis 120 Sekunden
- Leerung nur, wenn weiterhin der von Vaulta gesetzte Inhalt vorhanden ist
- manuelle Leerung jederzeit möglich
- Passwortanzeige nur auf bewusste Aktion und optional mit erneutem Master-Passwort
- Electron-Inhaltsschutz gegen viele Bildschirmaufnahmen, soweit Windows dies unterstützt
- Warnhinweis, dass Betriebssystem- oder Kameraaufnahmen nicht vollständig verhindert werden können

## 7. Kryptografisches Sicherheitskonzept

### 7.1 Grundsätze

- keine selbst entwickelte Kryptografie
- ausschließlich etablierte, geprüfte Algorithmen und Bibliotheken
- authentifizierte Verschlüsselung, damit Manipulation erkannt wird
- jedes verschlüsselte Objekt erhält einen eigenen zufälligen Nonce
- Formatversion und Algorithmusparameter werden mitgeführt
- Klartextdaten werden nie absichtlich in Logs, Crashreports oder temporären Dateien gespeichert

### 7.2 Schlüsselhierarchie

1. Bei der Einrichtung wird ein zufälliger 256-Bit-Profil-Hauptschlüssel erzeugt.
2. Das Master-Passwort wird mit Argon2id und einem individuellen zufälligen Salt zu einem Schlüsselableitungsschlüssel verarbeitet.
3. Dieser Schlüssel verschlüsselt den Profil-Hauptschlüssel; das Master-Passwort selbst wird nie gespeichert.
4. Aus dem Profil-Hauptschlüssel werden per HKDF getrennte Schlüssel für Tresore, Metadaten, Suchindizes und Protokolle abgeleitet.
5. Anhänge erhalten eigene zufällige Dateischlüssel, die wiederum durch den jeweiligen Tresorschlüssel geschützt werden.
6. Ein Wechsel des Master-Passworts verschlüsselt nur den Profil-Hauptschlüssel neu; nicht alle Einträge müssen neu verschlüsselt werden.

Die Argon2id-Parameter werden beim Einrichten anhand des Geräts kalibriert. Ziel ist ungefähr eine Sekunde Ableitungszeit bei mindestens 256 MB Speicher, sofern das Gerät dies zuverlässig erlaubt. Die Parameter werden im Header gespeichert und können später erhöht werden.

### 7.3 Datenverschlüsselung

- strukturierte Datensätze: AES-256-GCM oder XChaCha20-Poly1305 aus einer etablierten Bibliothek
- große Anhänge: authentifizierte, gestreamte Chunk-Verschlüsselung mit eindeutiger Reihenfolge und Integritätsprüfung
- Header enthalten nur zwingend erforderliche technische Werte wie Version, Salt, KDF-Parameter und Nonces
- fachliche Metadaten wie Titel, Typ, Tags und Dateinamen bleiben verschlüsselt

Die konkrete Bibliotheksauswahl wird vor Implementierung durch einen kleinen Sicherheits-Prototyp und eine Abhängigkeitsprüfung finalisiert. Bevorzugt werden Node.js-eigene Kryptoprimitiven und wenige, gepflegte native Abhängigkeiten.

### 7.4 Wiederherstellungsschlüssel

Der optionale Wiederherstellungsschlüssel besteht aus mindestens 256 zufälligen Bits und wird als gut abschreibbare Gruppen mit Prüfsumme dargestellt. Aus ihm wird ein separater Schlüssel abgeleitet, der eine zweite verschlüsselte Kopie des Profil-Hauptschlüssels schützt.

- Er wird genau einmal vollständig angezeigt und kann gedruckt oder als Datei gespeichert werden.
- Vaulta speichert ihn niemals im Klartext.
- Seine Einrichtung muss durch erneute Eingabe ausgewählter Gruppen bestätigt werden.
- Seine Verwendung entsperrt die Daten und erzwingt anschließend ein neues Master-Passwort sowie die erneute Einrichtung zusätzlicher Faktoren.
- Ohne Master-Passwort oder Wiederherstellungsschlüssel sind die Daten endgültig verloren.

### 7.5 Sicherheitsschlüssel

Ein kompatibler FIDO2-/WebAuthn-Sicherheitsschlüssel kann als echter zusätzlicher kryptografischer Faktor eingerichtet werden. Bevorzugt wird die PRF- beziehungsweise `hmac-secret`-Erweiterung, damit ein hardwaregebundener geheimer Wert in die Freigabe des Profil-Hauptschlüssels eingeht. Es werden mindestens zwei Sicherheitsschlüssel zur Registrierung empfohlen, damit ein defekter Schlüssel nicht sofort den Wiederherstellungsschlüssel erforderlich macht.

Fällt ein Gerät ohne PRF-/`hmac-secret`-Unterstützung zurück auf reine Anwesenheitsprüfung, wird dies sichtbar als schwächerer Modus gekennzeichnet. Der Sicherheitsschlüssel ersetzt standardmäßig nicht das Master-Passwort, sondern ergänzt es.

### 7.6 TOTP als Entsperrfaktor

Eine TOTP-App kann als zusätzliche lokale Zugangssperre aktiviert werden. Bei einer vollständig lokalen Anwendung liegt der Prüfzustand jedoch zwangsläufig auf demselben Gerät und kann von einem Angreifer mit vollständiger Kontrolle über Programm und Benutzerkonto umgangen werden. TOTP erhöht daher vor allem den Schutz gegen beiläufigen Zugriff, ist aber kein gleichwertiger kryptografischer Faktor wie ein kompatibler Sicherheitsschlüssel. Die Oberfläche darf TOTP nicht irreführend als Schutz gegen eine vollständige Gerätekopie darstellen.

## 8. Lokale Speicherung

Jeder Tresor wird in einer eigenen versionierten Containerdatei gespeichert. Eine kleine unverschlüsselte Profilkonfiguration darf ausschließlich nicht sensible App-Einstellungen enthalten. Sämtliche fachlichen Inhalte, Indizes, Protokolle und Anhangsnamen sind verschlüsselt.

Empfohlene Ablage:

```text
%APPDATA%/Vaulta/
  profile.json                 # nur technische, nicht sensible Einstellungen
  vaults/<vault-id>.vaulta     # verschlüsselter Tresorcontainer
  attachments/<vault-id>/...  # verschlüsselte Anhangschunks
  backups/                     # optionale verschlüsselte lokale Sicherungen
```

Schreibvorgänge erfolgen transaktional über temporäre neue Containerstände, Integritätsprüfung und atomaren Austausch. Nach einem Absturz wird nie automatisch eine ungeprüfte temporäre Version übernommen. Für SSDs kann kein verlässliches physisches Überschreiben garantiert werden; endgültiges Löschen wird deshalb primär als kryptografisches Löschen des betreffenden Schlüssels umgesetzt.

## 9. Backup, Import und Export

### 9.1 Backups

Für den produktiven Einsatz sind verschlüsselte Backups zwingend vorgesehen:

- natives Format `.vaulta-backup` mit Version, Integritätsprüfung und allen Anhängen
- manuelle Sicherung jederzeit
- optionale automatische Sicherung in einen frei wählbaren lokalen Ordner
- Rotation, beispielsweise 7 tägliche, 4 wöchentliche und 6 monatliche Stände
- Empfehlung eines getrennten USB-Datenträgers; ein Backup auf derselben Festplatte schützt nicht gegen deren Ausfall
- Wiederherstellungsprüfung vor dem Ersetzen bestehender Tresore

### 9.2 Import

Die erste Importstufe unterstützt die verbreitetsten Formate:

- Bitwarden
- 1Password
- LastPass
- KeePass/KeePassXC
- Proton Pass
- CSV-Exporte von Chrome, Edge und Firefox
- generisches CSV und JSON mit Feldzuordnung

Ein Assistent zeigt vor dem Import Vorschau, Zuordnung, Fehler und mögliche Dubletten. Importdateien werden niemals automatisch gelöscht. Vaulta weist den Benutzer deutlich darauf hin, unverschlüsselte Quelldateien anschließend sicher zu behandeln.

### 9.3 Export

- JSON für strukturierte Daten
- CSV für kompatible Tabellenimporte
- natives verschlüsseltes Backup als bevorzugtes Format
- Klartextexporte benötigen Master-Passwort, eine deutliche Warnung, Zielbestätigung und eine zweite bewusste Bestätigung
- Anhänge werden bei Klartextexport nur nach gesonderter Auswahl ausgegeben
- Exportvorgänge erscheinen ohne sensible Inhalte im Aktivitätsprotokoll

## 10. Aktivitätsprotokoll

Das lokale, verschlüsselte Protokoll enthält sicherheitsrelevante Ereignisse:

- Entsperren, Sperren und fehlgeschlagene Versuche
- Erstellung, Änderung, Verschiebung und Löschung von Einträgen
- Import, Export, Backup und Wiederherstellung
- Änderung sicherheitsrelevanter Einstellungen
- Registrierung oder Entfernung zusätzlicher Faktoren

Es enthält niemals Passwörter, TOTP-Seeds, Schlüsselmaterial, Feldwerte oder Klartext-Zwischenablagen. Eine konfigurierbare Aufbewahrung begrenzt Größe und Alter. Standard sind 5.000 Ereignisse beziehungsweise 180 Tage.

## 11. Technische Architektur

### 11.1 Technologieentscheidung

- Electron als Windows-Desktop-Shell
- TypeScript mit strengem Compiler-Modus
- Node.js ausschließlich im privilegierten Main-Prozess
- React für den Renderer und Vite für Entwicklungs- und Buildprozess
- pnpm mit festgeschriebener Lockdatei
- Electron Forge oder ein vergleichbar gepflegtes Packaging-Werkzeug für Windows
- Vitest, React Testing Library und Playwright für Tests

Electron ist nicht grundsätzlich zu unsicher. Das Risiko entsteht vor allem durch einen zu mächtigen Renderer und eine große Abhängigkeitsfläche. Deshalb wird das Projekt in klar getrennte Schichten zerlegt.

### 11.2 Komponenten

```text
React Renderer
    │ eng definierte, typisierte IPC-Aufrufe
    ▼
Preload Bridge
    │ Validierung und minimale API
    ▼
Application Services im Main-Prozess
    ├── Vault Service
    ├── Crypto Service
    ├── Attachment Service
    ├── Import/Export Service
    ├── Security Check Service
    └── Audit Service
            │
            ▼
    verschlüsselte lokale Container
```

Der Renderer erhält grundsätzlich nur die für die aktuelle Ansicht nötigen entschlüsselten Daten. Passwörter und private Schlüssel werden erst bei konkreter Anzeige- oder Kopieraktion angefordert. Kryptografische Schlüssel verlassen den Main-Prozess nicht.

### 11.3 Electron-Härtung

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`
- kein `remote`-Modul
- keine dynamische Ausführung über `eval` oder `new Function`
- strenge Content Security Policy ohne unsichere Inline-Skripte
- keine Navigation zu externen Inhalten im App-Fenster
- keine Shell- oder Link-Bridge; Websites bleiben kopierbar, Markdown-Links nicht anklickbar
- IPC-Allowlist mit Schema-Validierung für Argumente und Antworten
- Renderer kann keine frei gewählten Dateipfade lesen oder schreiben; native Pfadauswahlen werden im Main autorisiert
- Berechtigungen werden standardmäßig verweigert
- keine automatisch geladenen Remote-Ressourcen, Schriftarten oder Bilder
- ASAR-Integrität, fester Dependency-Lock und automatisierte Abhängigkeitsprüfung

## 12. Fehler-, Update- und Betriebsverhalten

- Fehlerdialoge enthalten keine Geheimnisse und bieten eine verständliche nächste Aktion.
- Lokale Diagnoseprotokolle sind standardmäßig minimal und niemals mit Tresorinhalten angereichert.
- Absturzberichte werden nicht automatisch versendet.
- Datenmigrationen sind versioniert, vorwärtsgerichtet und werden vorab durch ein Backup abgesichert.
- Updates sind manuell installierbar; die App bleibt ohne Internet vollständig nutzbar.
- GitHub Releases können Installationsdateien bereitstellen, werden aber nicht zwingend aus der Anwendung abgefragt.
- Ohne Budget für ein Windows-Code-Signing-Zertifikat bleibt der erste Build unsigniert. Windows SmartScreen kann deshalb warnen. Für dauerhafte Verteilung ist eine Signatur später dringend empfohlen.

Als Auslieferungsformen sind ein NSIS-Installer und optional eine portable ZIP-Version vorgesehen. Der Installer darf bestehende Tresordaten bei Update oder Deinstallation niemals ungefragt löschen.

## 13. Tests und Qualitätssicherung

### 13.1 Automatisierte Tests

- Unit-Tests für Schlüsselableitung, Ver- und Entschlüsselung, Generator und TOTP
- bekannte Testvektoren für alle Kryptoprimitiven
- Roundtrip- und Manipulationstests für Container und Anhänge
- Property-based Tests für Parser, Importer und benutzerdefinierte Felder
- Migrationstests für jede Datenformatversion
- UI-Komponententests für Maskierung, Bestätigungen und Fehlerzustände
- End-to-End-Tests für Einrichtung, Sperren, Entsperren, CRUD, Import, Export und Backup
- Tests für Absturz- und Stromausfallszenarien bei Schreibvorgängen
- statische Analyse, TypeScript-Prüfung und Dependency-Audit

### 13.2 GitHub Actions

Jeder Pull Request führt Formatprüfung, Linting, Typecheck, Unit- und Integrationstests aus. Ein separater Windows-Workflow baut Installer und portable Anwendung. Releases entstehen nur aus versionierten Tags, erzeugen Prüfsummen und hängen Build-Artefakte an einen GitHub Release. Geheimnisse für eine spätere Codesignierung werden ausschließlich als geschützte GitHub-Secrets verwaltet.

### 13.3 Sicherheitsprüfung vor Version 1.0

- manuelle Architektur- und IPC-Prüfung
- Dependency- und Lizenzprüfung
- Test auf Klartextreste in Dateien, Logs, Crashdumps und temporären Verzeichnissen
- Manipulationstests an Container, Header und Anhängen
- Prüfung von Zwischenablage, Auto-Sperre und Windows-Sitzungswechsel
- dokumentierter Wiederherstellungs- und Backup-Test auf einem frischen Windows-System

## 14. Entwicklungswellen

Jede Welle endet mit automatisierten Tests, einer lauffähigen Windows-Version und aktualisierter Dokumentation. Eine folgende Welle beginnt erst, wenn die Abnahmekriterien der vorherigen erfüllt sind.

### Welle 0 – Sicherheitsfundament und Prototyp

- Repository, TypeScript, Electron, React und CI einrichten
- Bedrohungsmodell und Schlüsselhierarchie als Architecture Decision Records festhalten
- Kryptografie-Prototyp mit Testvektoren und Containerformat erstellen
- Main-/Preload-/Renderer-Grenzen und IPC-Schemas aufsetzen
- Designsystem und klickbaren UI-Prototyp erstellen

**Abnahme:** Ein Testtresor lässt sich sicher anlegen, sperren, erneut öffnen und gegen Manipulation prüfen; der Renderer hat keinen direkten Node- oder Dateizugriff.

### Welle 1 – Nutzbarer lokaler Tresor

- Ersteinrichtung und Master-Passwort
- mehrere Tresore
- Zugangsdaten und sichere Notizen
- Erstellen, Lesen, Bearbeiten, Löschen und Papierkorb
- Suche, Ordner, Tags und Favoriten
- Passwortgenerator
- Auto-Sperre, Maskierung und Zwischenablageleerung

**Abnahme:** Vaulta ist für normale Zugangsdaten offline nutzbar, verliert bei Absturz keine bestätigten Daten und schreibt keine Klartexte auf die Festplatte.

### Welle 2 – Vollständige Datentypen und Anhänge

- Kreditkarten, Identitäten, WLAN, Lizenzen, SSH und Sonstige
- eigene Felder
- verschlüsselte Dateien und Dokumente
- sichere Vorschauen und Dateigrößenlimits
- TOTP in Zugangseinträgen

**Abnahme:** Alle vereinbarten Eintragstypen und Anhänge funktionieren mit Import-/Export-neutralem Datenmodell und Integritätsschutz.

### Welle 3 – Wiederherstellung und Datensicherheit

- Wiederherstellungsschlüssel
- verschlüsselte Backups und Rotation
- Wiederherstellungsassistent
- Aktivitätsprotokoll
- Migrations- und Ausfallsicherheit

**Abnahme:** Ein frisches System kann ausschließlich mit Backup plus gültigem Master- oder Wiederherstellungsschlüssel vollständig wiederhergestellt werden.

### Welle 4 – Import, Export und Sicherheitscheck

- Importer für bekannte Manager und Browser
- generische CSV-/JSON-Feldzuordnung
- Klartextexport mit mehrstufiger Bestätigung
- Offline-Prüfung auf schwache, alte und wiederverwendete Passwörter
- Sicherheitsübersicht mit konkreten lokalen Empfehlungen

**Abnahme:** Repräsentative Exportdateien werden nachvollziehbar importiert; kein Sicherheitscheck benötigt Netzwerkzugriff.

### Welle 5 – Zusätzliche Entsperrfaktoren und Härtung

- FIDO2/WebAuthn-Sicherheitsschlüssel
- optionale TOTP-Zugangssperre mit klarer Sicherheitserklärung
- erweiterter Sichtschutz
- Security-Testmatrix, Härtung und Performanceoptimierung
- Installer, portable Version und Releaseprozess

**Abnahme:** Verlustszenarien für Master-Passwort, TOTP-Gerät und Sicherheitsschlüssel sind getestet und führen niemals zu einer heimlichen Umgehung des Verschlüsselungsmodells.

### Welle 6 – Optionale Zukunftsfunktionen

- Untersuchung einer sicheren Passkey-Integration unter Windows
- wiederverwendbare eigene Vorlagen
- erweiterte lokale Berichte
- optional signierte Releases, falls später ein Budget vorhanden ist

Diese Welle ist nicht Voraussetzung für Version 1.0.

## 15. Produktweite Abnahmekriterien

Version 1.0 gilt als produktionsbereit, wenn:

- alle Wellen 0 bis 5 abgeschlossen sind,
- die Anwendung ohne Netzwerkverbindung installiert und vollständig genutzt werden kann,
- kein Tresorinhalt ohne Master- oder Wiederherstellungsschlüssel entschlüsselt werden kann,
- sensible Daten weder in Logs noch in temporären Dateien oder GitHub-Artefakten erscheinen,
- Backups und Wiederherstellung auf einem frischen Windows-System getestet sind,
- alle vereinbarten Datentypen, Anhänge, TOTP, Import, Export und Sicherheitscheck funktionieren,
- ein dokumentierter manueller Sicherheitsreview ohne offene kritische Befunde abgeschlossen ist,
- Installer und portable Version reproduzierbar durch GitHub Actions gebaut werden.

## 16. Festgelegte Produktentscheidungen

- **Name:** Vaulta als vorläufiger Arbeitstitel
- **Plattform:** Windows-Desktop
- **Technik:** gehärtetes Electron, Node.js, TypeScript und React
- **Betrieb:** lokal und vollständig offline
- **Benutzer:** ein Profil, mehrere Tresore
- **Design:** deutscher Dunkelmodus, modern, ruhig, teal-violette Akzente
- **Primärzugang:** Master-Passwort
- **Wiederherstellung:** optionaler, einmalig erzeugter Wiederherstellungsschlüssel
- **Zusatzschutz:** kompatibler FIDO2-Sicherheitsschlüssel; TOTP mit dokumentierter Offline-Einschränkung
- **Historie:** keine früheren Passwort- oder Feldwerte
- **Backups:** verschlüsselte native Sicherungen; Klartext-JSON/CSV nur nach starker Bestätigung
- **Netzwerk:** keine Funktionsabhängigkeit und keine Datenleckprüfung
- **Verteilung:** NSIS-Installer plus portable ZIP, zunächst ohne kostenpflichtige Codesignatur

## 17. Visueller Prototyp

Der erste visuelle Entwurf liegt unter [`assets/vaulta-ui-prototype.png`](assets/vaulta-ui-prototype.png). Er zeigt die geplante Drei-Spalten-Ansicht, dunkle Farbwelt, Tresorauswahl, Navigation, Eintragsliste und Detailansicht. Das Bild definiert Stil und Informationshierarchie, aber noch keine pixelgenaue Implementierung.
