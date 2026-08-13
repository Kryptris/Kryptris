# ADR-0006: Crash-feste Mehrdatei-Transaktionen

- Status: akzeptiert
- Datum: 21. Juli 2026

## Kontext

Der bestehende `AtomicFileWriter` schützt genau eine Datei. Cross-Vault-Move, Cross-Vault-Copy und
endgültiges Löschen mit Anhängen verändern jedoch mehrere verschlüsselte Tresor- und
Attachment-Dateien als eine fachliche Operation. Ein sequenzieller Best-Effort-Ablauf könnte nach
Prozessabsturz, Sperren oder I/O-Fehler einen nur teilweise sichtbaren Zustand hinterlassen.

## Entscheidung

Kryptris verwendet unterhalb des Main-Prozesses einen serialisierten Mehrdatei-Koordinator:

1. Alle Zielpfade werden relativ zum Daten-Root kanonisiert und gegen Traversal, Links und
   unbekannte Atomic-Artefakte geprüft.
2. Quellgenerationen werden über Existenz, Größe und SHA-256 gesnapshottet. Optional erzwingt der
   Aufrufer eine konkrete Generation oder ein noch nicht vorhandenes Ziel.
3. Vor dem ersten Austausch werden bytegenaue Rollback-Sidecars vorhandener Dateien fsynct und
   geprüft. Erst danach wird ein technisches Journal dauerhaft installiert.
4. Zielgenerationen werden einzeln atomar geschrieben oder gelöscht und anschließend vollständig
   gegen die im Journal festgelegten Hashes geprüft.
5. Erst ein dauerhafter terminaler Commit-Marker macht die Gesamtoperation abgeschlossen. Ohne
   Marker stellt die Startup-Recovery alle Quellen bytegenau wieder her.

Journale enthalten ausschließlich Transaktions-ID, relative Zielpfade, Aktion, Größen und Hashes.
Sidecars kopieren nur bereits verschlüsselte At-Rest-Bytes. Bereits neu verschlüsselte große
Anhänge werden über einen Main-only-`write-file`-Typ gestreamt; der absolute Staging-Pfad wird weder
persistiert noch an Renderer oder Audit weitergegeben. Der Koordinator prüft die reguläre,
symlinkfreie Staging-Datei vor Journalinstallation und nochmals während des Streams auf Identität,
Größe und Inhalt.

Vault-Writer werden für alle beteiligten Tresore in lexikografischer Reihenfolge gehalten. Andere
Renderer-Lesezugriffe sehen bis zum Commit die alte entschlüsselte Cachegeneration; neue
Cachegenerationen werden erst nach erfolgreichem Gesamtcommit veröffentlicht. Sperren invalidiert
die Auth-Epoch und lässt laufende Operationen vor Commit abbrechen beziehungsweise zurückrollen.

## Konsequenzen

- Ein Fehler kann zusätzliche verschlüsselte Rollback- oder Staging-Artefakte bis zum nächsten
  Start hinterlassen, aber keinen Klartextrest und keinen bestätigten Teilzustand.
- Große Anhänge benötigen keinen Gesamt-Klartext- oder Gesamt-Ciphertextbuffer.
- Schreibende Batch-, Cross-Vault-, Purge-, Merge-, Datenqualitäts- und Retention-Flows bereiten
  redigierte Auditereignisse vor und nehmen das verschlüsselte Auditdokument in denselben
  Mehrdatei-Commit auf. Ein Audit-I/O- oder CAS-Fehler rollt damit auch den fachlichen Zustand
  vollständig zurück.
- Der Import oder das Entfernen des optionalen Offline-Datenleckindex nimmt dessen binäre
  Indexgeneration, das geschützte Profilmanifest und den redigierten Auditdatensatz in denselben
  Commit auf. Der Index selbst ist kein Backupbestandteil und sein Quellpfad bleibt außerhalb von
  Journal, Audit und Renderer.
- Der Release-Artefaktscanner prüft auch reproduzierte Laufzeitbäume auf verbotene Klartextfelder,
  Caches, Berichte, Staging- und Transaktionsartefakte. Nur ein exakt strukturvalidierter
  `KRYBRCH1`-Header des öffentlichen Offline-Datenleckindexes ist in einem Rollback-Sidecar zulässig;
  diese Ausnahme akzeptiert keine beliebigen Klartextbytes und keine Fachwerte.
- Die Lösung ist von der Snapshot-basierten Formatmigration getrennt und erhöht keine
  Formatversion.

## Verworfene Alternativen

- **Nur mehrere `AtomicFileWriter` nacheinander:** kein Gesamtrollback nach Teilcommit.
- **Klartext-Staging:** widerspricht dem Bedrohungsmodell und erzeugt schwer kontrollierbare Reste.
- **Vollständige Anhänge im Speicher:** unnötige Spitzenlast und schlechter Abbruchpfad bei großen
  Dateien.
- **Quellpfade im Journal:** unnötige lokale Metadatenoffenlegung; die Recovery benötigt sie nicht.
