# Leistungsnachweis Welle 12

Stand: 13. August 2026

## Umfang und Reproduktion

Der Benchmark erzeugt ausschließlich deterministische, synthetische Einträge und misst im
**Main-Prozess** drei konkrete Pfade:

- `EntryViewService.listAsync()` für eine kalte Liste sowie eine neue Suche mit bereits warmem
  Sicherheitsreport; Suchergebnisse selbst werden nicht gecacht;
- `SecurityCheckService.scanAsync()` vollständig und mit kooperativem Abbruch;
- `DuplicateService.scan()` vollständig und mit kooperativem Abbruch.

Er wird mit folgendem Befehl ausgeführt:

```powershell
corepack pnpm benchmark:performance -- --output docs\performance-benchmark-YYYY-MM-DD.json
```

Der maschinenlesbare [Rohdatensatz vom 13. August 2026](performance-benchmark-2026-08-13.json)
entstand in **einem einzelnen Lauf** auf Windows 10.0.26200, x64, Node.js v24.14.0, AMD Ryzen 5 7600X
mit 12 logischen CPUs und 33.244.930.048 Byte Hauptspeicher (vor dem Lauf frei:
10.118.193.152 Byte). Er ist kein Median, keine Hardwareempfehlung und kein UI-Benchmark.

## Aufgezeichnete Main-Prozess-Zeiten

| Synthetische Einträge |  Kalte Liste | Suche mit warmem Sicherheitsreport | Sicherheitscheck vollständig | Dublettenscan vollständig |
| --------------------: | -----------: | ---------------------------------: | ---------------------------: | ------------------------: |
|                 1.000 |   410,068 ms |                           3,332 ms |                   348,758 ms |                 23,040 ms |
|                 5.000 | 4.388,800 ms |                          15,948 ms |                 4.473,648 ms |                 79,901 ms |
|                10.000 | 9.968,047 ms |                          30,710 ms |                 9.875,643 ms |                153,253 ms |

Die vollständigen Rohdaten enthalten zusätzlich Befund-, Fortschritts- und Yield-Zahlen sowie die
kooperativen Abbruchpunkte. Beim 10.000-Eintragslauf war das erste Yield des Sicherheitschecks nach
4,930 ms und das des Dublettenscans nach 5,363 ms messbar; beide Abbrüche wurden als abgebrochen
protokolliert. Diese Werte beschreiben ausschließlich den getesteten Main-Prozess-Lauf.

## Bewusste Abnahmegrenze

Die Renderer-Liste virtualisiert feste Zeilen, hält nur ein Fenster mit Overscan im DOM und besitzt
einen UI-Test für 10.000 Einträge, Home/End und begrenzte sichtbare Optionen. Die Suche wird 200 ms
entprellt; eine Anfragengeneration verhindert, dass eine verspätete Antwort neuere Eingaben
überschreibt. Diese Code- und UI-Tests ersetzen jedoch keine Performance-Messung im Chromium-Renderer.

Damit sind die Roadmap-Ziele „unter 200 ms bis zum ersten sinnvollen UI-Feedback“ und „kein
blockierter Renderer-Frame über 100 ms“ **nicht** durch diesen Nachweis erfüllt oder widerlegt. Nicht
gemessen wurden insbesondere IPC-/Structured-Clone-Kosten, React-Rendering, Browser-Frames,
Screenreader-Ausgabe, echte 200-%-Windows-Skalierung und der Zeitpunkt des ersten sichtbaren
Ladefeedbacks. Sie bleiben ein separater manueller beziehungsweise externer Abnahmenachweis auf dem
Referenzsystem.

Der Quelltest `corepack pnpm verify` bestand zum Dokumentstand mit 87 Testdateien und 487 Tests. Das
bestätigt die deterministischen Benchmark-Fixtures und die Cache-/Batch-Semantik, macht aus dem
Einzellauf aber keinen allgemeinen Leistungsgrenzwert.
