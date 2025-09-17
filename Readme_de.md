# NAS-Downloader (SH) – ALKIS Massendownload (GUI)

Kleines Windows-Tool, das **ALKIS/NAS-Dateien für Schleswig-Holstein** automatisiert herunterlädt.  
Eingabe ist eine **GeoJSON** mit den Feldern `gemeinde`, `gemarkung`, `flur`, `link_data`.  
Das Tool lädt die Dateien direkt von den offiziellen Servern.

> **Hinweis (Daten & Lizenz):** Dieses Repository enthält **keine** ALKIS-Daten.  
> Die GeoJSON muss von der **offiziellen Quelle** bezogen werden:  
> https://geodaten.schleswig-holstein.de/gaialight-sh/_apps/dladownload/single.php?file=ALKIS_SH_Massendownload.geojson&id=4  
> **Attribution:** © GeoBasis-DE/LVermGeo SH, Datenlizenz Deutschland – Namensnennung – Version 2.0 (dl-de/by-2-0)

---

## Was das Tool kann

- **Filter in der GUI**: Gemeinde (Dropdown + Suche), „Gemarkung enthält…“, „Flur enthält…“
- **Parallele Downloads** (1–16) mit automatischen Wiederholversuchen
- **Dateinamen-Optionen**: Umlaute **behalten** oder **transliterieren** (ä→ae, ß→ss, …)
- **CSV-Index** am Ende (`download_index.csv`)

---

## Was du brauchst

- **Windows 10/11** (empfohlen; läuft auch mit Python unter Linux/macOS)
- Eine GeoJSON mit `features[].properties` und den Feldern:
  - `gemeinde` (Text)
  - `gemarkung` (Text)
  - `flur` (Text/Zahl)
  - `link_data` (**Direktlink** zur NAS-Datei)
- Internetzugang

Die Feldnamen sind im Code als Konstanten gesetzt und bei Bedarf änderbar:
`FIELD_GEMEINDE`, `FIELD_GEMARKUNG`, `FIELD_FLUR`, `FIELD_URL`.

---

## Start

### Variante A: Ausführbare Datei (.exe)
1. ZIP aus den Releases herunterladen (sofern vorhanden) und entpacken.  
2. Programm starten (Doppelklick).

### Variante B: Python (ohne Zusatzpakete)
1. **Python 3.10–3.12** installieren.  
2. Script starten:
   ```bash
   python nas_downloader.py
Für SSL-Zertifikate nutzt das Script certifi. Falls nötig:

bash
Code kopieren
pip install certifi
Bedienung (kurz)
GeoJSON wählen, Zielordner wählen.

GeoJSON laden → Anzahl der Datensätze + Gemeinden werden angezeigt.

Filter setzen (Gemeinde exakt; Gemarkung/Flur = „enthält“).

Parallelität wählen (1–16).

Umlaute: „behalten“ oder „transliterieren“.

Vorschau → zeigt eine Liste der Treffer.

Download starten → Fortschritt im Log.
Am Ende wird download_index.csv im Zielordner abgelegt.

Ablage/Benennung

Ordner: <Ziel>/<Gemeinde_sicher>/

Datei: Gemarkung__Flur_<…>__<Server- oder URL-Name>.nas

Bei Namenskonflikt wird _1, _2, … angehängt.

Fehlerhilfe
GeoJSON lädt nicht → Datei/Encoding prüfen; es muss ein features[]-Array mit properties geben.

Keine Treffer → Schreibweise/Filter prüfen (Gemeinde = exakter Name).

HTTP 403/404/Timeout → Links veraltet/Server langsam → GeoJSON von der offiziellen Quelle neu laden, später erneut versuchen.

Umlaute komisch → Modus wechseln (behalten vs. transliterieren).

Langsam/Abbrüche → Parallelität anpassen, Internet prüfen.

Rechtliches
Datenquelle: © GeoBasis-DE/LVermGeo SH, dl-de/by-2-0 (Namensnennung erforderlich).

Dieses Tool (Code): GPL-3.0 – siehe LICENSE im Repository.

Hinweis: Das Tool lädt nur von der offiziellen Quelle. Dieses Repo liefert keine amtlichen Daten mit.

yaml
Code kopieren
