# NAS Downloader (SH) – ALKIS Bulk Download (GUI)

Small Windows tool that automates the download of **ALKIS/NAS files for Schleswig-Holstein**.  
Input is a **GeoJSON** with the fields `gemeinde`, `gemarkung`, `flur`, `link_data`.  
The tool downloads the files directly from the official servers.

> **Note (Data & License):** This repository does **not** include any ALKIS data.  
> The GeoJSON must be obtained from the **official source**:  
> https://geodaten.schleswig-holstein.de/gaialight-sh/_apps/dladownload/single.php?file=ALKIS_SH_Massendownload.geojson&id=4  
> **Attribution:** © GeoBasis-DE/LVermGeo SH, Data License Germany – Attribution – Version 2.0 (dl-de/by-2-0)

---

## Features

- **GUI filters**: Municipality (dropdown + search), “Gemarkung contains…”, “Flur contains…”  
- **Parallel downloads** (1–16) with automatic retries  
- **Filename options**: keep umlauts or transliterate (ä→ae, ß→ss, …)  
- **CSV index** at the end (`download_index.csv`)  

---

## Requirements

- **Windows 10/11** (recommended; also works with Python under Linux/macOS)  
- A GeoJSON with `features[].properties` containing the fields:  
  - `gemeinde` (text)  
  - `gemarkung` (text)  
  - `flur` (text/number)  
  - `link_data` (direct link to NAS file)  
- Internet access  

The field names are defined as constants in the code and can be adjusted:  
`FIELD_GEMEINDE`, `FIELD_GEMARKUNG`, `FIELD_FLUR`, `FIELD_URL`.  

---

## Getting Started

### Option A: Executable (.exe)

1. Download ZIP from Releases (if available) and extract.  
2. Run the program (double-click).  

### Option B: Python (no extra packages)

1. Install **Python 3.10–3.12**  
2. Run the script:  
   ```bash
   python nas_downloader.py

---

## Usage (short)

1. **Select GeoJSON**, **select output folder**
2. **Load GeoJSON** → number of records + municipalities is displayed
3. **Set filters**
   - Municipality = exact name
   - Gemarkung / Flur = "contains"
4. **Set parallel downloads** (1–16)
5. **Umlauts**: keep or transliterate
6. **Preview** → shows a list of matching records
7. **Start download**
   - Progress visible in the log
   - At the end, `download_index.csv` is written to the output folder

---

## File Storage / Naming

- **Folder:** `/<output>/<safe_municipality_name>/`
- **File:** `Gemarkung__Flur_<…>__<Name>.nas`
- **Name conflicts:** `_1`, `_2`, … are appended automatically

---

## Troubleshooting

- **GeoJSON not loading** → check file/encoding; must have a `features[]` array with `properties`.
- **No matches** → check spelling/filter (municipality = exact match).
- **HTTP 403 / 404 / Timeout** → links outdated or server slow → download a fresh GeoJSON from official source and retry later.
- **Umlauts look wrong** → switch mode (keep vs. transliterate).
- **Slow/unstable** → adjust parallel download setting, check internet connection.

---

## Legal

- **Data source:** © GeoBasis-DE/LVermGeo SH, **dl-de/by-2-0** (attribution required).
- **This tool (code):** GPL-3.0 – see `LICENSE` in the repository.
- **Note:** This tool only downloads from the official source. This repo does **not** contain any official data.
