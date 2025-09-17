#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, certifi
os.environ["SSL_CERT_FILE"] = certifi.where()


"""
NAS-Downloader GUI (Tkinter, nur Standardbibliothek)

- Liest GeoJSON (Fluren SH) mit Feldern:
  gemeinde, gemarkung, flur, link_data
- Filter nach Gemeinde (Dropdown), optional Gemarkung/Flur
- Parallel-Download, CSV-Index
- Umlaut-Modi: behalten vs. transliterieren
"""

import concurrent.futures as cf
import csv
import html
import json
import os
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ======= Feldzuordnung (Deine Spalten) =======
FIELD_GEMEINDE  = "gemeinde"
FIELD_GEMARKUNG = "gemarkung"
FIELD_FLUR      = "flur"
FIELD_URL       = "link_data"
# ============================================

# ======= Default-Pfade (anpassbar) =======
DEFAULT_GEOJSON = r"P:\Verm\Geodaten\AAA\Katalogdaten\ALKIS_SH_Massendownload.geojson"
DEFAULT_OUTDIR  = r"P:\Verm\Geodaten\AAA\Alkis\SH\Massendownload"
# ========================================

# Umlaut-Handling
UMLAUT_MAP = {
    "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
    "Ä": "Ae", "Ö": "Oe", "Ü": "Ue",
}

SAFE_CHARS_BASE = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SAFE_CHARS_WITH_UMLAUTS = SAFE_CHARS_BASE + "äöüÄÖÜß"

def safe_filename(name: str, keep_umlauts: bool, transliterate: bool, maxlen: int = 180) -> str:
    """Sanitize filename. Wahlweise Umlaute behalten oder transliterieren."""
    s = html.unescape(str(name)).strip()
    if transliterate:
        s = "".join(UMLAUT_MAP.get(ch, ch) for ch in s)
        allowed = SAFE_CHARS_BASE
    elif keep_umlauts:
        allowed = SAFE_CHARS_WITH_UMLAUTS
    else:
        allowed = SAFE_CHARS_BASE
    s = "".join(ch if ch in allowed else "_" for ch in s)
    s = re.sub(r"_+", "_", s).strip("_. ")
    return s[:maxlen] or "file"

def guess_filename_from_headers(url: str, headers: Dict[str, str], keep_umlauts: bool, transliterate: bool) -> str:
    cd = headers.get("Content-Disposition") or headers.get("content-disposition")
    if cd:
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
        if m:
            return safe_filename(urllib.parse.unquote(m.group(1)), keep_umlauts, transliterate)
    parsed = urllib.parse.urlparse(url)
    base = Path(parsed.path).name or "download"
    return safe_filename(base, keep_umlauts, transliterate)

def http_get(url: str, timeout=60) -> (bytes, Dict[str, str]):
    req = urllib.request.Request(url, headers={"User-Agent": "NAS-Downloader/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        headers = {k: v for k, v in resp.headers.items()}
    return data, headers

def load_features(geojson_path: Path) -> List[Dict[str, Any]]:
    with geojson_path.open("r", encoding="utf-8") as f:
        gj = json.load(f)
    feats = gj.get("features") or []
    if not isinstance(feats, list):
        raise ValueError("GeoJSON hat kein gültiges 'features'-Array.")
    return feats

def list_gemeinden(features: List[Dict[str, Any]]) -> List[str]:
    vals = set()
    for ft in features:
        props = ft.get("properties") or {}
        v = props.get(FIELD_GEMEINDE)
        if v:
            vals.add(str(v))
    return sorted(vals, key=lambda s: s.lower())

def match_like(val: Optional[str], pattern: Optional[str]) -> bool:
    if pattern is None or pattern == "":
        return True
    if val is None:
        return False
    return pattern.lower() in str(val).lower()

def select_records(features: List[Dict[str, Any]], gemeinde: Optional[str],
                   flur: Optional[str], gemarkung: Optional[str]) -> List[Dict[str, Any]]:
    out = []
    for ft in features:
        props = ft.get("properties") or {}
        if not props or not props.get(FIELD_URL):
            continue
        if gemeinde and str(props.get(FIELD_GEMEINDE, "")) != gemeinde:
            continue
        if flur and not match_like(props.get(FIELD_FLUR, ""), flur):
            continue
        if gemarkung and not match_like(props.get(FIELD_GEMARKUNG, ""), gemarkung):
            continue
        out.append(props)
    return out

def write_csv_index(rows: List[Dict[str, Any]], out_csv: Path):
    fields = ["status","file","bytes","url","gemeinde","gemarkung","flur","error"]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            row = {k: r.get(k, "") for k in fields}
            w.writerow(row)

def download_one(rec: Dict[str, Any], base_out: Path, keep_umlauts: bool, transliterate: bool,
                 retry: int = 3, sleep_sec: float = 1.5) -> Dict[str, Any]:
    gemeinde = str(rec.get(FIELD_GEMEINDE, "Unbekannt")).strip() or "Unbekannt"
    gemdir = base_out / safe_filename(gemeinde, keep_umlauts, transliterate, 80)
    gemdir.mkdir(parents=True, exist_ok=True)

    url = str(rec[FIELD_URL]).strip()
    label_parts = []
    if rec.get(FIELD_GEMARKUNG):
        label_parts.append(str(rec[FIELD_GEMARKUNG]))
    if rec.get(FIELD_FLUR):
        label_parts.append(f"Flur_{rec[FIELD_FLUR]}")
    prefix = safe_filename("__".join(label_parts) if label_parts else "NAS",
                           keep_umlauts, transliterate)

    last_err = None
    for _ in range(retry):
        try:
            data, headers = http_get(url)
            fname = guess_filename_from_headers(url, headers, keep_umlauts, transliterate)
            if "." not in Path(fname).name:
                fname = fname + ".nas"
            out_name = f"{prefix}__{fname}" if prefix else fname
            out_path = gemdir / out_name

            i = 1
            stem, suffix = out_path.stem, out_path.suffix
            while out_path.exists():
                out_path = gemdir / f"{stem}_{i}{suffix}"
                i += 1

            out_path.write_bytes(data)
            return {
                "status": "ok",
                "file": str(out_path),
                "bytes": len(data),
                "url": url,
                "gemeinde": gemeinde,
                "gemarkung": rec.get(FIELD_GEMARKUNG, ""),
                "flur": rec.get(FIELD_FLUR, ""),
            }
        except Exception as e:
            last_err = e
            time.sleep(sleep_sec)
    return {
        "status": "error",
        "error": repr(last_err),
        "url": url,
        "gemeinde": gemeinde,
        "gemarkung": rec.get(FIELD_GEMARKUNG, ""),
        "flur": rec.get(FIELD_FLUR, ""),
    }

# ---------------- GUI ----------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NAS-Downloader (SH) – 9gradost")
        self.geometry("820x560")

        self.geojson_var = tk.StringVar(value=DEFAULT_GEOJSON)
        self.outdir_var  = tk.StringVar(value=DEFAULT_OUTDIR)
        self.gemeinde_var = tk.StringVar()
        self.gemarkung_var = tk.StringVar()
        self.flur_var = tk.StringVar()
        self.conc_var = tk.IntVar(value=6)
        self.keep_umlauts_var = tk.BooleanVar(value=True)
        self.translit_var = tk.BooleanVar(value=False)

        self.features: List[Dict[str, Any]] = []
        self.gemeinden: List[str] = []
        self.gemeinden_all: List[str] = []  # ungefilterte Voll-Liste

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        # Pfade
        frm_paths = ttk.LabelFrame(self, text="Pfade")
        frm_paths.pack(fill="x", **pad)

        ttk.Label(frm_paths, text="GeoJSON:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_paths, textvariable=self.geojson_var, width=80).grid(row=0, column=1, sticky="we")
        ttk.Button(frm_paths, text="…", command=self.browse_geojson).grid(row=0, column=2)
        frm_paths.grid_columnconfigure(1, weight=1)

        ttk.Label(frm_paths, text="Zielordner:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm_paths, textvariable=self.outdir_var, width=80).grid(row=1, column=1, sticky="we")
        ttk.Button(frm_paths, text="…", command=self.browse_outdir).grid(row=1, column=2)

        # Filter
        frm_filters = ttk.LabelFrame(self, text="Filter")
        frm_filters.pack(fill="x", **pad)

        ttk.Button(frm_filters, text="GeoJSON laden", command=self.load_geojson).grid(row=0, column=0, sticky="w")

        ttk.Label(frm_filters, text="Gemeinde:").grid(row=1, column=0, sticky="w")
        self.cmb_gemeinde = ttk.Combobox(frm_filters, textvariable=self.gemeinde_var, values=[], state="normal", width=40)
        # Tippen → live filtern / springen
        self.cmb_gemeinde.bind("<KeyRelease>", self._on_gemeinde_type)
        # Enter → ersten Treffer übernehmen
        self.cmb_gemeinde.bind("<Return>", self._on_gemeinde_accept)
        self.cmb_gemeinde.grid(row=1, column=1, sticky="w")

        ttk.Label(frm_filters, text="Gemarkung (enthält):").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm_filters, textvariable=self.gemarkung_var, width=42).grid(row=2, column=1, sticky="w")

        ttk.Label(frm_filters, text="Flur (enthält):").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm_filters, textvariable=self.flur_var, width=42).grid(row=3, column=1, sticky="w")

        ttk.Label(frm_filters, text="Parallel (1–16):").grid(row=4, column=0, sticky="w")
        ttk.Spinbox(frm_filters, from_=1, to=16, textvariable=self.conc_var, width=6).grid(row=4, column=1, sticky="w")

        # Umlaute
        frm_umlaut = ttk.LabelFrame(self, text="Umlaute in Datei-/Ordnernamen")
        frm_umlaut.pack(fill="x", **pad)
        ttk.Checkbutton(frm_umlaut, text="Umlaute behalten (ä/ö/ü/ß)", variable=self.keep_umlauts_var,
                        command=self._umlaut_mode_changed).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(frm_umlaut, text="Stattdessen transliterieren (ae/oe/ue/ss)",
                        variable=self.translit_var, command=self._umlaut_mode_changed).grid(row=0, column=1, sticky="w")

        # Aktionen
        frm_actions = ttk.Frame(self)
        frm_actions.pack(fill="x", **pad)
        ttk.Button(frm_actions, text="Vorschau", command=self.preview).pack(side="left")
        ttk.Button(frm_actions, text="Download", command=self.download).pack(side="left")

        # Log
        frm_log = ttk.LabelFrame(self, text="Ausgabe")
        frm_log.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(frm_log, height=16)
        self.txt.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Bereit")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w", padx=8, pady=4)

    def _umlaut_mode_changed(self):
        # Exklusiv schalten
        if self.keep_umlauts_var.get() and self.translit_var.get():
            # Priorität: translit an => keep aus
            self.keep_umlauts_var.set(False)

    def browse_geojson(self):
        p = filedialog.askopenfilename(title="GeoJSON wählen", filetypes=[("GeoJSON", "*.geojson;*.json"), ("Alle Dateien", "*.*")])
        if p:
            self.geojson_var.set(p)

    def browse_outdir(self):
        d = filedialog.askdirectory(title="Zielordner wählen")
        if d:
            self.outdir_var.set(d)

    def load_geojson(self):
        path = Path(self.geojson_var.get())
        try:
            feats = load_features(path)
            self.features = feats
            self.gemeinden_all = list_gemeinden(feats)
            self.gemeinden = self.gemeinden_all[:]  # Start = ungefiltert
            self.cmb_gemeinde["values"] = self.gemeinden
            if self.gemeinden and not self.gemeinde_var.get():
                self.gemeinde_var.set(self.gemeinden[0])
            self.log(f"GeoJSON geladen: {path} – {len(feats)} Features, {len(self.gemeinden)} Gemeinden.")
        except Exception as e:
            messagebox.showerror("Fehler", f"GeoJSON konnte nicht geladen werden:\n{e}")

    def _collect_records(self) -> List[Dict[str, Any]]:
        if not self.features:
            self.load_geojson()
            if not self.features:
                return []
        recs = select_records(
            self.features,
            self.gemeinde_var.get(),
            self.flur_var.get().strip() or None,
            self.gemarkung_var.get().strip() or None,
        )
        return recs

    def preview(self):
        recs = self._collect_records()
        self.txt.delete("1.0", "end")
        self.log(f"Ausgewählte Datensätze: {len(recs)}")
        for r in recs[:500]:  # nicht endlos
            self.log(f"- {r.get(FIELD_GEMEINDE,'?')} | {r.get(FIELD_GEMARKUNG,'')} | {r.get(FIELD_FLUR,'')} -> {r.get(FIELD_URL)}")
        if len(recs) > 500:
            self.log(f"... ({len(recs)-500} weitere)")

    def download(self):
        out_dir = Path(self.outdir_var.get())
        if not out_dir.exists():
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Fehler", f"Zielordner kann nicht erstellt werden:\n{e}")
                return

        recs = self._collect_records()
        if not recs:
            messagebox.showinfo("Hinweis", "Keine Datensätze für die Filter gefunden.")
            return

        conc = max(1, min(16, int(self.conc_var.get())))
        keep_umlauts = bool(self.keep_umlauts_var.get())
        translit = bool(self.translit_var.get())

        self.txt.delete("1.0", "end")
        self.log(f"Starte Download: {len(recs)} Datensätze, Parallel={conc}")
        self.status_var.set("Download läuft…")

        results: List[Dict[str, Any]] = []
        q = queue.Queue()

        def worker():
            with cf.ThreadPoolExecutor(max_workers=conc) as ex:
                futs = [ex.submit(download_one, r, out_dir, keep_umlauts, translit) for r in recs]
                for fut in cf.as_completed(futs):
                    res = fut.result()
                    q.put(res)
            q.put(None)  # fertig

        threading.Thread(target=worker, daemon=True).start()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, certifi
os.environ["SSL_CERT_FILE"] = certifi.where()


"""
NAS-Downloader GUI (Tkinter, nur Standardbibliothek)

- Liest GeoJSON (Fluren SH) mit Feldern:
  gemeinde, gemarkung, flur, link_data
- Filter nach Gemeinde (Dropdown), optional Gemarkung/Flur
- Parallel-Download, CSV-Index
- Umlaut-Modi: behalten vs. transliterieren
"""

import concurrent.futures as cf
import csv
import html
import json
import os
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ======= Feldzuordnung (Deine Spalten) =======
FIELD_GEMEINDE  = "gemeinde"
FIELD_GEMARKUNG = "gemarkung"
FIELD_FLUR      = "flur"
FIELD_URL       = "link_data"
# ============================================

# ======= Default-Pfade (anpassbar) =======
DEFAULT_GEOJSON = r"P:\Verm\Geodaten\AAA\Katalogdaten\ALKIS_SH_Massendownload.geojson"
DEFAULT_OUTDIR  = r"P:\Verm\Geodaten\AAA\Alkis\SH\Massendownload"
# ========================================

# Umlaut-Handling
UMLAUT_MAP = {
    "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
    "Ä": "Ae", "Ö": "Oe", "Ü": "Ue",
}

SAFE_CHARS_BASE = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SAFE_CHARS_WITH_UMLAUTS = SAFE_CHARS_BASE + "äöüÄÖÜß"

def safe_filename(name: str, keep_umlauts: bool, transliterate: bool, maxlen: int = 180) -> str:
    """Sanitize filename. Wahlweise Umlaute behalten oder transliterieren."""
    s = html.unescape(str(name)).strip()
    if transliterate:
        s = "".join(UMLAUT_MAP.get(ch, ch) for ch in s)
        allowed = SAFE_CHARS_BASE
    elif keep_umlauts:
        allowed = SAFE_CHARS_WITH_UMLAUTS
    else:
        allowed = SAFE_CHARS_BASE
    s = "".join(ch if ch in allowed else "_" for ch in s)
    s = re.sub(r"_+", "_", s).strip("_. ")
    return s[:maxlen] or "file"

def guess_filename_from_headers(url: str, headers: Dict[str, str], keep_umlauts: bool, transliterate: bool) -> str:
    cd = headers.get("Content-Disposition") or headers.get("content-disposition")
    if cd:
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
        if m:
            return safe_filename(urllib.parse.unquote(m.group(1)), keep_umlauts, transliterate)
    parsed = urllib.parse.urlparse(url)
    base = Path(parsed.path).name or "download"
    return safe_filename(base, keep_umlauts, transliterate)

def http_get(url: str, timeout=60) -> (bytes, Dict[str, str]):
    req = urllib.request.Request(url, headers={"User-Agent": "NAS-Downloader/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        headers = {k: v for k, v in resp.headers.items()}
    return data, headers

def load_features(geojson_path: Path) -> List[Dict[str, Any]]:
    with geojson_path.open("r", encoding="utf-8") as f:
        gj = json.load(f)
    feats = gj.get("features") or []
    if not isinstance(feats, list):
        raise ValueError("GeoJSON hat kein gültiges 'features'-Array.")
    return feats

def list_gemeinden(features: List[Dict[str, Any]]) -> List[str]:
    vals = set()
    for ft in features:
        props = ft.get("properties") or {}
        v = props.get(FIELD_GEMEINDE)
        if v:
            vals.add(str(v))
    return sorted(vals, key=lambda s: s.lower())

def match_like(val: Optional[str], pattern: Optional[str]) -> bool:
    if pattern is None or pattern == "":
        return True
    if val is None:
        return False
    return pattern.lower() in str(val).lower()

def select_records(features: List[Dict[str, Any]], gemeinde: Optional[str],
                   flur: Optional[str], gemarkung: Optional[str]) -> List[Dict[str, Any]]:
    out = []
    for ft in features:
        props = ft.get("properties") or {}
        if not props or not props.get(FIELD_URL):
            continue
        if gemeinde and str(props.get(FIELD_GEMEINDE, "")) != gemeinde:
            continue
        if flur and not match_like(props.get(FIELD_FLUR, ""), flur):
            continue
        if gemarkung and not match_like(props.get(FIELD_GEMARKUNG, ""), gemarkung):
            continue
        out.append(props)
    return out

def write_csv_index(rows: List[Dict[str, Any]], out_csv: Path):
    fields = ["status","file","bytes","url","gemeinde","gemarkung","flur","error"]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            row = {k: r.get(k, "") for k in fields}
            w.writerow(row)

def download_one(rec: Dict[str, Any], base_out: Path, keep_umlauts: bool, transliterate: bool,
                 retry: int = 3, sleep_sec: float = 1.5) -> Dict[str, Any]:
    gemeinde = str(rec.get(FIELD_GEMEINDE, "Unbekannt")).strip() or "Unbekannt"
    gemdir = base_out / safe_filename(gemeinde, keep_umlauts, transliterate, 80)
    gemdir.mkdir(parents=True, exist_ok=True)

    url = str(rec[FIELD_URL]).strip()
    label_parts = []
    if rec.get(FIELD_GEMARKUNG):
        label_parts.append(str(rec[FIELD_GEMARKUNG]))
    if rec.get(FIELD_FLUR):
        label_parts.append(f"Flur_{rec[FIELD_FLUR]}")
    prefix = safe_filename("__".join(label_parts) if label_parts else "NAS",
                           keep_umlauts, transliterate)

    last_err = None
    for _ in range(retry):
        try:
            data, headers = http_get(url)
            fname = guess_filename_from_headers(url, headers, keep_umlauts, transliterate)
            if "." not in Path(fname).name:
                fname = fname + ".nas"
            out_name = f"{prefix}__{fname}" if prefix else fname
            out_path = gemdir / out_name

            i = 1
            stem, suffix = out_path.stem, out_path.suffix
            while out_path.exists():
                out_path = gemdir / f"{stem}_{i}{suffix}"
                i += 1

            out_path.write_bytes(data)
            return {
                "status": "ok",
                "file": str(out_path),
                "bytes": len(data),
                "url": url,
                "gemeinde": gemeinde,
                "gemarkung": rec.get(FIELD_GEMARKUNG, ""),
                "flur": rec.get(FIELD_FLUR, ""),
            }
        except Exception as e:
            last_err = e
            time.sleep(sleep_sec)
    return {
        "status": "error",
        "error": repr(last_err),
        "url": url,
        "gemeinde": gemeinde,
        "gemarkung": rec.get(FIELD_GEMARKUNG, ""),
        "flur": rec.get(FIELD_FLUR, ""),
    }

# ---------------- GUI ----------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NAS-Downloader (SH) – 9gradost")
        self.geometry("820x560")

        self.geojson_var = tk.StringVar(value=DEFAULT_GEOJSON)
        self.outdir_var  = tk.StringVar(value=DEFAULT_OUTDIR)
        self.gemeinde_var = tk.StringVar()
        self.gemarkung_var = tk.StringVar()
        self.flur_var = tk.StringVar()
        self.conc_var = tk.IntVar(value=6)
        self.keep_umlauts_var = tk.BooleanVar(value=True)
        self.translit_var = tk.BooleanVar(value=False)

        self.features: List[Dict[str, Any]] = []
        self.gemeinden: List[str] = []
        self.gemeinden_all: List[str] = []  # ungefilterte Voll-Liste

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        # Pfade
        frm_paths = ttk.LabelFrame(self, text="Pfade")
        frm_paths.pack(fill="x", **pad)

        ttk.Label(frm_paths, text="GeoJSON:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm_paths, textvariable=self.geojson_var, width=80).grid(row=0, column=1, sticky="we")
        ttk.Button(frm_paths, text="…", command=self.browse_geojson).grid(row=0, column=2)
        frm_paths.grid_columnconfigure(1, weight=1)

        ttk.Label(frm_paths, text="Zielordner:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm_paths, textvariable=self.outdir_var, width=80).grid(row=1, column=1, sticky="we")
        ttk.Button(frm_paths, text="…", command=self.browse_outdir).grid(row=1, column=2)

        # Filter
        frm_filters = ttk.LabelFrame(self, text="Filter")
        frm_filters.pack(fill="x", **pad)

        ttk.Button(frm_filters, text="GeoJSON laden", command=self.load_geojson).grid(row=0, column=0, sticky="w")

        ttk.Label(frm_filters, text="Gemeinde:").grid(row=1, column=0, sticky="w")
        self.cmb_gemeinde = ttk.Combobox(frm_filters, textvariable=self.gemeinde_var, values=[], state="normal", width=40)
        # Tippen → live filtern / springen
        self.cmb_gemeinde.bind("<KeyRelease>", self._on_gemeinde_type)
        # Enter → ersten Treffer übernehmen
        self.cmb_gemeinde.bind("<Return>", self._on_gemeinde_accept)
        self.cmb_gemeinde.grid(row=1, column=1, sticky="w")

        ttk.Label(frm_filters, text="Gemarkung (enthält):").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm_filters, textvariable=self.gemarkung_var, width=42).grid(row=2, column=1, sticky="w")

        ttk.Label(frm_filters, text="Flur (enthält):").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm_filters, textvariable=self.flur_var, width=42).grid(row=3, column=1, sticky="w")

        ttk.Label(frm_filters, text="Parallel (1–16):").grid(row=4, column=0, sticky="w")
        ttk.Spinbox(frm_filters, from_=1, to=16, textvariable=self.conc_var, width=6).grid(row=4, column=1, sticky="w")

        # Umlaute
        frm_umlaut = ttk.LabelFrame(self, text="Umlaute in Datei-/Ordnernamen")
        frm_umlaut.pack(fill="x", **pad)
        ttk.Checkbutton(frm_umlaut, text="Umlaute behalten (ä/ö/ü/ß)", variable=self.keep_umlauts_var,
                        command=self._umlaut_mode_changed).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(frm_umlaut, text="Stattdessen transliterieren (ae/oe/ue/ss)",
                        variable=self.translit_var, command=self._umlaut_mode_changed).grid(row=0, column=1, sticky="w")

        # Aktionen
        frm_actions = ttk.Frame(self)
        frm_actions.pack(fill="x", **pad)
        ttk.Button(frm_actions, text="Vorschau", command=self.preview).pack(side="left")
        ttk.Button(frm_actions, text="Download", command=self.download).pack(side="left")

        # Log
        frm_log = ttk.LabelFrame(self, text="Ausgabe")
        frm_log.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(frm_log, height=16)
        self.txt.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Bereit")
        ttk.Label(self, textvariable=self.status_var).pack(anchor="w", padx=8, pady=4)

    def _umlaut_mode_changed(self):
        # Exklusiv schalten
        if self.keep_umlauts_var.get() and self.translit_var.get():
            # Priorität: translit an => keep aus
            self.keep_umlauts_var.set(False)

    def browse_geojson(self):
        p = filedialog.askopenfilename(title="GeoJSON wählen", filetypes=[("GeoJSON", "*.geojson;*.json"), ("Alle Dateien", "*.*")])
        if p:
            self.geojson_var.set(p)

    def browse_outdir(self):
        d = filedialog.askdirectory(title="Zielordner wählen")
        if d:
            self.outdir_var.set(d)

    def load_geojson(self):
        path = Path(self.geojson_var.get())
        try:
            feats = load_features(path)
            self.features = feats
            self.gemeinden_all = list_gemeinden(feats)
            self.gemeinden = self.gemeinden_all[:]  # Start = ungefiltert
            self.cmb_gemeinde["values"] = self.gemeinden
            if self.gemeinden and not self.gemeinde_var.get():
                self.gemeinde_var.set(self.gemeinden[0])
            self.log(f"GeoJSON geladen: {path} – {len(feats)} Features, {len(self.gemeinden)} Gemeinden.")
        except Exception as e:
            messagebox.showerror("Fehler", f"GeoJSON konnte nicht geladen werden:\n{e}")

    def _collect_records(self) -> List[Dict[str, Any]]:
        if not self.features:
            self.load_geojson()
            if not self.features:
                return []
        recs = select_records(
            self.features,
            self.gemeinde_var.get(),
            self.flur_var.get().strip() or None,
            self.gemarkung_var.get().strip() or None,
        )
        return recs

    def preview(self):
        recs = self._collect_records()
        self.txt.delete("1.0", "end")
        self.log(f"Ausgewählte Datensätze: {len(recs)}")
        for r in recs[:500]:  # nicht endlos
            self.log(f"- {r.get(FIELD_GEMEINDE,'?')} | {r.get(FIELD_GEMARKUNG,'')} | {r.get(FIELD_FLUR,'')} -> {r.get(FIELD_URL)}")
        if len(recs) > 500:
            self.log(f"... ({len(recs)-500} weitere)")

    def download(self):
        out_dir = Path(self.outdir_var.get())
        if not out_dir.exists():
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Fehler", f"Zielordner kann nicht erstellt werden:\n{e}")
                return

        recs = self._collect_records()
        if not recs:
            messagebox.showinfo("Hinweis", "Keine Datensätze für die Filter gefunden.")
            return

        conc = max(1, min(16, int(self.conc_var.get())))
        keep_umlauts = bool(self.keep_umlauts_var.get())
        translit = bool(self.translit_var.get())

        self.txt.delete("1.0", "end")
        self.log(f"Starte Download: {len(recs)} Datensätze, Parallel={conc}")
        self.status_var.set("Download läuft…")

        results: List[Dict[str, Any]] = []
        q = queue.Queue()

        def worker():
            with cf.ThreadPoolExecutor(max_workers=conc) as ex:
                futs = [ex.submit(download_one, r, out_dir, keep_umlauts, translit) for r in recs]
                for fut in cf.as_completed(futs):
                    res = fut.result()
                    q.put(res)
            q.put(None)  # fertig

        threading.Thread(target=worker, daemon=True).start()

        def poll():
            try:
                while True:
                    item = q.get_nowait()
                    if item is None:
                        # fertig
                        ok = sum(1 for r in results if r.get("status") == "ok")
                        err = sum(1 for r in results if r.get("status") != "ok")
                        self.log(f"✅ Fertig: {ok} ok, {err} Fehler.")
                        csv_path = Path(out_dir) / "download_index.csv"
                        write_csv_index(results, csv_path)
                        self.log(f"📄 Index gespeichert: {csv_path}")
                        self.status_var.set("Fertig")
                        return
                    results.append(item)
                    if item.get("status") == "ok":
                        self.log(f"[OK] {item.get('file')}  ({item.get('bytes')} Bytes)")
                    else:
                        self.log(f"[FEHLER] {item.get('url')}  -> {item.get('error')}")
            except queue.Empty:
                self.after(200, poll)

        poll()

    def log(self, msg: str):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")

    def _filter_gemeinden(self, text: str) -> list[str]:
        if not text:
            return self.gemeinden_all[:]
        t = text.lower()
        starts = [g for g in self.gemeinden_all if g.lower().startswith(t)]
        if starts:
            return starts
        return [g for g in self.gemeinden_all if t in g.lower()]

    def _on_gemeinde_type(self, event):
        # Tasten ignorieren, die keinen Text ändern
        if event.keysym in ("Up", "Down", "Left", "Right", "Home", "End", "Tab", "Escape"):
            return

        typed = self.cmb_gemeinde.get()
        matches = self._filter_gemeinden(typed)

        # Liste im Dropdown aktualisieren
        self.gemeinden = matches
        self.cmb_gemeinde["values"] = matches

        if not matches:
            # Nichts zu vervollständigen
            self.cmb_gemeinde.selection_clear()
            return

        # Bei Backspace nur Liste aktualisieren, keine Auto-Vervollständigung
        if event.keysym == "BackSpace" or not typed:
            # Dropdown zeigen, damit man Auswahl sieht
            self.cmb_gemeinde.event_generate("<Down>")
            self.cmb_gemeinde.event_generate("<Up>")
            return

        best = matches[0]
        # Nur ergänzen, wenn bester Treffer wirklich mit Eingabe beginnt
        if best.lower().startswith(typed.lower()):
            # kompletten Vorschlag einsetzen, eigenen Teil selektionssicher lassen
            self.cmb_gemeinde.delete(0, tk.END)
            self.cmb_gemeinde.insert(0, best)
            # Nur den „angehängten“ Teil markieren
            self.cmb_gemeinde.selection_range(len(typed), tk.END)
            self.cmb_gemeinde.icursor(len(typed))

        # Dropdown kurz öffnen/schließen, damit Vorschläge sichtbar sind
        self.cmb_gemeinde.event_generate("<Down>")
        self.cmb_gemeinde.event_generate("<Up>")

    def _on_gemeinde_accept(self, event):
        if self.gemeinden:
            self.cmb_gemeinde.set(self.gemeinden[0])
            self.cmb_gemeinde.selection_clear()
            self.cmb_gemeinde.icursor("end")


        

if __name__ == "__main__":
    app = App()
    app.mainloop()
