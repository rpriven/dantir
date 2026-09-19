# Dantir Map

Put your Dantir exports on a map. One HTML file, no install, nothing uploaded.

## Quick start

1. Download **`dantir-map.standalone.html`** (one file, Leaflet inlined, nothing else needed),
   or clone the repo and use `dantir-map.html` with the `vendor/` folder beside it.
2. Open it in a browser. Nothing is hosted anywhere; it runs from your disk.
3. Drop your exports on it: the `.json`, `.kml`, or `.csv` files the dashboard's
   DOWNLOAD buttons give you. Drop as many as you like; sessions merge by MAC.

Try it first with the two synthetic sessions in `sample/` (`synthetic-2026-01-0*.json`: fake MACs, coordinates in
the ocean at Null Island, two devices repeated across both days).

## What you get

- **Markers by category**, dark theme matched to the device dashboard, with the same three
  themes (purple, tactical, ithildin) in a switcher on the drop page and the stats box.
  Only categories that actually have markers are listed. Click a legend row
  to hide that category, shift-click to show only it, `all` / `none` to reset.
- **Basemap picker** (top-right, the layers icon): ESRI dark gray, ESRI street, ESRI
  satellite, OpenStreetMap, CARTO, or **None**. The page starts with **None** so nothing about
  where your data sits leaves the machine until you choose; your pick is remembered in the
  browser, and `?basemap=dark|street|satellite|osm|carto|none` on the URL overrides it. With
  None the page makes zero network requests. OpenStreetMap refuses tiles to a page opened from disk (no
  Referer) and CARTO watermarks without an API key; they are listed so you can
  try them if that changes.
- **Session-date filter** (bottom-left): click a date to drop that session from the
  merge, shift-click to show only it. Counts, fixed-install verdicts and markers all
  recompute from the dates left on, so "what was new on Tuesday" is one click.
- **Popups** with names, method, best RSSI, total hits, and the session dates the
  device was seen.
- **Fixed-install test.** A MAC seen on two or more session dates with every fix
  within 150 m of its best-signal spot is flagged *fixed install*. A pole-mounted
  camera passes; a body cam or an in-car unit driving past does not. For the
  `axon` and `lawenf` categories the map splits them into `_fixed` / `_mobile` on
  that basis, because one detection cannot tell those apart and three drives can.
- **Export merged JSON** from the stats box: one record per MAC across everything
  you dropped, including the fixed-install verdict.

Detections without GPS (phone screen off, GPS not enabled on the dashboard) are
counted in the stats box but cannot be plotted.

The standalone file is regenerated with `bun tools/map/build-map.ts --standalone -o tools/map/dantir-map.standalone.html`
whenever the page changes; the two are the same renderer.

## Baking many sessions into one file

```
bun tools/map/build-map.ts path/to/exports/ -o my-map.html
```

Walks the paths you give it for Dantir JSON exports, embeds them and Leaflet into a
single self-contained HTML file. Open it anywhere. The output holds your MACs and
coordinates: keep it out of git and off the web.

Session dates come from the export filename (`dantir_YYYY-MM-DD_HHMMSS.json`);
files named differently fall back to their modification date.

## Privacy notes

- Everything runs in your browser. The only outbound traffic is basemap tiles from
  the provider you pick, and a tile request tells that provider roughly where you
  are looking. Choose **None** if that matters to you, or point the page at a
  self-hosted tile server.
- Leaflet is vendored under `vendor/leaflet/` (BSD-2, see its LICENSE) so the page
  does not load anything from a CDN.
- The repo never contains real exports. `.gitignore` refuses `dantir_*.json`,
  `*.kml`, `*.csv` under `data/`, and `tools/map/out/`. The maintainer's pre-commit
  gate (not shipped in this repo) additionally blocks full MAC addresses and coordinate
  pairs; the synthetic sample uses the locally-administered `02:da:` prefix, which is
  the one exception it allows (`.redteamignore`).

## Formats

| File | What is read |
|------|--------------|
| `.json` | The canonical export: an array of detections with `mac`, `cat`, `method`, `count`, `rssi`, `best_rssi`, `gps`, `best_gps`. Also accepts `{ "detections": [...] }`. |
| `.kml` | Placemarks named by MAC; category, method, RSSI and count are read back out of the description. |
| `.csv` | The dashboard CSV (header row with `mac`, `latitude`, `best_latitude`, ...). |

The JSON export is the richest; prefer it when you have the choice. KML and CSV carry no
category field, so devices from those files are categorized from their advertised name
(`Penguin-…` → flock, `Ring …` → ring, `wyze_hub` → camera, and so on) and otherwise land
in `unknown`.
