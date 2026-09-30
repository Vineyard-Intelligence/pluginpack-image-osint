# Image OSINT

A Vineyard **plugin pack** with two browser-only image tools. No server, no API key — and with EXIF,
**the image never leaves your machine**.

Two plugins:

- **Reverse Image Search** — for each selected **URL** (an image link), creates ready-to-click
  reverse-image-search leads — **Google Lens, Yandex, Bing, TinEye** — as URL nodes linked
  `reverse image search`. Pure link construction; no network call is made by the plugin.
- **EXIF Extract** — reads a locally-chosen **JPEG** entirely in the browser sandbox: creates a
  **File** node with its **SHA-256** and, if the photo carries GPS EXIF, a **Location** node linked
  `captured at`. Camera make/model/timestamp are reported in the run result. The plugin has **no
  network access** — the file is picked in the Run dialog and parsed locally.

## How it works

- **Reverse Image Search** builds the well-known by-URL search endpoints for each engine and stores
  them as URL nodes, so the analyst opens the leads themselves — no fetching or scraping.
- **EXIF Extract** computes the file's SHA-256 and parses the JPEG's EXIF (including GPS) in the
  browser. GPS coordinates become a Location node. Non-JPEG or EXIF-less images still yield a hashed
  File node.

## Layout

- `plugins/image-osint.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle.

No external data sources: reverse-search leads are constructed locally, and EXIF is parsed entirely in
the browser. No credentials, no cost, no uploads.
