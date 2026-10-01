# Image OSINT

A Vineyard **plugin pack** with one browser-only image tool. No server, no API key — and
**the image never leaves your machine**.

One plugin:

- **EXIF Extract** (`run.vineyard.plugins.exif_extract`) — reads photos picked in the Run dialog
  (no selection), locally without uploading them. Creates a **File** node per photo with its
  **SHA-256** and, for JPEGs, EXIF fields (camera make/model, body serial, lens, capture time,
  software), plus a **Location** node linked `captured at` when the photo has GPS coordinates.

## How it works

- **EXIF Extract** computes the file's SHA-256 and parses the JPEG's EXIF (including GPS) in the
  browser. GPS coordinates become a Location node. Non-JPEG or EXIF-less images still yield a hashed
  File node.

## Layout

- `plugins/image-osint.manifest.json` — the pack manifest (catalog entry source).
- `dist/` — runnable bundle.

No external data sources: EXIF is parsed entirely in the browser. No credentials, no cost, no uploads.
