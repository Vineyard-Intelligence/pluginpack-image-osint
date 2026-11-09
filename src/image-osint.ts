// Image OSINT — EXIF Extract: locally-chosen images → a SHA-256 File node each + (if the photo
// carries GPS) a Location node, parsed ENTIRELY in the sandbox. The image bytes are read in the
// browser and never leave it — the plugin has NO network scope.
//
// EXIF takes its images from `ctx.params.images` — the File objects the Run dialog's picker produced,
// handed straight across the sandbox boundary — so it declares `consumes: []` (selection-aware)
// rather than a node type. One run handles the whole batch: an analyst emptying a camera folder
// wants one task and one review, not one per photo.
import { definePlugin, definePluginPack } from './sdk';
import type { RunResult } from './sdk';

// =====================================================================================
// EXIF Extract (pure client-side binary parse; zero network)
// =====================================================================================
interface ExifOut {
    make?: string;
    model?: string;
    software?: string;
    dateTime?: string;
    /** Camera body serial (Exif 0xA431) — the tag that ties two photos to one physical camera. */
    bodySerial?: string;
    lensModel?: string;
    gps?: { lat: number; lon: number };
}

// Minimal JPEG/Exif reader: SOI → APP1("Exif") → TIFF → IFD0 (+ Exif/GPS sub-IFDs).
function parseJpegExif(b: Uint8Array): ExifOut | null {
    if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null; // not a JPEG
    // Find the APP1 (0xFFE1) segment that starts with "Exif\0\0".
    let p = 2;
    let tiff = -1;
    while (p + 4 < b.length) {
        if (b[p] !== 0xff) break;
        const marker = b[p + 1];
        const len = (b[p + 2] << 8) | b[p + 3];
        if (marker === 0xd9 || marker === 0xda) break; // EOI / start of scan
        if (marker === 0xe1 && b[p + 4] === 0x45 && b[p + 5] === 0x78 && b[p + 6] === 0x69 && b[p + 7] === 0x66) {
            tiff = p + 10; // skip "Exif\0\0"
            break;
        }
        p += 2 + len;
    }
    if (tiff < 0 || tiff + 8 > b.length) return null;

    const le = b[tiff] === 0x49 && b[tiff + 1] === 0x49; // 'II' little-endian, else 'MM' big-endian
    const u16 = (o: number) => (le ? b[o] | (b[o + 1] << 8) : (b[o] << 8) | b[o + 1]);
    const u32 = (o: number) => (le ? (u16(o) | (u16(o + 2) << 16)) >>> 0 : ((u16(o) << 16) | u16(o + 2)) >>> 0);

    const readIfd = (ifdOff: number): Map<number, { type: number; count: number; valOff: number }> => {
        const out = new Map<number, { type: number; count: number; valOff: number }>();
        if (ifdOff + 2 > b.length) return out;
        const n = u16(ifdOff);
        for (let i = 0; i < n; i++) {
            const e = ifdOff + 2 + i * 12;
            if (e + 12 > b.length) break;
            const tag = u16(e);
            const type = u16(e + 2);
            const count = u32(e + 4);
            out.set(tag, { type, count, valOff: e + 8 });
        }
        return out;
    };
    const typeSize: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
    const valueOffset = (ent: { type: number; count: number; valOff: number }) => {
        const size = (typeSize[ent.type] || 1) * ent.count;
        return size <= 4 ? ent.valOff : tiff + u32(ent.valOff);
    };
    const readAscii = (ent?: { type: number; count: number; valOff: number }) => {
        if (!ent) return '';
        const start = valueOffset(ent);
        let s = '';
        for (let i = 0; i < ent.count && start + i < b.length; i++) {
            const c = b[start + i];
            if (c === 0) break;
            s += String.fromCharCode(c);
        }
        return s.trim();
    };
    const readRational = (off: number): number => {
        const num = u32(off);
        const den = u32(off + 4);
        return den ? num / den : 0;
    };

    try {
        const ifd0 = readIfd(tiff + u32(tiff + 4));
        const out: ExifOut = {};
        out.make = readAscii(ifd0.get(0x010f)) || undefined;
        out.model = readAscii(ifd0.get(0x0110)) || undefined;
        out.software = readAscii(ifd0.get(0x0131)) || undefined;
        out.dateTime = readAscii(ifd0.get(0x0132)) || undefined;

        const exifPtr = ifd0.get(0x8769);
        if (exifPtr) {
            const exifIfd = readIfd(tiff + u32(exifPtr.valOff));
            out.dateTime = readAscii(exifIfd.get(0x9003)) || out.dateTime; // DateTimeOriginal preferred
            out.bodySerial = readAscii(exifIfd.get(0xa431)) || undefined; // BodySerialNumber
            out.lensModel = readAscii(exifIfd.get(0xa434)) || undefined; // LensModel
        }

        const gpsPtr = ifd0.get(0x8825);
        if (gpsPtr) {
            const gps = readIfd(tiff + u32(gpsPtr.valOff));
            const latRef = readAscii(gps.get(0x0001));
            const lonRef = readAscii(gps.get(0x0003));
            const latE = gps.get(0x0002);
            const lonE = gps.get(0x0004);
            if (latE && lonE) {
                const dms = (ent: { type: number; count: number; valOff: number }) => {
                    const o = valueOffset(ent);
                    return readRational(o) + readRational(o + 8) / 60 + readRational(o + 16) / 3600;
                };
                let lat = dms(latE);
                let lon = dms(lonE);
                if (/S/i.test(latRef)) lat = -lat;
                if (/W/i.test(lonRef)) lon = -lon;
                // Require a hemisphere ref to distinguish a genuine 0,0 fix from an empty GPS IFD
                // (all-zero rationals with no refs), rather than dropping the valid 0,0 coordinate.
                if (Number.isFinite(lat) && Number.isFinite(lon) && (latRef || lonRef)) out.gps = { lat, lon };
            }
        }
        return out;
    } catch {
        return null;
    }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    try {
        const digest = await (globalThis.crypto?.subtle?.digest(
            'SHA-256',
            bytes.buffer as ArrayBuffer,
        ) as Promise<ArrayBuffer>);
        return [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, '0')).join('');
    } catch {
        return '';
    }
}

const exifExtract = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.exif_extract',
        content_type: 'vineyard:plugin',
        name: 'EXIF Extract',
        version: '2.1.2',
        description:
            'Reads photos picked in the Run dialog (no selection), locally without uploading them. Creates a File node per photo with its SHA-256 and, for JPEGs, EXIF fields (camera make/model, body serial, lens, capture time, software), plus a Location node linked "captured at" when the photo has GPS coordinates.',
        icon: 'map-pin',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' } },
        io: {
            consumes: [],
            produces: [
                { typepack: 'run.vineyard.typepacks.endpoint', category: 'endpoint', name: 'file' },
                { typepack: 'run.vineyard.typepacks.geo', category: 'geo', name: 'location' },
            ],
        },
        // `format: 'file'` makes the Run dialog render a file picker; `type: 'array'` makes it a
        // multi-select. The values arrive as File objects, so name/type/size come with them and the
        // bytes are read here in the sandbox. Parsed locally; no network scope.
        params: {
            type: 'object',
            properties: {
                images: {
                    type: 'array',
                    format: 'file',
                    accept: 'image/*',
                    title: 'Image files',
                    description: 'One or more image files; EXIF and GPS are read from JPEGs only.',
                },
            },
            required: ['images'],
        },
        scopes: { graph: ['node:create', 'edge:create'] },
        // Determinate and cancellable now that it is a loop over a known count.
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        const images = (Array.isArray(ctx.params?.images) ? ctx.params.images : []) as File[];
        if (!images.length) {
            return { summary: 'No images provided — pick one or more in the Run dialog', counts: { files: 0 } };
        }

        let files = 0;
        let located = 0;
        let unreadable = 0;
        // Kept only to preserve the detailed one-photo report; a 50-photo batch gets the tally.
        let firstNote = '';

        for (let i = 0; i < images.length; i++) {
            if (ctx.signal?.aborted) break;
            const image = images[i];
            const fileName = image?.name || `image-${i + 1}.jpg`;
            ctx.progress?.set?.({
                percent: Math.round((i / images.length) * 100),
                message: `Parsing ${fileName} (${i + 1}/${images.length})`,
            });

            // Materialise ONE image at a time. The File objects themselves are handles to blobs the
            // browser already holds; it is this line that costs memory, so it must not be hoisted
            // into a `Promise.all` over the batch.
            let bytes: Uint8Array;
            try {
                bytes = new Uint8Array(await image.arrayBuffer());
            } catch {
                unreadable++;
                continue;
            }

            const sha256 = await sha256Hex(bytes);
            const exif = parseJpegExif(bytes);

            // Identity is content-based (hash-suffixed) so two distinct images never collapse — the
            // file_name alone is user-supplied, optional, and often a camera default (IMG_1234.JPG).
            // This is also what keeps a batch containing the same photo twice from forking into two
            // nodes that disagree.
            const fileNode = await ctx.graph!.createNode!({
                type: 'endpoint.file',
                data: {
                    file_name: sha256 ? `${fileName} [${sha256.slice(0, 12)}]` : fileName,
                    mime_type: image.type || 'application/octet-stream',
                    size_bytes: bytes.length,
                    ...(sha256 ? { sha256 } : {}),
                    // Everything EXIF gave us that is not the coordinate. It used to reach only the
                    // run summary — one line, and after batching only the FIRST photo's — so a
                    // 50-photo import threw away 49 camera identities. The properties panel renders
                    // data fields the type does not declare, so these land without pushing
                    // photo-specific columns onto the generic `endpoint.file` type.
                    ...(exif?.make ? { camera_make: exif.make } : {}),
                    ...(exif?.model ? { camera_model: exif.model } : {}),
                    ...(exif?.lensModel ? { lens_model: exif.lensModel } : {}),
                    ...(exif?.bodySerial ? { camera_serial: exif.bodySerial } : {}),
                    ...(exif?.dateTime ? { taken_at: exif.dateTime } : {}),
                    ...(exif?.software ? { software: exif.software } : {}),
                },
            });
            files++;

            let locatedNote = 'no GPS in EXIF';
            if (exif?.gps) {
                const { lat, lon } = exif.gps;
                const locNode = await ctx.graph!.createNode!({
                    type: 'geo.location',
                    data: { name: `${lat.toFixed(5)}, ${lon.toFixed(5)}`, latitude: lat, longitude: lon },
                });
                await ctx.graph!.createEdge!({
                    from: String(fileNode.id),
                    to: String(locNode.id),
                    label: 'captured at',
                });
                locatedNote = `GPS ${lat.toFixed(5)}, ${lon.toFixed(5)}`;
                located++;
            }

            if (i === 0) {
                const cam = [exif?.make, exif?.model].filter(Boolean).join(' ');
                const meta = [
                    cam && `camera: ${cam}`,
                    exif?.dateTime && `taken: ${exif.dateTime}`,
                    exif?.software && `software: ${exif.software}`,
                ]
                    .filter(Boolean)
                    .join(' · ');
                firstNote = `${fileName} — ${locatedNote}${meta ? ` · ${meta}` : ''}${
                    sha256 ? ` · sha256 ${sha256.slice(0, 12)}…` : ''
                }`;
            }
        }

        ctx.progress?.set?.({ percent: 100 });
        const summary =
            images.length === 1 && firstNote
                ? firstNote
                : `${files} image(s) — ${located} with GPS${unreadable ? ` · ${unreadable} unreadable` : ''}`;
        return { summary, counts: { files, located, unreadable } };
    },
});

// The pack's page in the catalog, in Markdown: the About section the marketplace drawer shows
// below the one-line `summary`. Kept as an array of lines rather than a template literal so the
// Markdown's backticks need no escaping.
const PACK_PAGE = [
    "For turning photos an analyst already holds into graph nodes: the camera that took them, when, and where, where the file still says so. Images are read and parsed inside Vineyard's plugin sandbox; the pack has no network access, so the image never leaves the analyst's machine.",
    '',
    '## Plugins',
    '',
    '### EXIF Extract',
    '',
    '- **Runs on:** image files picked in the Run dialog, one or many in a single run. It needs no selected node.',
    "- **Adds a File node per photo** with its `sha256`, `mime_type` and `size_bytes`. The node's `file_name` is the original name followed by the first 12 characters of the hash, so two different photos named `IMG_1234.JPG` stay separate, and the same file picked twice gives one node.",
    '- **For JPEGs with EXIF**, the File node also gets what the photo records: `camera_make`, `camera_model`, `lens_model`, `camera_serial` (the body serial number, which ties photos to one physical camera), `taken_at` (the original capture time when present) and `software`.',
    '- **Adds a Location node** (latitude, longitude, named by the coordinates) linked `captured at` when the photo carries a GPS position. A GPS block with no hemisphere reference is treated as empty rather than as a position at 0, 0.',
    '- **Limits:** EXIF and GPS are read from JPEG files only. Other images, and JPEGs without EXIF, still get a hashed File node. A file that cannot be read is counted in the run summary and the rest of the batch continues.',
    '',
    'The image itself is not stored in the graph, only the fields above.',
    '',
    '## Requirements',
    '',
    'None: no API key, no account, no server.',
    '',
    '## What it contacts',
    '',
    'Nothing. The plugin declares no network scope, so it cannot make requests. Hashing and EXIF parsing happen locally in the sandbox.',
    '',
    '## Source',
    '',
    'https://github.com/Vineyard-Intelligence/pluginpack-image-osint',
    '',
    'Licensed Apache-2.0. The bundle `dist/pack.mjs` is built from `src/` with a pinned esbuild, so it can be rebuilt and compared with `node build.mjs && git diff --exit-code dist/pack.mjs`. `node verify.mjs` runs the built bundle against synthetic JPEGs.',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.image_osint',
    content_type: 'vineyard:pluginpack',
    name: 'Image OSINT',
    version: '1.5.0',
    summary: 'Extracts EXIF metadata and GPS location from photos, parsed locally without uploading them.',
    description: PACK_PAGE,
    plugins: [exifExtract],
});
