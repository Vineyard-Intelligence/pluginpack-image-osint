#!/usr/bin/env node
/**
 * Self-check for the built pack: `node verify.mjs`.
 *
 * Drives the REAL dist/pack.mjs — the bundle the marketplace serves — against a fake host ctx and
 * synthetic JPEGs. It exists for the batch loop: EXIF Extract takes File objects now, one run per
 * batch rather than one run per photo, and the things that can quietly break are per-file (a photo
 * that fails to read killing the rest), aggregate (a miscounted tally), and contractual (the params
 * schema the Run dialog reads living in a different file from the code that consumes it).
 *
 * No framework on purpose — node:assert and a synthetic JPEG builder are the whole harness.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const pack = (await import('./dist/pack.mjs')).default;
const manifest = JSON.parse(readFileSync(new URL('./plugins/image-osint.manifest.json', import.meta.url)));
const exif = pack.plugins.find((p) => p.manifest.identifier === 'run.vineyard.plugins.exif_extract');
assert.ok(exif, 'exif_extract missing from the bundle');

// --- synthetic JPEGs -----------------------------------------------------------------------

/**
 * A little-endian Exif TIFF block: IFD0 (camera identity) + an Exif sub-IFD (timestamp, serial,
 * lens) + a GPS sub-IFD. Every field is optional, so a photo with a camera and no fix — the case
 * that used to lose everything — is expressible.
 *
 * Laid out in two passes because a value of 4 bytes or less lives INSIDE its 12-byte entry while
 * anything longer is stored out of line and referenced by a TIFF-relative offset. Getting that
 * wrong produces a file the parser reads as empty, which would make these assertions pass for the
 * wrong reason.
 */
function buildTiff({ make, model, software, dateTime, serial, lens, gps } = {}) {
    const ascii = (s) => Buffer.from(`${s}\0`, 'latin1');
    const rational3 = (deg) => {
        const b = Buffer.alloc(24);
        const d = Math.trunc(deg);
        const m = Math.round((deg - d) * 60);
        [d, 1, m, 1, 0, 1].forEach((v, i) => b.writeUInt32LE(v, i * 4));
        return b;
    };
    const A = (tag, v) => (v ? [{ tag, type: 2, count: ascii(v).length, data: ascii(v) }] : []);

    const ifd0 = [...A(0x010f, make), ...A(0x0110, model), ...A(0x0131, software)];
    const exif = [...A(0x9003, dateTime), ...A(0xa431, serial), ...A(0xa434, lens)];
    const gpsIfd = gps
        ? [
              ...A(0x0001, gps.lat >= 0 ? 'N' : 'S'),
              { tag: 0x0002, type: 5, count: 3, data: rational3(Math.abs(gps.lat)) },
              ...A(0x0003, gps.lon >= 0 ? 'E' : 'W'),
              { tag: 0x0004, type: 5, count: 3, data: rational3(Math.abs(gps.lon)) },
          ]
        : [];

    const ifdBytes = (n) => (n ? 2 + 12 * n + 4 : 0);
    const ifd0Count = ifd0.length + (exif.length ? 1 : 0) + (gpsIfd.length ? 1 : 0);
    const ifd0Off = 8;
    const exifOff = ifd0Off + ifdBytes(ifd0Count);
    const gpsOff = exifOff + ifdBytes(exif.length);
    let dataOff = gpsOff + ifdBytes(gpsIfd.length);
    const dataTotal = [...ifd0, ...exif, ...gpsIfd]
        .filter((e) => e.data.length > 4)
        .reduce((n, e) => n + e.data.length, 0);

    const b = Buffer.alloc(dataOff + dataTotal);
    b.write('II', 0, 'latin1');
    b.writeUInt16LE(42, 2);
    b.writeUInt32LE(ifd0Off, 4);

    const writeIfd = (off, entries) => {
        if (!entries.length) return;
        b.writeUInt16LE(entries.length, off);
        entries.forEach((e, i) => {
            const o = off + 2 + i * 12;
            b.writeUInt16LE(e.tag, o);
            b.writeUInt16LE(e.type, o + 2);
            b.writeUInt32LE(e.count, o + 4);
            if (e.pointer !== undefined) b.writeUInt32LE(e.pointer, o + 8);
            else if (e.data.length <= 4) e.data.copy(b, o + 8);
            else {
                b.writeUInt32LE(dataOff, o + 8);
                e.data.copy(b, dataOff);
                dataOff += e.data.length;
            }
        });
        b.writeUInt32LE(0, off + 2 + entries.length * 12); // no next IFD
    };

    const ptr = (tag, target) => ({ tag, type: 4, count: 1, data: Buffer.alloc(4), pointer: target });
    writeIfd(
        ifd0Off,
        [
            ...ifd0,
            ...(exif.length ? [ptr(0x8769, exifOff)] : []),
            ...(gpsIfd.length ? [ptr(0x8825, gpsOff)] : []),
        ],
    );
    writeIfd(exifOff, exif);
    writeIfd(gpsOff, gpsIfd);
    return b;
}

/** The original shorthand, kept so the GPS-only cases read as before. */
const tiffWithGps = (lat, lon) => buildTiff({ gps: { lat, lon } });

function jpeg(tiff) {
    if (!tiff) return Buffer.from([0xff, 0xd8, 0xff, 0xd9]); // SOI + EOI, no Exif
    const head = Buffer.alloc(4);
    head.writeUInt16BE(0xffe1, 0);
    head.writeUInt16BE(2 + 6 + tiff.length, 2); // length covers itself + "Exif\0\0" + TIFF
    return Buffer.concat([
        Buffer.from([0xff, 0xd8]),
        head,
        Buffer.from('Exif\0\0', 'binary'),
        tiff,
        Buffer.from([0xff, 0xd9]),
    ]);
}

const asFile = (name, buf) => new File([buf], name, { type: 'image/jpeg' });
/** The plugin only ever touches name/type/arrayBuffer, so a rejecting stub is a faithful bad file. */
const unreadableFile = (name) => ({
    name,
    type: 'image/jpeg',
    arrayBuffer: () => Promise.reject(new Error('read failed')),
});

// --- fake host -----------------------------------------------------------------------------

function makeCtx(images, { abortAfterNodes } = {}) {
    const nodes = [];
    const edges = [];
    const controller = new AbortController();
    const ctx = {
        run: { runId: 'r', projectId: 'p', pluginId: 'x', grantedScopes: {}, platform: 'web' },
        input: { selection: [] },
        params: { images },
        graph: {
            createNode: async (draft) => {
                nodes.push(draft);
                if (abortAfterNodes && nodes.length >= abortAfterNodes) controller.abort();
                return { id: `n${nodes.length}`, type: draft.type, data: draft.data };
            },
            createEdge: async (e) => void edges.push(e),
        },
        progress: { set: () => {} },
        signal: controller.signal,
    };
    return { ctx, nodes, edges };
}

const fileNodes = (nodes) => nodes.filter((n) => n.type === 'endpoint.file');
const locNodes = (nodes) => nodes.filter((n) => n.type === 'geo.location');

// --- checks --------------------------------------------------------------------------------

// The Run dialog reads the JSON manifest, not the bundle — so the contract that makes the picker
// multi-select at all lives in a file the plugin code cannot see. Assert they still agree.
{
    const m = manifest.plugins.find((p) => p.identifier === 'run.vineyard.plugins.exif_extract');
    const images = m.params.properties.images;
    assert.equal(images.format, 'file', 'params.images must be format:file or the picker is a text box');
    assert.equal(images.type, 'array', 'params.images must be type:array or the picker is single-select');
    assert.deepEqual(m.params.required, ['images']);
    assert.equal(m.version, exif.manifest.version, 'manifest.json and the bundle disagree on the version');
}

// A batch: three photos, one of them carrying GPS.
{
    const { ctx, nodes, edges } = makeCtx([
        asFile('a.jpg', jpeg(null)),
        asFile('b.jpg', jpeg(tiffWithGps(37.5, 127))),
        asFile('c.jpg', jpeg(null)),
    ]);
    const out = await exif.run(ctx);
    assert.equal(fileNodes(nodes).length, 3, 'one File node per photo');
    assert.equal(locNodes(nodes).length, 1, 'only the GPS photo makes a Location');
    assert.equal(edges.length, 1);
    assert.equal(edges[0].label, 'captured at');
    assert.deepEqual(out.counts, { files: 3, located: 1, unreadable: 0 });
    assert.match(out.summary, /3 image\(s\) — 1 with GPS/);

    const loc = locNodes(nodes)[0].data;
    assert.equal(Math.round(loc.latitude * 10) / 10, 37.5);
    assert.equal(Math.round(loc.longitude), 127);

    // Content-addressed identity: two different photos must not collapse onto one node.
    const names = fileNodes(nodes).map((n) => n.data.file_name);
    assert.equal(new Set(names).size, 3, 'file_name must stay distinct per photo');
    assert.ok(
        fileNodes(nodes).every((n) => typeof n.data.sha256 === 'string' && n.data.sha256.length === 64),
        'every File node carries a full SHA-256',
    );
}

// Every EXIF field the parser reads must reach the File node, not just the GPS fix. This is the
// regression that matters most: camera identity used to exist only in the run summary, and after
// batching only the FIRST photo's, so importing 50 photos discarded 49 camera identities.
{
    const tiff = buildTiff({
        make: 'NIKON CORPORATION',
        model: 'NIKON D850',
        software: 'Ver.1.01',
        dateTime: '2026:03:14 09:26:53',
        serial: '3012345',
        lens: 'NIKKOR Z 24-70mm f/2.8 S',
        gps: { lat: 37.5, lon: 127 },
    });
    const { ctx, nodes } = makeCtx([asFile('full.jpg', jpeg(tiff))]);
    await exif.run(ctx);
    const d = fileNodes(nodes)[0].data;
    assert.equal(d.camera_make, 'NIKON CORPORATION');
    assert.equal(d.camera_model, 'NIKON D850');
    assert.equal(d.software, 'Ver.1.01');
    assert.equal(d.taken_at, '2026:03:14 09:26:53');
    assert.equal(d.camera_serial, '3012345', 'body serial is the tie between two photos and one camera');
    assert.equal(d.lens_model, 'NIKKOR Z 24-70mm f/2.8 S');
}

// A photo with a camera but NO fix keeps its camera identity — the case that used to lose
// everything, since the only surviving output was the Location node.
{
    const tiff = buildTiff({ make: 'Apple', model: 'iPhone 15 Pro', dateTime: '2026:01:02 03:04:05' });
    const { ctx, nodes } = makeCtx([asFile('nogps.jpg', jpeg(tiff))]);
    const out = await exif.run(ctx);
    assert.equal(locNodes(nodes).length, 0, 'no GPS means no Location');
    const d = fileNodes(nodes)[0].data;
    assert.equal(d.camera_make, 'Apple');
    assert.equal(d.camera_model, 'iPhone 15 Pro');
    assert.equal(d.taken_at, '2026:01:02 03:04:05');
    assert.deepEqual(out.counts, { files: 1, located: 0, unreadable: 0 });
}

// Absent tags must be ABSENT, not empty strings — an empty property renders as a blank row in the
// inspector and reads as "we looked and there is nothing", which is a different claim.
{
    const { ctx, nodes } = makeCtx([asFile('bare.jpg', jpeg(null))]);
    await exif.run(ctx);
    const d = fileNodes(nodes)[0].data;
    for (const k of ['camera_make', 'camera_model', 'lens_model', 'camera_serial', 'taken_at', 'software']) {
        assert.ok(!(k in d), `${k} must be omitted when the photo has no EXIF, got ${JSON.stringify(d[k])}`);
    }
}

// Southern/western hemisphere refs must flip the sign.
{
    const { ctx, nodes } = makeCtx([asFile('s.jpg', jpeg(tiffWithGps(-33, -70)))]);
    await exif.run(ctx);
    const loc = locNodes(nodes)[0].data;
    assert.ok(loc.latitude < 0 && loc.longitude < 0, `expected southern/western, got ${loc.latitude},${loc.longitude}`);
}

// One photo still gets the detailed single-file report, not the tally.
{
    const { ctx } = makeCtx([asFile('solo.jpg', jpeg(tiffWithGps(37.5, 127)))]);
    const out = await exif.run(ctx);
    assert.match(out.summary, /^solo\.jpg — GPS 37\.50000, 127\.00000/, `got: ${out.summary}`);
}

// A photo that cannot be read is counted and SKIPPED — it must not end the batch.
{
    const { ctx, nodes } = makeCtx([
        unreadableFile('bad.jpg'),
        asFile('good.jpg', jpeg(tiffWithGps(37.5, 127))),
    ]);
    const out = await exif.run(ctx);
    assert.equal(out.counts.unreadable, 1);
    assert.equal(out.counts.files, 1, 'the readable photo after the bad one must still land');
    assert.equal(fileNodes(nodes).length, 1);
    assert.match(out.summary, /1 unreadable/);
}

// Stop must actually stop: aborting during photo 1 leaves photos 2 and 3 untouched.
{
    const { ctx, nodes } = makeCtx(
        [asFile('a.jpg', jpeg(null)), asFile('b.jpg', jpeg(null)), asFile('c.jpg', jpeg(null))],
        { abortAfterNodes: 1 },
    );
    const out = await exif.run(ctx);
    assert.equal(fileNodes(nodes).length, 1, 'abort must break the loop');
    assert.equal(out.counts.files, 1);
}

// Nothing picked: a clear message, no nodes, no throw.
for (const empty of [[], undefined]) {
    const { ctx, nodes } = makeCtx(empty);
    const out = await exif.run(ctx);
    assert.equal(nodes.length, 0);
    assert.match(out.summary, /No images provided/);
}

console.log('ok — image-osint pack verified');
