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

/** A little-endian Exif TIFF block whose IFD0 points at a GPS IFD holding lat/lon. */
function tiffWithGps(latDeg, lonDeg, latRef = 'N', lonRef = 'E') {
    const b = Buffer.alloc(128);
    b.write('II', 0, 'ascii');
    b.writeUInt16LE(42, 2);
    b.writeUInt32LE(8, 4); // IFD0 at +8

    b.writeUInt16LE(1, 8); // IFD0: one entry
    b.writeUInt16LE(0x8825, 10); // GPSInfoIFDPointer
    b.writeUInt16LE(4, 12); // LONG
    b.writeUInt32LE(1, 14);
    b.writeUInt32LE(26, 18); // -> GPS IFD at +26
    b.writeUInt32LE(0, 22); // no next IFD

    b.writeUInt16LE(4, 26); // GPS IFD: four entries
    const entry = (i, tag, type, count, write) => {
        const o = 28 + i * 12;
        b.writeUInt16LE(tag, o);
        b.writeUInt16LE(type, o + 2);
        b.writeUInt32LE(count, o + 4);
        write(o + 8);
    };
    entry(0, 0x0001, 2, 2, (o) => b.write(`${latRef}\0`, o, 'ascii')); // inline: 2 bytes <= 4
    entry(1, 0x0002, 5, 3, (o) => b.writeUInt32LE(80, o)); // pointer: 3 rationals = 24 bytes
    entry(2, 0x0003, 2, 2, (o) => b.write(`${lonRef}\0`, o, 'ascii'));
    entry(3, 0x0004, 5, 3, (o) => b.writeUInt32LE(104, o));
    b.writeUInt32LE(0, 76); // no next IFD

    const dms = (off, deg) => {
        const d = Math.trunc(deg);
        const m = Math.round((deg - d) * 60);
        b.writeUInt32LE(d, off);
        b.writeUInt32LE(1, off + 4);
        b.writeUInt32LE(m, off + 8);
        b.writeUInt32LE(1, off + 12);
        b.writeUInt32LE(0, off + 16);
        b.writeUInt32LE(1, off + 20);
    };
    dms(80, latDeg);
    dms(104, lonDeg);
    return b;
}

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

// Southern/western hemisphere refs must flip the sign.
{
    const { ctx, nodes } = makeCtx([asFile('s.jpg', jpeg(tiffWithGps(33, 70, 'S', 'W')))]);
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
