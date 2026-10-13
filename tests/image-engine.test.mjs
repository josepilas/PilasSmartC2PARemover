import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync, inflateSync } from 'node:zlib';
import { analyzeImage, removeImage, analyzeXmp, removeXmp, pngCRC } from '../dist/image-engine.js';

const enc = new TextEncoder();
const txt = x => enc.encode(x);
function join(...parts) {
  const bytes = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let p = 0;
  for (const piece of parts) { bytes.set(piece, p); p += piece.length; }
  return bytes;
}
function be32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function le32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; }
function box(type, body, extended = false) {
  if (!extended) return join(be32(body.length + 8), txt(type), body);
  const size = new Uint8Array(8); new DataView(size.buffer).setBigUint64(0, BigInt(body.length + 16));
  return join(be32(1), txt(type), size, body);
}
const STORE_UUID = Uint8Array.from([0x63, 0x32, 0x70, 0x61, 0, 0x11, 0, 0x10, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71]);
const BMFF_UUID = Uint8Array.from([0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81]);
function jumbf(c2pa = true, extra = 0) {
  const uuid = STORE_UUID.slice(); if (!c2pa) uuid[0] = 42;
  return box('jumb', join(box('jumd', join(uuid, new Uint8Array([3]), txt(c2pa ? 'c2pa\0' : 'other\0'))), box('cbor', join(new Uint8Array([0xa1, 0x61, 0x61, 1]), new Uint8Array(extra)))));
}
function app(marker, data) {
  const len = new Uint8Array(2); new DataView(len.buffer).setUint16(0, data.length + 2);
  return join(new Uint8Array([255, marker]), len, data);
}
function jpegFragment(manifest, split = manifest.length) {
  const parts = []; let z = 1;
  for (let p = 0; p < manifest.length; p += split) {
    const prefix = join(txt('JP'), new Uint8Array([0x02, 0x11]), be32(z++));
    parts.push(app(0xeb, join(prefix, p ? manifest.subarray(0, 8) : new Uint8Array(), manifest.subarray(p, p + split))));
  }
  return join(...parts);
}
const jpegScan = join(app(0xda, new Uint8Array([1, 1, 0, 0, 63, 0])), new Uint8Array([12, 255, 0, 25, 255, 0xd0, 44, 255, 0xd9]));
function jpeg(...metadata) { return join(new Uint8Array([255, 0xd8]), ...metadata, jpegScan); }
function chunk(type, data) {
  const content = join(txt(type), data);
  return join(be32(data.length), content, be32(pngCRC(content)));
}
const pngSignature = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const rawPixels = new Uint8Array([0, 10, 20, 30, 255]);
const compressedPixels = new Uint8Array(deflateSync(rawPixels));
function png(...metadata) {
  const ihdr = join(be32(1), be32(1), new Uint8Array([8, 6, 0, 0, 0]));
  return join(pngSignature, chunk('IHDR', ihdr), ...metadata, chunk('IDAT', compressedPixels), chunk('IEND', new Uint8Array()));
}
function riffChunk(type, data) { return join(txt(type), le32(data.length), data, data.length & 1 ? new Uint8Array(1) : new Uint8Array()); }
function riff(form, ...chunks) { const data = join(txt(form), ...chunks); return join(txt('RIFF'), le32(data.length), data); }
function xmp(provenance = 'https://example.test/manifest.c2pa') {
  return `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dc="http://purl.org/dc/elements/1.1/" dc:title="Keep this" dcterms:provenance="${provenance}"/></rdf:RDF></x:xmpmeta>`;
}

test('PNG removes caBX and preserves the exact compressed image, color profile, and original buffer', () => {
  const profile = chunk('iCCP', txt('preserve-profile\0\0binary-profile'));
  const original = png(profile, chunk('caBX', jumbf())), snapshot = original.slice();
  const info = analyzeImage(original, 'sample.png');
  assert.equal(info.format, 'PNG'); assert.equal(info.findings.length, 1); assert.equal(info.canRemove, true);
  assert.deepEqual(info.payloads[0], jumbf());
  const cleaned = removeImage(original, 'sample.png');
  assert.deepEqual(cleaned.bytes, png(profile)); assert.deepEqual(original, snapshot);
  assert.equal(analyzeImage(cleaned.bytes, 'sample.png').findings.length, 0);
  assert.deepEqual(new Uint8Array(inflateSync(compressedPixels)), rawPixels);
});

test('PNG selective XMP removal recomputes only affected metadata CRC', () => {
  const metadata = chunk('iTXt', join(txt('XML:com.adobe.xmp\0'), new Uint8Array([0, 0, 0, 0]), txt(xmp())));
  const original = png(metadata, chunk('caBX', jumbf()));
  const info = analyzeImage(original, 'sample.png'); assert.equal(info.findings.length, 2);
  const cleaned = removeImage(original, 'sample.png').bytes;
  const after = analyzeImage(cleaned, 'sample.png'); assert.equal(after.valid, true); assert.equal(after.findings.length, 0);
  const text = new TextDecoder().decode(cleaned);
  assert.ok(text.includes('Keep this')); assert.ok(!text.includes('example.test'));
  assert.ok(Buffer.from(cleaned).includes(Buffer.from(compressedPixels)));
});

test('PNG corruption and truncation never produce a cleaned file', () => {
  const original = png(chunk('caBX', jumbf())), broken = original.slice(); broken[broken.length - 1] ^= 1;
  assert.equal(analyzeImage(broken, 'bad.png').canRemove, false); assert.throws(() => removeImage(broken, 'bad.png'), /checksum/);
  assert.equal(analyzeImage(original.subarray(0, original.length - 5), 'bad.png').valid, false);
});

test('JPEG reassembles fragmented C2PA, retains unrelated APP11, EXIF, ICC and scan bytes', () => {
  const manifest = jumbf(true, 200), unrelated = jpegFragment(jumbf(false)), exif = app(0xe1, txt('Exif\0\0preserve')), icc = app(0xe2, txt('ICC_PROFILE\0preserve'));
  const original = jpeg(exif, unrelated, jpegFragment(manifest, 64), icc);
  const info = analyzeImage(original, 'sample.jpg');
  assert.equal(info.valid, true); assert.equal(info.findings.length, 1); assert.deepEqual(info.payloads[0], manifest);
  const cleaned = removeImage(original, 'sample.jpg'); assert.equal(cleaned.removed, 1);
  assert.deepEqual(cleaned.bytes, jpeg(exif, unrelated, icc));
  assert.equal(analyzeImage(cleaned.bytes, 'sample.jpg').findings.length, 0);
});

test('JPEG can identify APP11 between scans without altering entropy bytes', () => {
  const a = app(0xda, new Uint8Array([1, 1, 0, 0, 63, 0])), firstScan = new Uint8Array([3, 255, 0, 4, 255, 0xd1]);
  const original = join(new Uint8Array([255, 0xd8]), a, firstScan, jpegFragment(jumbf()), jpegScan);
  const cleaned = removeImage(original, 'progressive.jpg').bytes;
  assert.deepEqual(cleaned, join(new Uint8Array([255, 0xd8]), a, firstScan, jpegScan));
});

test('JPEG incomplete C2PA fragmentation fails safely', () => {
  const all = jpegFragment(jumbf(true, 200), 64), firstLength = new DataView(all.buffer).getUint16(2) + 2;
  const broken = jpeg(all.subarray(0, firstLength));
  assert.equal(analyzeImage(broken, 'bad.jpg').valid, false);
  assert.throws(() => removeImage(broken, 'bad.jpg'), /Incomplete/);
});

test('JPEG multipart offsets are retained using erased comments', () => {
  const original = join(jpeg(jpegFragment(jumbf())), txt('trailing secondary media'));
  const cleaned = removeImage(original, 'motion.jpg').bytes;
  assert.equal(cleaned.length, original.length);
  assert.deepEqual(cleaned.subarray(cleaned.length - 24), original.subarray(original.length - 24));
  assert.equal(cleaned[3], 0xfe); assert.ok(!Buffer.from(cleaned).includes(Buffer.from(txt('c2pa'))));
  assert.equal(analyzeImage(cleaned, 'motion.jpg').findings.length, 0);
});

test('JPEG APP1 XMP removes qualified provenance while retaining other metadata', () => {
  const original = jpeg(app(0xe1, join(txt('http://ns.adobe.com/xap/1.0/\0'), txt(xmp()))));
  const cleaned = removeImage(original, 'remote.jpg');
  assert.equal(cleaned.removed, 1); assert.equal(cleaned.bytes.length, original.length);
  assert.ok(new TextDecoder().decode(cleaned.bytes).includes('Keep this'));
  assert.equal(analyzeImage(cleaned.bytes, 'remote.jpg').findings.length, 0);
});

test('WebP and WAV remove C2PA including odd padding and repair RIFF size', () => {
  for (const [form, name, dataType] of [['WEBP', 'sample.webp', 'VP8L'], ['WAVE', 'sample.wav', 'data']]) {
    const media = riffChunk(dataType, new Uint8Array([4, 3, 2, 1])), extra = riffChunk('EXIF', txt('preserve'));
    const original = riff(form, media, extra, riffChunk('C2PA', new Uint8Array([9, 8, 7])));
    const cleaned = removeImage(original, name);
    assert.deepEqual(cleaned.bytes, riff(form, media, extra)); assert.equal(cleaned.removed, 1);
    assert.equal(analyzeImage(cleaned.bytes, name).findings.length, 0);
    assert.equal(new DataView(cleaned.bytes.buffer).getUint32(4, true), cleaned.bytes.length - 8);
  }
});

test('AVI indexes and RIFF offsets survive same-size JUNK neutralization', () => {
  const data = riffChunk('LIST', join(txt('movi'), txt('media bytes'))), index = riffChunk('idx1', new Uint8Array([10, 20, 30, 40]));
  const original = riff('AVI ', data, riffChunk('C2PA', jumbf()), index), cleaned = removeImage(original, 'video.avi').bytes;
  assert.equal(cleaned.length, original.length); assert.deepEqual(cleaned.subarray(cleaned.length - index.length), index);
  assert.ok(Buffer.from(cleaned).includes(Buffer.from(txt('JUNK')))); assert.ok(!Buffer.from(cleaned).includes(Buffer.from(txt('c2pa'))));
  assert.equal(analyzeImage(cleaned, 'video.avi').findings.length, 0);
});

test('RIFF oversized chunk is rejected', () => {
  const original = riff('WEBP', riffChunk('C2PA', jumbf())); new DataView(original.buffer).setUint32(16, original.length + 1, true);
  assert.equal(analyzeImage(original, 'bad.webp').valid, false); assert.throws(() => removeImage(original, 'bad.webp'), /exceeds/);
});

test('GIF removes only C2PA application extension and retains animation extension and image', () => {
  const header = join(txt('GIF89a'), new Uint8Array([1, 0, 1, 0, 0x80, 0, 0]), new Uint8Array([0, 0, 0, 255, 255, 255]));
  const loop = new Uint8Array([0x21, 0xff, 11, ...txt('NETSCAPE2.0'), 3, 1, 0, 0, 0]);
  const store = jumbf(), extension = new Uint8Array([0x21, 0xff, 11, ...txt('C2PA_GIF'), 1, 0, 0, store.length, ...store, 0]);
  const image = new Uint8Array([0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 1, 0, 0x3b]);
  const original = join(header, loop, extension, image), info = analyzeImage(original, 'animated.gif');
  assert.equal(info.findings.length, 1); assert.deepEqual(info.payloads[0], store);
  assert.deepEqual(removeImage(original, 'animated.gif').bytes, join(header, loop, image));
  const broken = original.subarray(0, original.length - 2); assert.equal(analyzeImage(broken, 'bad.gif').valid, false);
});

test('BMFF erases only the C2PA UUID, preserves exact size, media offsets and unrelated UUIDs', () => {
  const ftyp = box('ftyp', join(txt('avif'), new Uint8Array(4), txt('avifmif1'))), other = box('uuid', join(new Uint8Array(16).fill(7), txt('preserve this')));
  const manifest = jumbf(), c2pa = box('uuid', join(BMFF_UUID, new Uint8Array(4), txt('manifest\0'), new Uint8Array(8), manifest));
  const media = box('mdat', new Uint8Array([1, 2, 3, 4])), original = join(ftyp, other, c2pa, media);
  const info = analyzeImage(original, 'image.avif'); assert.equal(info.format, 'AVIF'); assert.deepEqual(info.payloads[0], manifest);
  const cleaned = removeImage(original, 'image.avif').bytes; assert.equal(cleaned.length, original.length);
  assert.deepEqual(cleaned.subarray(ftyp.length, ftyp.length + other.length), other);
  assert.deepEqual(cleaned.subarray(cleaned.length - media.length), media);
  assert.equal(new TextDecoder().decode(cleaned.subarray(ftyp.length + other.length + 4, ftyp.length + other.length + 8)), 'free');
  assert.equal(analyzeImage(cleaned, 'image.avif').findings.length, 0);
});

test('BMFF handles 64-bit box lengths, original/update manifests and zero-size final boxes', () => {
  const ftyp = box('ftyp', join(txt('isom'), new Uint8Array(4))), manifest = jumbf();
  const originalBox = box('uuid', join(BMFF_UUID, new Uint8Array(4), txt('original\0'), new Uint8Array(8), manifest), true);
  const update = join(be32(0), txt('uuid'), BMFF_UUID, new Uint8Array(4), txt('update\0'), manifest);
  const original = join(ftyp, originalBox, update), info = analyzeImage(original, 'video.mp4');
  assert.equal(info.findings.length, 2); assert.equal(info.payloads.length, 2);
  const cleaned = removeImage(original, 'video.mp4'); assert.equal(cleaned.bytes.length, original.length);
  assert.equal(analyzeImage(cleaned.bytes, 'video.mp4').findings.length, 0);
  const invalid = join(ftyp, be32(1), txt('uuid'), new Uint8Array(8).fill(255));
  assert.equal(analyzeImage(invalid, 'bad.mp4').valid, false); assert.throws(() => removeImage(invalid, 'bad.mp4'), /range/);
});

function tiffFixture(le, terminal = false, big = false) {
  const payload = jumbf(), head = big ? 16 : 8, cw = big ? 8 : 2, ew = big ? 20 : 12, width = big ? 8 : 4;
  const firstCount = terminal ? 2 : 3, firstEnd = head + cw + firstCount * ew + width, terminalOffset = firstEnd;
  const terminalEnd = terminal ? terminalOffset + cw + ew + width : firstEnd, pixelOffset = terminalEnd, payloadOffset = pixelOffset + 4;
  const b = new Uint8Array(payloadOffset + payload.length), d = new DataView(b.buffer);
  b.set(txt(le ? 'II' : 'MM')); d.setUint16(2, big ? 43 : 42, le);
  const offset = (o, n) => big ? d.setBigUint64(o, BigInt(n), le) : d.setUint32(o, n, le);
  const count = (o, n) => big ? d.setBigUint64(o, BigInt(n), le) : d.setUint16(o, n, le);
  if (big) { d.setUint16(4, 8, le); offset(8, head); } else offset(4, head);
  count(head, firstCount);
  function entry(o, tag, type, n, value) {
    d.setUint16(o, tag, le); d.setUint16(o + 2, type, le);
    if (big) d.setBigUint64(o + 4, BigInt(n), le); else d.setUint32(o + 4, n, le);
    const valueSlot = o + (big ? 12 : 8);
    if (type === 4 && n === 1) d.setUint32(valueSlot, value, le); else offset(valueSlot, value);
  }
  entry(head + cw, 273, 4, 1, pixelOffset);
  entry(head + cw + ew, 279, 4, 1, 4);
  if (terminal) { offset(firstEnd - width, terminalOffset); count(terminalOffset, 1); entry(terminalOffset + cw, 0xcd41, 7, payload.length, payloadOffset); }
  else entry(head + cw + 2 * ew, 0xcd41, 7, payload.length, payloadOffset);
  b.set([0x11, 0x22, 0x33, 0x44], pixelOffset); b.set(payload, payloadOffset);
  return { b, payload, pixelOffset, payloadOffset, head, cw, ew, firstEnd, terminalOffset, terminalEnd, d };
}

test('TIFF little/big endian tag compaction preserves strip offsets and erases payload bytes', () => {
  for (const le of [true, false]) for (const big of [false, true]) {
    const f = tiffFixture(le, false, big), before = f.b.slice(), info = analyzeImage(f.b, 'camera.dng');
    assert.equal(info.valid, true); assert.equal(info.findings.length, 1); assert.deepEqual(info.payloads[0], f.payload);
    const cleaned = removeImage(f.b, 'camera.dng').bytes, d = new DataView(cleaned.buffer);
    assert.deepEqual(f.b, before); assert.equal(cleaned.length, before.length);
    assert.equal(big ? Number(d.getBigUint64(f.head, le)) : d.getUint16(f.head, le), 2);
    assert.deepEqual(cleaned.subarray(f.pixelOffset, f.pixelOffset + 4), before.subarray(f.pixelOffset, f.pixelOffset + 4));
    assert.ok(cleaned.subarray(f.payloadOffset).every(v => v === 0));
    assert.equal(analyzeImage(cleaned, 'camera.dng').findings.length, 0);
  }
});

test('TIFF appended C2PA-only directory is unlinked while image IFD is preserved', () => {
  for (const le of [true, false]) {
    const f = tiffFixture(le, true), cleaned = removeImage(f.b, 'image.tiff').bytes;
    assert.equal(new DataView(cleaned.buffer).getUint32(f.firstEnd - 4, le), 0);
    assert.deepEqual(cleaned.subarray(f.head, f.firstEnd - 4), f.b.subarray(f.head, f.firstEnd - 4));
    assert.ok(cleaned.subarray(f.terminalOffset, f.terminalEnd).every(v => v === 0));
    assert.deepEqual(cleaned.subarray(f.pixelOffset, f.pixelOffset + 4), f.b.subarray(f.pixelOffset, f.pixelOffset + 4));
    assert.equal(analyzeImage(cleaned, 'image.tiff').valid, true);
  }
});

test('TIFF shared C2PA/image bytes and cyclic directories fail safely', () => {
  const f = tiffFixture(true); f.d.setUint32(f.head + f.cw + 2 * f.ew + 8, f.pixelOffset, true);
  assert.equal(analyzeImage(f.b, 'unsafe.tiff').valid, false); assert.throws(() => removeImage(f.b, 'unsafe.tiff'), /overlaps/);
  const loop = tiffFixture(true); loop.d.setUint32(loop.firstEnd - 4, loop.head, true);
  assert.equal(analyzeImage(loop.b, 'loop.tiff').valid, false); assert.throws(() => removeImage(loop.b, 'loop.tiff'), /Cyclic/);
});

test('XMP recognizes namespace aliases/elements and preserves comments, CDATA and foreign namespaces', () => {
  const xml = `<x xmlns:p="http://purl.org/dc/terms/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><!-- <p:provenance>comment</p:provenance> --><![CDATA[<p:provenance>text</p:provenance>]]><p:provenance rdf:resource="https://example.test/external"/><y xmlns:p="urn:foreign" p:provenance="Keep foreign"/><z xmlns:p="http://purl.org/dc/terms/"><p:provenance>https://example.test/second</p:provenance></z></x>`;
  const original = txt(xml), info = analyzeXmp(original); assert.equal(info.findings.length, 2);
  const cleaned = removeXmp(original); assert.equal(cleaned.bytes.length, original.length); assert.equal(cleaned.removed, 2);
  const text = new TextDecoder().decode(cleaned.bytes);
  assert.ok(text.includes('comment')); assert.ok(text.includes('CDATA')); assert.ok(text.includes('Keep foreign')); assert.ok(!text.includes('example.test'));
  assert.equal(analyzeXmp(cleaned.bytes).findings.length, 0);
});

test('XMP malformed XML and UTF16 are preserved with explicit warning', () => {
  const malformed = txt('<x xmlns:p="http://purl.org/dc/terms/" p:provenance="https://example.test"><bad></x>');
  const cleaned = removeXmp(malformed); assert.equal(cleaned.removed, 0); assert.deepEqual(cleaned.bytes, malformed); assert.ok(cleaned.warnings.length);
  const utf16 = new Uint8Array(Buffer.from(xmp(), 'utf16le')); assert.equal(removeXmp(utf16).removed, 0);
});

test('XMP ownership-history prose is preserved; only C2PA-style URI references are targeted', () => {
  const prose = txt(xmp('Purchased from a local estate, 1941'));
  assert.equal(analyzeXmp(prose).findings.length, 0); assert.deepEqual(removeXmp(prose).bytes, prose);
  const element = txt('<x xmlns:d="http://purl.org/dc/terms/"><d:provenance>Transferred by the owner in 1995</d:provenance></x>');
  assert.equal(analyzeXmp(element).findings.length, 0); assert.deepEqual(removeXmp(element).bytes, element);
  for (const reference of ['self#jumbf=/c2pa/urn:c2pa:example', 'c2pa://example/manifest', 'urn:c2pa:1234']) assert.equal(analyzeXmp(txt(xmp(reference))).findings.length, 1);
  const escaped = txt(xmp('https&#x3a;//example.test/manifest?a=1&amp;b=2'));
  assert.equal(analyzeXmp(escaped).findings[0].detail, 'https://example.test/manifest?a=1&b=2');
  assert.equal(removeXmp(escaped).removed, 1);
});

test('Unrecognized signatures are not edited based on filenames', () => {
  const bytes = txt('This text contains c2pa and dcterms:provenance.');
  for (const name of ['fake.jpg', 'fake.png', 'fake.webp', 'fake.pdf', 'fake.docx']) { assert.equal(analyzeImage(bytes, name), null); assert.equal(removeImage(bytes, name), null); }
});

test('Malformed recognized container truncations consistently fail safely', () => {
  for (const [name, bytes] of [['x.jpg', jpeg(jpegFragment(jumbf()))], ['x.png', png(chunk('caBX', jumbf()))], ['x.webp', riff('WEBP', riffChunk('C2PA', jumbf()))], ['x.tiff', tiffFixture(true).b]]) {
    const signatureEnd = name.endsWith('jpg') ? 2 : name.endsWith('tiff') ? 4 : name.endsWith('webp') ? 12 : 8;
    for (let end = signatureEnd; end < bytes.length; end += 7) {
      const truncated = bytes.subarray(0, end), analysis = analyzeImage(truncated, name);
      if (analysis?.valid === false) { assert.equal(analysis.canRemove, false); assert.throws(() => removeImage(truncated, name)); }
    }
  }
});
