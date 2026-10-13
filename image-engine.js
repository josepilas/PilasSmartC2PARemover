/*
 * Container-aware Content Credentials inspection and removal.
 * C2PA 2.4 Appendix A and section 11.5:
 * https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html
 * This module identifies containers; it does not verify signatures or trust.
 */

const STORE_UUID = Uint8Array.from([0x63, 0x32, 0x70, 0x61, 0, 0x11, 0, 0x10, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71]);
const BMFF_UUID = Uint8Array.from([0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81]);
const XMP_UUID = Uint8Array.from([0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac]);
const PNG_SIGNATURE = Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]);
const encoder = new TextEncoder();
const MAX_ITEMS = 100000;

export const imageSupport = [
  { format: 'JPEG', extensions: ['jpg', 'jpeg'], status: 'supported', method: 'C2PA APP11 fragments; selective XMP references' },
  { format: 'PNG', extensions: ['png', 'apng'], status: 'supported', method: 'caBX chunks; uncompressed XMP references' },
  { format: 'WebP', extensions: ['webp'], status: 'supported', method: 'C2PA RIFF chunks; selective XMP references' },
  { format: 'WAV', extensions: ['wav', 'bwf'], status: 'supported', method: 'C2PA RIFF chunks; selective XMP references' },
  { format: 'AVI', extensions: ['avi'], status: 'supported', method: 'C2PA RIFF chunks; same-size neutralization keeps indexes' },
  { format: 'GIF', extensions: ['gif'], status: 'supported', method: 'C2PA_GIF application extensions' },
  { format: 'TIFF / DNG', extensions: ['tif', 'tiff', 'dng'], status: 'supported', method: 'Classic TIFF and BigTIFF C2PA tag 0xCD41; fixed-offset surgery' },
  { format: 'AVIF / HEIC / HEIF', extensions: ['avif', 'heic', 'heif'], status: 'supported', method: 'Top-level C2PA UUID boxes; same-size free boxes' },
  { format: 'MP4 / MOV / M4A', extensions: ['mp4', 'mov', 'm4a', 'm4v', 'm4s'], status: 'supported', method: 'Top-level C2PA UUID boxes; same-size free boxes' },
];

function error(message) { throw new Error(message); }
function requireBytes(b, start, count, label = 'data') {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(count) || start < 0 || count < 0 || start + count > b.length) error(`Truncated or invalid ${label}.`);
}
function eq(b, offset, value) {
  if (offset < 0 || offset + value.length > b.length) return false;
  for (let i = 0; i < value.length; i++) if (b[offset + i] !== value[i]) return false;
  return true;
}
function ascii(b, offset, count) {
  requireBytes(b, offset, count);
  let s = '';
  for (let i = offset; i < offset + count; i++) s += String.fromCharCode(b[i]);
  return s;
}
function u16(b, o, le = false) { requireBytes(b, o, 2); return new DataView(b.buffer, b.byteOffset + o, 2).getUint16(0, le); }
function u32(b, o, le = false) { requireBytes(b, o, 4); return new DataView(b.buffer, b.byteOffset + o, 4).getUint32(0, le); }
function u64(b, o, le = false) {
  requireBytes(b, o, 8);
  const n = new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, le);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) error('An offset exceeds the safely addressable range.');
  return Number(n);
}
function put16(b, o, n, le = false) { new DataView(b.buffer, b.byteOffset + o, 2).setUint16(0, n, le); }
function put32(b, o, n, le = false) { new DataView(b.buffer, b.byteOffset + o, 4).setUint32(0, n, le); }
function put64(b, o, n, le = false) { new DataView(b.buffer, b.byteOffset + o, 8).setBigUint64(0, BigInt(n), le); }
function writeAscii(b, o, s) { b.set(encoder.encode(s), o); }
function concat(parts) {
  const n = parts.reduce((s, b) => s + b.length, 0);
  const result = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { result.set(p, o); o += p.length; }
  return result;
}
function cutRanges(b, ranges) {
  const sorted = ranges.slice().sort((a, c) => a.start - c.start);
  const pieces = [];
  let end = 0;
  for (const r of sorted) {
    if (r.start < end || r.end > b.length || r.start >= r.end) error('Overlapping removal ranges.');
    pieces.push(b.subarray(end, r.start)); end = r.end;
  }
  pieces.push(b.subarray(end));
  return concat(pieces);
}
function overlaps(a, b) { return a.start < b.end && b.start < a.end; }
function xmlValue(text) {
  const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' };
  return text.replace(/&([^;\s]+);/g, (token, entity) => {
    if (Object.hasOwn(named, entity)) return named[entity];
    if (/^#(?:[0-9]+|x[0-9a-f]+)$/i.test(entity)) {
      const value = entity[1].toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : parseInt(entity.slice(1), 10);
      if (value > 0 && value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff)) return String.fromCodePoint(value);
    }
    return token;
  });
}
function base(format, mime, method) { return { format, mime, supported: true, canRemove: false, valid: true, method, findings: [], warnings: [], payloads: [], _remove: [], _patch: [] }; }
function found(r, start, end, payload, label, detail = '') {
  r.findings.push({ kind: 'embedded', label, location: `Byte ${start.toLocaleString('en-US')}`, bytes: end - start, detail });
  if (payload?.length) r.payloads.push(payload.slice());
}
function finish(r) { r.canRemove = r.valid && r.findings.length > 0; return r; }

// Byte-identical space replacement avoids rewriting unrelated XML or changing
// offsets. Only namespace-qualified dc:terms provenance properties are edited.
function xmpReferences(b, start, end, result, location) {
  if (end <= start) return;
  if (end - start > 16 * 1024 * 1024) { result.warnings.push(`${location} exceeds the metadata inspection limit and is preserved.`); return; }
  const text = ascii(b, start, end - start);
  if (!/provenance/.test(text)) return;
  const ranges = [], stack = [], dc = 'http://purl.org/dc/terms/';
  let p = 0, roots = 0;
  const qualifies = (name, ns, attribute = false) => {
    const colon = name.indexOf(':'), prefix = colon < 0 ? '' : name.slice(0, colon), local = colon < 0 ? name : name.slice(colon + 1);
    return local === 'provenance' && (!attribute || colon >= 0) && ns[prefix] === dc;
  };
  try {
    if (text.includes('\0') && text.replace(/\0+$/, '').includes('\0')) error('Unsupported XMP encoding.');
    while (p < text.length) {
      const open = text.indexOf('<', p);
      if (open < 0) break;
      if (text.startsWith('<!--', open)) { const close = text.indexOf('-->', open + 4); if (close < 0) error('Unclosed XML comment.'); p = close + 3; continue; }
      if (text.startsWith('<![CDATA[', open)) { const close = text.indexOf(']]>', open + 9); if (close < 0) error('Unclosed XML CDATA.'); p = close + 3; continue; }
      if (text.startsWith('<?', open)) { const close = text.indexOf('?>', open + 2); if (close < 0) error('Unclosed XML processing instruction.'); p = close + 2; continue; }
      if (text.startsWith('<!', open)) error('XML declarations requiring entity expansion are not supported.');
      let close = open + 1, quote = '';
      for (; close < text.length; close++) {
        const c = text[close];
        if (quote) { if (c === quote) quote = ''; }
        else if (c === '"' || c === "'") quote = c;
        else if (c === '>') break;
      }
      if (close === text.length || quote) error('Unclosed XML tag.');
      const token = text.slice(open + 1, close), ending = token.startsWith('/');
      if (ending) {
        const name = token.slice(1).trim(), node = stack.pop();
        if (!node || node.name !== name || !/^[A-Za-z_][\w.:-]*$/.test(name)) error('Unbalanced XML tags.');
        if (node.target) ranges.push({ start: start + node.open, end: start + close + 1, uri: node.uri || text.slice(node.content, open).replace(/<[^>]*>/g, '').trim() });
      } else {
        const match = token.match(/^([A-Za-z_][\w.:-]*)/);
        if (!match) error('Invalid XML element name.');
        const name = match[1], selfClosing = /\/\s*$/.test(token), ns = { ...(stack.at(-1)?.ns || {}) }, attrs = [], names = new Set();
        if (!stack.length && ++roots > 1) error('XML has multiple root elements.');
        let at = name.length, limit = selfClosing ? token.lastIndexOf('/') : token.length;
        while (at < limit) {
          if (/^\s*$/.test(token.slice(at, limit))) break;
          const attr = token.slice(at, limit).match(/^(\s+)([A-Za-z_][\w.:-]*)\s*=\s*(["'])([^]*?)\3/);
          if (!attr || names.has(attr[2])) error('Invalid or duplicated XML attribute.');
          if (attr[4].includes('<')) error('Unescaped XML attribute content.');
          names.add(attr[2]);
          const a = { name: attr[2], value: attr[4], start: start + open + 1 + at, end: start + open + 1 + at + attr[0].length };
          attrs.push(a);
          if (a.name === 'xmlns') ns[''] = xmlValue(a.value);
          else if (a.name.startsWith('xmlns:')) ns[a.name.slice(6)] = xmlValue(a.value);
          at += attr[0].length;
        }
        const target = qualifies(name, ns), uri = attrs.find(a => a.name.endsWith(':resource') && ns[a.name.slice(0, -9)] === 'http://www.w3.org/1999/02/22-rdf-syntax-ns#')?.value || '';
        if (target && selfClosing) ranges.push({ start: start + open, end: start + close + 1, uri });
        for (const a of attrs) if (qualifies(a.name, ns, true)) ranges.push({ ...a, uri: a.value });
        if (!selfClosing) stack.push({ name, ns, open, content: close + 1, target, uri });
      }
      p = close + 1;
    }
    if (stack.length) error('Unclosed XML elements.');
  } catch (e) {
    result.warnings.push(`${location} is preserved: ${e.message}`);
    return;
  }
  for (const range of ranges) {
    if (ranges.some(other => other !== range && other.start <= range.start && other.end >= range.end)) continue;
    // Dublin Core provenance can contain ordinary ownership-history prose.
    // C2PA uses this property specifically as a URI reference. Do not erase
    // generic provenance text or infer a credential from a free-form sentence.
    const uri = xmlValue(range.uri).trim();
    if (!/^(?:https?:\/\/[^\s<>]+|self#jumbf(?:=|\/).+|c2pa:[^\s<>]+|urn:c2pa:[^\s<>]+)$/i.test(uri)) continue;
    result.findings.push({ kind: 'remote', label: 'XMP provenance reference', location, bytes: range.end - range.start, detail: uri.slice(0, 1000) });
    result._patch.push({ start: range.start, end: range.end, fill: 32 });
  }
}

/** Inspect standalone UTF-8 XMP. A reference is not proof of a remote manifest. */
export function analyzeXmp(bytes, location = 'XMP metadata') {
  if (!(bytes instanceof Uint8Array)) error('Expected a Uint8Array.');
  const r = base('XMP', 'application/rdf+xml', 'Erase only namespace-qualified XMP provenance properties');
  xmpReferences(bytes, 0, bytes.length, r, location);
  const { _patch, _remove, ...visible } = finish(r);
  return visible;
}
export function removeXmp(bytes, location = 'XMP metadata') {
  if (!(bytes instanceof Uint8Array)) error('Expected a Uint8Array.');
  const r = base('XMP', 'application/rdf+xml', 'Erase only namespace-qualified XMP provenance properties');
  xmpReferences(bytes, 0, bytes.length, r, location);
  const out = bytes.slice();
  for (const patch of r._patch) out.fill(32, patch.start, patch.end);
  return { bytes: out, removed: r.findings.length, findings: r.findings, method: r.method, warnings: r.warnings };
}

function boxAt(b, p, end) {
  requireBytes(b, p, 8, 'box header');
  let size = u32(b, p), header = 8;
  if (size === 1) { size = u64(b, p + 8); header = 16; }
  else if (size === 0) size = end - p;
  if (size < header || p + size > end || p + size > b.length) error('Invalid box length.');
  return { start: p, end: p + size, header, type: ascii(b, p + 4, 4), size };
}
function isStore(b, start, availableEnd, allowPartial = false) {
  try {
    requireBytes(b, start, 8);
    let outerSize = u32(b, start), header = 8;
    if (outerSize === 1) { outerSize = u64(b, start + 8); header = 16; }
    if (ascii(b, start + 4, 4) !== 'jumb' || outerSize < header + 8 + 17) return false;
    if (!allowPartial && start + outerSize > availableEnd) return false;
    const desc = boxAt(b, start + header, availableEnd);
    if (desc.type !== 'jumd' || desc.size < desc.header + 17 || !eq(b, desc.start + desc.header, STORE_UUID)) return false;
    const flags = b[desc.start + desc.header + 16];
    if (!(flags & 2)) return false; // JUMBF label present flag.
    const labelStart = desc.start + desc.header + 17;
    return ascii(b, labelStart, 5) === 'c2pa\0';
  } catch { return false; }
}

function jpeg(b) {
  const r = base('JPEG', 'image/jpeg', 'Lossless removal of C2PA APP11 segments and selective XMP references');
  const segments = [];
  let p = 2, eoi = false, scan = false, items = 0, offsetSensitive = false;
  while (p < b.length) {
    if (++items > MAX_ITEMS) error('Too many JPEG segments.');
    if (scan) {
      // Entropy bytes, FF00 stuffing, fill bytes, and restart markers are copied.
      while (p < b.length) {
        if (b[p] !== 255) { p++; continue; }
        let q = p + 1;
        while (q < b.length && b[q] === 255) q++;
        if (q >= b.length) error('Truncated JPEG scan.');
        if (b[q] === 0 || (b[q] >= 0xd0 && b[q] <= 0xd7)) { p = q + 1; continue; }
        scan = false; break;
      }
      if (scan) error('JPEG scan has no end marker.');
    }
    const start = p;
    if (b[p++] !== 255) error('Invalid JPEG marker boundary.');
    while (p < b.length && b[p] === 255) p++;
    requireBytes(b, p, 1, 'JPEG marker');
    const marker = b[p++];
    if (marker === 0xd9) { eoi = true; break; }
    if (marker === 0xd8 || marker === 0 || (marker >= 0xd0 && marker <= 0xd7)) error('Unexpected JPEG marker.');
    if (marker === 1) continue;
    const length = u16(b, p);
    if (length < 2) error('Invalid JPEG segment length.');
    const data = p + 2, end = p + length;
    requireBytes(b, p, length, 'JPEG segment');
    const s = { start, end, data, marker, markerOffset: p - 1 };
    segments.push(s);
    if (marker === 0xe2 && ascii(b, data, Math.min(4, end - data)) === 'MPF\0') offsetSensitive = true;
    if (marker === 0xe1 && end - data >= 29 && ascii(b, data, 29) === 'http://ns.adobe.com/xap/1.0/\0') {
      const text = ascii(b, data + 29, end - data - 29);
      if (/GCamera:MicroVideo|MotionPhoto|MicroVideoOffset|Container:Directory/.test(text)) offsetSensitive = true;
      xmpReferences(b, data + 29, end, r, 'JPEG APP1 XMP');
    }
    if (marker === 0xe1 && end - data >= 35 && ascii(b, data, 35) === 'http://ns.adobe.com/xmp/extension/\0') {
      r.warnings.push('Extended XMP packets are preserved; provenance references split across those packets are not inspected.');
    }
    p = end;
    if (marker === 0xda) scan = true;
  }
  if (!eoi) error('JPEG is missing its end-of-image marker.');
  if (p < b.length) {
    offsetSensitive = true;
    r.warnings.push('Trailing or multipart content is preserved. C2PA inside a secondary image or appended video is not inspected.');
  }
  for (let i = 0; i < segments.length; i++) {
    const first = segments[i];
    if (first.marker !== 0xeb || first.end - first.data < 16 || ascii(b, first.data, 2) !== 'JP' || u32(b, first.data + 4) !== 1) continue;
    if (!isStore(b, first.data + 8, first.end, true)) continue;
    const boxHeader = u32(b, first.data + 8) === 1 ? 16 : 8;
    const total = boxHeader === 16 ? u64(b, first.data + 16) : u32(b, first.data + 8);
    const en = u16(b, first.data + 2), parts = [b.subarray(first.data + 8, first.end)], group = [first];
    let collected = parts[0].length, z = 1;
    while (collected < total) {
      const next = segments[++i];
      if (!next || next.marker !== 0xeb || next.start !== group.at(-1).end || next.end - next.data < 8 + boxHeader || ascii(b, next.data, 2) !== 'JP' || u16(b, next.data + 2) !== en || u32(b, next.data + 4) !== ++z || !eq(b, next.data + 8, b.subarray(first.data + 8, first.data + 8 + boxHeader))) error('Incomplete or inconsistent C2PA JPEG fragments; the original is preserved.');
      parts.push(b.subarray(next.data + 8 + boxHeader, next.end)); group.push(next);
      collected += parts.at(-1).length;
    }
    if (collected !== total) error('C2PA JPEG fragments do not match the declared JUMBF length.');
    const payload = concat(parts);
    if (!isStore(payload, 0, payload.length)) error('Invalid C2PA JPEG manifest container.');
    found(r, first.start, group.at(-1).end, payload, 'C2PA manifest store', `${group.length} JPEG APP11 segment${group.length === 1 ? '' : 's'}; JUMBF UUID and label identified.`);
    for (const s of group) r._remove.push(s);
  }
  if (offsetSensitive && r._remove.length) {
    r._neutralizeJpeg = true;
    r.method = 'Replace C2PA APP11 with same-size empty JPEG comments; preserve file offsets';
    r.warnings.push('C2PA payloads are erased without changing file length, preserving multipart and metadata offsets.');
  }
  return finish(r);
}

const crcTable = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = (n & 1) ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
export function pngCRC(bytes) { let c = 0xffffffff; for (const x of bytes) c = crcTable[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function png(b) {
  const r = base('PNG', 'image/png', 'Remove caBX chunks; preserve image chunks and their original compressed bytes');
  let p = 8, items = 0, ihdr = false, idat = false, iend = false;
  r._crcChunks = [];
  while (p < b.length) {
    if (++items > MAX_ITEMS) error('Too many PNG chunks.');
    requireBytes(b, p, 12, 'PNG chunk');
    const size = u32(b, p), end = p + 12 + size, data = p + 8, type = ascii(b, p + 4, 4);
    requireBytes(b, p, 12 + size, 'PNG chunk');
    if (!/^[A-Za-z]{4}$/.test(type)) error('Invalid PNG chunk type.');
    if (pngCRC(b.subarray(p + 4, end - 4)) !== u32(b, end - 4)) error(`PNG ${type} checksum failed; the original is preserved.`);
    if (!ihdr) { if (type !== 'IHDR' || size !== 13) error('PNG has no valid first IHDR chunk.'); ihdr = true; }
    else if (type === 'IHDR') error('PNG contains duplicate IHDR chunks.');
    if (type === 'IDAT') idat = true;
    if (type === 'caBX') {
      found(r, p, end, b.subarray(data, end - 4), 'C2PA caBX chunk', 'Standard C2PA PNG manifest container.');
      r._remove.push({ start: p, end });
    }
    if (type === 'iTXt' || type === 'tEXt') {
      const zero = b.subarray(data, end - 4).indexOf(0);
      if (zero < 0) error(`Invalid PNG ${type} metadata chunk.`);
      const keyword = ascii(b, data, zero);
      if (keyword === 'XML:com.adobe.xmp') {
        let textStart = data + zero + 1;
        if (type === 'iTXt') {
          requireBytes(b, textStart, 2, 'PNG iTXt compression fields');
          const compressed = b[textStart], compression = b[textStart + 1];
          textStart += 2;
          if (compressed > 1 || compression !== 0) error('Invalid PNG iTXt compression fields.');
          for (let z = 0; z < 2; z++) {
            const stop = b.subarray(textStart, end - 4).indexOf(0);
            if (stop < 0) error('Invalid PNG iTXt text fields.');
            textStart += stop + 1;
          }
          if (compressed) { r.warnings.push('Compressed PNG XMP is preserved; remote provenance in compressed XMP is not inspected.'); p = end; continue; }
        }
        const before = r._patch.length;
        xmpReferences(b, textStart, end - 4, r, `PNG ${type} XMP`);
        if (r._patch.length > before) r._crcChunks.push({ start: p, end });
      }
    }
    p = end;
    if (type === 'IEND') { if (size !== 0) error('Invalid PNG IEND length.'); iend = true; break; }
  }
  if (!iend || !idat) error('PNG is missing its image data or end marker.');
  if (p < b.length) r.warnings.push('Data after the PNG end marker is preserved and is not inspected.');
  return finish(r);
}

function riff(b) {
  const form = ascii(b, 8, 4);
  const format = form === 'WEBP' ? 'WebP' : form === 'WAVE' ? 'WAV' : form === 'AVI ' ? 'AVI' : 'RIFF';
  const mime = form === 'WEBP' ? 'image/webp' : form === 'WAVE' ? 'audio/wav' : form === 'AVI ' ? 'video/x-msvideo' : 'application/octet-stream';
  const r = base(format, mime, 'Remove C2PA RIFF chunks and update container size');
  if (format === 'AVI' || format === 'RIFF') { r._neutralizeRiff = true; r.method = 'Erase C2PA payloads as same-size JUNK chunks; preserve indexes and offsets'; }
  const end = 8 + u32(b, 4, true);
  if (end < 12 || end > b.length) error('Invalid RIFF container size.');
  let p = 12, items = 0;
  while (p < end) {
    if (++items > MAX_ITEMS) error('Too many RIFF chunks.');
    requireBytes(b, p, 8, 'RIFF chunk');
    const type = ascii(b, p, 4), size = u32(b, p + 4, true), data = p + 8, chunkEnd = data + size + (size & 1);
    if (chunkEnd > end) error('RIFF chunk exceeds its container.');
    if (type === 'C2PA') { found(r, p, chunkEnd, b.subarray(data, data + size), 'C2PA RIFF chunk'); r._remove.push({ start: p, end: chunkEnd, data }); }
    if (type === 'XMP ' || type === '_PMX') xmpReferences(b, data, data + size, r, `${format} XMP chunk`);
    p = chunkEnd;
  }
  if (p !== end) error('Invalid RIFF chunk alignment.');
  r._riffEnd = end;
  if (end < b.length) {
    r.warnings.push('Additional RIFF/AVIX containers or trailing content are preserved; only the first RIFF container is inspected.');
    if (format === 'WAV' || format === 'WebP') { r._neutralizeRiff = true; r.method = 'Erase C2PA payloads as same-size JUNK chunks; preserve trailing content offsets'; }
  }
  return finish(r);
}

function gif(b) {
  const r = base('GIF', 'image/gif', 'Remove C2PA_GIF application extensions; preserve animation and image blocks');
  requireBytes(b, 0, 13, 'GIF header');
  let p = 13 + ((b[10] & 128) ? 3 * (1 << ((b[10] & 7) + 1)) : 0), trailer = false, items = 0;
  requireBytes(b, 0, p, 'GIF global palette');
  function subblocks(start) {
    const pieces = []; let q = start, count = 0;
    while (true) {
      if (++count > MAX_ITEMS) error('Too many GIF data sub-blocks.');
      requireBytes(b, q, 1, 'GIF sub-block');
      const n = b[q++];
      if (n === 0) return { end: q, pieces };
      requireBytes(b, q, n, 'GIF sub-block');
      pieces.push(b.subarray(q, q + n)); q += n;
    }
  }
  while (p < b.length) {
    if (++items > MAX_ITEMS) error('Too many GIF blocks.');
    const start = p, type = b[p++];
    if (type === 0x3b) { trailer = true; break; }
    if (type === 0x2c) {
      requireBytes(b, p, 9, 'GIF image descriptor');
      const packed = b[p + 8]; p += 9;
      if (packed & 128) p += 3 * (1 << ((packed & 7) + 1));
      requireBytes(b, p, 1, 'GIF LZW code size'); p++;
      p = subblocks(p).end;
    } else if (type === 0x21) {
      requireBytes(b, p, 2, 'GIF extension header');
      const label = b[p++], n = b[p];
      if (label === 0xff) {
        if (n !== 11) error('Invalid GIF application extension length.');
        requireBytes(b, p + 1, n, 'GIF application identifier');
        const c2pa = ascii(b, p + 1, 8) === 'C2PA_GIF';
        const dataStart = p + 1 + n, blocks = subblocks(dataStart);
        if (c2pa) {
          found(r, start, blocks.end, concat(blocks.pieces), 'C2PA GIF application extension', `Version ${b[p + 9]}.${b[p + 10]}`);
          r._remove.push({ start, end: blocks.end });
        }
        if (ascii(b, p + 1, 11) === 'XMP DataXMP') r.warnings.push('GIF XMP is preserved; external provenance references inside GIF XMP are not inspected.');
        p = blocks.end;
      } else {
        p = subblocks(p).end;
      }
    } else error('Unknown or malformed GIF block.');
  }
  if (!trailer) error('GIF is missing its trailer.');
  if (p < b.length) r.warnings.push('Data after the GIF trailer is preserved and is not inspected.');
  return finish(r);
}

function bmff(b, filename) {
  let format = 'BMFF', mime = 'application/octet-stream';
  const ext = filename.split('.').pop().toLowerCase();
  const r = base(format, mime, 'Erase top-level C2PA UUID boxes as same-size free boxes; preserve absolute media offsets');
  let p = 0, items = 0;
  while (p < b.length) {
    if (++items > MAX_ITEMS) error('Too many BMFF boxes.');
    const box = boxAt(b, p, b.length), data = p + box.header;
    if (box.type === 'ftyp') {
      if (box.size < box.header + 8) error('Invalid BMFF file-type box.');
      const brands = ascii(b, data, 4) + ascii(b, data + 8, box.end - data - 8);
      if (/avif|avis/.test(brands)) { format = 'AVIF'; mime = 'image/avif'; }
      else if (/heic|heix|hevc|hevx/.test(brands)) { format = 'HEIC'; mime = 'image/heic'; }
      else if (/mif1|msf1/.test(brands)) { format = 'HEIF'; mime = 'image/heif'; }
      else if (/qt  /.test(brands)) { format = 'MOV'; mime = 'video/quicktime'; }
      else if (ext === 'm4a') { format = 'M4A'; mime = 'audio/mp4'; }
      else { format = 'MP4'; mime = 'video/mp4'; }
    }
    if (box.type === 'uuid') {
      if (box.size < box.header + 16) error('Truncated BMFF UUID box.');
      if (eq(b, data, BMFF_UUID)) {
        const purposeStart = data + 20;
        let purposeEnd = purposeStart;
        if (purposeStart <= box.end) { while (purposeEnd < box.end && purposeEnd - purposeStart < 128 && b[purposeEnd]) purposeEnd++; }
        const purpose = purposeEnd < box.end && purposeEnd > purposeStart ? ascii(b, purposeStart, purposeEnd - purposeStart) : '';
        let payload = null;
        // FullBox version/flags then zero-terminated box_purpose. Manifest
        // purpose adds an 8-byte absolute manifest offset before JUMBF.
        if (['manifest', 'original', 'update'].includes(purpose) && purposeEnd + (purpose === 'update' ? 1 : 9) <= box.end) {
          const jumbStart = purposeEnd + (purpose === 'update' ? 1 : 9);
          if (isStore(b, jumbStart, box.end)) payload = b.subarray(jumbStart, box.end);
        }
        found(r, p, box.end, payload, 'C2PA BMFF UUID box', purpose ? `Purpose: ${purpose}` : 'C2PA UUID identified; payload syntax is not interpreted.');
        r._remove.push(box);
      } else if (eq(b, data, XMP_UUID)) xmpReferences(b, data + 16, box.end, r, `${format} top-level XMP UUID box`);
    }
    p = box.end;
  }
  if (format === 'BMFF') {
    if (ext === 'mov') { format = 'MOV'; mime = 'video/quicktime'; }
    else if (ext === 'm4s') { format = 'MP4 fragment'; mime = 'video/mp4'; }
  }
  r.format = format; r.mime = mime; r._bmff = true;
  r.warnings.push('Inspection covers standard top-level C2PA UUID boxes. Embedded thumbnails, nested nonstandard metadata, and manifests in separate stream fragments are outside this pass.');
  return finish(r);
}

function tiff(b, filename) {
  const le = ascii(b, 0, 2) === 'II', version = u16(b, 2, le), big = version === 43;
  const width = big ? 8 : 4, countWidth = big ? 8 : 2, entryWidth = big ? 20 : 12;
  const readOffset = (o) => big ? u64(b, o, le) : u32(b, o, le);
  const readCount = (o) => big ? u64(b, o, le) : u16(b, o, le);
  const writeOffset = (out, o, n) => big ? put64(out, o, n, le) : put32(out, o, n, le);
  const writeCount = (out, o, n) => big ? put64(out, o, n, le) : put16(out, o, n, le);
  const headerSize = big ? 16 : 8;
  const r = base(/\.dng$/i.test(filename) ? 'DNG' : (big ? 'BigTIFF' : 'TIFF'), 'image/tiff', 'Remove C2PA IFD tags and erase manifest payloads while preserving all other offsets');
  if (version !== 42 && version !== 43) error('Unsupported TIFF version.');
  requireBytes(b, 0, headerSize, 'TIFF header');
  if (big && (u16(b, 4, le) !== 8 || u16(b, 6, le) !== 0)) error('Unsupported BigTIFF offset format.');
  const firstPointer = big ? 8 : 4, first = readOffset(firstPointer), ifds = [], visited = new Set(), protectedRanges = [{ start: 0, end: headerSize }], payloads = [], queue = [{ offset: first, main: true, pointer: firstPointer }];
  const typeSizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8 };
  let totalEntries = 0;
  function values(entry) {
    if (![3, 4, 13, 16, 18].includes(entry.type)) error('Unsupported TIFF pointer type.');
    const stride = typeSizes[entry.type], out = [];
    for (let i = 0; i < entry.count; i++) {
      const o = entry.data + i * stride;
      out.push(stride === 8 ? u64(b, o, le) : stride === 4 ? u32(b, o, le) : u16(b, o, le));
    }
    return out;
  }
  while (queue.length) {
    const request = queue.shift();
    if (!request.offset) continue;
    if (visited.has(request.offset)) error('Cyclic or shared TIFF IFD pointers; safe removal is unavailable.');
    visited.add(request.offset);
    if (visited.size > 10000) error('Too many TIFF directories.');
    const offset = request.offset, count = readCount(offset);
    totalEntries += count;
    if (totalEntries > MAX_ITEMS) error('Too many TIFF entries.');
    const end = offset + countWidth + count * entryWidth + width;
    requireBytes(b, offset, end - offset, 'TIFF directory');
    const ifd = { ...request, count, end, nextPointer: end - width, entries: [], targets: [] };
    protectedRanges.push({ start: offset, end });
    for (let i = 0; i < count; i++) {
      const entryOffset = offset + countWidth + i * entryWidth, tag = u16(b, entryOffset, le), type = u16(b, entryOffset + 2, le);
      const n = big ? u64(b, entryOffset + 4, le) : u32(b, entryOffset + 4, le), size = typeSizes[type];
      if (!size) error(`Unsupported TIFF field type ${type}; the original is preserved.`);
      const length = n * size;
      if (!Number.isSafeInteger(length)) error('TIFF tag length exceeds the safe range.');
      const valueOffset = entryOffset + (big ? 12 : 8), inline = length <= width, data = inline ? valueOffset : readOffset(valueOffset);
      requireBytes(b, data, length, 'TIFF tag value');
      const entry = { index: i, entryOffset, tag, type, count: n, length, data, inline };
      ifd.entries.push(entry);
      if (tag === 0xcd41) {
        if (type !== 7) error('C2PA TIFF tag has an invalid field type.');
        ifd.targets.push(entry);
        if (!inline && length) payloads.push({ start: data, end: data + length, entry });
        found(r, entryOffset, entryOffset + entryWidth, b.subarray(data, data + length), 'C2PA TIFF tag 0xCD41', `${length.toLocaleString('en-US')} payload bytes in ${request.main ? 'main' : 'sub'}-IFD.`);
      } else if (!inline && length) protectedRanges.push({ start: data, end: data + length });
      if (tag === 700) xmpReferences(b, data, data + length, r, `${r.format} XMP tag 700`);
      if ([330, 34665, 34853, 40965].includes(tag)) {
        for (const child of values(entry)) if (child) queue.push({ offset: child, main: false, pointer: null });
      }
    }
    // Protect every declared strip/tile/JPEG data range, not just tag arrays.
    for (const [offsetTag, sizeTag] of [[273, 279], [324, 325], [513, 514]]) {
      const os = ifd.entries.find(e => e.tag === offsetTag), ns = ifd.entries.find(e => e.tag === sizeTag);
      if (os && ns) {
        const offsets = values(os), lengths = values(ns);
        if (offsets.length !== lengths.length) error('TIFF image data offsets and sizes disagree.');
        for (let i = 0; i < offsets.length; i++) { requireBytes(b, offsets[i], lengths[i], 'TIFF image data'); protectedRanges.push({ start: offsets[i], end: offsets[i] + lengths[i] }); }
      }
    }
    const next = readOffset(ifd.nextPointer);
    if (next) queue.push({ offset: next, main: request.main, pointer: ifd.nextPointer });
    ifds.push(ifd);
  }
  if (!first) error('TIFF contains no image directory.');
  for (const range of payloads) {
    if (protectedRanges.some(p => overlaps(p, range)) || payloads.some(p => p !== range && overlaps(p, range))) error('C2PA TIFF payload overlaps another structure or image data; safe removal is unavailable.');
  }
  r._tiffApply = (out) => {
    for (const range of payloads) out.fill(0, range.start, range.end);
    // Process child/last directories first so rewritten next pointers survive
    // compaction of an earlier directory.
    for (const ifd of ifds.slice().reverse()) {
      if (!ifd.targets.length) continue;
      const kept = ifd.entries.filter(e => e.tag !== 0xcd41);
      if (!kept.length && ifd.main && ifd.pointer != null && ifd.offset !== first && readOffset(ifd.nextPointer) === 0) {
        writeOffset(out, ifd.pointer, 0); out.fill(0, ifd.offset, ifd.end); continue;
      }
      const next = big ? u64(out, ifd.nextPointer, le) : u32(out, ifd.nextPointer, le);
      // Copy kept original entries before altering the overlapping table area.
      const entries = kept.map(e => out.slice(e.entryOffset, e.entryOffset + entryWidth));
      out.fill(0, ifd.offset, ifd.end);
      writeCount(out, ifd.offset, kept.length);
      entries.forEach((entry, i) => out.set(entry, ifd.offset + countWidth + i * entryWidth));
      writeOffset(out, ifd.offset + countWidth + kept.length * entryWidth, next);
    }
  };
  r.warnings.push('Manifest bytes are erased in place; TIFF file size remains unchanged. Proprietary maker-note structures are preserved and are not recursively inspected.');
  return finish(r);
}

function identify(b, filename) {
  if (eq(b, 0, PNG_SIGNATURE)) return { format: 'PNG', mime: 'image/png', parse: () => png(b) };
  if (b.length >= 2 && b[0] === 255 && b[1] === 0xd8) return { format: 'JPEG', mime: 'image/jpeg', parse: () => jpeg(b) };
  if (b.length >= 6 && ['GIF87a', 'GIF89a'].includes(ascii(b, 0, 6))) return { format: 'GIF', mime: 'image/gif', parse: () => gif(b) };
  if (b.length >= 4 && ['II', 'MM'].includes(ascii(b, 0, 2)) && [42, 43].includes(u16(b, 2, ascii(b, 0, 2) === 'II'))) return { format: /\.dng$/i.test(filename) ? 'DNG' : 'TIFF', mime: 'image/tiff', parse: () => tiff(b, filename) };
  if (b.length >= 12 && ascii(b, 0, 4) === 'RIFF') return { format: ascii(b, 8, 4) === 'WEBP' ? 'WebP' : ascii(b, 8, 4) === 'WAVE' ? 'WAV' : ascii(b, 8, 4) === 'AVI ' ? 'AVI' : 'RIFF', mime: 'application/octet-stream', parse: () => riff(b) };
  if (b.length >= 8 && (ascii(b, 4, 4) === 'ftyp' || (/\.(mp4|mov|m4a|m4v|m4s|heic|heif|avif)$/i.test(filename) && ['moov', 'moof', 'mdat', 'free', 'skip', 'uuid', 'styp', 'wide'].includes(ascii(b, 4, 4))))) return { format: 'BMFF', mime: 'application/octet-stream', parse: () => bmff(b, filename) };
  return null;
}

/** Inspect recognized formats without uploading data or verifying signatures. */
export function analyzeImage(bytes, fileName = '') {
  if (!(bytes instanceof Uint8Array)) error('Expected a Uint8Array.');
  const id = identify(bytes, String(fileName));
  if (!id) return null;
  try {
    const r = id.parse();
    const { _remove, _patch, _crcChunks, _neutralizeJpeg, _neutralizeRiff, _riffEnd, _bmff, _tiffApply, ...visible } = r;
    return visible;
  } catch (e) {
    return { format: id.format, mime: id.mime, supported: true, valid: false, canRemove: false, method: 'Original preserved because safe structural editing is unavailable', findings: [], warnings: [e.message || 'Invalid container.'], payloads: [] };
  }
}

/** Return a new buffer. The original is never changed. Unsafe files throw. */
export function removeImage(bytes, fileName = '') {
  if (!(bytes instanceof Uint8Array)) error('Expected a Uint8Array.');
  const id = identify(bytes, String(fileName));
  if (!id) return null;
  const r = id.parse(), out = bytes.slice();
  for (const patch of r._patch) out.fill(patch.fill, patch.start, patch.end);
  for (const chunk of r._crcChunks || []) put32(out, chunk.end - 4, pngCRC(out.subarray(chunk.start + 4, chunk.end - 4)));
  let cleaned = out;
  if (r._tiffApply) r._tiffApply(cleaned);
  else if (r._bmff) {
    for (const box of r._remove) { writeAscii(out, box.start + 4, 'free'); out.fill(0, box.start + box.header, box.end); }
  } else if (r._neutralizeJpeg) {
    for (const s of r._remove) { out[s.markerOffset] = 0xfe; out.fill(0, s.data, s.end); }
  } else if (r._neutralizeRiff) {
    for (const chunk of r._remove) { writeAscii(out, chunk.start, 'JUNK'); out.fill(0, chunk.data, chunk.end); }
  } else {
    cleaned = cutRanges(out, r._remove);
    if (r._riffEnd != null) put32(cleaned, 4, r._riffEnd - r._remove.reduce((n, c) => n + c.end - c.start, 0) - 8, true);
  }
  return { bytes: cleaned, removed: r.findings.length, method: r.method, warnings: r.warnings.slice() };
}
