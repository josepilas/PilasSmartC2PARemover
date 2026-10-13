/**
 * Bounded, read-only inspection of C2PA JUMBF, JSON and CBOR metadata.
 * This is a metadata decoder, never a C2PA validator or identity verifier.
 * Sources: C2PA Technical Specification 2.4; RFC 8949; RFC 9052;
 * contentauth/c2pa-rs sdk/src/jumbf/boxes.rs (JUMBF description layout).
 */
export const MANIFEST_SOURCES = Object.freeze([
  { title: 'C2PA Technical Specification 2.4', url: 'https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html' },
  { title: 'CBOR — RFC 8949', url: 'https://www.rfc-editor.org/rfc/rfc8949.html' },
  { title: 'COSE — RFC 9052', url: 'https://www.rfc-editor.org/rfc/rfc9052.html' },
  { title: 'C2PA SDK JUMBF description implementation', url: 'https://github.com/contentauth/c2pa-rs/blob/main/sdk/src/jumbf/boxes.rs' },
]);

const LIMITS = Object.freeze({ payloads: 128, payloadBytes: 64 * 1024 * 1024, boxes: 4096, depth: 24, cborItems: 24000, textBytes: 2 * 1024 * 1024, decodedBytes: 8 * 1024 * 1024, jsonNodes: 24000, preview: 48 });
const decoder = new TextDecoder('utf-8', { fatal: true });
const looseDecoder = new TextDecoder('utf-8');
const UNVERIFIED = 'Metadata is decoded only. Cryptographic signatures, asset bindings, certificate chains, and signer identity are not verified.';
const BREAK = Symbol('CBOR break');

function hex(bytes, max = bytes.length) {
  let result = '';
  for (let i = 0; i < Math.min(bytes.length, max); i++) result += bytes[i].toString(16).padStart(2, '0');
  return result;
}
function binary(bytes) {
  return { $binary: true, byteLength: bytes.length, hexPreview: hex(bytes, LIMITS.preview), truncated: bytes.length > LIMITS.preview };
}
function uuid(bytes) {
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function error(message) { return new Error(message); }
function isObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function isMap(value) { return isObject(value) && !(value instanceof Uint8Array) && !('$tag' in value); }
function own(value, key) { return isObject(value) && Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined; }

/** Ensure every result can be JSON.stringify'd without precision loss or unsafe properties. */
export function safeMetadata(value) {
  const seen = new WeakSet();
  let nodes = 0;
  function visit(item, depth) {
    if (++nodes > LIMITS.jsonNodes) return '[Inspection item limit reached]';
    if (depth > LIMITS.depth + 8) return '[Inspection depth limit reached]';
    if (typeof item === 'bigint') return { $integer: item.toString() };
    if (typeof item === 'number' && !Number.isFinite(item)) return { $float: String(item) };
    if (item === undefined) return { $undefined: true };
    if (item instanceof Uint8Array) return binary(item);
    if (item === null || typeof item !== 'object') return item;
    if (seen.has(item)) return '[Repeated reference]';
    seen.add(item);
    if (Array.isArray(item)) {
      const output = [];
      for (const child of item) {
        if (nodes >= LIMITS.jsonNodes) { output.push('[Inspection item limit reached]'); break; }
        output.push(visit(child, depth + 1));
      }
      return output;
    }
    const output = Object.create(null);
    for (const key of Object.keys(item)) {
      if (nodes >= LIMITS.jsonNodes) { output.$inspectionTruncated = true; break; }
      output[key] = visit(item[key], depth + 1);
    }
    return output;
  }
  return visit(value, 0);
}

/** A bounded CBOR decoder. Byte strings remain binary until safeMetadata is called. */
function readCbor(bytes) {
  let position = 0, items = 0, decodedBytes = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  function need(length) { if (!Number.isSafeInteger(length) || length < 0 || position + length > bytes.length) throw error(`Truncated CBOR at byte ${position}`); }
  function take(length) { need(length); const result = bytes.subarray(position, position + length); position += length; return result; }
  function argument(ai) {
    if (ai < 24) return ai;
    if (ai === 24) { need(1); return bytes[position++]; }
    if (ai === 25) { need(2); const n = view.getUint16(position); position += 2; return n; }
    if (ai === 26) { need(4); const n = view.getUint32(position); position += 4; return n; }
    if (ai === 27) { need(8); const n = view.getBigUint64(position); position += 8; return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n; }
    if (ai === 31) return null;
    throw error(`Reserved CBOR additional information ${ai}`);
  }
  function length(value) {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw error('CBOR length exceeds safe inspection limits');
    return value;
  }
  function account(n, text = false) {
    if (text && n > LIMITS.textBytes) throw error('CBOR text exceeds inspection size limit');
    decodedBytes += n;
    if (decodedBytes > LIMITS.decodedBytes) throw error('CBOR decoded bytes exceed inspection size limit');
  }
  function read(depth = 0, allowBreak = false) {
    if (depth > LIMITS.depth) throw error('CBOR nesting exceeds inspection depth limit');
    if (++items > LIMITS.cborItems) throw error('CBOR item count exceeds inspection limit');
    need(1);
    const initial = bytes[position++], major = initial >> 5, ai = initial & 31;
    if (initial === 255) { if (allowBreak) return BREAK; throw error('Unexpected CBOR break'); }
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 25) {
        need(2); const h = view.getUint16(position); position += 2;
        const sign = h & 0x8000 ? -1 : 1, exponent = (h >> 10) & 31, fraction = h & 1023;
        return exponent === 31 ? (fraction ? NaN : sign * Infinity) : exponent === 0 ? sign * 2 ** -14 * (fraction / 1024) : sign * 2 ** (exponent - 15) * (1 + fraction / 1024);
      }
      if (ai === 26) { need(4); const n = view.getFloat32(position); position += 4; return n; }
      if (ai === 27) { need(8); const n = view.getFloat64(position); position += 8; return n; }
      if (ai < 20) return { $simple: ai };
      if (ai === 24) { need(1); const simple = bytes[position++]; if (simple < 32) throw error('Invalid CBOR simple value encoding'); return { $simple: simple }; }
      throw error('Invalid CBOR simple or float value');
    }
    const arg = argument(ai);
    if (major === 0 || major === 1) {
      if (arg === null) throw error('Indefinite CBOR integer');
      if (major === 0) return arg;
      // -1 - MAX_SAFE_INTEGER falls outside the safe-number range as well.
      return typeof arg === 'bigint' || arg === Number.MAX_SAFE_INTEGER ? -1n - BigInt(arg) : -1 - arg;
    }
    if (major === 2 || major === 3) {
      if (arg !== null) { const n = length(arg); account(n, major === 3); const b = take(n); return major === 2 ? b : decoder.decode(b); }
      const pieces = []; let total = 0;
      while (true) {
        need(1);
        if (bytes[position] === 255) { position++; break; }
        if ((bytes[position] >> 5) !== major || (bytes[position] & 31) === 31) throw error('Invalid indefinite CBOR string chunk');
        const piece = read(depth + 1);
        total += major === 2 ? piece.length : piece.length;
        if (total > LIMITS.decodedBytes) throw error('Indefinite CBOR string exceeds inspection limit');
        pieces.push(piece);
      }
      if (major === 3) return pieces.join('');
      const output = new Uint8Array(total); let at = 0;
      for (const piece of pieces) { output.set(piece, at); at += piece.length; }
      return output;
    }
    if (major === 4 || major === 5) {
      const count = arg === null ? Infinity : length(arg);
      if (count > LIMITS.cborItems && count !== Infinity) throw error('CBOR collection exceeds inspection item limit');
      const output = major === 4 ? [] : Object.create(null), entries = [], keys = new Set();
      let ordinaryMap = true;
      try {
        for (let i = 0; i < count; i++) {
          const key = read(depth + 1, arg === null);
          if (key === BREAK) break;
          if (major === 4) { output.push(key); continue; }
          let item;
          try { item = read(depth + 1); } catch (failure) { if ('partial' in failure) entries.push([key, failure.partial]); throw failure; }
          entries.push([key, item]);
          if ((typeof key !== 'string' && typeof key !== 'number') || keys.has(String(key))) ordinaryMap = false;
          if (typeof key === 'string' || typeof key === 'number') { output[String(key)] = item; keys.add(String(key)); }
        }
      } catch (failure) {
        failure.partial = major === 4 ? output : ordinaryMap ? output : { $map: entries };
        throw failure;
      }
      return major === 4 ? output : ordinaryMap ? output : { $map: entries };
    }
    if (major === 6) {
      if (arg === null) throw error('Indefinite CBOR tag');
      return { $tag: typeof arg === 'bigint' ? arg.toString() : arg, value: read(depth + 1) };
    }
    throw error(`Unsupported CBOR major type ${major}`);
  }
  try {
    const value = read();
    return { value, warnings: position < bytes.length ? [`${bytes.length - position} trailing CBOR bytes were not decoded`] : [] };
  } catch (failure) {
    return { value: own(failure, 'partial'), warnings: [failure.message], partial: true };
  }
}

function unwrapTag(value) { while (isObject(value) && '$tag' in value && 'value' in value) value = value.value; return value; }

// Read certificate names for display only. Does not validate certificate or issuer identity.
function certificateNames(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 1024 * 1024) return null;
  let nodes = 0;
  function tlv(at, end = bytes.length) {
    if (++nodes > 256 || at + 2 > end) throw error('Invalid DER');
    const tag = bytes[at++]; let n = bytes[at++];
    if (n & 128) { const count = n & 127; if (!count || count > 4 || at + count > end) throw error('Invalid DER length'); n = 0; for (let i = 0; i < count; i++) n = n * 256 + bytes[at++]; }
    if (at + n > end) throw error('Truncated DER');
    return { tag, start: at, end: at + n };
  }
  function children(item) { const out = []; for (let at = item.start; at < item.end;) { const child = tlv(at, item.end); out.push(child); at = child.end; } return out; }
  function name(item) {
    const attrs = [];
    const names = { '550403': 'CN', '550406': 'C', '550407': 'L', '550408': 'ST', '55040a': 'O', '55040b': 'OU', '2a864886f70d010901': 'emailAddress' };
    for (const set of children(item)) for (const seq of children(set)) {
      const pair = children(seq); if (pair.length !== 2 || pair[0].tag !== 6) continue;
      const type = names[hex(bytes.subarray(pair[0].start, pair[0].end))]; if (!type) continue;
      const b = bytes.subarray(pair[1].start, pair[1].end); let value;
      if ([12, 19, 20, 22].includes(pair[1].tag)) value = looseDecoder.decode(b);
      else if (pair[1].tag === 30 && b.length % 2 === 0) { value = ''; for (let i = 0; i < b.length; i += 2) value += String.fromCharCode(b[i] * 256 + b[i + 1]); }
      if (value) attrs.push(`${type}=${value}`);
    }
    return attrs.join(', ');
  }
  try {
    const root = tlv(0); if (root.tag !== 48 || root.end !== bytes.length) return null;
    const certificate = children(root);
    if (certificate.length !== 3 || certificate[0].tag !== 48 || certificate[1].tag !== 48 || certificate[2].tag !== 3) return null;
    const tbs = children(certificate[0]);
    const offset = tbs[0].tag === 0xa0 ? 1 : 0;
    if (tbs.length < offset + 6 || tbs[offset].tag !== 2 || tbs.slice(offset + 1, offset + 6).some(item => item.tag !== 48)) return null;
    const issuer = name(tbs[offset + 2]), subject = name(tbs[offset + 4]);
    return issuer || subject ? { issuer, subject, verification: 'Certificate name fields only; not verified' } : null;
  } catch { return null; }
}

function inspectCose(value) {
  const array = unwrapTag(value);
  if (!Array.isArray(array) || array.length !== 4 || !(array[0] instanceof Uint8Array) || !isMap(array[1])) return null;
  const protectedData = array[0].length ? readCbor(array[0]) : { value: Object.create(null), warnings: [] };
  const headers = unwrapTag(protectedData.value);
  const chain = own(headers, '33') ?? own(array[1], '33') ?? own(headers, 'x5chain') ?? own(array[1], 'x5chain');
  const certificates = (Array.isArray(chain) ? chain : chain instanceof Uint8Array ? [chain] : []).slice(0, 8).map(certificateNames).filter(Boolean);
  return { type: 'COSE_Sign1 structure', protectedHeaders: safeMetadata(headers), unprotectedHeaders: safeMetadata(array[1]), certificates, signature: safeMetadata(array[3]), verification: 'Not performed', warnings: protectedData.warnings };
}

/** Inspect extracted manifest payloads; never throws for malformed user files. */
export function inspectManifests(payloads) {
  const result = { labels: [], claims: [], assertions: [], summary: {}, boxes: [], raw: [], warnings: [UNVERIFIED], verification: { performed: false } };
  const labelSet = new Set(), warningSet = new Set(result.warnings), actions = new Set();
  let boxCount = 0, ingredients = 0;
  function warn(message) { if (warningSet.size < 160 && !warningSet.has(message)) { warningSet.add(message); result.warnings.push(message); } }
  function addLabel(label) { if (label && !labelSet.has(label)) { labelSet.add(label); result.labels.push(label); } }
  function summarize(data, label, isClaim) {
    data = unwrapTag(data);
    if (!isMap(data)) return;
    if (isClaim) {
      const generators = own(data, 'claim_generator_info');
      const generator = own(data, 'claim_generator') ?? (Array.isArray(generators) ? own(generators[0], 'name') : own(generators, 'name'));
      const title = own(data, 'dc:title') ?? own(data, 'title');
      if (typeof generator === 'string' && !result.summary.generator) result.summary.generator = generator;
      if (typeof title === 'string' && !result.summary.title) result.summary.title = title;
    }
    if (/^c2pa\.actions(?:\.|$)/.test(label)) {
      const list = own(data, 'actions');
      if (Array.isArray(list)) for (const item of list) { const action = own(item, 'action'); if (typeof action === 'string') actions.add(action); }
    }
    if (/^c2pa\.ingredient(?:\.|$)/.test(label)) ingredients++;
  }
  function record(data, encoding, path, label, ancestors, node, partial = false) {
    const unwrapped = unwrapTag(data);
    const claim = /^c2pa\.claim(?:\.|$)/.test(label) || node?.contentType?.startsWith('6332636c-') || (isMap(unwrapped) && (own(unwrapped, 'claim_generator') || own(unwrapped, 'claim_generator_info')) && !ancestors.includes('c2pa.assertions'));
    const assertion = ancestors.includes('c2pa.assertions');
    const entry = { label: label || (claim ? 'Unlabelled claim data' : 'Unlabelled metadata'), path, encoding, data: safeMetadata(data) };
    if (partial) entry.partial = true;
    if (claim) result.claims.push(entry);
    else if (assertion) result.assertions.push(entry);
    const cose = label === 'c2pa.signature' ? inspectCose(data) : null;
    if (cose) entry.cose = cose;
    result.raw.push(entry);
    summarize(data, label, claim);
  }
  function description(bytes, at, end) {
    const desc = {};
    if (end - at < 17) { warn('Truncated JUMBF description'); return desc; }
    desc.contentType = uuid(bytes.subarray(at, at + 16)); desc.flags = bytes[at + 16]; let position = at + 17;
    if (desc.flags & 2) {
      let zero = position; while (zero < end && bytes[zero] !== 0 && zero - position <= LIMITS.textBytes) zero++;
      if (zero === end || zero - position > LIMITS.textBytes) warn('JUMBF label is unterminated or exceeds inspection limit');
      desc.label = looseDecoder.decode(bytes.subarray(position, Math.min(zero, position + LIMITS.textBytes))); addLabel(desc.label); position = zero + 1;
    }
    if (desc.flags & 4) { if (position + 4 <= end) { desc.id = new DataView(bytes.buffer, bytes.byteOffset + position, 4).getUint32(0); position += 4; } else warn('Truncated JUMBF box identifier'); }
    if (desc.flags & 8) { if (position + 32 <= end) { desc.descriptionHash = binary(bytes.subarray(position, position + 32)); position += 32; } else warn('Truncated JUMBF description hash'); }
    if (desc.flags & 16) desc.privateData = binary(bytes.subarray(Math.min(position, end), end));
    return desc;
  }
  function parseBoxes(bytes, start, end, depth, ancestors, path, parentDescription = {}) {
    const output = [];
    if (depth > LIMITS.depth) { warn('JUMBF nesting exceeds inspection depth limit'); return output; }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let at = start; at < end;) {
      if (++boxCount > LIMITS.boxes) { warn('JUMBF box count exceeds inspection limit'); break; }
      if (end - at < 8) { if (bytes.subarray(at, end).some(v => v !== 0)) warn(`Truncated JUMBF box header at byte ${at}`); break; }
      let size = view.getUint32(at), header = 8;
      const type = String.fromCharCode(...bytes.subarray(at + 4, at + 8));
      if (size === 1) { if (end - at < 16) { warn(`Truncated extended JUMBF box header at byte ${at}`); break; } const large = view.getBigUint64(at + 8); if (large > BigInt(Number.MAX_SAFE_INTEGER)) { warn('JUMBF box size exceeds safe inspection range'); break; } size = Number(large); header = 16; }
      if (size === 0) size = end - at;
      if (size < header || size > end - at) { warn(`Invalid or truncated ${type} box at byte ${at}`); break; }
      const body = at + header, boxEnd = at + size, node = { type, offset: at, size };
      const nodePath = `${path}/${type}[${output.length}]`;
      if (type === 'jumd') Object.assign(node, description(bytes, body, boxEnd));
      else if (type === 'jumb') {
        // JUMBF labels and content UUIDs are in the first child description box.
        let desc = {};
        if (boxEnd - body >= 8 && String.fromCharCode(...bytes.subarray(body + 4, body + 8)) === 'jumd') {
          let descSize = view.getUint32(body), descHeader = 8;
          if (descSize === 1 && boxEnd - body >= 16) { const big = view.getBigUint64(body + 8); descSize = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : 0; descHeader = 16; }
          if (descSize >= descHeader && descSize <= boxEnd - body) desc = description(bytes, body + descHeader, body + descSize);
        } else warn(`JUMBF superbox at byte ${at} has no first description box`);
        Object.assign(node, desc);
        const next = desc.label ? [...ancestors, desc.label] : ancestors;
        node.children = parseBoxes(bytes, body, boxEnd, depth + 1, next, nodePath, desc);
      } else if (type === 'cbor' || type === 'json') {
        const data = bytes.subarray(body, boxEnd), label = parentDescription.label || ancestors.at(-1) || '';
        if (data.length > LIMITS.decodedBytes) { node.data = binary(data); warn(`${type.toUpperCase()} content exceeds inspection size limit`); }
        else if (type === 'cbor') {
          const parsed = readCbor(data);
          for (const message of parsed.warnings) warn(`${label || type}: ${message}`);
          node.data = safeMetadata(parsed.value);
          if (parsed.value !== undefined) record(parsed.value, type, nodePath, label, ancestors.slice(0, -1), parentDescription, parsed.partial);
          else node.data = binary(data);
        } else {
          try { const parsed = JSON.parse(decoder.decode(data).replace(/\0+$/, '')); node.data = safeMetadata(parsed); record(parsed, type, nodePath, label, ancestors.slice(0, -1), parentDescription); }
          catch (failure) { node.data = binary(data); warn(`${label || type}: JSON decoding failed (${failure.message})`); }
        }
      } else if (type === 'xml ') {
        const data = bytes.subarray(body, boxEnd); node.text = looseDecoder.decode(data.subarray(0, LIMITS.textBytes)); if (data.length > LIMITS.textBytes) warn('XML metadata preview is truncated');
      } else { node.data = binary(bytes.subarray(body, boxEnd)); if (type === 'brob') warn('Compressed Brotli JUMBF metadata is present; inspection does not decompress this box'); }
      output.push(node); at = boxEnd;
    }
    return output;
  }
  if (!Array.isArray(payloads)) { warn('Manifest payload input must be an array'); return result; }
  if (payloads.length > LIMITS.payloads) warn('Manifest payload count exceeds inspection limit');
  for (let i = 0; i < Math.min(payloads.length, LIMITS.payloads); i++) {
    const bytes = payloads[i];
    if (!(bytes instanceof Uint8Array)) { warn(`Payload ${i + 1} is not a Uint8Array`); continue; }
    if (bytes.length > LIMITS.payloadBytes) { warn(`Payload ${i + 1} exceeds the 64 MiB inspection limit`); continue; }
    if (!bytes.length) { warn(`Payload ${i + 1} is empty`); continue; }
    try {
      let offset = -1;
      for (let at = 0; at <= Math.min(512, bytes.length - 8); at++) {
        const type = String.fromCharCode(...bytes.subarray(at + 4, at + 8));
        if (['jumb', 'jumd', 'cbor', 'json'].includes(type)) {
          // An occurrence of "jumbf" in JSON/CBOR text is not a box header.
          if (at > 0) {
            const size = new DataView(bytes.buffer, bytes.byteOffset + at, 4).getUint32(0);
            if (size !== 0 && size !== 1 && (size < 8 || size > bytes.length - at)) continue;
            if (size === 1 && bytes.length - at < 16) continue;
          }
          offset = at; break;
        }
      }
      if (offset >= 0) {
        if (offset) warn(`Payload ${i + 1}: skipped ${offset} bytes before the first JUMBF box`);
        result.boxes.push(...parseBoxes(bytes, offset, bytes.length, 0, [], `payload[${i}]`));
      } else {
        const firstText = looseDecoder.decode(bytes.subarray(0, 64)).trimStart();
        if (/^[\[{]/.test(firstText) && bytes.length <= LIMITS.decodedBytes) {
          try { record(JSON.parse(decoder.decode(bytes)), 'json', `payload[${i}]`, '', [], null); }
          catch (failure) { warn(`Payload ${i + 1}: JSON decoding failed (${failure.message})`); result.raw.push({ path: `payload[${i}]`, encoding: 'binary', data: binary(bytes) }); }
        } else if ((bytes[0] >> 5) === 5 || bytes[0] === 0xd2 || (bytes[0] === 0xd9 && bytes[1] === 0xd9 && bytes[2] === 0xf7)) {
          const parsed = readCbor(bytes); for (const message of parsed.warnings) warn(`Payload ${i + 1}: ${message}`);
          if (parsed.value !== undefined) record(parsed.value, 'cbor', `payload[${i}]`, '', [], null, parsed.partial);
          else result.raw.push({ path: `payload[${i}]`, encoding: 'binary', data: binary(bytes) });
        } else { result.raw.push({ path: `payload[${i}]`, encoding: 'binary', data: binary(bytes) }); warn(`Payload ${i + 1}: no readable JUMBF, JSON or CBOR structure was found`); }
      }
    } catch (failure) { warn(`Payload ${i + 1}: inspection stopped (${failure.message})`); }
  }
  if (actions.size) result.summary.actions = [...actions];
  if (ingredients) result.summary.ingredients = ingredients;
  return result;
}
