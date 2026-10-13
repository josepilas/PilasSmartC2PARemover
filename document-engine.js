import { PDFDocument, PDFName, PDFRef, PDFDict, PDFArray, PDFRawStream, decodePDFRawStream } from './vendor/pdf-lib.esm.js';
import { analyzeImage, removeImage, analyzeXmp, removeXmp } from './image-engine.js';

// Container handling follows C2PA 2.4, Appendix A.4 (PDF) and A.6 (ZIP).
// This is structural discovery/removal; it does not validate C2PA signatures.
const UTF8 = new TextDecoder();
const LATIN = new TextDecoder('latin1');
const MAX_EXPANDED = 256 * 1024 * 1024;
const MAX_PART = 96 * 1024 * 1024;
const PACKAGE_TYPES = {
  docx: ['DOCX', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  docm: ['DOCM', 'application/vnd.ms-word.document.macroEnabled.12'],
  dotx: ['DOTX', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'],
  dotm: ['DOTM', 'application/vnd.ms-word.template.macroEnabled.12'],
  xlsx: ['XLSX', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  xlsm: ['XLSM', 'application/vnd.ms-excel.sheet.macroEnabled.12'],
  xltx: ['XLTX', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'],
  xltm: ['XLTM', 'application/vnd.ms-excel.template.macroEnabled.12'],
  pptx: ['PPTX', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  pptm: ['PPTM', 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'],
  potx: ['POTX', 'application/vnd.openxmlformats-officedocument.presentationml.template'],
  potm: ['POTM', 'application/vnd.ms-powerpoint.template.macroEnabled.12'],
  ppsx: ['PPSX', 'application/vnd.openxmlformats-officedocument.presentationml.slideshow'],
  ppsm: ['PPSM', 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12'],
  odt: ['ODT', 'application/vnd.oasis.opendocument.text'],
  ods: ['ODS', 'application/vnd.oasis.opendocument.spreadsheet'],
  odp: ['ODP', 'application/vnd.oasis.opendocument.presentation'],
  odg: ['ODG', 'application/vnd.oasis.opendocument.graphics'],
  ott: ['OTT', 'application/vnd.oasis.opendocument.text-template'],
  epub: ['EPUB', 'application/epub+zip'],
  oxps: ['OpenXPS', 'application/oxps'],
  xps: ['XPS', 'application/vnd.ms-xpsdocument'],
  zip: ['ZIP', 'application/zip'],
};
const ext = name => String(name || '').split('.').pop().toLowerCase();
const bytesOf = value => value instanceof Uint8Array ? value : new Uint8Array(value);
const unique = items => [...new Set(items)];
const pdfName = key => PDFName.of(key);
const dictOf = object => object instanceof PDFDict ? object : object?.dict instanceof PDFDict ? object.dict : null;
const pdfString = value => {
  if (value instanceof PDFName) return value.decodeText();
  if (typeof value?.decodeText === 'function') return value.decodeText();
  return '';
};
const base = (format, mime, method) => ({ format, mime, supported: true, canRemove: true, method, findings: [], warnings: [], payloads: [], valid: true });
const PDF_METHOD = 'Full PDF rewrite with C2PA attachment and orphan-object removal';
const ZIP_METHOD = 'Package manifest removal and embedded-media cleanup';

function decodePdfStream(stream) {
  const decoder = decodePDFRawStream(stream);
  const chunks = [];
  let length = 0;
  for (;;) {
    const chunk = decoder.getBytes(64 * 1024);
    length += chunk.length;
    if (length > MAX_PART) throw new Error('Decoded PDF stream exceeds the 96 MB inspection limit.');
    if (chunk.length) chunks.push(chunk);
    if (chunk.length < 64 * 1024) break;
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

function identify(bytes, filename) {
  if (LATIN.decode(bytes.subarray(0, Math.min(1024, bytes.length))).includes('%PDF-')) return 'pdf';
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && ((bytes[2] === 3 && bytes[3] === 4) || (bytes[2] === 5 && bytes[3] === 6))) return 'zip';
  if (bytes.length >= 8 && [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1].every((v, i) => bytes[i] === v)) return 'ole';
  if (ext(filename) === 'pdf') return 'pdf';
  if (PACKAGE_TYPES[ext(filename)]) return 'zip';
  if (['doc', 'xls', 'ppt'].includes(ext(filename))) return 'ole';
  return null;
}

function pdfWalk(context, callback) {
  const visited = new Set();
  const walk = (object, location) => {
    if (!object || visited.has(object)) return;
    visited.add(object);
    callback(object, location);
    const dictionary = dictOf(object);
    if (dictionary) for (const [key, value] of dictionary.entries()) if (!(value instanceof PDFRef)) walk(value, `${location}/${key.decodeText()}`);
    if (object instanceof PDFArray) for (let i = 0; i < object.size(); i++) if (!(object.get(i) instanceof PDFRef)) walk(object.get(i), `${location}[${i}]`);
  };
  for (const [ref, object] of context.enumerateIndirectObjects()) walk(object, `Object ${ref.objectNumber} ${ref.generationNumber}`);
}

function pdfInventory(doc) {
  const context = doc.context;
  const records = [];
  pdfWalk(context, (object, location) => records.push({ object, location, dictionary: dictOf(object) }));
  const credentialObjects = new Set();
  const credentialStreams = new Set();
  const specs = [];
  const warnings = [];
  const metadataPatches = [];
  let signed = false;
  let unresolved = false;
  for (const record of records) {
    const dictionary = record.dictionary;
    if (!dictionary) continue;
    const subtype = pdfString(context.lookup(dictionary.get(pdfName('Subtype'))));
    const type = pdfString(context.lookup(dictionary.get(pdfName('Type'))));
    if (type === 'Sig' || dictionary.has(pdfName('ByteRange')) || dictionary.has(pdfName('DocMDP'))) signed = true;
    if (record.object instanceof PDFRawStream && (subtype === 'application/c2pa' || subtype === 'application/x-c2pa')) credentialStreams.add(record.object);
    const relationship = pdfString(context.lookup(dictionary.get(pdfName('AFRelationship'))));
    const filename = pdfString(context.lookup(dictionary.get(pdfName('UF')))) || pdfString(context.lookup(dictionary.get(pdfName('F'))));
    const embedded = context.lookup(dictionary.get(pdfName('EF')));
    if (relationship === 'C2PA_Manifest' || (embedded instanceof PDFDict && (/\.c2pa$/i.test(filename) || /^application\/(?:x-)?c2pa$/.test(subtype)))) {
      credentialObjects.add(record.object);
      specs.push({ ...record, filename, embedded });
      if (!(embedded instanceof PDFDict)) unresolved = true;
      else {
        let streamFound = false;
        for (const [, value] of embedded.entries()) {
          const stream = context.lookup(value);
          if (stream instanceof PDFRawStream) {
            credentialStreams.add(stream);
            streamFound = true;
          } else if (stream) unresolved = true;
        }
        if (!streamFound) unresolved = true;
      }
    }
  }
  // A typed C2PA stream may have a non-standard file specification: remove its
  // aliases too, rather than leave dangling references or recoverable bytes.
  for (const record of records) {
    if (!record.dictionary || credentialObjects.has(record.object)) continue;
    const embedded = context.lookup(record.dictionary.get(pdfName('EF')));
    if (embedded instanceof PDFDict && embedded.values().some(value => credentialStreams.has(context.lookup(value)))) {
      credentialObjects.add(record.object);
      specs.push({ ...record, filename: pdfString(context.lookup(record.dictionary.get(pdfName('UF')))) || pdfString(context.lookup(record.dictionary.get(pdfName('F')))), embedded });
    }
  }
  const payloads = [];
  const findings = [];
  for (const stream of credentialStreams) {
    const spec = specs.find(record => record.embedded instanceof PDFDict && record.embedded.values().some(value => context.lookup(value) === stream));
    const location = spec?.location || records.find(record => record.object === stream)?.location || 'Embedded file stream';
    let decoded;
    try {
      decoded = decodePdfStream(stream);
      if (decoded.length > MAX_PART) throw new Error('Manifest exceeds the inspection limit.');
      payloads.push(decoded);
    } catch (error) {
      warnings.push(`Manifest payload could not be decoded at ${location}; its attachment can still be removed.`);
    }
    findings.push({ kind: 'embedded', label: 'PDF C2PA manifest', location: `${location}${spec?.filename ? ` · ${spec.filename}` : ''}`, bytes: decoded?.length ?? stream.getContents().length, detail: 'Embedded file stream with C2PA_Manifest association or application/c2pa subtype.' });
  }
  for (const spec of specs) if (!(spec.embedded instanceof PDFDict) || !spec.embedded.values().some(value => credentialStreams.has(context.lookup(value)))) findings.push({ kind: 'embedded', label: 'PDF C2PA file specification', location: spec.location, detail: 'Manifest association exists, but its payload is missing or uses an unsupported stream object.' });
  for (const record of records) {
    if (!(record.object instanceof PDFRawStream) || pdfString(context.lookup(record.dictionary.get(pdfName('Type')))) !== 'Metadata') continue;
    try {
      const metadata = decodePdfStream(record.object);
      if (metadata.length > MAX_PART) throw new Error('PDF metadata exceeds the inspection limit.');
      const xmp = analyzeXmp(metadata, record.location);
      warnings.push(...xmp.warnings);
      if (xmp.warnings.length) unresolved = true;
      if (xmp.findings.length) {
        findings.push(...xmp.findings.map(finding => ({ ...finding, label: 'PDF XMP provenance reference' })));
        const refs = context.enumerateIndirectObjects().filter(([, object]) => object === record.object).map(([ref]) => ref);
        if (refs.length && xmp.canRemove) metadataPatches.push({ ...record, bytes: metadata, refs });
        else unresolved = true;
      }
    } catch (error) {
      warnings.push(`PDF metadata could not be fully inspected at ${record.location}: ${error.message}`);
      unresolved = true;
    }
  }
  if (signed) warnings.push('This PDF contains a digital signature. Rewriting would invalidate it, so removal is disabled.');
  if (doc.isEncrypted) warnings.push('Encrypted PDFs cannot be safely rewritten in this browser. Decrypt an authorized copy first.');
  if (unresolved) warnings.push('Some provenance structures cannot be safely resolved. Removal is disabled to avoid an incomplete result.');
  return { records, credentialObjects, credentialStreams, metadataPatches, findings, payloads, signed, unresolved, warnings };
}

async function loadPdf(bytes) {
  return PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false, throwOnInvalidObject: true });
}

async function analyzePdf(bytes) {
  const result = base('PDF', 'application/pdf', PDF_METHOD);
  try {
    const doc = await loadPdf(bytes);
    if (doc.isEncrypted) {
      result.encrypted = true;
      result.canRemove = false;
      result.warnings.push('Encrypted PDF: inspection of encrypted contents is incomplete and removal is disabled.');
      return result;
    }
    const inventory = pdfInventory(doc);
    Object.assign(result, { findings: inventory.findings, warnings: inventory.warnings, payloads: inventory.payloads, signed: inventory.signed, encrypted: doc.isEncrypted, canRemove: !inventory.signed && !inventory.unresolved, pages: doc.getPageCount() });
  } catch (error) {
    result.valid = false;
    result.canRemove = false;
    result.warnings.push(`PDF could not be safely parsed: ${error.message}`);
  }
  return result;
}

function cleanPdfGraph(doc, inventory) {
  const context = doc.context;
  const targets = new Set([...inventory.credentialObjects, ...inventory.credentialStreams]);
  for (const record of inventory.records) {
    if (record.dictionary && pdfString(context.lookup(record.dictionary.get(pdfName('Subtype')))) === 'FileAttachment' && targets.has(context.lookup(record.dictionary.get(pdfName('FS'))))) targets.add(record.object);
  }
  const targetRefs = new Set(context.enumerateIndirectObjects().filter(([, object]) => targets.has(object)).map(([ref]) => ref));
  const isTarget = object => targets.has(object) || targetRefs.has(object);
  // The EmbeddedFiles name tree stores alternating names and file-spec refs.
  // Remove entire pairs and rebuild Limits, rather than corrupt its pairing.
  const cleanNameTree = (value, seen = new Set()) => {
    const node = context.lookup(value);
    if (!(node instanceof PDFDict) || seen.has(node)) return [];
    seen.add(node);
    const names = context.lookup(node.get(pdfName('Names')));
    let bounds = [];
    if (names instanceof PDFArray) {
      if (names.size() % 2) throw new Error('Malformed embedded-file name tree; removal cannot safely continue.');
      for (let i = names.size() - 2; i >= 0; i -= 2) if (isTarget(names.get(i + 1)) || isTarget(context.lookup(names.get(i + 1)))) { names.remove(i + 1); names.remove(i); }
      if (names.size()) bounds = [names.get(0), names.get(names.size() - 2)];
      else node.delete(pdfName('Names'));
    }
    const kids = context.lookup(node.get(pdfName('Kids')));
    if (kids instanceof PDFArray) {
      const childBounds = [];
      for (let i = kids.size() - 1; i >= 0; i--) {
        const range = cleanNameTree(kids.get(i), seen);
        if (!range.length) kids.remove(i);
        else childBounds.unshift(range);
      }
      if (childBounds.length) bounds = [childBounds[0][0], childBounds.at(-1)[1]];
      else node.delete(pdfName('Kids'));
    }
    if (bounds.length) node.set(pdfName('Limits'), context.obj(bounds));
    else node.delete(pdfName('Limits'));
    return bounds;
  };
  for (const record of inventory.records) if (record.dictionary?.has(pdfName('EmbeddedFiles'))) {
    if (!cleanNameTree(record.dictionary.get(pdfName('EmbeddedFiles'))).length) record.dictionary.delete(pdfName('EmbeddedFiles'));
  }
  const visited = new Set();
  const prune = object => {
    if (!object || visited.has(object) || targets.has(object)) return;
    visited.add(object);
    const dictionary = dictOf(object);
    if (dictionary) for (const [key, value] of dictionary.entries()) {
      if (isTarget(value) || isTarget(context.lookup(value))) dictionary.delete(key);
      else if (!(value instanceof PDFRef)) prune(value);
    }
    if (object instanceof PDFArray) for (let i = object.size() - 1; i >= 0; i--) {
      if (isTarget(object.get(i)) || isTarget(context.lookup(object.get(i)))) object.remove(i);
      else if (!(object.get(i) instanceof PDFRef)) prune(object.get(i));
    }
  };
  for (const [, object] of context.enumerateIndirectObjects()) prune(object);
  for (const ref of targetRefs) context.delete(ref);
  // pdf-lib serializes orphan objects unless explicitly removed. Mark from the
  // trailer roots, then sweep, excluding original revision and orphan payloads.
  const reachable = new Set();
  const walked = new Set();
  const mark = value => {
    if (!value) return;
    if (value instanceof PDFRef) {
      if (reachable.has(value)) return;
      reachable.add(value);
      mark(context.lookup(value));
      return;
    }
    if (walked.has(value)) return;
    walked.add(value);
    const dictionary = dictOf(value);
    if (dictionary) for (const [, child] of dictionary.entries()) mark(child);
    if (value instanceof PDFArray) for (let i = 0; i < value.size(); i++) mark(value.get(i));
  };
  for (const root of Object.values(context.trailerInfo)) mark(root);
  for (const [ref] of context.enumerateIndirectObjects()) if (!reachable.has(ref)) context.delete(ref);
}

async function removePdf(bytes) {
  const doc = await loadPdf(bytes);
  if (doc.isEncrypted) throw new Error('Encrypted PDFs are inspection-only.');
  const inventory = pdfInventory(doc);
  if (inventory.signed || inventory.unresolved) throw new Error(inventory.warnings.join(' '));
  if (!inventory.findings.length) return { bytes: bytes.slice(), removed: 0, method: PDF_METHOD, warnings: inventory.warnings };
  for (const metadata of inventory.metadataPatches) {
    const cleaned = removeXmp(metadata.bytes, metadata.location);
    const dictionary = metadata.dictionary.clone(doc.context);
    dictionary.delete(pdfName('Filter'));
    dictionary.delete(pdfName('DecodeParms'));
    dictionary.set(pdfName('Length'), doc.context.obj(cleaned.bytes.length));
    const replacement = PDFRawStream.of(dictionary, cleaned.bytes);
    for (const ref of metadata.refs) doc.context.assign(ref, replacement);
  }
  cleanPdfGraph(doc, inventory);
  const output = await doc.save({ useObjectStreams: false, addDefaultPage: false, updateFieldAppearances: false });
  const verified = await analyzePdf(output);
  if (!verified.valid || verified.findings.length) throw new Error('Verification failed: rewritten PDF still has a provenance structure.');
  return { bytes: output, removed: inventory.findings.length, method: PDF_METHOD, warnings: inventory.warnings };
}

function zipPreflight(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset--) {
    if (view.getUint32(offset, true) === 0x06054b50 && offset + 22 + view.getUint16(offset + 20, true) === bytes.length) { end = offset; break; }
  }
  if (end < 0) throw new Error('ZIP end-of-directory record was not found.');
  if (view.getUint16(end + 4, true) || view.getUint16(end + 6, true)) throw new Error('Multi-volume packages are inspection-only.');
  const count = view.getUint16(end + 10, true);
  let offset = view.getUint32(end + 16, true);
  const size = view.getUint32(end + 12, true);
  if (count === 0xffff || offset === 0xffffffff || size === 0xffffffff) throw new Error('ZIP64 packages exceed the supported rewrite profile.');
  if (count > 6000 || offset + size > end) throw new Error('Package directory exceeds the safe inspection limit.');
  let expanded = 0;
  const names = new Set();
  for (let i = 0; i < count; i++) {
    if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) throw new Error('Malformed ZIP directory.');
    if (view.getUint16(offset + 8, true) & 1) throw new Error('Encrypted packages are inspection-only.');
    const method = view.getUint16(offset + 10, true);
    if (![0, 8].includes(method)) throw new Error('This ZIP compression method cannot be safely rewritten.');
    const length = view.getUint32(offset + 24, true);
    expanded += length;
    if (length > MAX_PART || expanded > MAX_EXPANDED) throw new Error('Expanded package exceeds the 256 MB inspection limit (96 MB per part).');
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    if (offset + 46 + nameLength + extraLength + commentLength > bytes.length) throw new Error('Truncated ZIP directory.');
    const name = UTF8.decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
    if (names.has(name)) throw new Error('Duplicate ZIP part names cannot be safely rewritten.');
    names.add(name);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  if (offset !== view.getUint32(end + 16, true) + size) throw new Error('Unexpected ZIP directory records cannot be safely rewritten.');
  return { count, expanded };
}

function normalizePart(path) {
  const parts = String(path).replace(/\\/g, '/').split('/');
  const result = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') result.pop();
    else result.push(part);
  }
  return result.join('/');
}
const credentialPart = name => /\.c2pa$/i.test(name);
const credentialMime = value => /^application\/(?:x-)?c2pa(?:;|$)/i.test(value || '');
const credentialRelation = value => /(?:^|[/#])c2pa(?:[-_](?:manifest|credential))?$/i.test(value || '');

function decodeXml(value) {
  return String(value).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, token) => {
    if (token[0] === '#') {
      const code = token[1].toLowerCase() === 'x' ? parseInt(token.slice(2), 16) : parseInt(token.slice(1), 10);
      return code <= 0x10ffff ? String.fromCodePoint(code) : '\ufffd';
    }
    return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[token.toLowerCase()];
  });
}

// Minimal XML tokenization preserves unaffected XML byte-for-byte. Comments,
// CDATA and quoted attributes cannot accidentally become removable elements.
function xmlElements(text) {
  if (/<!DOCTYPE/i.test(text)) throw new Error('XML with a document type cannot be safely edited.');
  const tokens = [];
  const stack = [];
  let offset = 0;
  while ((offset = text.indexOf('<', offset)) >= 0) {
    const start = offset;
    if (text.startsWith('<!--', start)) { const end = text.indexOf('-->', start + 4); if (end < 0) throw new Error('Malformed XML comment.'); offset = end + 3; continue; }
    if (text.startsWith('<![CDATA[', start)) { const end = text.indexOf(']]>', start + 9); if (end < 0) throw new Error('Malformed XML CDATA.'); offset = end + 3; continue; }
    if (text.startsWith('<?', start)) { const end = text.indexOf('?>', start + 2); if (end < 0) throw new Error('Malformed XML instruction.'); offset = end + 2; continue; }
    let quote = '';
    let end = start + 1;
    for (; end < text.length; end++) {
      const char = text[end];
      if (quote) { if (char === quote) quote = ''; }
      else if (char === '"' || char === "'") quote = char;
      else if (char === '>') break;
    }
    if (end >= text.length) throw new Error('Malformed XML element.');
    const tag = text.slice(start, end + 1);
    const match = /^<\s*(\/?)\s*([A-Za-z_][\w:.-]*)/.exec(tag);
    if (!match) throw new Error('Unsupported XML declaration.');
    if (match[1]) {
      const open = stack.pop();
      if (!open || open.name !== match[2]) throw new Error('Unbalanced package XML.');
      open.end = end + 1;
    } else {
      const attrs = {};
      const attrPattern = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
      let attr;
      while ((attr = attrPattern.exec(tag))) attrs[attr[1].split(':').pop()] = decodeXml(attr[2] ?? attr[3]);
      const token = { name: match[2], localName: match[2].split(':').pop(), attrs, start, end: end + 1 };
      tokens.push(token);
      if (!/\/\s*>$/.test(tag)) stack.push(token);
    }
    offset = end + 1;
  }
  if (stack.length) throw new Error('Unclosed package XML.');
  return tokens;
}

function relationshipBase(name) {
  if (name === '_rels/.rels') return '';
  const match = /^(.*\/)?_rels\/[^/]+\.rels$/.exec(name);
  return match?.[1] || '';
}

function targetPart(source, target) {
  let path = String(target || '').split('#')[0];
  try { path = decodeURIComponent(path); } catch { /* Literal URI is still safe to compare. */ }
  return normalizePart(path.startsWith('/') ? path : relationshipBase(source) + path);
}

function packageType(filename, zip) {
  const declared = PACKAGE_TYPES[ext(filename)];
  if (declared) return declared;
  if (zip.file('word/document.xml')) return PACKAGE_TYPES.docx;
  if (zip.file('xl/workbook.xml')) return PACKAGE_TYPES.xlsx;
  if (zip.file('ppt/presentation.xml')) return PACKAGE_TYPES.pptx;
  if (zip.file('META-INF/container.xml')) return PACKAGE_TYPES.epub;
  return PACKAGE_TYPES.zip;
}

async function packageInventory(bytes, filename) {
  const preflight = zipPreflight(bytes);
  if (!globalThis.JSZip) throw new Error('The local ZIP engine is unavailable.');
  const zip = await globalThis.JSZip.loadAsync(bytes, { checkCRC32: true, createFolders: false });
  const [format, mime] = packageType(filename, zip);
  const result = base(format, mime, ZIP_METHOD);
  const entries = Object.values(zip.files).filter(entry => !entry.dir);
  const removedParts = new Set();
  const xmlParts = [];
  const mediaParts = [];
  const data = new Map();
  let signed = false;
  let encrypted = false;
  let unsafe = false;
  for (const entry of entries) {
    const name = entry.name;
    if (entry.unsafeOriginalName && entry.unsafeOriginalName !== name) unsafe = true;
    if (/^_xmlsignatures\//i.test(name) || /^META-INF\/(?:documentsignatures|macrosignatures|signatures)\.xml$/i.test(name)) signed = true;
    if (/^META-INF\/encryption\.xml$/i.test(name)) encrypted = true;
    if (credentialPart(name)) removedParts.add(name);
    if (/\.rels$/i.test(name) || name === '[Content_Types].xml' || /^META-INF\/manifest\.xml$/i.test(name) || /\.opf$/i.test(name)) {
      try {
        const rawXml = await entry.async('uint8array');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(rawXml);
        const encoding = /^\s*<\?xml\b[^>]*\bencoding\s*=\s*["']([^"']+)["']/i.exec(text)?.[1];
        if (encoding && !/^(?:utf-?8|us-ascii)$/i.test(encoding)) throw new Error('Package XML uses an unsupported encoding; it is preserved.');
        const elements = xmlElements(text);
        xmlParts.push({ name, text, elements });
        for (const item of elements) {
          if (item.localName === 'Override' && credentialMime(item.attrs.ContentType)) removedParts.add(normalizePart(item.attrs.PartName));
          if (item.localName === 'Default' && credentialMime(item.attrs.ContentType)) for (const candidate of entries) if (ext(candidate.name) === String(item.attrs.Extension).toLowerCase()) removedParts.add(candidate.name);
          if (item.localName === 'Relationship' && item.attrs.TargetMode !== 'External' && credentialRelation(item.attrs.Type)) removedParts.add(targetPart(name, item.attrs.Target));
          if (item.localName === 'file-entry' && credentialMime(item.attrs['media-type'])) removedParts.add(normalizePart(item.attrs['full-path']));
          if (item.localName === 'item' && credentialMime(item.attrs['media-type'])) removedParts.add(normalizePart(name.slice(0, name.lastIndexOf('/') + 1) + item.attrs.href));
        }
      } catch (error) {
        result.warnings.push(`${name}: ${error.message}`);
        unsafe = true;
      }
    }
  }
  // Native C2PA embedding uses this fixed name. Case variants/extensions are
  // treated as explicit sidecars, not as a claim that they conform to C2PA.
  for (const name of removedParts) {
    const entry = zip.file(name);
    if (!entry) continue;
    const payload = await entry.async('uint8array');
    data.set(name, payload);
    result.payloads.push(payload);
    result.findings.push({ kind: 'embedded', label: /^META-INF\/content_credential\.c2pa$/i.test(name) ? 'Package C2PA manifest' : 'C2PA sidecar part', location: name, bytes: payload.length, detail: name === 'META-INF/content_credential.c2pa' ? 'Standard C2PA ZIP-based manifest store.' : 'Explicit manifest filename, content type, or package relationship.' });
  }
  for (const part of xmlParts) for (const item of part.elements) {
    if (item.localName === 'Relationship' && item.attrs.TargetMode === 'External' && credentialRelation(item.attrs.Type)) result.findings.push({ kind: 'remote', label: 'External C2PA package relationship', location: `${part.name} · ${item.attrs.Id || ''}`, detail: item.attrs.Target || '' });
    else if (item.localName === 'Relationship' && item.attrs.TargetMode !== 'External' && credentialRelation(item.attrs.Type) && !zip.file(targetPart(part.name, item.attrs.Target))) result.findings.push({ kind: 'embedded', label: 'C2PA package reference', location: `${part.name} · ${item.attrs.Id || ''}`, detail: 'The C2PA relationship points to a missing manifest part. The stale reference can be removed.' });
    else if (item.localName === 'Override' && credentialMime(item.attrs.ContentType) && !zip.file(normalizePart(item.attrs.PartName))) result.findings.push({ kind: 'embedded', label: 'C2PA content-type reference', location: part.name, detail: 'The content-type entry points to a missing manifest part.' });
    else if (item.localName === 'Default' && credentialMime(item.attrs.ContentType) && !entries.some(entry => ext(entry.name) === String(item.attrs.Extension).toLowerCase())) result.findings.push({ kind: 'embedded', label: 'C2PA content-type declaration', location: part.name, detail: 'The package declares a C2PA content type without any matching part.' });
    else if (item.localName === 'file-entry' && credentialMime(item.attrs['media-type']) && !zip.file(normalizePart(item.attrs['full-path']))) result.findings.push({ kind: 'embedded', label: 'C2PA package manifest reference', location: part.name, detail: 'The package manifest points to a missing C2PA part.' });
    else if (item.localName === 'item' && credentialMime(item.attrs['media-type']) && !zip.file(normalizePart(part.name.slice(0, part.name.lastIndexOf('/') + 1) + item.attrs.href))) result.findings.push({ kind: 'embedded', label: 'C2PA EPUB manifest reference', location: part.name, detail: 'The EPUB manifest points to a missing C2PA part.' });
  }
  for (const entry of entries) {
    if (removedParts.has(entry.name) || /\.(?:xml|rels|opf|txt|csv|json|html|xhtml|css)$/i.test(entry.name)) continue;
    const content = await entry.async('uint8array');
    const isXmp = /\.xmp$/i.test(entry.name);
    const image = isXmp ? analyzeXmp(content, entry.name) : await analyzeImage(content, entry.name);
    if (!image) continue;
    if (isXmp && image.warnings.length) unsafe = true;
    if (image.findings.length) {
      mediaParts.push({ name: entry.name, bytes: content, analysis: image, isXmp });
      for (const finding of image.findings) result.findings.push({ ...finding, label: `Embedded ${image.format}: ${finding.label}`, location: `${entry.name} · ${finding.location}` });
      result.payloads.push(...image.payloads);
      if (!image.canRemove) unsafe = true;
    }
    for (const warning of image.warnings) result.warnings.push(`${entry.name}: ${warning}`);
  }
  if (signed) result.warnings.push('This package contains native digital signatures. Removal is disabled because a rewrite or embedded-media edit may invalidate them.');
  if (encrypted) result.warnings.push('Encrypted package components were detected. Complete inspection/removal cannot be guaranteed, so removal is disabled.');
  if (unsafe) result.warnings.push('The package has unsafe paths, malformed XML, or unsupported embedded provenance. Removal is disabled to avoid an incomplete result.');
  Object.assign(result, { signed, encrypted, canRemove: !signed && !encrypted && !unsafe, entries: preflight.count, expandedBytes: preflight.expanded, embeddedMedia: mediaParts.length, warnings: unique(result.warnings) });
  return { result, zip, removedParts, xmlParts, mediaParts, data };
}

function editPackageXml(part, removedParts) {
  const removedIds = new Set();
  const ranges = [];
  for (const item of part.elements) {
    let remove = false;
    if (item.localName === 'Relationship') {
      remove = credentialRelation(item.attrs.Type) || (item.attrs.TargetMode !== 'External' && removedParts.has(targetPart(part.name, item.attrs.Target)));
    } else if (item.localName === 'Override') remove = credentialMime(item.attrs.ContentType) || removedParts.has(normalizePart(item.attrs.PartName));
    else if (item.localName === 'Default') remove = credentialMime(item.attrs.ContentType) || /^c2pa$/i.test(item.attrs.Extension || '');
    else if (item.localName === 'file-entry') remove = credentialMime(item.attrs['media-type']) || removedParts.has(normalizePart(item.attrs['full-path']));
    else if (item.localName === 'item') {
      remove = credentialMime(item.attrs['media-type']) || removedParts.has(normalizePart(part.name.slice(0, part.name.lastIndexOf('/') + 1) + item.attrs.href));
      if (remove && item.attrs.id) removedIds.add(item.attrs.id);
    }
    if (remove) ranges.push([item.start, item.end]);
  }
  for (const item of part.elements) if (item.localName === 'itemref' && removedIds.has(item.attrs.idref)) ranges.push([item.start, item.end]);
  ranges.sort((a, b) => a[0] - b[0]);
  let text = '';
  let offset = 0;
  for (const [start, end] of ranges) { if (start < offset) continue; text += part.text.slice(offset, start); offset = end; }
  return text + part.text.slice(offset);
}

async function analyzePackage(bytes, filename) {
  try { return (await packageInventory(bytes, filename)).result; }
  catch (error) {
    const [format, mime] = PACKAGE_TYPES[ext(filename)] || PACKAGE_TYPES.zip;
    const result = base(format, mime, ZIP_METHOD);
    result.valid = false;
    result.canRemove = false;
    result.warnings.push(`Package could not be safely inspected: ${error.message}`);
    return result;
  }
}

async function removePackage(bytes, filename) {
  const inventory = await packageInventory(bytes, filename);
  if (!inventory.result.canRemove) throw new Error(inventory.result.warnings.join(' '));
  if (!inventory.result.findings.length) return { bytes: bytes.slice(), removed: 0, method: ZIP_METHOD, warnings: inventory.result.warnings };
  for (const name of inventory.removedParts) inventory.zip.remove(name);
  for (const part of inventory.xmlParts) {
    const edited = editPackageXml(part, inventory.removedParts);
    if (edited !== part.text) inventory.zip.file(part.name, edited, { createFolders: false });
  }
  for (const part of inventory.mediaParts) {
    const clean = part.isXmp ? removeXmp(part.bytes, part.name) : await removeImage(part.bytes, part.name);
    if (!clean) throw new Error(`Embedded media could not be rewritten: ${part.name}`);
    inventory.zip.file(part.name, clean.bytes, { createFolders: false });
  }
  // EPUB and ODF require an uncompressed, first local-header mimetype entry.
  // A fresh archive preserves that order and every remaining part's content.
  const rebuilt = new globalThis.JSZip();
  const ordered = Object.values(inventory.zip.files).sort((a, b) => (a.name === 'mimetype' ? -1 : b.name === 'mimetype' ? 1 : 0));
  for (const entry of ordered) {
    if (entry.dir) { rebuilt.file(entry.name, null, { dir: true, date: entry.date, createFolders: false }); continue; }
    rebuilt.file(entry.name, await entry.async('uint8array'), { createFolders: false, date: entry.date, comment: entry.comment, unixPermissions: entry.unixPermissions, dosPermissions: entry.dosPermissions, compression: entry.name === 'mimetype' ? 'STORE' : 'DEFLATE' });
  }
  rebuilt.comment = inventory.zip.comment;
  const output = await rebuilt.generateAsync({ type: 'uint8array', compression: 'DEFLATE', compressionOptions: { level: 6 }, streamFiles: false, mimeType: inventory.result.mime });
  const verified = await analyzePackage(output, filename);
  if (!verified.valid || verified.findings.length) throw new Error('Verification failed: rewritten package still contains detected provenance.');
  return { bytes: output, removed: inventory.result.findings.length, method: ZIP_METHOD, warnings: inventory.result.warnings };
}

export async function analyzeDocument(input, filename = '') {
  const bytes = bytesOf(input);
  const type = identify(bytes, filename);
  if (type === 'pdf') return analyzePdf(bytes);
  if (type === 'zip') return analyzePackage(bytes, filename);
  if (type === 'ole') {
    const modern = !!PACKAGE_TYPES[ext(filename)];
    const result = base(modern ? 'Encrypted Office / OLE' : (ext(filename).toUpperCase() || 'OLE'), modern ? 'application/x-ole-storage' : ({ doc: 'application/msword', xls: 'application/vnd.ms-excel', ppt: 'application/vnd.ms-powerpoint' }[ext(filename)] || 'application/x-ole-storage'), 'Inspection only');
    result.canRemove = false;
    result.encrypted = modern;
    result.inspectionOnly = true;
    result.warnings.push(modern ? 'This Office file is an OLE container, commonly used for encrypted OOXML. Open and save an authorized unencrypted copy before inspection.' : 'Legacy binary Office containers are inspection-only. Convert to DOCX, XLSX, or PPTX to inspect their package structure safely.');
    return result;
  }
  return null;
}

export async function removeDocument(input, filename = '') {
  const bytes = bytesOf(input);
  const type = identify(bytes, filename);
  if (type === 'pdf') return removePdf(bytes);
  if (type === 'zip') return removePackage(bytes, filename);
  if (type === 'ole') throw new Error('Binary or encrypted Office containers are inspection-only.');
  return null;
}
