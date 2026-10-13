import test from 'node:test';
import assert from 'node:assert/strict';
import JSZip from 'jszip';
import { PDFDocument, PDFName, PDFString, PDFArray, PDFRawStream, decodePDFRawStream } from '../dist/vendor/pdf-lib.esm.js';
import { analyzeDocument, removeDocument } from '../dist/document-engine.js';
import { analyzeImage } from '../dist/image-engine.js';

globalThis.JSZip = JSZip;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const name = value => PDFName.of(value);

async function pdfFixture({ signed = false, annotation = false, orphan = true, remote = false } = {}) {
  const doc = await PDFDocument.create({ updateMetadata: false });
  const page = doc.addPage([300, 200]);
  page.drawText('Visible page content remains intact.');
  const payload = encoder.encode('SECRET-C2PA-MANIFEST-PAYLOAD-0123456789');
  const manifestStream = doc.context.stream(payload, { Type: 'EmbeddedFile', Subtype: 'application/c2pa' });
  const manifestRef = doc.context.register(manifestStream);
  const credential = doc.context.obj({ Type: 'Filespec', AFRelationship: 'C2PA_Manifest', F: PDFString.of('credential.c2pa'), EF: { F: manifestRef } });
  const credentialRef = doc.context.register(credential);
  const unrelatedStream = doc.context.stream(encoder.encode('KEEP-THIS-UNRELATED-ATTACHMENT'), { Type: 'EmbeddedFile', Subtype: 'text/plain' });
  const unrelatedRef = doc.context.register(unrelatedStream);
  const unrelated = doc.context.register(doc.context.obj({ Type: 'Filespec', AFRelationship: 'Data', F: PDFString.of('notes.txt'), EF: { F: unrelatedRef } }));
  const leaf = doc.context.register(doc.context.obj({ Names: [PDFString.of('credential.c2pa'), credentialRef, PDFString.of('notes.txt'), unrelated], Limits: [PDFString.of('credential.c2pa'), PDFString.of('notes.txt')] }));
  doc.catalog.set(name('Names'), doc.context.obj({ EmbeddedFiles: { Kids: [leaf] } }));
  doc.catalog.set(name('AF'), doc.context.obj([credentialRef, unrelated]));
  page.node.set(name('AF'), credentialRef);
  if (annotation) {
    const annot = doc.context.register(doc.context.obj({ Type: 'Annot', Subtype: 'FileAttachment', Rect: [0, 0, 10, 10], FS: credentialRef }));
    const ordinaryAnnot = doc.context.register(doc.context.obj({ Type: 'Annot', Subtype: 'Text', Rect: [10, 10, 20, 20], Contents: PDFString.of('Keep this note.') }));
    page.node.set(name('Annots'), doc.context.obj([annot, ordinaryAnnot]));
  }
  if (orphan) doc.context.register(doc.context.stream(encoder.encode('SECRET-C2PA-ORPHAN-PAYLOAD'), { Type: 'EmbeddedFile', Subtype: 'application/c2pa' }));
  if (signed) {
    const signature = doc.context.register(doc.context.obj({ Type: 'Sig', ByteRange: [0, 100, 200, 300], Contents: PDFString.of('not-a-valid-signature') }));
    doc.catalog.set(name('Perms'), doc.context.obj({ DocMDP: signature }));
  }
  if (remote) {
    const metadata = doc.context.register(doc.context.stream(encoder.encode('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="https://example.com/credential.c2pa"/></rdf:RDF></x:xmpmeta>'), { Type: 'Metadata', Subtype: 'XML' }));
    doc.catalog.set(name('Metadata'), metadata);
  }
  return doc.save({ useObjectStreams: false });
}

test('PDF removal deletes manifest bytes, aliases, orphan streams, and attachment annotation while retaining pages and other attachments', async () => {
  const source = await pdfFixture({ annotation: true });
  const analysis = await analyzeDocument(source, 'input.pdf');
  assert.equal(analysis.format, 'PDF');
  assert.equal(analysis.canRemove, true);
  assert.equal(analysis.findings.length, 2);
  assert.equal(analysis.payloads.length, 2);
  const clean = await removeDocument(source, 'input.pdf');
  assert.equal(clean.removed, 2);
  assert.equal(decoder.decode(clean.bytes).includes('SECRET-C2PA'), false);
  assert.equal(decoder.decode(clean.bytes).includes('C2PA_Manifest'), false);
  const doc = await PDFDocument.load(clean.bytes, { updateMetadata: false });
  assert.equal(doc.getPageCount(), 1);
  assert.equal(doc.getPage(0).node.has(name('AF')), false);
  const af = doc.context.lookup(doc.catalog.get(name('AF')));
  assert.ok(af instanceof PDFArray);
  assert.equal(af.size(), 1);
  const remainingSpec = doc.context.lookup(af.get(0));
  assert.equal(remainingSpec.lookup(name('F')).decodeText(), 'notes.txt');
  const remainingStream = remainingSpec.lookup(name('EF')).lookup(name('F'));
  assert.ok(remainingStream instanceof PDFRawStream);
  assert.equal(decoder.decode(decodePDFRawStream(remainingStream).decode()), 'KEEP-THIS-UNRELATED-ATTACHMENT');
  assert.equal(doc.getPage(0).node.lookup(name('Annots')).size(), 1);
  const nameTree = doc.catalog.lookup(name('Names')).lookup(name('EmbeddedFiles'));
  const leaf = doc.context.lookup(nameTree.lookup(name('Kids')).get(0));
  assert.equal(leaf.lookup(name('Names')).size(), 2);
  assert.equal(leaf.lookup(name('Limits')).get(0).decodeText(), 'notes.txt');
  assert.equal((await analyzeDocument(clean.bytes, 'clean.pdf')).findings.length, 0);
});

test('PDF native signatures are inspection-only and XMP provenance is selectively removable', async () => {
  const signed = await pdfFixture({ signed: true });
  const analysis = await analyzeDocument(signed, 'signed.pdf');
  assert.equal(analysis.signed, true);
  assert.equal(analysis.canRemove, false);
  await assert.rejects(removeDocument(signed, 'signed.pdf'), /digital signature/);
  const remote = await pdfFixture({ remote: true });
  const remoteAnalysis = await analyzeDocument(remote, 'remote.pdf');
  assert.equal(remoteAnalysis.canRemove, true);
  assert.ok(remoteAnalysis.findings.some(finding => finding.kind === 'remote'));
  const cleaned = await removeDocument(remote, 'remote.pdf');
  assert.equal((await analyzeDocument(cleaned.bytes, 'clean.pdf')).findings.length, 0);
  assert.equal(decoder.decode(cleaned.bytes).includes('https://example.com/credential.c2pa'), false);
  assert.equal(decoder.decode(cleaned.bytes).includes('http://purl.org/dc/terms/'), true);
});

function concat(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1; }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const chunk = new Uint8Array(data.length + 12);
  const view = new DataView(chunk.buffer);
  view.setUint32(0, data.length);
  chunk.set(encoder.encode(type), 4);
  chunk.set(data, 8);
  view.setUint32(chunk.length - 4, crc32(chunk.subarray(4, chunk.length - 4)));
  return chunk;
}

function provenancePng() {
  // A valid PNG container with one minimal manifest-store JUMBF in caBX.
  const jumd = concat(Uint8Array.from([0x63, 0x32, 0x70, 0x61, 0, 0x11, 0, 0x10, 0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71, 3]), encoder.encode('c2pa\0'));
  const box = (type, data) => { const out = new Uint8Array(data.length + 8); new DataView(out.buffer).setUint32(0, out.length); out.set(encoder.encode(type), 4); out.set(data, 8); return out; };
  const jumbf = box('jumb', box('jumd', jumd));
  const ihdr = new Uint8Array(13); new DataView(ihdr.buffer).setUint32(0, 1); new DataView(ihdr.buffer).setUint32(4, 1); ihdr[8] = 8; ihdr[9] = 6;
  return concat(Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]), pngChunk('IHDR', ihdr), pngChunk('caBX', jumbf), pngChunk('IDAT', Uint8Array.from([120, 156, 99, 0, 1, 0, 0, 5, 0, 1])), pngChunk('IEND', new Uint8Array()));
}

async function docxFixture({ signed = false, embedded = true, malformed = false } = {}) {
  const zip = new JSZip();
  zip.file('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="c2pa" ContentType="application/c2pa"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/META-INF/content_credential.c2pa" ContentType="application/c2pa"/></Types>');
  zip.file('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Keep the document text.</w:t></w:r></w:p></w:body></w:document>');
  zip.file('_rels/.rels', malformed ? '<Relationships><Relationship' : '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rDoc" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rCredential" Type="https://c2pa.org/relationships/c2pa-manifest" Target="META-INF/content_credential.c2pa"/><Relationship Id="rExternal" Type="https://c2pa.org/relationships/c2pa-manifest" TargetMode="External" Target="https://example.com/manifest.c2pa"/></Relationships>');
  zip.file('META-INF/content_credential.c2pa', encoder.encode('SECRET-C2PA-PACKAGE-MANIFEST'), { compression: 'STORE' });
  if (embedded) zip.file('word/media/image1.png', provenancePng());
  if (signed) zip.file('_xmlsignatures/sig1.xml', '<Signature/>');
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
}

test('DOCX removes standardized package manifest, external relationships and embedded image C2PA with selective XML cleanup', async () => {
  const source = await docxFixture();
  const analysis = await analyzeDocument(source, 'input.docx');
  assert.equal(analysis.canRemove, true);
  assert.equal(analysis.format, 'DOCX');
  assert.equal(analysis.embeddedMedia, 1);
  assert.ok(analysis.findings.some(finding => finding.location === 'META-INF/content_credential.c2pa'));
  assert.ok(analysis.findings.some(finding => finding.kind === 'remote'));
  const clean = await removeDocument(source, 'input.docx');
  const zip = await JSZip.loadAsync(clean.bytes, { checkCRC32: true });
  assert.equal(zip.file('META-INF/content_credential.c2pa'), null);
  const rels = await zip.file('_rels/.rels').async('string');
  assert.equal(rels.includes('rCredential'), false);
  assert.equal(rels.includes('rExternal'), false);
  assert.equal(rels.includes('rDoc'), true);
  const types = await zip.file('[Content_Types].xml').async('string');
  assert.equal(types.includes('application/c2pa'), false);
  assert.equal(types.includes('image/png'), true);
  assert.equal((await analyzeImage(await zip.file('word/media/image1.png').async('uint8array'), 'image.png')).findings.length, 0);
  assert.equal(await zip.file('word/document.xml').async('string'), await (await JSZip.loadAsync(source)).file('word/document.xml').async('string'));
  assert.equal((await analyzeDocument(clean.bytes, 'clean.docx')).findings.length, 0);
});

test('ODF removes manifest entries and preserves first, uncompressed mimetype', async () => {
  const zip = new JSZip();
  zip.file('content.xml', '<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>');
  zip.file('mimetype', 'application/vnd.oasis.opendocument.text', { compression: 'STORE' });
  zip.file('META-INF/manifest.xml', '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="META-INF/content_credential.c2pa" manifest:media-type="application/c2pa"/></manifest:manifest>');
  zip.file('META-INF/content_credential.c2pa', 'SECRET-C2PA-ODF');
  const clean = await removeDocument(await zip.generateAsync({ type: 'uint8array' }), 'input.odt');
  const view = new DataView(clean.bytes.buffer, clean.bytes.byteOffset, clean.bytes.byteLength);
  assert.equal(view.getUint16(8, true), 0);
  assert.equal(decoder.decode(clean.bytes.subarray(30, 30 + view.getUint16(26, true))), 'mimetype');
  const result = await JSZip.loadAsync(clean.bytes);
  assert.equal(result.file('META-INF/content_credential.c2pa'), null);
  assert.equal((await result.file('META-INF/manifest.xml').async('string')).includes('application/c2pa'), false);
});

test('signed packages, malformed XML, and corrupted ZIP cannot be rewritten', async () => {
  for (const options of [{ signed: true }, { malformed: true }]) {
    const source = await docxFixture({ ...options, embedded: false });
    assert.equal((await analyzeDocument(source, 'input.docx')).canRemove, false);
    await assert.rejects(removeDocument(source, 'input.docx'));
  }
  const corrupted = Uint8Array.from([80, 75, 3, 4, 1, 2, 3, 4]);
  const analysis = await analyzeDocument(corrupted, 'corrupt.docx');
  assert.equal(analysis.canRemove, false);
  assert.equal(analysis.valid, false);
  await assert.rejects(removeDocument(corrupted, 'corrupt.docx'));
});

test('legacy binary Office formats are inspection-only and unknown files are unhandled', async () => {
  const ole = Uint8Array.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  assert.equal((await analyzeDocument(ole, 'old.doc')).canRemove, false);
  assert.equal((await analyzeDocument(ole, 'encrypted.docx')).encrypted, true);
  await assert.rejects(removeDocument(ole, 'old.doc'), /inspection-only/);
  assert.equal(await analyzeDocument(encoder.encode('arbitrary text'), 'notes.txt'), null);
  assert.equal(await removeDocument(encoder.encode('arbitrary text'), 'notes.txt'), null);
});

test('ordinary clean document removal returns byte-identical input', async () => {
  const doc = await PDFDocument.create(); doc.addPage();
  const pdf = await doc.save();
  assert.deepEqual((await removeDocument(pdf, 'clean.pdf')).bytes, pdf);
  const zip = new JSZip(); zip.file('word/document.xml', '<document/>');
  const source = await zip.generateAsync({ type: 'uint8array' });
  assert.deepEqual((await removeDocument(source, 'clean.docx')).bytes, source);
});

test('stale package relationship and type declarations are detected and removed without requiring a payload', async () => {
  const zip = new JSZip();
  zip.file('word/document.xml', '<document>Keep text.</document>');
  zip.file('[Content_Types].xml', '<Types><Default Extension="c2pa" ContentType="application/c2pa"/></Types>');
  zip.file('_rels/.rels', '<Relationships><Relationship Id="stale" Type="https://c2pa.org/relationships/c2pa-manifest" Target="META-INF/missing.c2pa"/></Relationships>');
  const source = await zip.generateAsync({ type: 'uint8array' });
  assert.equal((await analyzeDocument(source, 'stale.docx')).findings.length, 2);
  const cleaned = await removeDocument(source, 'stale.docx');
  assert.equal(cleaned.removed, 2);
  assert.equal((await analyzeDocument(cleaned.bytes, 'clean.docx')).findings.length, 0);
  assert.equal(await (await JSZip.loadAsync(cleaned.bytes)).file('word/document.xml').async('string'), '<document>Keep text.</document>');
});
