import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { deflateSync } from 'node:zlib';
import JSZip from 'jszip';
import { PDFDocument, PDFName, PDFString, StandardFonts, rgb } from '../dist/vendor/pdf-lib.esm.js';
import { analyzeDocument, removeDocument } from '../dist/document-engine.js';
import { analyzeImage } from '../dist/image-engine.js';
import { inspectManifests } from '../dist/manifest-reader.js';

globalThis.JSZip = JSZip;
const folder = fileURLToPath(new URL('../tests/fixtures/', import.meta.url));
await fs.mkdir(folder, { recursive: true });
const text = new TextEncoder();
const concat = (...parts) => {
  const bytes = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return bytes;
};
const uuid = hex => Uint8Array.from(hex.match(/../g), value => parseInt(value, 16));
function box(type, bytes) {
  const result = new Uint8Array(bytes.length + 8);
  new DataView(result.buffer).setUint32(0, result.length);
  result.set(text.encode(type), 4);
  result.set(bytes, 8);
  return result;
}
function jumb(label, contentType, ...children) {
  return box('jumb', concat(box('jumd', concat(uuid(contentType), Uint8Array.of(3), text.encode(label), Uint8Array.of(0))), ...children));
}
const JSON_UUID = '6a736f6e00110010800000aa00389b71';
const STORE_UUID = '6332706100110010800000aa00389b71';
const MANIFEST_UUID = '63326d6100110010800000aa00389b71';
const json = (label, value) => jumb(label, JSON_UUID, box('json', text.encode(JSON.stringify(value))));
function manifest(title) {
  return jumb('c2pa', STORE_UUID,
    jumb('urn:c2pa:pilas-qa-unsigned-demo', MANIFEST_UUID,
      json('c2pa.claim.v2', {
        claim_generator_info: [{ name: 'Pilas QA Fixture - UNSIGNED DEMO', version: '1.0' }],
        'dc:title': title,
        'dc:format': 'application/x-pilas-qa-fixture',
        demo: true,
        signed: false,
        notice: 'Synthetic JSON claim for UI testing. No signature, trusted signer, or asset binding is asserted.',
      }),
      jumb('c2pa.assertions', JSON_UUID,
        json('c2pa.actions.v2', { actions: [{ action: 'c2pa.created', softwareAgent: 'Pilas QA Fixture - UNSIGNED DEMO' }] }),
        json('org.pilas.qa', { fixture: true, authenticated: false, purpose: 'Local browser inspection and removal testing only.' }))));
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1; }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const result = new Uint8Array(data.length + 12);
  const view = new DataView(result.buffer);
  view.setUint32(0, data.length);
  result.set(text.encode(type), 4);
  result.set(data, 8);
  view.setUint32(result.length - 4, crc32(result.subarray(4, result.length - 4)));
  return result;
}
function demoPng() {
  const width = 240, height = 120;
  const scanlines = new Uint8Array(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    const row = y * (1 + width * 4);
    for (let x = 0; x < width; x++) {
      const offset = row + 1 + x * 4;
      const ellipse = ((x - 180) / 37) ** 2 + ((y - 58) / 37) ** 2 < 1;
      const stripe = x > 20 && x < 120 && y > 32 && y < 40;
      const stripe2 = x > 20 && x < 94 && y > 52 && y < 60;
      const stripe3 = x > 20 && x < 105 && y > 72 && y < 80;
      scanlines.set(ellipse ? [187, 203, 116, 255] : stripe || stripe2 || stripe3 ? [226, 239, 162, 255] : [29, 48, 44, 255], offset);
    }
  }
  const header = new Uint8Array(13);
  const view = new DataView(header.buffer);
  view.setUint32(0, width); view.setUint32(4, height); header[8] = 8; header[9] = 6;
  return concat(Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('caBX', manifest('Unsigned embedded PNG demo')), chunk('IDAT', deflateSync(scanlines)), chunk('IEND', new Uint8Array()));
}
const png = demoPng();
await fs.writeFile(path.join(folder, 'unsigned-demo-image.png'), png);

const pdf = await PDFDocument.create({ updateMetadata: false });
const page = pdf.addPage([595, 842]);
const regular = await pdf.embedFont(StandardFonts.Helvetica);
const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
page.drawRectangle({ x: 0, y: 720, width: 595, height: 122, color: rgb(0.1, 0.18, 0.16) });
page.drawText('Pilas Smart C2PA Remover', { x: 42, y: 789, size: 22, font: bold, color: rgb(0.94, 0.97, 0.88) });
page.drawText('Browser QA document - UNSIGNED DEMO', { x: 42, y: 753, size: 12, font: regular, color: rgb(0.75, 0.82, 0.6) });
for (const [line, y] of [
  ['This visible page should remain intact after C2PA removal.', 666],
  ['The PDF contains a native associated C2PA manifest attachment.', 641],
  ['The synthetic JSON claim is unsigned and has no verified identity.', 616],
  ['The ordinary notes.txt attachment must remain available.', 591],
]) page.drawText(line, { x: 42, y, size: 12, font: regular, color: rgb(0.15, 0.2, 0.18) });
const visibleImage = await pdf.embedPng(png);
page.drawImage(visibleImage, { x: 42, y: 406, width: 360, height: 180 });
page.drawText('Generated locally for structural tests. Not a signed Content Credential.', { x: 42, y: 355, size: 10, font: regular, color: rgb(0.4, 0.45, 0.42) });
const credentialStream = pdf.context.register(pdf.context.stream(manifest('Unsigned PDF associated-file demo'), { Type: 'EmbeddedFile', Subtype: 'application/c2pa' }));
const credential = pdf.context.register(pdf.context.obj({ Type: 'Filespec', AFRelationship: 'C2PA_Manifest', Subtype: 'application/c2pa', F: PDFString.of('content_credential.c2pa'), EF: { F: credentialStream } }));
const noteText = 'Ordinary attachment: preserve this file when removing the C2PA associated manifest.\nThis is an unsigned synthetic QA fixture.\n';
const noteStream = pdf.context.register(pdf.context.stream(text.encode(noteText), { Type: 'EmbeddedFile', Subtype: 'text/plain' }));
const note = pdf.context.register(pdf.context.obj({ Type: 'Filespec', AFRelationship: 'Data', F: PDFString.of('notes.txt'), EF: { F: noteStream } }));
pdf.catalog.set(PDFName.of('AF'), pdf.context.obj([credential, note]));
pdf.catalog.set(PDFName.of('Names'), pdf.context.obj({ EmbeddedFiles: { Names: [PDFString.of('content_credential.c2pa'), credential, PDFString.of('notes.txt'), note] } }));
const pdfBytes = await pdf.save({ useObjectStreams: false });
await fs.writeFile(path.join(folder, 'unsigned-demo-document.pdf'), pdfBytes);

const docx = new JSZip();
const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>
<w:p><w:r><w:rPr><w:b/><w:sz w:val="40"/></w:rPr><w:t>Pilas browser QA document</w:t></w:r></w:p>
<w:p><w:r><w:t>This document text and image should remain intact after cleaning.</w:t></w:r></w:p>
<w:p><w:r><w:t>UNSIGNED DEMO: synthetic credentials with no verified signer or asset binding.</w:t></w:r></w:p>
<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="3048000" cy="1524000"/><wp:docPr id="1" name="Unsigned demo image"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="image1.png"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="rImage"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="3048000" cy="1524000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>
<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>
</w:body></w:document>`;
docx.file('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="c2pa" ContentType="application/c2pa"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>');
docx.file('_rels/.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rDocument" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>');
docx.file('word/document.xml', documentXml);
docx.file('word/_rels/document.xml.rels', '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rImage" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/></Relationships>');
docx.file('word/media/image1.png', png);
docx.file('META-INF/content_credential.c2pa', manifest('Unsigned Word package demo'), { compression: 'STORE' });
const docxBytes = await docx.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
await fs.writeFile(path.join(folder, 'unsigned-demo-document.docx'), docxBytes);
await fs.writeFile(path.join(folder, 'truncated-signature.png'), Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]));
// A legacy/OLE header fixture, deliberately insufficient to be a real Word
// document. It exercises the inspection-only branch, never a rewrite branch.
const ole = new Uint8Array(512);
ole.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
ole.set([0x3e, 0x00], 24); ole.set([0x03, 0x00], 26); ole.set([0xfe, 0xff], 28); ole.set([0x09, 0x00], 30); ole.set([0x06, 0x00], 32);
await fs.writeFile(path.join(folder, 'legacy-ole-header.doc'), ole);
await fs.writeFile(path.join(folder, 'README.md'), '# Local browser QA fixtures\n\nThe PDF, DOCX, and PNG contain synthetic JUMBF JSON claims explicitly marked UNSIGNED DEMO. They do not contain authentic C2PA signatures or asset bindings.\n\n- unsigned-demo-document.pdf: one visible page, native C2PA associated-file attachment, and ordinary notes.txt attachment.\n- unsigned-demo-document.docx: minimal Word package with visible text, a displayed PNG carrying C2PA, and the standard META-INF/content_credential.c2pa part.\n- unsigned-demo-image.png: valid, visible PNG with a caBX manifest chunk.\n- truncated-signature.png: only the eight-byte PNG signature; malformed input.\n- legacy-ole-header.doc: synthetic 512-byte OLE header, intentionally not a complete Word document; inspection-only input.\n\nRegenerate with node scripts/make-fixtures.mjs.\n');

for (const [filename, bytes] of [['unsigned-demo-document.pdf', pdfBytes], ['unsigned-demo-document.docx', docxBytes]]) {
  const analysis = await analyzeDocument(bytes, filename);
  if (!analysis.canRemove || !analysis.findings.length) throw new Error(`${filename}: expected removable C2PA fixture.`);
  const inspected = inspectManifests(analysis.payloads);
  if (!inspected.summary.generator?.includes('UNSIGNED DEMO')) throw new Error(`${filename}: unsigned demo summary missing.`);
  const cleaned = await removeDocument(bytes, filename);
  if ((await analyzeDocument(cleaned.bytes, filename)).findings.length) throw new Error(`${filename}: removal verification failed.`);
  console.log(`${filename}: ${bytes.length} bytes; ${analysis.findings.length} detected structures; generator ${inspected.summary.generator}`);
}
console.log(`unsigned-demo-image.png: ${png.length} bytes; ${analyzeImage(png, 'demo.png').findings.length} manifest chunk`);
console.log(`Fixtures: ${folder}`);
