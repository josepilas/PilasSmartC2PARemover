# Pilas Smart C2PA Remover

A browser-local application for inspecting Content Credentials and removing supported embedded C2PA structures. Files remain in memory; there is no file upload endpoint. Original files are preserved, and every output is re-scanned before download.

## Run locally

With Node.js installed, run `node scripts/serve.mjs` from this directory and open `http://127.0.0.1:4173`. The application is buildless, and its runtime libraries are included in `dist/vendor/`.

For engine tests: install the locked dependencies with `npm ci`, then run `npm test`. Regenerate the clearly unsigned browser fixtures with `node scripts/make-fixtures.mjs`.

## Implemented handling

- JPEG: C2PA JUMBF APP11 fragments and selective XMP references. Unrelated APP11, EXIF, ICC, and compressed image data are preserved.
- PNG/APNG: caBX chunks and supported uncompressed XMP references; changed metadata CRCs are repaired.
- WebP/WAV/BWF: C2PA RIFF chunks, supported XMP references, and container size repair.
- GIF: C2PA_GIF application extensions; image and animation extensions are preserved.
- TIFF/DNG/BigTIFF: C2PA tag 0xCD41 with fixed-offset directory surgery and payload erasure.
- AVIF/HEIC/HEIF/MP4/MOV/M4A/M4V/M4S: top-level C2PA UUID boxes become equal-size, erased `free` boxes to preserve media offsets.
- AVI: equal-size erased `JUNK` chunks preserve indexes and offsets.
- PDF: C2PA associated files, attachment references, orphan payloads, and supported XMP references. A full graph rewrite excludes old revisions and unreachable objects.
- DOCX/XLSX/PPTX, macro/template variants, ODF, EPUB, XPS, and ZIP: standardized `META-INF/content_credential.c2pa`, explicit sidecars and references, and supported embedded image/media cleanup.

## Scope and limitations

This tool reads metadata; it does not perform cryptographic signature, certificate-chain, trust-list, or identity verification. Claims and certificate names are unverified data.

Legacy binary Office files, signed/encrypted documents, malformed structures, unsupported archive codecs, and unusual or unresolved embeddings are not rewritten. Compressed/extended XMP, proprietary maker notes, nested BMFF locations, multipart media, SVG, MP3, and FLAC are not comprehensively supported. Consult each file's warnings.

Removal targets supported embedded structures and references. It cannot erase external provenance records, remote manifests, invisible watermarks, or watermark-based discovery. Ordinary EXIF metadata is not removed. XMP remote references are identified structurally through `dcterms:provenance` URI properties; remote content is not fetched.

Limits: 100 MB per file, 30 files and 400 MB per session; ZIP inspection is bounded to 256 MB expanded data, 96 MB per part, and 6,000 entries. Processing large documents can take time and browser memory.

## Research and dependencies

Embedding paths follow the [C2PA 2.4 Technical Specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html), especially Appendix A. Metadata decoding also follows [CBOR RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) and [COSE RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).

Runtime libraries: pdf-lib 1.17.1 and JSZip 3.10.1. Their license texts are included in `dist/vendor/`. Google Fonts provides DM Sans and Manrope; system sans-serif fonts are the fallback.

## Validation

41 automated tests cover structural preservation, targeted removal, malformed inputs, signed documents, ZIP packages, PDF orphan pruning, bounded manifest decoding, and XMP ownership-history preservation. Browser QA covers the sample PNG workflow, PDF/Word batch processing, unsupported files, responsive layouts, settings, activity, and downloads. Public C2PA SDK fixtures were also checked for signed JPEG, MP4, and PNG remote-reference removal, and unsigned image/media detection.
