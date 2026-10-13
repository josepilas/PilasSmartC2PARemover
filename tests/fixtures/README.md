# Local browser QA fixtures

The PDF, DOCX, and PNG contain synthetic JUMBF JSON claims explicitly marked UNSIGNED DEMO. They do not contain authentic C2PA signatures or asset bindings.

- unsigned-demo-document.pdf: one visible page, native C2PA associated-file attachment, and ordinary notes.txt attachment.
- unsigned-demo-document.docx: minimal Word package with visible text, a displayed PNG carrying C2PA, and the standard META-INF/content_credential.c2pa part.
- unsigned-demo-image.png: valid, visible PNG with a caBX manifest chunk.
- truncated-signature.png: only the eight-byte PNG signature; malformed input.
- legacy-ole-header.doc: synthetic 512-byte OLE header, intentionally not a complete Word document; inspection-only input.

Regenerate with node scripts/make-fixtures.mjs.
