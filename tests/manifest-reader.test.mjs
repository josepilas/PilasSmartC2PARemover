import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectManifests, safeMetadata, MANIFEST_SOURCES } from '../dist/manifest-reader.js';

const text = new TextEncoder();
const concat = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let at = 0; for (const a of arrays) { out.set(a, at); at += a.length; } return out;
};
function cbor(value) {
  const header = (major, n) => n < 24 ? Uint8Array.of(major * 32 + n) : n < 256 ? Uint8Array.of(major * 32 + 24, n) : Uint8Array.of(major * 32 + 25, n >> 8, n & 255);
  if (value === null) return Uint8Array.of(246);
  if (typeof value === 'string') { const b = text.encode(value); return concat(header(3, b.length), b); }
  if (typeof value === 'number') return value >= 0 ? header(0, value) : header(1, -value - 1);
  if (value instanceof Uint8Array) return concat(header(2, value.length), value);
  if (Array.isArray(value)) return concat(header(4, value.length), ...value.map(cbor));
  const entries = Object.entries(value);
  return concat(header(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)]));
}
function box(type, data, mode = 'standard') {
  const head = new Uint8Array(mode === 'extended' ? 16 : 8), view = new DataView(head.buffer);
  view.setUint32(0, mode === 'extended' ? 1 : mode === 'zero' ? 0 : head.length + data.length); head.set(text.encode(type), 4);
  if (mode === 'extended') view.setBigUint64(8, BigInt(head.length + data.length));
  return concat(head, data);
}
function jumb(label, ...children) {
  const uuid = Uint8Array.from('63626f7200110010800000aa00389b71'.match(/../g), h => parseInt(h, 16));
  const desc = box('jumd', concat(uuid, Uint8Array.of(3), text.encode(label), Uint8Array.of(0)));
  return box('jumb', concat(desc, ...children));
}
const content = (label, data) => jumb(label, box('cbor', cbor(data)));

test('real nested JUMBF claims and assertion types populate the display summary', () => {
  const claim = content('c2pa.claim.v2', { claim_generator_info: [{ name: 'Camera Tool', version: '4.1' }], 'dc:title': 'Sunrise', signature: 'self#jumbf=c2pa.signature', created_assertions: [] });
  const assertions = jumb('c2pa.assertions',
    content('c2pa.actions.v2', { actions: [{ action: 'c2pa.created', softwareAgent: 'Camera Tool' }, { action: 'c2pa.edited' }] }),
    content('c2pa.ingredient.v3', { title: 'Original.jpg', relationship: 'parentOf', instanceID: 'urn:uuid:source' }),
    jumb('org.example.metadata', box('json', text.encode(JSON.stringify({ name: 'Original author', editing: true })))));
  const manifest = jumb('c2pa', jumb('urn:c2pa:test-manifest', claim, assertions));
  const result = inspectManifests([manifest]);
  assert.equal(result.claims.length, 1);
  assert.equal(result.assertions.length, 3);
  assert.equal(result.summary.generator, 'Camera Tool');
  assert.equal(result.summary.title, 'Sunrise');
  assert.deepEqual(result.summary.actions, ['c2pa.created', 'c2pa.edited']);
  assert.equal(result.summary.ingredients, 1);
  assert.equal(result.assertions[2].data.editing, true);
  assert.ok(result.labels.includes('c2pa.claim.v2'));
  assert.equal(result.verification.performed, false);
  assert.ok(result.warnings.some(w => /identity are not verified/.test(w)));
  assert.doesNotThrow(() => JSON.stringify(result));
});

test('v1 claim fields work and arbitrary metadata does not become a verified signer', () => {
  const result = inspectManifests([content('c2pa.claim', { claim_generator: 'Editor/2', 'dc:title': 'Untitled', issuer: 'An untrusted assertion', signature: 'self#jumbf=c2pa.signature' })]);
  assert.equal(result.summary.generator, 'Editor/2');
  assert.equal(result.claims[0].data.issuer, 'An untrusted assertion');
  assert.equal(result.summary.issuer, undefined);
  const plain = inspectManifests([text.encode(JSON.stringify({ claim_generator: 'Bare JSON/1', signature: 'self#jumbf=c2pa.signature' }))]);
  assert.equal(plain.summary.generator, 'Bare JSON/1');
});

test('CBOR tags, large integers, binary values, floats, and numeric map keys stay JSON safe', () => {
  const big = Uint8Array.of(27, 255, 255, 255, 255, 255, 255, 255, 255);
  const half = Uint8Array.of(249, 0x3e, 0x00); // float16 1.5
  const inf = Uint8Array.of(249, 0x7c, 0x00);
  const data = concat(Uint8Array.of(164), cbor('large'), big, cbor('half'), half, cbor('infinity'), inf, cbor('tagged'), Uint8Array.of(0xc1), cbor(new Uint8Array(120).fill(42)));
  const result = inspectManifests([jumb('org.example.numbers', box('cbor', data))]);
  const parsed = result.raw[0].data;
  assert.equal(parsed.large.$integer, '18446744073709551615');
  assert.equal(parsed.half, 1.5);
  assert.equal(parsed.infinity.$float, 'Infinity');
  assert.equal(parsed.tagged.$tag, 1);
  assert.equal(parsed.tagged.value.byteLength, 120);
  assert.equal(parsed.tagged.value.hexPreview.length, 96);
  assert.equal(parsed.tagged.value.truncated, true);
  assert.doesNotThrow(() => JSON.stringify(result));
  assert.equal(inspectManifests([box('cbor', Uint8Array.of(0xa1, 1, 0x26))]).raw[0].data['1'], -7);
});

test('COSE_Sign1 decodes its protected headers without claiming validity', () => {
  const protectedHeaders = Uint8Array.of(0xa1, 1, 0x26); // {1: -7}, ES256 algorithm identifier
  const cose = concat(Uint8Array.of(0xd2), cbor([protectedHeaders, {}, null, new Uint8Array(64).fill(255)]));
  const result = inspectManifests([jumb('c2pa.signature', box('cbor', cose))]);
  assert.equal(result.raw[0].data.$tag, 18);
  assert.equal(result.raw[0].cose.protectedHeaders['1'], -7);
  assert.equal(result.raw[0].cose.verification, 'Not performed');
  assert.equal(result.raw[0].cose.signature.byteLength, 64);
  assert.deepEqual(result.raw[0].cose.certificates, []);
});

test('indefinite CBOR strings, arrays and maps parse correctly', () => {
  const data = concat(Uint8Array.of(0xbf), cbor('claim_generator'), Uint8Array.of(0x7f), cbor('Camera'), cbor('/1'), Uint8Array.of(0xff), cbor('values'), Uint8Array.of(0x9f, 1, 2, 0xff), cbor('bytes'), Uint8Array.of(0x5f, 0x42, 1, 2, 0x41, 3, 0xff), Uint8Array.of(0xff));
  const result = inspectManifests([data]);
  assert.equal(result.summary.generator, 'Camera/1');
  assert.deepEqual(result.claims[0].data.values, [1, 2]);
  assert.equal(result.claims[0].data.bytes.hexPreview, '010203');
});

test('duplicate and complex CBOR keys are preserved as map entries', () => {
  const result = inspectManifests([box('cbor', Uint8Array.of(0xa2, 1, 2, 1, 3))]);
  assert.deepEqual(result.raw[0].data.$map, [[1, 2], [1, 3]]);
  const complex = inspectManifests([box('cbor', Uint8Array.of(0xa1, 0x81, 1, 2))]);
  assert.deepEqual(complex.raw[0].data.$map, [[[1], 2]]);
});

test('truncated CBOR preserves preceding complete metadata and reports partial state', () => {
  const data = concat(Uint8Array.of(0xa2), cbor('claim_generator'), cbor('Recoverable/1'), cbor('broken'), Uint8Array.of(0x78, 100, 1));
  const result = inspectManifests([content('c2pa.actions', { actions: [{ action: 'c2pa.created' }] }), jumb('c2pa.claim', box('cbor', data))]);
  assert.equal(result.summary.generator, 'Recoverable/1');
  assert.equal(result.claims[0].partial, true);
  assert.ok(result.warnings.some(w => /Truncated CBOR/.test(w)));
  assert.deepEqual(result.summary.actions, ['c2pa.created']);
});

test('extended-size and zero-size boxes parse inside their parent boundary', () => {
  for (const mode of ['extended', 'zero']) {
    const result = inspectManifests([box('json', text.encode('{"claim_generator":"Tool/1"}'), mode)]);
    assert.equal(result.summary.generator, 'Tool/1');
    assert.equal(result.claims.length, 1);
  }
  const truncated = new Uint8Array(12); new DataView(truncated.buffer).setUint32(0, 99); truncated.set(text.encode('jumb'), 4);
  assert.ok(inspectManifests([truncated]).warnings.some(w => /truncated jumb/.test(w)));
  const impossible = box('jumb', new Uint8Array(0), 'extended'); new DataView(impossible.buffer).setBigUint64(8, 0xffffffffffffffffn);
  assert.ok(inspectManifests([impossible]).warnings.some(w => /safe inspection range/.test(w)));
});

test('malformed siblings leave already decoded claims readable', () => {
  const claim = content('c2pa.claim', { claim_generator: 'Good/1' });
  const broken = box('json', text.encode('{broken'));
  const result = inspectManifests([concat(claim, broken)]);
  assert.equal(result.summary.generator, 'Good/1');
  assert.ok(result.warnings.some(w => /JSON decoding failed/.test(w)));
});

test('parser limits nesting, collections and invalid text rather than recursing indefinitely', () => {
  let deep = content('c2pa.claim', { claim_generator: 'Hidden/1' });
  for (let i = 0; i < 30; i++) deep = jumb(`nested-${i}`, deep);
  assert.ok(inspectManifests([deep]).warnings.some(w => /nesting exceeds/.test(w)));
  assert.ok(inspectManifests([box('cbor', Uint8Array.of(0x9a, 0xff, 0xff, 0xff, 0xff))]).warnings.some(w => /item limit/.test(w)));
  assert.ok(inspectManifests([box('cbor', Uint8Array.of(0x62, 0xc3, 0x28))]).warnings.length > 1);
  assert.doesNotThrow(() => inspectManifests([Uint8Array.of(255), null, new Uint8Array()]));
});

test('JSON dangerous keys remain data and cyclic metadata is display-safe', () => {
  const result = inspectManifests([text.encode('{"__proto__":{"polluted":true},"claim_generator":"Tool"}')]);
  assert.equal({}.polluted, undefined);
  assert.equal(result.raw[0].data.__proto__.polluted, true);
  const cycle = { n: 18446744073709551615n }; cycle.self = cycle;
  assert.equal(safeMetadata(cycle).n.$integer, '18446744073709551615');
  assert.doesNotThrow(() => JSON.stringify(safeMetadata(cycle)));
  assert.ok(MANIFEST_SOURCES.every(source => source.url.startsWith('https://')));
});
