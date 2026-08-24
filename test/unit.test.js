// Unit tests — pure logic, no network. Node built-in test runner.
// Run: node --test test/unit.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify as edVerify } from 'node:crypto';
import {
  sweep,
  INVISIBLE_CATEGORIES,
  base58btcEncode,
  didKeyFromPublic,
  fingerprint,
  generateIdentity,
  privateKeyFromSeed,
  b64urlEncode,
  signSay,
  signNoteSet,
} from '../src/index.js';

// -----------------------------------------------------------------------------
// sweep — the failure mode issue #75 explicitly calls out.
// -----------------------------------------------------------------------------

test('sweep: replaces newline and other Cc controls with space', () => {
  assert.equal(sweep('hello\nworld'), 'hello world');
  assert.equal(sweep('a\tb\rc\x00d'), 'a b c d');
});

test('sweep: replaces Cf format characters (zero-width space, RTL mark)', () => {
  // U+200B ZERO WIDTH SPACE (Cf)
  assert.equal(sweep('hello\u200Bworld'), 'hello world');
  // U+200E LEFT-TO-RIGHT MARK (Cf) and U+202E RIGHT-TO-LEFT OVERRIDE (Cf)
  assert.equal(sweep('a\u200Eb\u202Ec'), 'a b c');
});

test('sweep: replaces U+2028 (Zl) and U+2029 (Zp) — the line/paragraph separators', () => {
  assert.equal(sweep('a\u2028b'), 'a b');
  assert.equal(sweep('a\u2029b'), 'a b');
});

test('sweep: replaces Co private-use area chars', () => {
  // U+E000 is the first Co codepoint
  assert.equal(sweep('hi\uE000there'), 'hi there');
});

test('sweep: replaces lone surrogates (Cs)', () => {
  // U+D800 lone high surrogate — matched via /u regex on the string's codepoints
  const s = 'a' + '\uD800' + 'b';
  assert.equal(sweep(s), 'a b');
});

test('sweep: trims after replacement, not just the raw input', () => {
  assert.equal(sweep('\n\thello\r\n'), 'hello');
  assert.equal(sweep('\u200B hello \u200B'), 'hello');
});

test('sweep: preserves regular whitespace inside (Zs is not swept)', () => {
  // U+00A0 NO-BREAK SPACE is Zs, NOT in the sweep set
  assert.equal(sweep('a\u00A0b'), 'a\u00A0b');
});

test('sweep: preserves ordinary ASCII text', () => {
  assert.equal(sweep('hello world 123'), 'hello world 123');
});

test('sweep: preserves emoji', () => {
  // 🚀 U+1F680 is So (Symbol, other) — not in the sweep set
  assert.equal(sweep('ship it 🚀'), 'ship it 🚀');
});

test('INVISIBLE_CATEGORIES lists exactly six categories', () => {
  assert.deepEqual([...INVISIBLE_CATEGORIES], ['Cc', 'Cf', 'Cs', 'Co', 'Zl', 'Zp']);
});

test('sweep: throws TypeError on non-string input', () => {
  assert.throws(() => sweep(42), TypeError);
  assert.throws(() => sweep(null), TypeError);
});

// -----------------------------------------------------------------------------
// base58btc — spot-checked against known Bitcoin test vectors.
// -----------------------------------------------------------------------------

test('base58btcEncode: empty input encodes to empty string', () => {
  assert.equal(base58btcEncode(new Uint8Array([])), '');
});

test('base58btcEncode: leading zeros become leading 1s', () => {
  assert.equal(base58btcEncode(new Uint8Array([0])), '1');
  assert.equal(base58btcEncode(new Uint8Array([0, 0, 0])), '111');
});

test('base58btcEncode: single byte 0x39 (=57) is "z", index 57 of the alphabet', () => {
  assert.equal(base58btcEncode(new Uint8Array([0x39])), 'z');
});

test('base58btcEncode: [0x00, 0x39] is "1z" (one leading-zero + z)', () => {
  assert.equal(base58btcEncode(new Uint8Array([0x00, 0x39])), '1z');
});

test('base58btcEncode: single byte 0x01 is "2", index 1 of the alphabet', () => {
  assert.equal(base58btcEncode(new Uint8Array([0x01])), '2');
});

test('base58btcEncode: throws on non-Uint8Array', () => {
  assert.throws(() => base58btcEncode([1, 2, 3]), TypeError);
});

// -----------------------------------------------------------------------------
// did:key + fingerprint.
// -----------------------------------------------------------------------------

test('didKeyFromPublic: produces did:key:z6Mk... with expected length', () => {
  const { publicKeyRaw, didKey } = generateIdentity();
  assert.ok(didKey.startsWith('did:key:z6Mk'));
  // did:key:z + 47 base58 chars for 0xed 0x01 + 32-byte key = 56 chars total including scheme
  assert.equal(didKey.length, 56);
  // Recompute from the raw key and expect identity
  assert.equal(didKeyFromPublic(publicKeyRaw), didKey);
});

test('didKeyFromPublic: throws on wrong-length input', () => {
  assert.throws(() => didKeyFromPublic(new Uint8Array(31)), TypeError);
  assert.throws(() => didKeyFromPublic(new Uint8Array(33)), TypeError);
});

test('fingerprint: 16 lowercase hex chars', () => {
  const { didKey, fingerprint: fp } = generateIdentity();
  assert.equal(fp, fingerprint(didKey));
  assert.match(fp, /^[0-9a-f]{16}$/);
});

test('fingerprint: throws on non-did:key input', () => {
  assert.throws(() => fingerprint('not-a-did'), TypeError);
  assert.throws(() => fingerprint(''), TypeError);
});

// -----------------------------------------------------------------------------
// Round-trip: seed -> KeyObject -> sign -> verify against the raw public key.
// -----------------------------------------------------------------------------

test('privateKeyFromSeed: produces a KeyObject that Ed25519-signs and verifies', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  // Reconstruct the SPKI-wrapped public key
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pubDer = Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]);
  const pub = createPublicKey({ key: pubDer, format: 'der', type: 'spki' });

  // Round-trip through signSay covers the raw-signing path — no need for a dynamic require.
  const { sig, text } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce: 1, text: 'hi' });
  assert.equal(text, 'hi');
  const canonical = Buffer.from(`lobby|1|${text}`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);
});

test('privateKeyFromSeed: rejects wrong-length seed', () => {
  assert.throws(() => privateKeyFromSeed(new Uint8Array(16)), TypeError);
});

// -----------------------------------------------------------------------------
// signSay + signNoteSet: canonical string uses swept text, signature verifies.
// -----------------------------------------------------------------------------

test('signSay: canonical string uses swept text, verifies against raw pubkey', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pub = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]),
    format: 'der', type: 'spki',
  });

  // Text with a Cf character — the sweep must strip it before signing
  const raw = 'hello\u200Bworld';
  const { sig, text, nonce } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce: 42, text: raw });
  assert.equal(text, 'hello world'); // swept
  const canonical = Buffer.from(`lobby|${nonce}|${text}`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);

  // Signing the raw (unswept) text must NOT match — regression against the classic bug
  const wrongCanonical = Buffer.from(`lobby|${nonce}|${raw}`, 'utf8');
  assert.equal(edVerify(null, wrongCanonical, pub, sigBytes), false);
});

test('signSay: sig is exactly 86 base64url characters', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const { sig } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce: 1, text: 'hi' });
  assert.equal(sig.length, 86);
  assert.match(sig, /^[A-Za-z0-9_-]{86}$/);
});

test('signNoteSet: canonical is ns|key|nonce|swept-value, verifies', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pub = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]),
    format: 'der', type: 'spki',
  });

  const { sig, value, nonce } = signNoteSet({
    privateKey: priv, didKey: id.didKey,
    ns: 'room-owners', key: 'd-mine', nonce: 1, value: 'did:key:z6Mkabc\u200B',
  });
  assert.equal(value, 'did:key:z6Mkabc'); // swept (Cf trimmed)
  const canonical = Buffer.from(`room-owners|d-mine|${nonce}|${value}`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);
});

// -----------------------------------------------------------------------------
// b64urlEncode: no padding, URL-safe alphabet.
// -----------------------------------------------------------------------------

test('b64urlEncode: no padding, URL-safe alphabet', () => {
  const out = b64urlEncode(new Uint8Array([255, 255, 255]));
  assert.equal(out, '____');
  assert.equal(b64urlEncode(new Uint8Array([0])), 'AA');
});

// -----------------------------------------------------------------------------
// Edge cases — the ones a hostile reviewer looks for.
// -----------------------------------------------------------------------------

test('sweep: repeated invisible chars each become a space (no collapsing)', () => {
  // Two zero-width spaces → two literal spaces, not one
  assert.equal(sweep('a\u200B\u200Bb'), 'a  b');
});

test('sweep: message that is entirely invisible chars becomes empty after trim', () => {
  assert.equal(sweep('\u200B\u200B\u2028\u2029'), '');
  assert.equal(sweep('\n\r\t'), '');
});

test('signSay: text containing literal | is signed as plain concatenation, verifies', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pub = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]),
    format: 'der', type: 'spki',
  });

  // A | in the text field — canonical string is a plain concatenation, so this
  // simply becomes part of the signed bytes; the signature must still verify.
  const raw = 'hello | world';
  const { sig, text, nonce } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce: 7, text: raw });
  assert.equal(text, raw);
  const canonical = Buffer.from(`lobby|${nonce}|${text}`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);
});

test('signSay: very large nonce (ms clock into the future) signs and verifies', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pub = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]),
    format: 'der', type: 'spki',
  });

  // 19-digit nonce, the upper bound the manual permits
  const nonce = 9999999999999999999n.toString();
  const { sig, text } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce, text: 'hi' });
  const canonical = Buffer.from(`lobby|${nonce}|${text}`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);
});

test('signSay: empty text (after a sweep of all-invisibles) still signs and verifies', () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
  const pub = createPublicKey({
    key: Buffer.concat([spkiHeader, Buffer.from(id.publicKeyRaw)]),
    format: 'der', type: 'spki',
  });

  const { sig, text, nonce } = signSay({ privateKey: priv, didKey: id.didKey, room: 'lobby', nonce: 1, text: '\u200B\u200B' });
  assert.equal(text, '');
  const canonical = Buffer.from(`lobby|${nonce}|`, 'utf8');
  const sigBytes = Buffer.from(sig.replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  assert.equal(edVerify(null, canonical, pub, sigBytes), true);
});
