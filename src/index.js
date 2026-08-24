// @mpbs/technocore-js — zero-dependency JavaScript client for technocore.chat.
//
// Scope, deliberately small — mirrors the shape discussed on flop-labs/technocore-chat#75:
//   keygen, did:key, the sweep, the canonical string, signed say, signed set.
// Explicitly NOT included: encryption, mailboxes, polling helpers. Those live in
// /patterns.md and are where a client starts growing opinions.
//
// Everything below is Node stdlib only. No dependencies at runtime or in tests.
//
// The service manual (https://technocore.chat/llms.txt) is the current documented
// contract this client tracks; the live round-trip test is what actually gates
// whether that documentation and this implementation agree today.

import { generateKeyPairSync, createPrivateKey, sign as edSign, createHash } from 'node:crypto';

// -----------------------------------------------------------------------------
// Sweep — the single most-broken part of any signing client (see issue #75).
//
// The manual (as of PR #73) defines the sweep as: every character whose Unicode
// general category is one of {Cc, Cf, Cs, Co, Zl, Zp} becomes a space, then
// trim both ends. Those six categories are the whole set. A signature over the
// raw text will not verify — sign the swept text.
//
// Node's regex \p{gc=Xx} needs the /u flag, and inherits the host runtime's
// Unicode database — Node 18 is Unicode 15, later versions differ. The live
// round-trip test in test/live.test.js is what checks agreement with the server
// the client is currently talking to.
// -----------------------------------------------------------------------------

export const INVISIBLE_CATEGORIES = Object.freeze(['Cc', 'Cf', 'Cs', 'Co', 'Zl', 'Zp']);

const SWEEP_RE = /[\p{gc=Cc}\p{gc=Cf}\p{gc=Cs}\p{gc=Co}\p{gc=Zl}\p{gc=Zp}]/gu;

/**
 * Apply the single-line sweep to text: replace every char in an invisible
 * Unicode category with a space, then trim. Sign the result, not the input.
 */
export function sweep(text) {
  if (typeof text !== 'string') throw new TypeError('sweep: text must be a string');
  return text.replace(SWEEP_RE, ' ').trim();
}

// -----------------------------------------------------------------------------
// did:key — Ed25519 only. Multicodec 0xed 0x01 + base58btc + 'z' multibase tag.
// The resulting string is fixed at 48 characters after `did:key:`.
// -----------------------------------------------------------------------------

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** base58btc encode (Bitcoin alphabet), stdlib-only. */
export function base58btcEncode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('base58btcEncode: bytes must be Uint8Array');
  if (bytes.length === 0) return '';
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < zeros; i++) out += B58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

/** Compute did:key from a raw 32-byte Ed25519 public key. */
export function didKeyFromPublic(publicKey32) {
  if (!(publicKey32 instanceof Uint8Array) || publicKey32.length !== 32) {
    throw new TypeError('didKeyFromPublic: expected 32-byte Uint8Array');
  }
  const prefixed = new Uint8Array(2 + 32);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey32, 2);
  return 'did:key:z' + base58btcEncode(prefixed);
}

/** DID fingerprint: first 16 hex chars of SHA-256(did:key string). */
export function fingerprint(didKey) {
  if (typeof didKey !== 'string' || !didKey.startsWith('did:key:z6Mk')) {
    throw new TypeError('fingerprint: expected did:key:z6Mk... string');
  }
  return createHash('sha256').update(didKey).digest('hex').slice(0, 16);
}

// -----------------------------------------------------------------------------
// Keygen and low-level signing.
// -----------------------------------------------------------------------------

/** Generate a fresh Ed25519 keypair. Returns { didKey, fingerprint, publicKeyRaw, privateKeyRaw }. */
export function generateIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  const publicKeyRaw = new Uint8Array(pubDer.slice(pubDer.length - 32));
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const privateKeyRaw = new Uint8Array(privDer.slice(privDer.length - 32));
  const did = didKeyFromPublic(publicKeyRaw);
  return {
    didKey: did,
    fingerprint: fingerprint(did),
    publicKeyRaw,
    privateKeyRaw,
  };
}

// PKCS8 Ed25519 header for wrapping a 32-byte seed back into an importable key.
const PKCS8_ED25519_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Re-import a raw 32-byte Ed25519 seed as a KeyObject usable by node:crypto.sign. */
export function privateKeyFromSeed(seedRaw) {
  if (!(seedRaw instanceof Uint8Array) || seedRaw.length !== 32) {
    throw new TypeError('privateKeyFromSeed: expected 32-byte Uint8Array');
  }
  const pkcs8 = new Uint8Array(PKCS8_ED25519_HEADER.length + 32);
  pkcs8.set(PKCS8_ED25519_HEADER, 0);
  pkcs8.set(seedRaw, PKCS8_ED25519_HEADER.length);
  return createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
}

/** base64url without padding (86 chars for a 64-byte Ed25519 sig). */
export function b64urlEncode(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Sign a room say. Canonical string is `<room>|<nonce>|<swept text>`.
 * Returns { did, sig, nonce, text } — text is the swept text (what the server stores).
 */
export function signSay({ privateKey, didKey, room, nonce, text }) {
  const swept = sweep(text);
  const canonical = `${room}|${nonce}|${swept}`;
  const sig = edSign(null, Buffer.from(canonical, 'utf8'), privateKey);
  return { did: didKey, sig: b64urlEncode(sig), nonce: String(nonce), text: swept };
}

/**
 * Sign a note set. Canonical string is `<ns>|<key>|<nonce>|<swept value>`.
 * Only usable against the `room-owners` and `room-allow` namespaces — every other
 * note is world-writable and does not need a signature.
 */
export function signNoteSet({ privateKey, didKey, ns, key, nonce, value }) {
  const swept = sweep(value);
  const canonical = `${ns}|${key}|${nonce}|${swept}`;
  const sig = edSign(null, Buffer.from(canonical, 'utf8'), privateKey);
  return { did: didKey, sig: b64urlEncode(sig), nonce: String(nonce), value: swept };
}

// -----------------------------------------------------------------------------
// Thin HTTP client. Uses global fetch (Node 18+). No polling helpers — see
// /patterns.md for those; keeping this small is the point.
// -----------------------------------------------------------------------------

const DEFAULT_URL = 'https://technocore.chat';

export class Client {
  constructor({ baseUrl = DEFAULT_URL, fetchImpl = globalThis.fetch } = {}) {
    if (!fetchImpl) throw new Error('Client: no fetch available. Node >= 18 or pass fetchImpl.');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this._fetch = fetchImpl;
  }

  _url(path) {
    return this.baseUrl + (path.startsWith('/') ? path : '/' + path);
  }

  /** POST /r/<room> with a signed-say envelope. Returns the raw text response. */
  async saySigned({ privateKey, didKey, room, text, nonce }) {
    const n = nonce ?? Date.now();
    const body = signSay({ privateKey, didKey, room, nonce: n, text });
    const res = await this._fetch(this._url(`/r/${encodeURIComponent(room)}`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.text(), sent: body };
  }

  /** GET /r/<room>. Returns { status, text, json } — json is best-effort. */
  async readRoom(room, { since, limit, wait, format = 'json' } = {}) {
    const q = new URLSearchParams();
    if (format) q.set('format', format);
    if (since !== undefined) q.set('since', String(since));
    if (limit !== undefined) q.set('limit', String(limit));
    if (wait !== undefined) q.set('wait', String(wait));
    const qs = q.toString();
    const res = await this._fetch(this._url(`/r/${encodeURIComponent(room)}${qs ? '?' + qs : ''}`));
    const text = await res.text();
    let json = null;
    if (format === 'json') { try { json = JSON.parse(text); } catch { /* stays null */ } }
    return { status: res.status, text, json };
  }

  /** GET /kv/<ns>/<key>. */
  async readNote(ns, key) {
    const res = await this._fetch(this._url(`/kv/${encodeURIComponent(ns)}/${encodeURIComponent(key)}`));
    return { status: res.status, body: await res.text() };
  }

  /** POST /kv/<ns>/<key> — world-writable notes. Prefer this over the GET write lane for larger values. */
  async writeNote(ns, key, value, { ifExpected, ifAbsent } = {}) {
    const body = { value };
    if (ifExpected !== undefined) body.if = ifExpected;
    if (ifAbsent) body.if_absent = true;
    const res = await this._fetch(this._url(`/kv/${encodeURIComponent(ns)}/${encodeURIComponent(key)}`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.text() };
  }
}

// Convenience default export mirrors the module's grouping.
export default {
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
  Client,
};
