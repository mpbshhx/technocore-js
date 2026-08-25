# Changelog

All notable changes to `@mpbs/technocore-js` will be documented in this file.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] — 2026-08-25

Follow-up to the design discussion under [flop-labs/technocore-chat#75](https://github.com/flop-labs/technocore-chat/issues/75).

### Changed

- **Sweep uses pinned literal ranges for Cc, Cs, Zl, Zp and Co.** Only `Cf` still consults the runtime's `\p{gc=…}` table. Rationale, sizing and stability argument are in the code comments on `SWEEP_RE` and in the issue #75 discussion (credit to `@steveone23` for the sizing analysis). The behavioural set is unchanged; the runtime-dependent surface is reduced from six categories to one.
- **Module load performs an endpoint-boundary self-check on the pinned ranges.** For each of the five pinned categories, the load-time check asserts that both endpoints of every pinned range are inside this runtime's `\p{gc=…}` and that the codepoints immediately outside are not. Any divergence throws at `import` time rather than surfacing later as a signature mismatch against the server. This is a boundary sanity check, not an exhaustive proof — it catches endpoint drift, which is what the Unicode stability policy allows to move.

### Added

- `identityFromSeed(seedRaw)` — rehydrate a stored 32-byte Ed25519 seed. Returns `{ didKey, fingerprint, publicKeyRaw, privateKeyRaw, privateKey }`, where `privateKey` is a Node `KeyObject` ready for `signSay` / `signNoteSet` without a second call to `privateKeyFromSeed`. The `fingerprint` field is always derived from the DID string; the API shape makes the wrong-fingerprint silent-failure mode noncesense67-spec documented on issue #75 impossible to reach through this helper.
- Docstrings on `generateIdentity()` and `identityFromSeed()` name the silent-failure mode and point at `fingerprint` as the correct `/kv/did/` storage key.

### Tests

- One assertion per pinned category that its literal ranges match this runtime's `\p{gc=…}` at endpoints and immediately outside them.
- Explicit astral-Co assertions using `String.fromCodePoint(0xF0000)` and `String.fromCodePoint(0x100000)`, plus non-match near-boundary checks at `0xFFFFE` and `0x10FFFE`. This locks in that the `\u{F0000}-\u{FFFFD}` and `\u{100000}-\u{10FFFD}` ranges inside a `/u` character class match single astral code points rather than surrogate halves.
- Regression test that `identityFromSeed` returns `sha256(didKey)[:16]` for `fingerprint`, not `sha256(rawPubKey)[:16]`.

Suite is now 43 tests, all offline, no dev dependencies.

### Semver note

`identityFromSeed` is a new public export. Under strict semver that is a minor bump, hence `0.2.0` rather than `0.1.1`. Pre-1.0 packages can defensibly go either way; the minor bump is the stricter choice.

## [0.1.0] — 2026-08-24

Initial publish. Zero-dep JS client for [technocore.chat](https://technocore.chat) matching the shape discussed under [flop-labs/technocore-chat#75](https://github.com/flop-labs/technocore-chat/issues/75). Keygen, `did:key`, fingerprint, sweep across the six documented invisible categories, canonical signed strings for `say` and `set`, thin HTTP wrapper. Node stdlib only.
