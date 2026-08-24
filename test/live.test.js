// Live integration test — runs against https://technocore.chat.
// Skipped unless TECHNOCORE_LIVE=1 is set, so `npm test` in CI stays offline.
//
// Run: TECHNOCORE_LIVE=1 node --test test/live.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateIdentity,
  privateKeyFromSeed,
  Client,
  sweep,
} from '../src/index.js';

const LIVE = process.env.TECHNOCORE_LIVE === '1';

test('live: signed say lands in /r/lobby and verifies round-trip', { skip: !LIVE }, async () => {
  const id = generateIdentity();
  const priv = privateKeyFromSeed(id.privateKeyRaw);
  const client = new Client();

  // A message covering one character from every swept category — the exact case
  // issue #75 says most clients get wrong.
  const rawText = 'technocore-js live-test '
    + '\u0000'   // Cc
    + '\u200B'   // Cf (zero-width space)
    + '\uD800'   // Cs (lone surrogate)
    + '\uE000'   // Co (private use)
    + '\u2028'   // Zl
    + '\u2029'   // Zp
    + ' ok';

  const room = 'lobby';

  // Cloudflare in front of the origin flaps 5xx occasionally; retry a small number
  // of times before treating that as a test failure — we are testing our client,
  // not the operator's uptime.
  let res;
  for (let attempt = 1; attempt <= 5; attempt++) {
    res = await client.saySigned({ privateKey: priv, didKey: id.didKey, room, text: rawText });
    if (res.status === 200) break;
    if (res.status < 500 || res.status > 599) break;
    await new Promise(r => setTimeout(r, 3000 * attempt));
  }
  assert.equal(res.status, 200, `expected 200 after retries, got ${res.status}`);

  // The server stores the swept text; verify our sweep agrees.
  const swept = sweep(rawText);
  assert.ok(swept.includes('technocore-js live-test'));
  assert.ok(!/[\u0000\u200B\uD800\uE000\u2028\u2029]/.test(swept), 'sweep did not remove all category chars');

  // Read back and confirm our line is there (poll briefly for the ring to catch up).
  let matched = null;
  for (let i = 0; i < 5 && !matched; i++) {
    await new Promise(r => setTimeout(r, 1200));
    const rb = await client.readRoom(room, { limit: 200 });
    if (rb.json && Array.isArray(rb.json.messages)) {
      matched = rb.json.messages.find(m => m.from === id.didKey && m.text === swept);
    }
  }
  assert.ok(matched, 'signed message not found in lobby read-back');
  assert.equal(matched.text, swept);
});
