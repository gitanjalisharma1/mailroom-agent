'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonical, PROFILE, proposalDigest } = require('./server');
const ACTIONS = ['create_draft','update_internal_record','send_approved_notice','request_confirmation','quarantine_item','no_action'];

async function main() {
  const rawUrl = process.env.MAILROOM_URL;
  if (!rawUrl) throw new Error('Set MAILROOM_URL to your deployed HTTPS service URL first.');
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('MAILROOM_URL must be a public HTTPS base URL with no credentials, path, query, or fragment.');
  }
  const base = url.origin;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const evaluationId = `smoke-${crypto.randomUUID()}`;
  const dossierId = `smoke-case-${crypto.randomUUID()}`;
  const body = {
    profile: PROFILE,
    operation: 'propose',
    evaluationId,
    receiptVerifier: { algorithm: 'Ed25519', publicKeyJwk: publicKey.export({ format: 'jwk' }) },
    corpus: { coreId: 'local-smoke-test', auditId: `audit-${crypto.randomUUID()}`, stableCount: 1, freshCount: 0 },
    allowedActions: ACTIONS,
    dossiers: [{
      dossierId, partition: 'stable_core', receivedAt: new Date().toISOString(),
      mailbox: 'orders@example.test', objective: 'Prepare a draft order status response.',
      sources: [{ sourceId: `source-${dossierId}`, kind: 'email', provenance: 'external sender', title: 'Order status inquiry',
        lines: [{ lineId: `line-${dossierId}`, text: 'Please prepare an order status draft for orders@example.test, reference ORDER-SMOKE-1, current status delayed.' }] }]
    }]
  };

  async function post(path, payload) {
    const response = await fetch(`${base}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(50000)
    });
    const contentType = response.headers.get('content-type') || '';
    assert.match(contentType, /application\/json/i, `${path} should return JSON`);
    const text = await response.text();
    assert.ok(Buffer.byteLength(text) < 512 * 1024, 'response must be under 512 KiB');
    let json;
    try { json = JSON.parse(text); } catch { throw new Error(`${path} returned invalid JSON: ${text.slice(0, 300)}`); }
    return { status: response.status, json };
  }

  const health = await fetch(`${base}/health`, { signal: AbortSignal.timeout(15000) });
  assert.equal(health.status, 200, 'health check should return HTTP 200');
  assert.deepEqual(await health.json(), { ok: true });
  console.log('Health endpoint: OK');

  const proposed = await post('/', body);
  assert.equal(proposed.status, 200, `propose failed: ${JSON.stringify(proposed.json)}`);
  const response = proposed.json;
  assert.equal(response.profile, PROFILE);
  assert.equal(response.evaluationId, evaluationId);
  assert.equal(response.status, 'awaiting_receipts');
  assert.match(response.inputDigest, /^[a-f0-9]{64}$/);
  assert.equal(response.proposals?.length, 1, 'must return exactly one proposal for the test dossier');
  const proposal = response.proposals[0];
  assert.equal(proposal.dossierId, dossierId);
  assert.match(proposal.callId, /^[A-Za-z0-9._:-]{12,128}$/);
  assert.ok(ACTIONS.includes(proposal.action));
  assert.ok(Array.isArray(proposal.evidence) && proposal.evidence.length > 0);
  assert.equal(new Set(proposal.evidence).size, proposal.evidence.length);
  assert.ok(proposal.evidence.every(id => id === `line-${dossierId}`));
  const pDigest = proposalDigest(proposal);
  console.log(`Propose endpoint: OK (${proposal.action})`);

  const receipt = {
    dossierId: proposal.dossierId, callId: proposal.callId, action: proposal.action,
    accepted: true, proposalDigest: pDigest, receiptId: `receipt-${crypto.randomUUID()}`
  };
  const signedMessage = { profile: PROFILE, evaluationId, inputDigest: response.inputDigest, receipt };
  const signature = crypto.sign(null, Buffer.from(canonical(signedMessage), 'utf8'), privateKey).toString('base64');
  const commitBody = { profile: PROFILE, operation: 'commit', evaluationId, inputDigest: response.inputDigest,
    receipts: [{ ...receipt, receiptSignature: signature }] };

  const invalid = await post('/commit', { ...commitBody, receipts: [{ ...commitBody.receipts[0], receiptSignature: Buffer.alloc(64).toString('base64') }] });
  assert.ok(invalid.status === 400 || invalid.status === 422, 'invalid Ed25519 signature must be rejected');
  console.log('Invalid signature rejection: OK');

  const committed = await post('/commit', commitBody);
  assert.equal(committed.status, 200, `commit failed: ${JSON.stringify(committed.json)}`);
  assert.equal(committed.json.status, 'completed');
  assert.equal(committed.json.outcomes?.length, 1);
  assert.equal(committed.json.outcomes[0].status, 'executed');
  const replay = await post('/commit', commitBody);
  assert.deepEqual(replay.json, committed.json, 'exact commit replay should return the stored result');
  console.log('Valid receipt commit and exact replay: OK');
  console.log('Live smoke test passed. This used one synthetic proposal and did not use a grader Check.');
}

main().catch(error => { console.error(`Live smoke test failed: ${error.message}`); process.exitCode = 1; });
