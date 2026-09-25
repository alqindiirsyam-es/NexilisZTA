'use strict';
// node verify-backend.js <compiled Swift test binary> <ServerZTAiOS directory>
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { createRequire } = require('node:module');
const http = require('node:http');
const net = require('node:net');
const [binary, serverDir] = process.argv.slice(2);
assert.ok(binary && serverDir, 'usage: node verify-backend.js <Swift binary> <ServerZTAiOS>');
const backendRequire = createRequire(path.join(path.resolve(serverDir), 'zta-server-ios.js'));
const { createRilEnrollment } = backendRequire('./ril-enrollment');
const { createRilVerifier } = backendRequire('./ril-verifier');
const { createReplayStore } = backendRequire('./ril-replay-store');
const { createRilRelyingParty } = backendRequire('./ril-relying-party');
const express = backendRequire('express');
const output = execFileSync(binary, { encoding: 'utf8', timeout: 30000 });
const marker = output.indexOf('RIL_FIXTURES:');
assert.ok(marker >= 0);
console.log(output.slice(0, marker).trim());
const fixture = JSON.parse(output.slice(marker + 'RIL_FIXTURES:'.length));
const canonical = object => '{' + Object.keys(object).sort().map(k => JSON.stringify(k) + ':' + JSON.stringify(object[k])).join(',') + '}';
assert.equal(fixture.canonicalJSON, canonical({ path: 'a/b\n\x01é\u2028', quote: '"\\', timestamp_ms: 1 }));
const core = fixture.core;
const signature = Buffer.from(core.headers.Signature.slice(6, -1), 'base64');
const publicKey = crypto.createPublicKey({ key: Buffer.from(core.publicKeySPKI, 'base64'), format: 'der', type: 'spki' });
assert.ok(crypto.verify('sha256', Buffer.from(core.signatureBase), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ril-swift-node-'));
async function main() {
  const enrollment = fixture.enrollment;
  const context = enrollment.challenge;
  const app = { appId: context.app_id, bundleId: context.bundle_id, env: context.environment, tenantId: null };
  const registrations = new Map([[context.key_id, { appId: context.app_id, counter: 0, publicKeyPem: enrollment.appAttestPublicKey }]]);
  const service = createRilEnrollment({ storeDir: dir, origin: context.origin, isDev: false,
    registrations, getApp: () => app, getTenant: () => null, isAppUsable: () => true, isRevoked: () => false,
    now: () => context.server_epoch_ms,
    authorizeSession: req => {
      assert.equal(req.get('X-Nexilis-ZTA-Session'), 'test-session');
      return { token: 'test-session', record: { keyId: context.key_id } };
    },
    sessionForDigest: digest => digest === crypto.createHash('sha256').update('test-session').digest('base64url')
      ? { keyId: context.key_id } : null });
  const req = { rawHeaders: ['X-Nexilis-ZTA-Session', 'test-session', 'Content-Type', 'application/json'],
    body: enrollment.body, get: name => ({ 'x-nexilis-zta-session': 'test-session', 'content-type': 'application/json' })[name.toLowerCase()] };
  function invoke(handler) {
    const res = { set() { return this; }, status(value) { this.code = value; return this; }, json(value) { this.body = value; } };
    handler(req, res); return res;
  }
  // Only control challenge entropy for this isolated fixture, restore functions immediately.
  const randomUUID = crypto.randomUUID, randomBytes = crypto.randomBytes;
  let challenge;
  try {
    crypto.randomUUID = () => context.nonce_id;
    crypto.randomBytes = size => { assert.equal(size, 32); return Buffer.from(context.nonce, 'base64'); };
    challenge = invoke(service.challenge);
  } finally { crypto.randomUUID = randomUUID; crypto.randomBytes = randomBytes; }
  assert.equal(challenge.code, 200);
  const result = invoke(service.enroll);
  assert.equal(result.code, 200, JSON.stringify(result.body));
  assert.equal(result.body.status, 'enrolled');
  assert.equal(invoke(service.enroll).body.error, 'RIL_CHALLENGE_INVALID');

  createReplayStore({ storeDir: dir, now: () => context.server_epoch_ms - 65000 });
  const appHTTP = express();
  appHTTP.use(createRilVerifier({ storeDir: dir, origin: context.origin,
    policyJSON: JSON.stringify({ [context.app_id]: { 'GET /zta/security-pack': 'enforce', 'POST /zta/telemetry/events': 'enforce' } }),
    applicationForRequest: service.applicationForRequest, resolveKey: service.resolveKey,
    now: () => context.server_epoch_ms, audit() {} }));
  appHTTP.get('/zta/security-pack', (_req, res) => res.json({ ok: true }));
  appHTTP.post('/zta/telemetry/events', (_req, res) => res.json({ ok: true }));
  function send(tamper = false, post = false) {
    return new Promise((resolve, reject) => {
      const incoming = new http.IncomingMessage(new net.Socket());
      const payload = post ? fixture.pilotPost : fixture.clientRequest;
      const body = post ? Buffer.from(payload.body, 'base64') : Buffer.alloc(0);
      if (post && tamper) body[0] ^= 1;
      incoming.method = post ? 'POST' : 'GET';
      incoming.url = post ? '/zta/telemetry/events' : '/zta/security-pack' + (tamper ? '?changed=1' : '');
      incoming.headers = Object.fromEntries(Object.entries(payload.headers).map(([k, v]) => [k.toLowerCase(), v]));
      incoming.headers.host = 'zta.example'; incoming.headers['content-length'] = String(body.length);
      incoming.rawHeaders = Object.entries(incoming.headers).flat();
      const response = new http.ServerResponse(incoming);
      const timeout = setTimeout(() => reject(new Error('HTTP fixture timed out')), 2000);
      response.end = data => { clearTimeout(timeout); resolve({ code: response.statusCode, body: JSON.parse(String(data)) }); };
      appHTTP.handle(incoming, response, error => { clearTimeout(timeout); reject(error || new Error('route missing')); });
      if (body.length) incoming.push(body);
      incoming.push(null);
    });
  }
  assert.equal((await send(true)).body.error, 'RIL_INVALID_SIGNATURE');
  assert.equal((await send()).code, 200);
  assert.equal((await send()).body.error, 'RIL_REPLAY');
  assert.equal((await send(true, true)).body.error, 'RIL_DIGEST_MISMATCH');
  assert.equal((await send(false, true)).code, 200);
  assert.equal((await send(false, true)).body.error, 'RIL_REPLAY');
  // Relying backend: what a guard in front of https://api.example forwards to /zta/ril/verify.
  const secret = 'relying-party-secret-0123456789';
  const rp = createRilRelyingParty({ storeDir: dir, now: () => context.server_epoch_ms, audit() {},
    relyingPartiesJSON: JSON.stringify({ api: { secret_sha256: crypto.createHash('sha256').update(secret).digest('hex'),
      origins: ['https://api.example'], app_ids: [context.app_id] } }), resolveKeyForBinding: service.resolveKeyForBinding });
  const relying = fixture.relying, headers = relying.headers;
  const relyingBody = Buffer.from(relying.body, 'base64');
  function verify(changes = {}) {
    const url = new URL(relying.url);
    const body = { method: 'POST', authority: url.host, path: url.pathname, query: url.search || '?',
      content_type: headers['Content-Type'], content_digest: headers['Content-Digest'],
      body_sha256: crypto.createHash('sha256').update(relyingBody).digest('base64'),
      signature_input: headers['Signature-Input'], signature: headers.Signature,
      binding: headers['X-Nexilis-ZTA-Binding'], ...changes };
    const values = { authorization: 'Bearer ' + secret, 'x-nexilis-ril-relying-party': 'api' };
    const res = { set() { return this; }, status(value) { this.code = value; return this; }, json(value) { this.body = value; } };
    rp.handler({ body, get: name => values[name.toLowerCase()] }, res);
    return res;
  }
  assert.equal(headers['X-Nexilis-ZTA-Session'], undefined);
  assert.equal(verify({ body_sha256: crypto.createHash('sha256').update('other').digest('base64') }).body.error, 'RIL_DIGEST_MISMATCH');
  assert.equal(verify({ path: '/v1/other' }).body.error, 'RIL_INVALID_SIGNATURE');
  const verified = verify();
  assert.equal(verified.code, 200, JSON.stringify(verified.body));
  assert.equal(verified.body.app_id, context.app_id);
  assert.equal(verify().body.error, 'RIL_REPLAY');
  console.log('Swift → Node: canonical JSON, P1363/SPKI, enrollment/App Attest fixture, signed GET/POST, relying-backend verification, tampering and replay checks passed.');
}
main().catch(error => { console.error(error); process.exitCode = 1; })
  .finally(() => fs.rmSync(dir, { recursive: true, force: true }));
