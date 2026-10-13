import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import { check, parseTarget, exitCode } from '../src/index.js';
import { hasOpenssl, makePki } from './pki.js';

const skip = !hasOpenssl() && 'openssl CLI not available';
let pki; const servers = [];
const serve = (opts) => new Promise((ok) => { const s = tls.createServer(opts, (c) => c.end()); s.on('tlsClientError', () => {}); s.listen(0, '127.0.0.1', () => ok(`localhost:${s.address().port}`)); servers.push(s); });
const rules = (r) => new Set(r.findings.map((f) => f.rule));
let good, legacy, weak, self;
before(async () => {
  if (skip) return;
  pki = makePki();
  good = await serve({ ...pki.good, minVersion: 'TLSv1.2' });
  legacy = await serve({ ...pki.good, minVersion: 'TLSv1', maxVersion: 'TLSv1.2', ciphers: 'ALL:@SECLEVEL=0' });
  weak = await serve({ ...pki.weak, ciphers: 'DEFAULT:@SECLEVEL=0' });
  self = await serve(pki.self);
});
after(() => servers.forEach((s) => s.close()));
const ca = () => [...tls.rootCertificates, pki.ca];

test('parseTarget', () => {
  assert.deepEqual(parseTarget('example.com'), { host: 'example.com', port: 443 });
  assert.deepEqual(parseTarget('example.com:8443'), { host: 'example.com', port: 8443 });
  assert.deepEqual(parseTarget('https://example.com:9443/x'), { host: 'example.com', port: 9443 });
  assert.deepEqual(parseTarget('[::1]:8443'), { host: '::1', port: 8443 });
});
test('healthy endpoint', { skip }, async () => {
  const r = await check([good], { ca: ca() });
  const s = rules(r);
  for (const k of ['untrusted-chain', 'self-signed', 'hostname-mismatch', 'cert-expired', 'legacy-protocol', 'weak-key', 'no-tls13']) assert.ok(!s.has(k), k);
  assert.equal(r.targets[0].summary.protocol, 'TLSv1.3');
  assert.equal(exitCode(r, 'high'), 0);
});
test('untrusted without the CA', { skip }, async () => { assert.ok(rules(await check([good], { quick: true })).has('incomplete-chain') || rules(await check([good], { quick: true })).has('untrusted-chain')); });
test('self-signed', { skip }, async () => { assert.ok(rules(await check([self], { quick: true })).has('self-signed')); });
test('hostname mismatch', { skip }, async () => { assert.ok(rules(await check([good], { ca: ca(), servername: 'other.example', quick: true })).has('hostname-mismatch')); });
test('expiry windows via now', { skip }, async () => {
  const day = 864e5;
  assert.ok(rules(await check([good], { ca: ca(), quick: true, now: new Date(Date.now() + 200 * day) })).has('cert-expired'));
  assert.ok(rules(await check([good], { ca: ca(), quick: true, now: new Date(Date.now() + 80 * day) })).has('cert-expiring'));
  assert.ok(rules(await check([good], { ca: ca(), quick: true, now: new Date(Date.now() + 65 * day) })).has('cert-expiring-soon'));
  assert.ok(rules(await check([good], { ca: ca(), quick: true, now: new Date(Date.now() - 2 * day) })).has('cert-not-yet-valid'));
});
test('weak key, SHA-1 signature, long validity', { skip }, async () => {
  const s = rules(await check([weak], { ca: ca(), quick: true }));
  for (const k of ['weak-key', 'weak-signature', 'long-validity']) assert.ok(s.has(k), k);
});
test('legacy protocols and no TLS 1.3', { skip }, async () => {
  const r = await check([legacy], { ca: ca() });
  const s = rules(r);
  assert.ok(s.has('no-tls13'));
  // TLS 1.0/1.1 detection depends on the local OpenSSL build allowing them at SECLEVEL=0
  const probe = await new Promise((ok) => { const c = tls.connect({ host: '127.0.0.1', port: Number(legacy.split(':')[1]), minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0', rejectUnauthorized: false }, () => { c.destroy(); ok(true); }); c.on('error', () => ok(false)); });
  if (probe) { assert.ok(s.has('legacy-protocol')); assert.ok(s.has('weak-cipher')); assert.ok(s.has('no-forward-secrecy')); }
  assert.ok(s.has('cbc-cipher') || r.targets[0].summary.cipher);
});
test('connect error is fatal (exit 2)', async () => {
  const s = net.createServer(); await new Promise((ok) => s.listen(0, '127.0.0.1', ok)); const port = s.address().port; await new Promise((ok) => s.close(ok));
  const r = await check([`127.0.0.1:${port}`], { timeout: 2000 }); assert.equal(exitCode(r, 'high'), 2); assert.equal(r.findings[0].rule, 'connect-error');
});
test('allowlist and severity override', { skip }, async () => {
  const r = await check([self], { quick: true, allow: [{ rule: 'self-signed', target: 'localhost:*', reason: 'dev' }], severity: { 'long-validity': 'off' } });
  assert.ok(!rules(r).has('self-signed')); assert.equal(r.suppressed.length, 1);
});
test('CLI', { skip }, async () => {
  const bin = new URL('../bin/tls-sentinel.js', import.meta.url).pathname;
  const run = (args) => new Promise((ok) => { const p = require_spawn(bin, args); ok(p); });
  for (const f of ['json', 'sarif', 'markdown', 'text']) { const p = await run([self, '--quick', '-f', f]); assert.equal(p.status, 1, f); assert.ok(p.stdout.length); }
  assert.equal((await run([])).status, 2);
  assert.equal((await run([self, '--timeout', 'x'])).status, 2);
});
import { spawn } from 'node:child_process';
function require_spawn(bin, args) { return new Promise((ok) => { const p = spawn(process.execPath, [bin, ...args]); let out = ''; p.stdout.on('data', (d) => { out += d; }); p.on('close', (status) => ok({ status, stdout: out })); }); }
