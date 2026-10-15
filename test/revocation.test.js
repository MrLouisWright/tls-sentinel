import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { check, parseCert, aiaUrls, crlUrls, mustStaple, sctCount, buildOcspRequest, parseOcspResponse, gradeTarget, negotiate } from '../src/index.js';
import { OID } from '../src/der.js';
import { hasOpenssl } from './pki.js';

const skip = !hasOpenssl() && 'openssl CLI not available';
let d; let ocspPort; const servers = [];
const o = (...a) => execFileSync('openssl', a, { cwd: d, stdio: ['ignore', 'pipe', 'pipe'] });
const der = (pem) => Buffer.from(pem.toString().replace(/-----[^-]+-----|\s/g, ''), 'base64');
const rules = (r) => new Set(r.findings.map((f) => f.rule));
const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => { servers.push(srv); ok(srv.address().port); }));
let certs = {};
function leaf(name, ext) {
  writeFileSync(join(d, `${name}.ext`), `subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:false\n${ext}`);
  o('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=localhost');
  o('x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', '90', '-sha256', '-extfile', `${name}.ext`);
  const serial = o('x509', '-in', `${name}.pem`, '-noout', '-serial').toString().trim().split('=')[1];
  return { key: readFileSync(join(d, `${name}.key`)), cert: readFileSync(join(d, `${name}.pem`)), serial };
}
before(async () => {
  if (skip) return;
  d = mkdtempSync(join(tmpdir(), 'tls-rev-'));
  o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '3650', '-subj', '/CN=Rev CA', '-addext', 'basicConstraints=critical,CA:true', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  // OCSP responder backed by openssl ocsp and an index file
  ocspPort = await listen(http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', () => {
      writeFileSync(join(d, 'req.der'), Buffer.concat(chunks));
      o('ocsp', '-index', 'index.txt', '-rsigner', 'ca.pem', '-rkey', 'ca.key', '-CA', 'ca.pem', '-reqin', 'req.der', '-respout', 'resp.der');
      res.writeHead(200, { 'content-type': 'application/ocsp-response' }); res.end(readFileSync(join(d, 'resp.der')));
    });
  }));
  const aia = `authorityInfoAccess=OCSP;URI:http://127.0.0.1:${ocspPort}/\ncrlDistributionPoints=URI:http://127.0.0.1/ca.crl\n`;
  certs.good = leaf('good', aia); certs.revoked = leaf('revoked', aia); certs.staple = leaf('staple', `${aia}tlsfeature=status_request\n`);
  const exp = '301231000000Z';
  writeFileSync(join(d, 'index.txt'), `V\t${exp}\t\t${certs.good.serial}\tunknown\t/CN=localhost\nR\t${exp}\t261001000000Z\t${certs.revoked.serial}\tunknown\t/CN=localhost\nV\t${exp}\t\t${certs.staple.serial}\tunknown\t/CN=localhost\n`);
  writeFileSync(join(d, 'index.txt.attr'), 'unique_subject = no\n');
});
after(() => servers.forEach((s) => s.close()));
const caList = () => [...tls.rootCertificates, readFileSync(join(d, 'ca.pem'), 'utf8')];
const serveTls = async (c) => { const s = tls.createServer({ ...c }, (x) => x.end()); s.on('tlsClientError', () => {}); return `127.0.0.1:${await listen(s)}`; };

test('DER: AIA, CRL, Must-Staple, SCT extensions', { skip }, () => {
  const pc = parseCert(der(certs.staple.cert));
  assert.deepEqual(aiaUrls(pc.extensions[OID.aia]).ocsp, [`http://127.0.0.1:${ocspPort}/`]);
  assert.deepEqual(crlUrls(pc.extensions[OID.crlDp]), ['http://127.0.0.1/ca.crl']);
  assert.equal(mustStaple(pc.extensions[OID.tlsFeature]), true);
  assert.equal(mustStaple(parseCert(der(certs.good.cert)).extensions[OID.tlsFeature]), false);
  assert.equal(sctCount(undefined), 0);
});
test('OCSP request is accepted by openssl; responses parse good/revoked', { skip }, () => {
  const ca = der(readFileSync(join(d, 'ca.pem')));
  for (const [name, want] of [['good', 'good'], ['revoked', 'revoked']]) {
    writeFileSync(join(d, 'req.der'), buildOcspRequest(der(certs[name].cert), ca));
    assert.match(o('ocsp', '-reqin', 'req.der', '-req_text').toString(), new RegExp(`Serial Number: ${certs[name].serial}`, 'i'));
    o('ocsp', '-index', 'index.txt', '-rsigner', 'ca.pem', '-rkey', 'ca.key', '-CA', 'ca.pem', '-reqin', 'req.der', '-respout', 'resp.der');
    const r = parseOcspResponse(readFileSync(join(d, 'resp.der')));
    assert.equal(r.responseStatus, 'successful'); assert.equal(r.certStatus, want);
    if (want === 'revoked') assert.equal(r.revokedAt, '2026-10-01T00:00:00.000Z');
  }
});
test('--revocation queries OCSP: revoked cert is critical, good is clean', { skip }, async () => {
  const rev = await serveTls(certs.revoked); const good = await serveTls(certs.good);
  const r = await check([rev], { ca: caList(), quick: true, revocation: true });
  assert.ok(rules(r).has('cert-revoked')); assert.equal(r.targets[0].summary.revocation, 'revoked'); assert.equal(r.targets[0].summary.grade, 'F');
  const g = await check([good], { ca: caList(), quick: true, revocation: true });
  assert.ok(!rules(g).has('cert-revoked')); assert.equal(g.targets[0].summary.revocation, 'good');
});
test('Must-Staple without a stapled response', { skip }, async () => {
  const t = await serveTls(certs.staple);
  assert.ok(rules(await check([t], { ca: caList(), quick: true })).has('must-staple-not-stapled'));
});
test('STARTTLS over SMTP, and refusal is reported', { skip }, async () => {
  const smtp = (offer) => net.createServer((sock) => {
    sock.write('220 test ESMTP\r\n');
    sock.on('data', (b) => {
      const l = b.toString();
      if (/^EHLO/.test(l)) sock.write(`250-test\r\n${offer ? '250-STARTTLS\r\n' : ''}250 SIZE 1000\r\n`);
      else if (/^STARTTLS/.test(l)) { sock.removeAllListeners('data'); sock.write('220 go ahead\r\n', () => { const t = new tls.TLSSocket(sock, { isServer: true, key: certs.good.key, cert: certs.good.cert }); t.on('error', () => {}); t.on('secure', () => t.end()); }); }
    });
    sock.on('error', () => {});
  });
  const port = await listen(smtp(true));
  const r = await check([`127.0.0.1:${port}`], { ca: caList(), quick: true, starttls: 'smtp' });
  assert.ok(!rules(r).has('connect-error')); assert.ok(r.targets[0].summary.protocol);
  const port2 = await listen(smtp(false));
  const r2 = await check([`127.0.0.1:${port2}`], { quick: true, starttls: 'smtp', timeout: 3000 });
  assert.ok(rules(r2).has('starttls-failed'));
  await assert.rejects(negotiate('gopher', { host: '127.0.0.1', port: port2 }), /unknown STARTTLS/);
});
test('SSL Labs-style grades', () => {
  assert.equal(gradeTarget([]).grade, 'A');
  assert.equal(gradeTarget([{ rule: 'no-tls13' }]).grade, 'A-');
  assert.equal(gradeTarget([{ rule: 'legacy-protocol', evidence: 'TLSv1,TLSv1.1' }, { rule: 'no-tls13' }]).grade, 'B');
  assert.equal(gradeTarget([{ rule: 'weak-cipher', evidence: '3DES (DES-CBC3-SHA)' }]).grade, 'C');
  assert.equal(gradeTarget([{ rule: 'weak-cipher', evidence: 'RC4 (RC4-SHA)' }]).grade, 'F');
  assert.equal(gradeTarget([{ rule: 'hostname-mismatch' }]).grade, 'M');
  assert.equal(gradeTarget([{ rule: 'self-signed' }, { rule: 'no-tls13' }]).grade, 'T');
  assert.equal(gradeTarget([{ rule: 'weak-key', evidence: 'rsa 1024' }]).grade, 'B');
});
test('--min-grade adds a finding', { skip }, async () => {
  const t = await serveTls(certs.good);
  const r = await check([t], { ca: caList(), quick: true, minGrade: 'A' });
  assert.equal(r.targets[0].summary.grade, 'A'); assert.ok(!rules(r).has('grade-below-minimum'));
  const s = await check([t], { quick: true, minGrade: 'A' });
  assert.ok(rules(s).has('grade-below-minimum'));
});
