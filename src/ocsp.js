// OCSP: build a request, read a response's certificate status (the response signature is not verified).
import { createHash } from 'node:crypto';
import { parseCert, readTlv, children, seq, tlv, oidHex, OID } from './der.js';

export function buildOcspRequest(leafDer, issuerDer) {
  const leaf = parseCert(leafDer); const issuer = parseCert(issuerDer);
  const nameHash = createHash('sha1').update(leaf.issuerDer).digest();
  const keyHash = createHash('sha1').update(issuer.publicKeyBits).digest();
  const certId = seq(seq(oidHex(OID.sha1), Buffer.from([0x05, 0x00])), tlv(0x04, nameHash), tlv(0x04, keyHash), leaf.serialTlv);
  return seq(seq(seq(seq(certId))));
}

const STATUS = ['successful', 'malformedRequest', 'internalError', 'tryLater', '(unused)', 'sigRequired', 'unauthorized'];
const time = (t) => { const s = t.value.toString('latin1'); const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/.exec(s); return m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString() : null; };

/** Parse an OCSPResponse (DER). Returns { responseStatus, certStatus: good|revoked|unknown, thisUpdate, nextUpdate, revokedAt }. */
export function parseOcspResponse(der) {
  const top = children(readTlv(der));
  const responseStatus = STATUS[top[0].value[0]] || String(top[0].value[0]);
  if (responseStatus !== 'successful' || !top[1]) return { responseStatus };
  const rb = children(children(top[1])[0]); if (rb[0].value.toString('hex') !== OID.basicOcsp) return { responseStatus, error: 'not a basic OCSP response' };
  const basic = readTlv(rb[1].value); const tbs = children(basic)[0]; const parts = children(tbs);
  const responses = parts.find((p) => p.tag === 0x30);
  const single = children(responses)[0]; const s = children(single);
  const st = s[1]; const certStatus = st.tag === 0x80 ? 'good' : (st.tag & 0x1f) === 1 ? 'revoked' : 'unknown';
  const revokedAt = certStatus === 'revoked' ? time(children(st)[0]) : undefined;
  const next = s.find((x) => x.tag === 0xa0);
  return { responseStatus, certStatus, thisUpdate: time(s[2]), nextUpdate: next ? time(children(next)[0]) : null, ...(revokedAt ? { revokedAt } : {}) };
}

/** Ask the responder (HTTP POST, application/ocsp-request). */
export async function queryOcsp(url, leafDer, issuerDer, { timeout = 10000, fetchImpl = globalThis.fetch } = {}) {
  const body = buildOcspRequest(leafDer, issuerDer);
  const r = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/ocsp-request', accept: 'application/ocsp-response' }, body, signal: AbortSignal.timeout(timeout) });
  if (!r.ok) throw new Error(`OCSP responder returned HTTP ${r.status}`);
  return parseOcspResponse(Buffer.from(await r.arrayBuffer()));
}
