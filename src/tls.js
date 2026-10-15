import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { negotiate } from './starttls.js';

const UNTRUSTED = { DEPTH_ZERO_SELF_SIGNED_CERT: 'self-signed', SELF_SIGNED_CERT_IN_CHAIN: 'self-signed', UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'incomplete-chain', UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'incomplete-chain', UNABLE_TO_GET_ISSUER_CERT: 'untrusted-chain', CERT_UNTRUSTED: 'untrusted-chain', CERT_REVOKED: 'untrusted-chain' };
export { UNTRUSTED };

/** One TLS handshake. Never sends application data. Resolves { ok, protocol, cipher, authorized, authorizationError, chain, ocsp } or { ok:false, error }. */
export async function handshake(o) {
  if (!o.starttls) return tlsHandshake(o);
  let socket; try { socket = await negotiate(o.starttls, o); } catch (e) { return { ok: false, error: `STARTTLS (${o.starttls}): ${e.code || e.message}`, code: e.code, starttlsFailed: true }; }
  return tlsHandshake({ ...o, socket });
}
function tlsHandshake({ host, port = 443, servername, timeout = 10000, ca, minVersion, maxVersion, ciphers, socket, starttls }) {
  return new Promise((resolve) => {
    let done = false; let ocsp = null; let timer;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); try { sock.destroy(); } catch {} resolve(r); };
    const sni = servername ?? (/^[\d.]+$|:/.test(host) ? undefined : host);
    let sock;
    try { sock = tls.connect({ host, port, servername: sni, rejectUnauthorized: false, requestOCSP: true, ca, minVersion, maxVersion, ciphers, ...(socket ? { socket } : {}), ...(starttls ? {} : { ALPNProtocols: ['http/1.1'] }) }); }
    catch (e) { done = true; return resolve({ ok: false, error: e.code || e.message, code: e.code, unsupported: true }); }
    timer = setTimeout(() => finish({ ok: false, error: `timeout after ${timeout} ms` }), timeout);
    sock.on('OCSPResponse', (r) => { ocsp = r; });
    sock.once('secureConnect', () => {
      const chain = []; let c = sock.getPeerCertificate(true); const seen = new Set();
      while (c && c.raw && !seen.has(c.fingerprint256)) { seen.add(c.fingerprint256); chain.push(c); c = c.issuerCertificate; }
      finish({ ok: true, protocol: sock.getProtocol(), cipher: sock.getCipher(), authorized: sock.authorized, authorizationError: sock.authorizationError ? String(sock.authorizationError.code || sock.authorizationError) : null, chain, ocsp: ocsp && ocsp.length ? true : false, ocspResponse: ocsp && ocsp.length ? ocsp : null });
    });
    sock.once('error', (e) => finish({ ok: false, error: e.code || e.message, code: e.code }));
  });
}

/** Facts about a peer certificate object from getPeerCertificate(). */
export function certInfo(c) {
  const x = new X509Certificate(c.raw);
  const keyType = x.publicKey.asymmetricKeyType; const det = x.publicKey.asymmetricKeyDetails || {};
  const bits = keyType === 'rsa' || keyType === 'rsa-pss' ? det.modulusLength : keyType === 'ec' ? ({ prime256v1: 256, secp384r1: 384, secp521r1: 521, secp224r1: 224, secp192r1: 192, 'P-256': 256, 'P-384': 384, 'P-521': 521 })[det.namedCurve] ?? 0 : keyType === 'ed25519' ? 256 : keyType === 'ed448' ? 448 : det.modulusLength;
  let sigAlg = '';
  try { const der = c.raw; const hex = der.toString('hex'); const m = /06092a864886f70d0101(..)/.exec(hex); const map = { '04': 'md5WithRSA', '05': 'sha1WithRSA', '0b': 'sha256WithRSA', '0c': 'sha384WithRSA', '0d': 'sha512WithRSA', '0a': 'rsassaPss' }; if (m) sigAlg = map[m[1]] || ''; else if (/06082a8648ce3d0403(..)/.test(hex)) sigAlg = { '02': 'ecdsa-with-SHA256', '03': 'ecdsa-with-SHA384', '04': 'ecdsa-with-SHA512' }[/06082a8648ce3d0403(..)/.exec(hex)[1]] || 'ecdsa'; else if (/06072a8648ce3d0401/.test(hex)) sigAlg = 'ecdsa-with-SHA1'; } catch {}
  return {
    subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), subjectAltName: x.subjectAltName || '',
    validFrom: new Date(x.validFrom).toISOString(), validTo: new Date(x.validTo).toISOString(), serial: x.serialNumber,
    fingerprint256: x.fingerprint256, keyType, bits, sigAlg, selfIssued: x.subject === x.issuer, x509: x,
  };
}
