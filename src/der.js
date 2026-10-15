// Minimal DER reader/writer: enough for X.509 extensions, OCSP requests and responses.
export function readTlv(buf, off = 0) {
  const tag = buf[off]; let len = buf[off + 1]; let hdr = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i]; hdr = 2 + n; }
  return { tag, len, hdr, start: off, valueStart: off + hdr, end: off + hdr + len, value: buf.subarray(off + hdr, off + hdr + len), raw: buf.subarray(off, off + hdr + len) };
}
export function children(tlv) { const out = []; let o = 0; const v = tlv.value; while (o < v.length) { const c = readTlv(v, o); out.push(c); o = c.end; } return out; }
const encLen = (n) => { if (n < 128) return Buffer.from([n]); const b = []; while (n) { b.unshift(n & 0xff); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); };
export const tlv = (tag, ...parts) => { const v = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), encLen(v.length), v]); };
export const seq = (...p) => tlv(0x30, ...p);
export const oidHex = (hex) => tlv(0x06, Buffer.from(hex, 'hex'));

/** Pieces of a certificate needed for OCSP and extension checks. */
export function parseCert(der) {
  const cert = readTlv(der); const [tbs] = children(cert); const t = children(tbs);
  let i = t[0].tag === 0xa0 ? 1 : 0;
  const serial = t[i]; const issuer = t[i + 2]; const subject = t[i + 4]; const spki = t[i + 5];
  const ext = t.find((x) => x.tag === 0xa3);
  const extensions = {};
  if (ext) for (const e of children(children(ext)[0])) { const parts = children(e); const oid = parts[0].value.toString('hex'); const critical = parts.length === 3 && parts[1].tag === 0x01 && parts[1].value[0] !== 0; extensions[oid] = { critical, value: parts[parts.length - 1].value }; }
  const bitString = children(spki)[1];
  return { serial: serial.value, serialTlv: serial.raw, issuerDer: issuer.raw, subjectDer: subject.raw, publicKeyBits: bitString.value.subarray(1), extensions };
}

export const OID = {
  sct: '2b06010401d679020402', // 1.3.6.1.4.1.11129.2.4.2 embedded SCT list
  aia: '2b06010505070101', // authorityInfoAccess
  ocsp: '2b06010505073001', // id-ad-ocsp
  caIssuers: '2b06010505073002',
  crlDp: '551d1f', // cRLDistributionPoints
  tlsFeature: '2b06010505070118', // 1.3.6.1.5.5.7.1.24 (OCSP Must-Staple)
  basicOcsp: '2b0601050507300101',
  sha1: '2b0e03021a',
};

/** URLs from authorityInfoAccess: { ocsp: [...], caIssuers: [...] } */
export function aiaUrls(ext) {
  const out = { ocsp: [], caIssuers: [] }; if (!ext) return out;
  for (const ad of children(readTlv(ext.value))) { const [m, loc] = children(ad); const k = m.value.toString('hex'); if (loc.tag === 0x86) (k === OID.ocsp ? out.ocsp : k === OID.caIssuers ? out.caIssuers : []).push(loc.value.toString('latin1')); }
  return out;
}
export function crlUrls(ext) { if (!ext) return []; return [...ext.value.toString('latin1').matchAll(/https?:\/\/[\x21-\x7e]+?\.crl/g)].map((m) => m[0]); }
/** Count of SCTs in the embedded SCT list extension. */
export function sctCount(ext) {
  if (!ext) return 0; const inner = readTlv(ext.value).value; if (inner.length < 2) return 0;
  const total = inner.readUInt16BE(0); let o = 2; let n = 0;
  while (o + 2 <= Math.min(inner.length, total + 2)) { const l = inner.readUInt16BE(o); o += 2 + l; n++; }
  return n;
}
export function mustStaple(ext) { if (!ext) return false; return children(readTlv(ext.value)).some((c) => c.tag === 0x02 && c.value.length === 1 && c.value[0] === 5); }
