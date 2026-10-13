import { readFileSync } from 'node:fs';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { handshake, certInfo, UNTRUSTED } from './tls.js';
import tls from 'node:tls';

export { handshake, certInfo, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'tls-sentinel', version: VERSION, rules: RULES, title: 'tls-sentinel', emoji: '🔒', defaultFailOn: 'high' };

/** "example.com", "example.com:8443", "https://example.com:8443/x", "[::1]:443" -> { host, port } */
export function parseTarget(t) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) { const u = new URL(t); return { host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || (u.protocol === 'https:' ? 443 : NaN) }; }
  const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(t) || /^([^:]+)(?::(\d+))?$/.exec(t);
  if (!m) throw new Error(`cannot parse ${t}`);
  return { host: m[1], port: m[2] ? Number(m[2]) : 443 };
}

const WEAK = { '3DES': 'DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA', RC4: 'RC4-SHA:RC4-MD5:ECDHE-RSA-RC4-SHA', NULL: 'NULL-SHA:NULL-SHA256:ECDHE-RSA-NULL-SHA', EXPORT: 'EXP-RC4-MD5:EXP-DES-CBC-SHA', anonymous: 'ADH-AES128-SHA:AECDH-AES128-SHA:ADH-AES256-GCM-SHA384' };

async function checkOne(target, o) {
  let host, port; try { ({ host, port } = parseTarget(target)); if (!port || port > 65535) throw new Error('bad port'); } catch (e) { return { target, fatal: true, raw: [], errors: [`Invalid target ${target}: ${e.message}`] }; }
  const name = `${host}:${port}`; const base = { host, port, servername: o.servername, timeout: o.timeout ?? 10000, ca: o.ca };
  const raw = []; const add = (rule, message, extra = {}) => raw.push({ rule, location: name, message, ...extra });
  let h = await handshake(base);
  if (!h.ok && /HANDSHAKE_FAILURE|NO_PROTOCOLS|UNSUPPORTED_PROTOCOL|VERSION|CIPHER/i.test(h.error)) { const legacyOnly = await handshake({ ...base, minVersion: 'TLSv1', ciphers: 'ALL:@SECLEVEL=0' }); if (legacyOnly.ok) h = legacyOnly; }
  if (!h.ok) return { target: name, fatal: true, raw: [{ rule: 'connect-error', location: name, message: `TLS handshake with ${name} failed: ${h.error}` }], errors: [`${name}: ${h.error}`] };
  const now = o.now ? new Date(o.now) : new Date();
  const leaf = h.chain[0]; const info = leaf ? certInfo(leaf) : null;
  const summary = { protocol: h.protocol, cipher: h.cipher?.standardName || h.cipher?.name };
  if (info) {
    const days = Math.floor((new Date(info.validTo) - now) / 864e5);
    Object.assign(summary, { subject: info.subject, issuer: info.issuer, validTo: info.validTo, daysLeft: days, key: `${info.keyType} ${info.bits}`, sigAlg: info.sigAlg || undefined, san: info.subjectAltName.slice(0, 300) });
    if (new Date(info.validTo) <= now) add('cert-expired', `Certificate expired ${info.validTo} (${-days} days ago)`, { evidence: info.fingerprint256 });
    else if (new Date(info.validFrom) > now) add('cert-not-yet-valid', `Certificate is valid from ${info.validFrom}`);
    else if (days < (o.criticalDays ?? 14)) add('cert-expiring', `Certificate expires in ${days} days (${info.validTo})`, { evidence: info.validTo });
    else if (days < (o.warnDays ?? 30)) add('cert-expiring-soon', `Certificate expires in ${days} days (${info.validTo})`, { evidence: info.validTo });
    const life = Math.round((new Date(info.validTo) - new Date(info.validFrom)) / 864e5);
    if (life > 398 && !info.selfIssued) add('long-validity', `Certificate lifetime is ${life} days (browsers reject public certs over 398)`);
    const checkName = o.servername || host;
    const err = tls.checkServerIdentity(checkName, { ...leaf, subjectaltname: leaf.subjectaltname });
    if (err) add('hostname-mismatch', `Certificate is for ${info.subjectAltName || info.subject}, not ${checkName}`, { evidence: checkName });
    if ((/^rsa/.test(info.keyType) && info.bits < 2048) || (info.keyType === 'ec' && info.bits < 256)) add('weak-key', `${info.keyType.toUpperCase()} ${info.bits}-bit key`, { evidence: `${info.keyType} ${info.bits}` });
    if (/sha1|md5/i.test(info.sigAlg)) add('weak-signature', `Certificate signed with ${info.sigAlg}`, { evidence: info.sigAlg });
  }
  if (!h.authorized && h.authorizationError && !['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(h.authorizationError)) {
    const r = UNTRUSTED[h.authorizationError] || 'untrusted-chain';
    add(r, r === 'incomplete-chain' ? `Chain could not be built (${h.authorizationError}); the server probably omits intermediate certificates` : `Certificate is not trusted (${h.authorizationError})`, { evidence: h.authorizationError });
  }
  if (h.cipher && h.protocol === 'TLSv1.2' && /CBC|SHA$/i.test(h.cipher.standardName || h.cipher.name) && !/GCM|CHACHA|CCM/i.test(h.cipher.standardName || h.cipher.name)) add('cbc-cipher', `Negotiated ${h.cipher.standardName || h.cipher.name}`);
  if (o.quick) { summary.ocspStapled = h.ocsp; return { target: name, summary, raw }; }
  if (!h.ocsp) add('no-ocsp-stapling', 'Server does not staple an OCSP response');
  // protocol probes
  const legacy = [];
  for (const v of ['TLSv1', 'TLSv1.1']) { const p = await handshake({ ...base, minVersion: v, maxVersion: v, ciphers: 'DEFAULT@SECLEVEL=0' }); if (p.ok && p.protocol === v) legacy.push(v); }
  if (legacy.length) add('legacy-protocol', `Accepts ${legacy.join(' and ')}`, { evidence: legacy.join(',') });
  if (h.protocol !== 'TLSv1.3') { const p = await handshake({ ...base, minVersion: 'TLSv1.3' }); if (!p.ok) add('no-tls13', 'TLS 1.3 is not supported'); }
  summary.protocols = [...legacy, ...(await Promise.all(['TLSv1.2', 'TLSv1.3'].map(async (v) => ((await handshake({ ...base, minVersion: v, maxVersion: v })).ok ? v : null)))).filter(Boolean)];
  const weak = [];
  for (const [k, c] of Object.entries(WEAK)) { const p = await handshake({ ...base, maxVersion: 'TLSv1.2', minVersion: 'TLSv1', ciphers: `${c}@SECLEVEL=0` }); if (p.ok) weak.push(`${k} (${p.cipher?.name})`); }
  if (weak.length) add('weak-cipher', `Accepts ${weak.join(', ')}`, { evidence: weak.join(',') });
  const rsa = await handshake({ ...base, maxVersion: 'TLSv1.2', ciphers: 'kRSA:@SECLEVEL=0' });
  if (rsa.ok) add('no-forward-secrecy', `Accepts static RSA key exchange (${rsa.cipher?.name})`, { evidence: rsa.cipher?.name });
  return { target: name, summary, raw };
}

/** Check TLS endpoints. Options: warnDays, criticalDays, timeout, servername, ca, quick (one handshake only), now, concurrency, allow, severity. */
export async function check(targets, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const out = new Array(targets.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(opts.concurrency || 4, targets.length) }, async () => { while (i < targets.length) { const k = i++; out[k] = await checkOne(targets[k], opts); } }));
  return buildReport(TOOL, out, opts);
}
