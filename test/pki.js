// Test-only PKI generated at runtime with the openssl CLI (nothing secret is committed).
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function hasOpenssl() { try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; } }
export function makePki() {
  const d = mkdtempSync(join(tmpdir(), 'tls-sentinel-'));
  const o = (...a) => execFileSync('openssl', a, { cwd: d, stdio: ['ignore', 'ignore', 'pipe'] });
  o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '3650', '-subj', '/CN=Test CA', '-addext', 'basicConstraints=critical,CA:true', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  const leaf = (name, { bits = 2048, md = 'sha256', days = 90, san = 'DNS:localhost,IP:127.0.0.1' } = {}) => {
    writeFileSync(join(d, `${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:false\n`);
    o('req', '-newkey', `rsa:${bits}`, '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', '/CN=localhost');
    o('x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', String(days), `-${md}`, '-extfile', `${name}.ext`);
    return { key: readFileSync(join(d, `${name}.key`)), cert: readFileSync(join(d, `${name}.pem`)) };
  };
  o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'self.key', '-out', 'self.pem', '-days', '30', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1');
  return {
    ca: readFileSync(join(d, 'ca.pem'), 'utf8'),
    good: leaf('good'), weak: leaf('weak', { bits: 1024, md: 'sha1', days: 800 }),
    self: { key: readFileSync(join(d, 'self.key')), cert: readFileSync(join(d, 'self.pem')) },
  };
}
