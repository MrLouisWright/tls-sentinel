// SSL Labs-style grade from findings. HSTS is header-sentinel's job, so the top grade here is A (not A+).
export const GRADES = ['A', 'A-', 'B', 'C', 'M', 'T', 'F'];
const CAPS = {
  'cert-expired': 'T', 'cert-not-yet-valid': 'T', 'untrusted-chain': 'T', 'self-signed': 'T', 'weak-signature': 'T', 'cert-revoked': 'F', 'hostname-mismatch': 'M',
  'legacy-protocol': 'B', 'no-forward-secrecy': 'B', 'incomplete-chain': 'B', 'no-tls13': 'A-', 'must-staple-not-stapled': 'B',
};
/** Grade a target from its findings (and summary). Returns { grade, reasons }. */
export function gradeTarget(findings, summary = {}) {
  let worst = 0; const reasons = [];
  const cap = (g, why) => { const i = GRADES.indexOf(g); if (i > worst) worst = i; reasons.push(`${g}: ${why}`); };
  for (const f of findings) {
    if (f.rule === 'weak-cipher') { if (/RC4|NULL|EXPORT|anonymous/.test(f.evidence || f.message)) cap('F', 'RC4/NULL/EXPORT/anonymous ciphers'); else cap('C', '3DES ciphers'); continue; }
    if (f.rule === 'weak-key') { const bits = Number(/(\d+)/.exec(f.evidence || '')?.[1] || 0); cap(bits && bits < 1024 ? 'F' : 'B', `weak key (${f.evidence})`); continue; }
    if (f.rule === 'legacy-protocol' && /TLSv1(,|$)/.test(f.evidence || '') && !/1\.1/.test(f.evidence || '')) { cap('B', 'TLS 1.0'); continue; }
    if (CAPS[f.rule]) cap(CAPS[f.rule], f.rule);
  }
  if (summary.protocols && !summary.protocols.includes('TLSv1.2') && !summary.protocols.includes('TLSv1.3')) cap('F', 'no TLS 1.2 or 1.3');
  return { grade: GRADES[worst], reasons };
}
export const gradeRank = (g) => GRADES.indexOf(g);
