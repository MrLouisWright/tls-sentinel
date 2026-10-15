#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';
import { runCli, UsageError } from '../src/cli-core.js';
import { check, TOOL } from '../src/index.js';

const HELP = `tls-sentinel {VERSION} — check TLS endpoints: certificates, trust, protocols and ciphers

Usage: tls-sentinel <host[:port]|https://url> [...] [options]

Each target gets a normal handshake (certificate, chain, name, expiry) plus probes for TLS 1.0/1.1,
TLS 1.3, weak ciphers and static RSA. Only handshakes are made; no application data is sent.

      --warn-days <n>        Medium finding when the certificate expires within n days (default 30)
      --critical-days <n>    High finding within n days (default 14)
      --quick                One handshake only: skip protocol and cipher probes
      --servername <name>    SNI / expected name (default: the target host)
      --ca <file>            Extra trusted CA bundle (PEM), e.g. for internal PKI
      --timeout <ms>         Per-handshake timeout (default 10000)
      --concurrency <n>      Targets checked in parallel (default 4)
      --starttls <proto>     Negotiate STARTTLS first: smtp (587), imap (143), pop3 (110), ftp (21), postgres (5432)
      --revocation           Ask the certificate's OCSP responder when no response is stapled (one HTTP POST)
      --min-grade <g>        Fail when the SSL Labs-style grade is below g (A, A-, B, C, M, T, F)
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { 'warn-days': { type: 'string' }, 'critical-days': { type: 'string' }, quick: { type: 'boolean' }, servername: { type: 'string' }, ca: { type: 'string' }, timeout: { type: 'string' }, concurrency: { type: 'string' }, starttls: { type: 'string' }, revocation: { type: 'boolean' }, 'min-grade': { type: 'string' } },
  async run(o, pos, cfg) {
    const targets = pos.length ? pos : cfg.targets || [];
    if (!targets.length) throw new UsageError('No host given');
    const num = (n) => { const v = o[n] ?? cfg[n.replace(/-(.)/g, (_, c) => c.toUpperCase())]; if (v === undefined) return undefined; const x = Number(v); if (!Number.isFinite(x) || x < 0) throw new UsageError(`--${n} must be a number`); return x; };
    let ca; const caPath = o.ca || cfg.ca; if (caPath) { try { ca = [...rootCertificates, readFileSync(caPath, 'utf8')]; } catch (e) { throw new UsageError(`Cannot read --ca ${caPath}: ${e.code || e.message}`); } }
    return check(targets, { warnDays: num('warn-days'), criticalDays: num('critical-days'), quick: o.quick ?? cfg.quick, servername: o.servername, ca, timeout: num('timeout'), concurrency: num('concurrency'), allow: cfg.allow, severity: cfg.severity, starttls: o.starttls || cfg.starttls, revocation: o.revocation ?? cfg.revocation, minGrade: o['min-grade'] || cfg.minGrade });
  },
});
