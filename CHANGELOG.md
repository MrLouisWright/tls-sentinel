# Changelog

## 1.0.0 - 2026-10-14

### Added before first publish

- Revocation: stapled OCSP responses are parsed (`cert-revoked`). `--revocation` asks the certificate's OCSP responder when nothing is stapled, with one HTTP POST and an OCSP request built in-house; the response signature is not verified. Also new: `must-staple-not-stapled`, `no-revocation-info` (no OCSP URL or CRL DP) and `ocsp-error`.
- Certificate Transparency: `no-sct` for publicly trusted certificates without embedded SCTs. The SCT count, OCSP URL and CRL are added to the summary.
- STARTTLS: `--starttls smtp|imap|pop3|ftp|postgres` (default ports 587/143/110/21/5432), as testssl does. It runs the same certificate, protocol and cipher checks; `starttls-failed` when the server refuses.
- SSL Labs-style grade (`A`, `A-`, `B`, `C`, `M`, `T`, `F`) in each target's summary, with reasons. `--min-grade <g>` fails below it (`grade-below-minimum`). The top grade is A, because A+ needs HSTS and HSTS stays in header-sentinel.
- Small DER helpers exported: `parseCert`, `aiaUrls`, `crlUrls`, `sctCount`, `mustStaple`, `buildOcspRequest`, `parseOcspResponse`.

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

- First release: TLS endpoint checker with 18 rules covering certificate expiry, trust, host name, chain completeness, key size, signature algorithm, TLS 1.0/1.1, TLS 1.3 support, weak and non-forward-secret ciphers and OCSP stapling. `--quick` mode for expiry monitoring, `--ca` for internal PKI.
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
