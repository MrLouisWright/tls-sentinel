# Changelog

## 1.0.0 - 2026-10-14

- First release: TLS endpoint checker with 18 rules covering certificate expiry, trust, host name, chain completeness, key size, signature algorithm, TLS 1.0/1.1, TLS 1.3 support, weak and non-forward-secret ciphers and OCSP stapling. `--quick` mode for expiry monitoring, `--ca` for internal PKI.
- Text, JSON, SARIF and Markdown output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
