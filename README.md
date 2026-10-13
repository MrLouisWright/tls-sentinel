# tls-sentinel

> Check TLS endpoints for expiring or untrusted certificates, hostname mismatches, missing intermediates, weak keys and signatures, TLS 1.0/1.1, weak ciphers and missing TLS 1.3.

`tls-sentinel` connects to each `host[:port]`, inspects the certificate chain the server sends, and probes which protocol versions and cipher families it accepts. It uses Node's own TLS stack, so there is no `openssl` binary or external service involved, and it only performs handshakes (no HTTP request is sent), so it works for any TLS service: HTTPS, SMTPS, IMAPS, LDAPS, databases. CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**.

```
$ tls-sentinel example.com mail.example.com:993 --warn-days 21
```

## What it checks

- **Certificate**: expired, not yet valid, expiring within `--critical-days` (default 14, high) or `--warn-days` (default 30, medium), host name not covered, self-signed, chain not trusted, intermediates missing, RSA < 2048 / EC < 256 bits, SHA-1/MD5 signatures, lifetimes over 398 days, no OCSP stapling.
- **Protocols and ciphers**: accepts TLS 1.0 or 1.1, no TLS 1.3, accepts 3DES/RC4/NULL/EXPORT/anonymous suites, accepts static-RSA key exchange (no forward secrecy), negotiates CBC on TLS 1.2.

Probe results depend on what the local OpenSSL can still offer: OpenSSL 3 (Node 18+) has dropped RC4 and EXPORT suites, so a server that *only* accepts those shows up as a `connect-error`. Use `--quick` to skip the probes and make one handshake per target (good for frequent expiry monitoring). Unreachable targets exit with code 2. `--ca` adds an internal CA bundle on top of Node's root store.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `cert-expired` | critical | Certificate has expired |
| `cert-not-yet-valid` | critical | Certificate is not valid yet |
| `hostname-mismatch` | critical | Certificate does not cover the host name |
| `untrusted-chain` | critical | Chain does not lead to a trusted root |
| `self-signed` | critical | Self-signed certificate |
| `incomplete-chain` | high | Server does not send the intermediate certificates |
| `cert-expiring` | high | Certificate expires within the critical window (default 14 days) |
| `cert-expiring-soon` | medium | Certificate expires within the warning window (default 30 days) |
| `weak-key` | high | RSA key < 2048 bits or EC key < 256 bits |
| `weak-signature` | high | Certificate signed with SHA-1 or MD5 |
| `legacy-protocol` | high | Server accepts TLS 1.0 or TLS 1.1 |
| `weak-cipher` | high | Server accepts 3DES, RC4, NULL, EXPORT or anonymous ciphers |
| `no-forward-secrecy` | low | Server accepts static-RSA key exchange (no forward secrecy) |
| `cbc-cipher` | low | Server prefers a CBC-mode cipher on TLS 1.2 |
| `no-tls13` | low | TLS 1.3 is not supported |
| `long-validity` | low | Certificate lifetime is longer than 398 days |
| `no-ocsp-stapling` | info | No OCSP response stapled |
| `connect-error` | high | Could not connect or complete a TLS handshake |

## Install and run

```bash
npx tls-sentinel example.com www.example.com:443 api.example.com:8443
npx tls-sentinel internal.corp:636 --ca corp-root.pem --quick --warn-days 45
npx tls-sentinel https://example.com --format sarif > tls.sarif
```

Run it on a schedule (for example a daily GitHub Actions cron) to catch expiring certificates.

## Library

```js
import { check, exitCode } from 'tls-sentinel';
const report = await check(['example.com'], { quick: true, warnDays: 21 });
console.log(report.targets[0].summary.daysLeft);
process.exitCode = exitCode(report, 'high');
```

## Configuration

Put a `.tls-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "no-tls13": "high" },
  "allow": [
    { "rule": "no-tls13", "match": "legacy.example.com*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `no-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/tls-sentinel@v1
    with:
      targets: 'example.com'
      fail-on: high
      sarif: tls-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: tls-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `warn-days`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## License

MIT © Louis Wright
