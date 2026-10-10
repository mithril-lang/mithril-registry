# Flame Sword observation contract

## Input shape

Both analysis operations accept the same JSON object:

```json
{
  "domain": "example.com",
  "subdomains": [
    {"subdomain": "www.example.com", "http_status": 301, "https_status": 200},
    {"subdomain": "admin.example.com", "https_status": 403},
    {"subdomain": "staging.example.com", "http_status": 200}
  ]
}
```

Rules (mirrors the browser worker's `analysis.py` validation):

- `domain` is a required string, at most 253 characters, matching the
  standard hostname label pattern.
- `subdomains` is a required array of at most 500 objects; each
  `subdomain` entry must be a hostname that equals the domain or ends
  with `.domain` (compared case-insensitively; extra keys are dropped,
  and the canonical form is lower-cased).
- `http_status` / `https_status` are integers 100-599 or null (absent
  and null normalize to null). Booleans and numbers are rejected.
- The raw request body is bounded to 32 KiB by the CLI
  (`request_too_large`) and the MCP bridge.

## Output

`flame_sword_report_validate` returns `{domain, subdomains, valid,
execution: "local-cli-validation", limitations}`.

`flame_sword_report_analyze` returns:

- `domain`, `subdomains` — normalized input;
- `analysis` — the vendored analyst output: `summary` (totals, HTTPS
  adoption, fixed `analysis_timestamp`), `insights` (prose triage
  lines), `risk_assessment` (level Low/Medium/High/Critical, score,
  factors, critical-asset counts), `attack_surface` (vectors with
  priority and description), `recommendations` (prioritized actions,
  tool names, timelines), `high_value_targets`, `vulnerability_summary`;
- `execution: "local-cli-vendored-analyst"`,
  `evidence: "user-supplied observations"`;
- `limitations` — fixed block; first line always states that no
  network scan was performed.

## The bounded scan contract (`flame_sword_scan`)

Input: `{"domain": "<hostname>", "options": {<step>: <bool>}}` —
`domain` follows the same rules as the analyst operations; `options` is
optional, each key must be one of `subdomains`, `ports`, `dns`,
`real_ip`, `tls`, `tech`, `email`, `ai` and each value a boolean
(`invalid_options` otherwise). Defaults: the seven collection steps are
enabled, `ai` is disabled.

Collection steps (all GET-only / no host mutation):

| step | what runs | bounded by |
| --- | --- | --- |
| `subdomains` | apex + 17 fixed keywords, each probed over HTTP and HTTPS (status, final URL, byte size) | 18 hosts |
| `ports` | TCP connect to the apex on 80/443/8080/8443 | 4 ports |
| `dns` | raw DNS wire queries A/AAAA/CNAME/NS/MX/TXT (UDP 53, TCP 53 fallback) | 6 types |
| `real_ip` | apex A records, labeled "no CDN-origin guarantee" | 1 query |
| `tls` | one stdlib `ssl` handshake to the apex on 443 (version, cipher, subject, SANs, expiry vs fixed clock) | 1 handshake |
| `tech` | vendored 30-signature table over the primary response (headers + body, 64 KiB cap) | vendored table |
| `email` | GET probes of 6 fixed login paths on hosts answering 200/301/302/401/403 | 6 paths |
| `ai` | one Mithril `chat/completions` call with the scan as payload | opt-in, fail-soft |

Output: `{scan, domain, subdomains, execution:
"local-cli-stdlib-scanner", evidence, limitations}`. `scan` carries
`options` (the resolved booleans) and `observations` keyed by step.
Probe-level failures are labeled per observation in `error` fields
(e.g. `TimeoutError:timed out`, `dns_unreachable (udp_unreachable; tcp
fallback also failed)`, `mithril_key_unavailable`); they never abort
the scan and never raise. The `subdomains` rows (subdomain +
http_status + https_status) satisfy the analyst validation contract and
feed `flame_sword_report_analyze` unchanged.

Scan output is a live observation: it is not byte-deterministic across
runs, and a zero-finding scan is not a safety or completeness
statement.

## Failure handling

| reason | trigger |
| --- | --- |
| `invalid_domain` | domain missing, too long, or not hostname-shaped |
| `invalid_options` | scan `options` key not a step name or value not a boolean |
| `too_many_subdomains` | more than 500 observations or not an array |
| `domain_mismatch` | a hostname is not within the report domain |
| `invalid_status` | a status is not an integer 100-599 or null |
| `file_not_found` | `--input` path does not exist or cannot be read |
| `request_too_large` | raw body over 32 KiB |
| `analyst_error` | the vendored analyst returns an unexpected shape |

All failures print
`flame-sword operation failed: <reason>; inspect the retained input
before retrying` to stderr and exit 1 (no stack trace). The MCP bridge
wraps the same reasons in `isError` results.

## Determinism

The CLI injects a frozen clock (`2026-01-01T00:00:00`) into the
vendored analyst module, which otherwise calls `datetime.now()` for
`analysis_timestamp` and one insight line. No other non-determinism is
used by the rule engine (sets are iterated after `sorted`). Identical
input bytes therefore yield byte-identical output.

## What this contract does not cover

- Full scanner execution: nmap port sweeps beyond the fixed 4-port set,
  dnspython-based DNS traversal, full Wappalyzer matching and the
  broader email/user enumeration all happen in the flame-sword
  repository runtime. This skill's scan covers the bounded stdlib
  subset above.
- Report export (JSON/PDF) and the Flask UI are scanner features.
- The browser worker (Pyodide) accepts the same analyst shape with a
  1 MiB import bound and its own consent-gated AI preview.
