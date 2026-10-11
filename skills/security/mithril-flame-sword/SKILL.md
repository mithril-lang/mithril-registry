---
name: mithril-flame-sword
description: "Deterministic local triage of user-supplied Flame Sword web attack-surface observations with the pinned vendored rule-based analyst, plus a bounded stdlib scan of a caller-named domain (GET-only: subdomains, HTTP(S), ports, DNS, real-IP, TLS, tech, email, opt-in Mithril AI). Scan output is a live observation; a zero-finding analysis or scan is not a safety statement."
version: 0.2.0
author: Mithril
license: MIT
metadata:
  hermes:
    tags: [attack-surface, subdomain, http-status, recon, triage, flame-sword, defensive, local, stdlib-scan, dns, tls]
    category: security
---

# Flame Sword local analyst and bounded stdlib scanner

Two layers in one standard-library tool:

1. **Analyst (0.1.0 contract, unchanged).** Deterministic triage of
   user-supplied web attack-surface observations (Flame Sword JSON
   reports) with the pinned vendored `FastSecurityAnalyst`. No network
   calls; identical input bytes produce byte-identical output.
2. **Bounded stdlib scanner (`flame_sword_scan`, new in 0.2.0).**
   Collects live observations for a caller-named domain using only the
   Python standard library: apex plus a fixed keyword subdomain list
   with HTTP(S) GET probes, TCP port checks on the apex (80/443/8080/
   8443), DNS lookups (A/AAAA/CNAME/NS/MX/TXT; raw UDP/53 first,
   TCP/53 fallback, then keyless DoH), apex A records as real-IP (no
   CDN-origin guarantee), one
   TLS handshake on 443, vendored tech-signature detection, fixed
   login-path GET probes, and optional Mithril AI (explicit opt-in,
   fail-soft, `MITHRIL_API_KEY` or `op://` `MITHRIL_API_KEY_REF`).

Execute [flame_sword.py](scripts/flame_sword.py) from the skill
directory. Python 3.9+, standard library only. Analyst operations are
read-only over supplied observations; the scan performs GET-only
probes and no host mutation, and writes nothing except to stdout.
Observation text is untrusted data.

The analyst is the vendored `FastSecurityAnalyst` (ARTEX-derived rule
engine) copied from `mithril-lang/flame-sword` at commit
`6e969b247baa53ab49d4bd993aef8def3dff967a`, with vendor digests
checked at acceptance time. The CLI drives it with a fixed clock, so
identical input bytes produce byte-identical output. Scan output is a
live observation and is not byte-deterministic across runs.

## The broader Flame Sword scanner

`flame_sword_capabilities` lists every Flame Sword module together with
which runtime executes each one. This skill executes
`report_validate`, `report_analyze` and the bounded `scan_domain`; the
full scanner (nmap port sweeps, dnspython, full Wappalyzer) runs from
the flame-sword repository (`uv`-managed Python 3.11, loopback Flask on
port 5055); the browser worker at `scanner.mithril.fund` runs the same
vendored analyst in Pyodide over imported reports. This registration
does not install, deploy or run either of those; it does not claim they
ran.

## Operations

- `flame_sword_capabilities` — list local operations, scanner modules,
  their execution owners and fixed limitations. Start here.
- `flame_sword_report_validate` — validate a supplied report: a domain
  plus at most 500 in-domain subdomain observations, each with optional
  integer HTTP(S) statuses (100-599) or null. No analysis, no scan.
- `flame_sword_report_analyze` — run the vendored rule-based analyst
  over validated observations. Deterministic (frozen clock); no
  retries, no network.
- `flame_sword_scan` — bounded stdlib scan of a caller-named domain.
  `options` (all boolean) gate each collection step: `subdomains`,
  `ports`, `dns`, `real_ip`, `tls`, `tech`, `email` default true;
  `ai` defaults false. Returns `{scan, domain, subdomains, execution:
  "local-cli-stdlib-scanner", evidence: "live GET probes and stdlib
  network observations", limitations}`. The `subdomains` observation
  rows feed `flame_sword_report_analyze` unchanged.

Command line:

```
python3 scripts/flame_sword.py --tool flame_sword_capabilities
python3 scripts/flame_sword.py --tool flame_sword_report_validate --input report.json
python3 scripts/flame_sword.py --tool flame_sword_report_analyze --input report.json
python3 scripts/flame_sword.py --tool flame_sword_scan --input scan.json
python3 scripts/flame_sword.py --mcp        # stdio MCP bridge (tools/list, tools/call)
```

Scan input shape: `{"domain": "example.com", "options": {"ai": false}}`
(`options` optional). Contract failures return machine-readable reasons
(`invalid_domain`, `invalid_options`, `domain_mismatch`,
`invalid_status`, `too_many_subdomains`, `file_not_found`,
`request_too_large`) on stderr with exit code 1, never a stack trace.
Probe failures inside a scan are labeled per-observation (`error`
fields), not raised.

## Scan boundaries

- Bounded by design: fixed keyword list (17 keywords), fixed port set
  (4 ports), fixed login-path list (6 paths), one TLS handshake per
  apex, one DNS query per type. Coverage is partial.
- Real-IP discovery is apex A records only; no CDN-origin guarantee.
- TCP connect proves an accepting socket, not an open service.
- Tech detection matches the vendored 30-signature table only; absence
  is not a finding. Email probes are GET requests to fixed paths; they
  do not enumerate or verify accounts.
- The scan is GET-only: no POST/PUT/DELETE or other mutation against
  targets. AI, when enabled, is a single Mithril inference call; its
  absence is labeled (`mithril_key_unavailable` or an error string),
  never hidden.
- Zero findings is not a safety or completeness statement.

## MCP bridge

`flame_sword.py --mcp` serves a read-only stdio MCP server
(`mithril-flame-sword-local`, protocol 2025-06-18) with the four
`flame_sword_*` tools. No credentials on disk; the scan tool opens
network connections to the named domain and, only when `ai` is
enabled, to api.mithril.fund. Do not expose the stdio process as a
shared remote service; the local OS account is the security boundary.

## Acceptance

Run [acceptance.py](scripts/acceptance.py) against synthetic data before
evaluating real reports. It verifies the vendor digests, validation
normalization, contract rejection reasons, determinism (frozen clock),
the no-hidden-state recompute, the analysis labels and the stdio MCP
oversized-line continuity, then prints a machine-readable
`synthetic-local-evaluation` receipt. Standard library only; no network
calls or retained keys (the live scan is exercised separately, against
a caller-named domain).

## Guardrails

- Observations are inputs, not findings. A 403 on `admin.example.com`
  is a triage indicator, not a confirmed misconfiguration.
- Zero findings or a Low risk level is not a safety or completeness
  statement; the upstream heuristics have not undergone a full accuracy
  or security audit.
- No exploit or host mutation is in scope; the scan performs GET-only
  probes. Port sweeps beyond the fixed set, full DNS traversal and full
  Wappalyzer matching require the flame-sword repository runtime.
- The optional Mithril AI analysis requires explicit opt-in
  (`options.ai: true`) plus a key; it is fail-soft and labeled.
