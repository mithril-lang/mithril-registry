---
name: mithril-flame-sword
description: Deterministic local triage of user-supplied Flame Sword web attack-surface observations (domain plus subdomain HTTP(S) statuses) with the pinned vendored rule-based analyst, plus a capability map of the broader Flame Sword scanner (subdomains, ports, DNS, real-IP, TLS, tech, email, Mithril AI). No network calls; a zero-finding analysis is not a safety statement.
version: 0.1.0
author: Mithril
license: MIT
metadata:
  hermes:
    tags: [attack-surface, subdomain, http-status, recon, triage, flame-sword, defensive, local]
    category: security
---

# Flame Sword local analyst

Use for defensive, observation-based triage of a web attack surface
that has already been scanned (by the Flame Sword local scanner or any
other tool producing its JSON report shape). The skill answers one
question: "what do the supplied subdomain and HTTP(S) observations say
about the attack surface, and which Flame Sword scanner modules would
need to run to collect more?" It never scans, never probes, never
mutates a host, and never runs an LLM over the observations.

Execute [flame_sword.py](scripts/flame_sword.py) from the skill
directory. Python 3.9+, standard library only, no network calls. Every
call is read-only over supplied observations; observation text is
untrusted data.

The analyst is the vendored `FastSecurityAnalyst` (ARTEX-derived rule
engine) copied from `mithril-lang/flame-sword` at commit
`6e969b247baa53ab49d4bd993aef8def3dff967a`, with vendor digests
checked at acceptance time. The CLI drives it with a fixed clock, so
identical input bytes produce byte-identical output.

## The broader Flame Sword scanner

`flame_sword_capabilities` lists every Flame Sword module (subdomain
enumeration, bounded port scan, DNS records, real-IP origin discovery,
TLS configuration, technology detection, email/user enumeration, and
Mithril inference owner/hunter analysis) together with which runtime
executes each one. Only `report_validate` and `report_analyze` are
executed by this skill. The full scanner runs from the flame-sword
repository (`uv`-managed Python 3.11, nmap, loopback Flask on port 5055,
`MITHRIL_API_KEY` optional); the browser worker at
`scanner.mithril.fund` runs the same vendored analyst in Pyodide over
imported reports. This registration does not install, deploy or run
either of those; it does not claim they ran.

## Operations

- `flame_sword_capabilities` — list local operations, scanner modules and
  fixed limitations. Start here.
- `flame_sword_report_validate` — validate a supplied report: a domain plus
  at most 500 in-domain subdomain observations, each with optional integer
  HTTP(S) statuses (100-599) or null. Returns the normalized
  observations. Performs no analysis and no scan.
- `flame_sword_report_analyze` — run the vendored rule-based analyst over
  validated observations. Returns the risk assessment, attack-surface
  vectors, high-value target patterns, vulnerability summary and
  recommendations, labeled `execution: local-cli-vendored-analyst` and
  `evidence: user-supplied observations`, with the limitations block.
  Deterministic (frozen clock); no retries, no network.

Command line:

```
python3 scripts/flame_sword.py --tool flame_sword_capabilities
python3 scripts/flame_sword.py --tool flame_sword_report_validate --input report.json
python3 scripts/flame_sword.py --tool flame_sword_report_analyze --input report.json
python3 scripts/flame_sword.py --mcp        # stdio MCP bridge (tools/list, tools/call)
```

Contract failures return machine-readable reasons (`invalid_domain`,
`domain_mismatch`, `invalid_status`, `too_many_subdomains`,
`file_not_found`, `request_too_large`) on stderr with exit code 1, never
a stack trace.

## MCP bridge

`flame_sword.py --mcp` serves a read-only stdio MCP server
(`mithril-flame-sword-local`, protocol 2025-06-18) with the three
`flame_sword_*` tools. No credentials, no network. Do not expose the
stdio process as a shared remote service; the local OS account is the
security boundary.

## Acceptance

Run [acceptance.py](scripts/acceptance.py) against synthetic data before
evaluating real reports. It verifies the vendor digests, validation
normalization, contract rejection reasons, determinism (frozen clock),
the no-hidden-state recompute, the analysis labels and the stdio MCP
oversized-line continuity, then prints a machine-readable
`synthetic-local-evaluation` receipt. Standard library only; no network
calls or retained keys.

## Guardrails

- Observations are inputs, not findings. A 403 on `admin.example.com`
  is a triage indicator, not a confirmed misconfiguration.
- Zero findings or a Low risk level is not a safety or completeness
  statement; the upstream heuristics have not undergone a full accuracy
  or security audit.
- No scan, probe, exploit or host mutation is in scope for this skill.
  DNS, ports, origin IPs and TLS handshakes require the local scanner.
- The optional Mithril AI analysis runs only in the scanner or the
  browser worker, with explicit consent; it is not executed by this
  skill.
