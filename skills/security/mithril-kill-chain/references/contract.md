# Contract

Inputs, limits, and failure handling for the three `killchain_*` operations.

## `killchain_phases`

- Input: no arguments.
- Output: the seven phases with `id`, `key`, `ja`/`en` names, `evidenceTypes` and `registryEntries`.
- Failures: none (static data).

## `killchain_evaluate`

- Input shape:
  ```json
  {
    "caseId": "case-2026-1008",
    "phases": [
      {"phase": "reconnaissance",
       "evidence": [{"type": "domain-asset", "source": "osint-catalog", "note": "optional"}]}
    ]
  }
  ```
- `caseId`: optional, string, ≤128 chars, `[A-Za-z0-9_-]+`.
- `phases`: optional array, ≤7 entries, each `phase` must be one of the seven keys. Duplicated phases are rejected.
- `evidence`: optional array per phase, ≤100 entries. Each entry: `type` (required, nonempty string), `source`/`note` (optional strings, ≤512/≤1024 chars). Unknown keys are rejected.
- Per-phase status:
  - `covered` — at least one evidence `type` is in the phase's `evidenceTypes`.
  - `partial` — evidence supplied but none matched the phase's types.
  - `absent` — no evidence supplied for the phase.
- Verdict: `first-covered-phase-N` (lowest covered phase id) or `no-covered-phase`.
- `invalid_input` — any violation of the shape above. The tool does not mutate state; the same payload retried gives the same result.

## `killchain_pcap_probe`

- Input: `{"path": "/absolute/path/file.pcap"}` (≤512 chars, existing file).
- Accepts: classic pcap v2 (magic `a1b2c3d4`, little- or big-endian), linktype 1 (Ethernet) or 12 (loopback), ≤16 MiB, ≤20000 packets.
- Failures: `file_not_found`, `file_too_large`, `unsupported_pcap` (bad magic), `unsupported_linktype`.
- Output bounds: each indicator list ≤50 entries; beacon candidates ≤50. Truncation keeps the lexicographically smallest candidates (by src, dst, dstPort), so the same bytes always yield the same list.
- Beacon rule: ≥3 intervals, median interval within 1–3600 s, coefficient of variation ≤0.25.
- All indicators are derived from the supplied bytes only. No network, no state.

## MCP bridge

- `--mcp` reads one JSON-RPC 2.0 request per line on stdin, writes one line per response.
- `initialize` accepts protocol versions 2025-03-26, 2025-06-18, 2025-11-25 (else 2025-11-25).
- `tools/call` returns `isError: true` with a short reason (`invalid_input`, `file_not_found`, ...) on failure; never a stack trace.
- Lines >32 KiB → `-32600 Request too large`. The bridge drains the oversized line (up to 1 MiB) and continues; it does not exit. Lines >1 MiB desynchronize the line framing after the error, so a client that sends one should reconnect.
- Parse errors → `-32700`. Unknown methods → `-32601`.
- Requests without `id` (notifications) are ignored and get no response.

## CLI failures

- `--tool` runs print the machine-readable reason on stderr (`invalid_input`, `file_not_found`, `request_too_large`, ...), exit 1, and never a stack trace. The same payload retried gives the same result; inspect the retained input before retrying.

## Non-goals

- No attack execution, host remediation, or evidence collection.
- No attribution, actor naming, or legal qualification.
- No TLS certificate validation, IPsec, or non-IPv4 families (IPv6, ARP-only captures are skipped silently).
- Not a packet analyzer: bounded, deterministic, first-pass only.
