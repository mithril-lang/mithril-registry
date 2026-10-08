# Kill-chain local evaluation validation receipt

Date: 2026-10-08. Local qualification only. Dependency environment: Python standard library only (verified at acceptance run time; interpreter tested locally on macOS arm64, CI on Linux and macOS with Python 3.12). Skill version 0.3.0. The skill retains no dependency lock because it imports no third-party module; the acceptance exercise asserts that by scanning `killchain.py`'s top-level imports against `sys.stdlib_module_names` and failing the run if a non-stdlib import appears.

## Observable validation

- Kill-chain unit suite: 15 tests passed. They cover the seven-phase definitions, covered/partial/absent evaluation, malformed-input rejection, little- and big-endian pcap probes, unsupported-capture rejection, file-size ordering, deterministic beacon truncation, MCP initialize/tools-list, unknown-method and notification handling, the stdio round trip, CLI dispatch, machine-readable CLI failure reasons, and oversized MCP line continuity.
- Synthetic acceptance (`acceptance.py`): `synthetic-local-evaluation`, 7 phases evaluated, 4-phase covered case with verdict `first-covered-phase-1`, a changed-evidence case that shifts the verdict to `first-covered-phase-3` (recomputed, not cached), byte-identical output across repeated runs on identical input, one DNS query, one TLS SNI, one HTTP host and one beacon candidate (9 packets), machine-readable `unsupported_pcap` and `file_not_found` reasons without stack traces, and the MCP bridge's oversized-line continuity (Request-too-large, then continues, exit code 0). No vendor/customer connection, no network calls, no keys retained.
- No dependency lock or offline wheel install: the skill is stdlib-only, so the CI job runs the unit suite, the synthetic acceptance, and `build_index.py --check` directly, and the acceptance exercise re-verifies stdlib-only on every run. This is a deliberate deviation from the forensic-evidence kit, which locks `cryptography` and installs it offline.

CI definitions (`.github/workflows/killchain-evaluation.yml`) run Linux/macOS Python 3.12 acceptance on pull requests and main. The CI result belongs to the exact PR commit; consult its checks rather than treating the existence of the workflow as a pass.

## Reproduction

```sh
python3 -m unittest discover -s scripts -p 'test_kill_chain.py'
python3 skills/security/mithril-kill-chain/scripts/acceptance.py
python3 skills/security/mithril-kill-chain/scripts/acceptance.py --prepare /abs/empty/dir
python3 scripts/build_index.py --check
git diff --check
```

The receipt is local qualification, not a vulnerability or native-dependency attestation. The bounded pcap probe remains a first-pass triage filter, not a packet analyzer; coverage remains an evidence-availability statement, not attack attribution.

Unperformed: full-capture packet-analyzer confirmation of beacon candidates, IPv6/ARP-family captures, TLS certificate validation, non-classic pcap v2 formats, multi-tenant or shared-remote MCP use, and production deployment.
