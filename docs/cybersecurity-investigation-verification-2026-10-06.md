# Cybersecurity investigation 0.2.0 verification

Measured 2026-10-06 JST, Registry. Extends the existing 0.1.0 standalone skill/CLI/stdio MCP; no Worker deployment, vendor remediation, credentials creation or customer scan.

## Implemented

- Seven product adapters in total. Added Microsoft Graph Defender alerts_v2, CrowdStrike selected alert details (Alerts:READ), Tenable existing vulnerability export chunk, and Wazuh Indexer fixed read alert search. Existing Cortex XDR/Vision One/Wiz support remains. Network is opt-in; Wiz stays supplied-export only.
- Wazuh self-hosted origin is operator-pinned, uses a separately provisioned read-only index account and normal TLS verification, with optional operator CA. No TLS bypass. CrowdStrike/Defender bearer and Tenable keys are environment references; OAuth issuance/refresh and export job creation remain outside the adapter.
- Local MCP search/timeline/compare/export re-normalize original source bytes only after SHA-256 receipt verification. Search is literal and paginated; timelines preserve raw time and uncertainty; compare is sample change rather than resolution; export is additive/private with source hashes and gaps.
- Skill workflows cover alert triage, evidence-grounded asset/CVE correlation and a private evidence report. Vendor asset namespaces are not silently equated.

## Observable validation

- 59 Registry tests: 47 passed and 12 existing engine/provisioning tests skipped without operator engine checkouts.
- 13 cybersecurity behavioral tests: original seven plus six covering all new source shapes, exact API requests over an actual loopback HTTP simulator with synthetic credentials, prohibited destinations, raw-byte tampering, timeline/unknown times, paginated search/export and ambiguous/sample comparisons.
- Official MCP TypeScript SDK 1.32.1 connected to the actual Python stdio process. Seven advertised tools, seven products, import/search/timeline/compare/export all passed; missing-policy collection returned a tool error. No live vendor call was made by SDK validation.
- Deterministic Registry generation/check and plugin artifact check passed. Product skill metadata follows the Registry-required frontmatter conventions. No extra runtime dependency beyond Python3.10+.

## Remaining qualification

Actual Wazuh installation and authentication, representative vendor exports, real vendor API credentials, entitlement, bearer refresh, deployment-region coverage and end-to-end case/cloud-vault consumption remain unverified. Docker CLI was present, but the configured OrbStack daemon socket was absent (docker info failed), so no local real Wazuh deployment was started. Simulators do not qualify real vendor servers.

Network responses are bounded to2MiB and1000rows per supplied report. Vendor API requests select at most100 records/IDs where the contract allows. No automatic pagination/retry. Each investigation accepts at most16 runs; result pages at most200rows/2MiB. Timeline orders explicit zoned ISO and Tenable declared epoch-seconds; unknown times remain excluded with counts, and submicrosecond ordering/clock skew remain gaps. Digests detect retained-byte drift; editing both source and receipt is not prevented and is not vendor attestation. Export includes normalized claims and references, not original raw runs or automatic redaction.
