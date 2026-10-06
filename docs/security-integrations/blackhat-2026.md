# Black Hat 2026 integration inventory

Snapshot: 2026-10-06. The official [USA](https://blackhat.com/us-26/event-sponsors.html), [Asia](https://blackhat.com/asia-26/event-sponsors.html) and [Europe](https://blackhat.com/europe/event-sponsors.html) lists contain469,59and114distinct event/display-name entries respectively. Combined:642entries,538exact display names, including associations, media, government, brands and products. These are not counts of distinct legal companies. Europe is a provisional pre-event list. [MEA2026](https://blackhatmea.com/faq) has not published its confirmed list;2025is not substituted.

[Roster CSV](blackhat-2026-roster.csv) preserves original display names, event, category and official source. Source line offsets are zero-based positions in the fetched web text, not stable HTML DOM identifiers. Category and alphabetical listings were deduplicated; alphabetical-only entries are labeled rather than assigned an inferred sponsor tier.

[Candidate matrix](integration-matrix.csv) assesses91candidates in24sectors.89are confirmed in these lists; CrowdStrike and Wazuh are separate existing-adapter comparisons. Presence in the list, public API documentation, MCP documentation, source implementation, fixture qualification and live qualification are distinct states. Technical status describes discovery of public material, not an exhaustive endpoint audit. The remaining roster entries have not had a detailed API contract review.

## Implemented first wave

- runZero: fixed asset Export API, no scans or remote modifications.
- Okta System Log: one bounded page with pre-provisioned read OAuth bearer, manual cursor selection.
- Censys Platform: selected public IP host observation with explicit organization/entitlement; no scan/search.
- Local stdio MCP: context observations use existing import/search/timeline/compare/export plus exact-IP correlation. Static contract/coverage resources are available.
- Receipt v2: normalizer version, requested selection, retained bytes/rows and explicit incomplete-or-unknown coverage. Unsigned receipts are not vendor authenticity/custody attestation.

All three adapters are fixture/loopback-tested, not live vendor-qualified. Nothing in the roster enables a remote credential, hosted MCP connection, scan or remediation. The local integration is not a hosted vendor MCP proxy.

## Public research corrections and next work

Axonius's public overview confirms API v2 exists, but detailed documentation requires developer access and dedicated service-account permissions. The matrix's original public API discovery label does not establish an implementation-ready contract. Axonius is deferred pending that contract; no guessed query/export adapter is included.

Next candidate waves: existing-adapter pagination/tenant qualification; SIEM/Google SecOps/Elastic/Splunk log context; Sysdig runtime; GitGuardian/Semgrep/JFrog/GitLab code and supply-chain context; Binalyze/Magnet/TheHive evidence/case context. Select by authorized tenant access and missing data, not sponsor tier. Further evidence custody, signed receipts, case/vault linking and identity resolution require independent scope and verification.

The candidate matrix is a research snapshot. Beta/reference implementations, private schemas, contract entitlements, product versions, vendor credits and data rights still need review before each implementation. No prices or live compatibility are inferred from conference participation.
