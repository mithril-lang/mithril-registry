# Product contracts (reviewed 2026-10-06)

| ID | Source shape | Live read | Gaps |
| --- | --- | --- | --- |
| paloalto-cortex-xdr | `reply.alerts[]` | `POST /public_api/v1/alerts/get_alerts`, fixed 100-result window | Basic key only; advanced key signing, incidents, PCAP and live tenant qualification pending |
| trendmicro-vision-one | `items[]` | `GET /v3.0/workbench/alerts`, first server page | Region selection required; nextLink is not followed; live qualification pending |
| wiz | `data.issues.nodes[]` | Unavailable | Supplied issue-page JSON only; tenant schema, OAuth/scopes, live GraphQL and export variants pending |

Normalization maps vendor ID, title/description, severity and one reported timestamp. Missing fields stay null; no generic severity conversion or timestamp invention. The retained raw file is the authority for every unmapped field. This is not a substitute for a vendor console, complete security scan, compliance certification or original forensic acquisition.

Cortex XDR policy (basic key only; exact operator tenant):

```json
{"product":"paloalto-cortex-xdr","origin":"https://api-TENANT.xdr.REGION.paloaltonetworks.com","authMode":"basic","tokenEnv":"CORTEX_XDR_API_KEY","keyIdEnv":"CORTEX_XDR_KEY_ID","offset":0}
```

Replace uppercase placeholders with the actual lowercase hostname from the operator's tenant. Only `api-<tenant>.xdr.<region>.paloaltonetworks.com` origins are admitted. Other deployment domains require an explicitly reviewed adapter update, not a suffix override. `offset` selects a single window, maximum100000; `total_count` is retained as vendor metadata, not asserted as collection completeness.

Vision One policy:

```json
{"product":"trendmicro-vision-one","origin":"https://api.xdr.trendmicro.com","tokenEnv":"TREND_VISION_ONE_TOKEN"}
```

Use the exact region origin from the console (`api[.<region>].xdr.trendmicro.com`). HTTPS certificate verification is enabled. Redirects and environment proxies are refused; credentials cannot be forwarded through nextLink. A declared User-Agent identifies this integration. Each request is bounded to30seconds and2MiB. Exports have at most1000rows; malformed shapes, duplicate JSON keys and vendor error payloads are rejected. No customer API credentials are supplied by this repository.

## Official sources

- [Cortex XDR Get all Alerts](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-all-Alerts): read POST, Authorization and x-xdr-auth-id, maximum100-result window and license requirements. TLS verification stays on regardless of insecure snippets in examples.
- [Trend Micro official API cookbook](https://github.com/trendmicro/tm-v1-api-cookbook/blob/main/detection-and-response/python/detection_and_response.py): bearer authentication, regional origin and Workbench items/nextLink. This adapter does not inherit the cookbook's remediation APIs or retry loops.
- [Wiz integrations](https://www.wiz.io/integrations) and [tenant documentation](https://docs.wiz.io/): API details require an authorized tenant. The Wiz supplied-export shape here is an explicit adapter contract, not claimed as a verified universal vendor schema.

## Adding another product

Add an explicit product entry, fixture-tested export shape and field mapping, official source and qualification gaps. Add live collection only with a verified method/path/auth contract, exact tenant-origin admission and least-privileged credentials. Test malformed/error payloads, credentials, redirect/nextLink handling, coverage and original-byte retention. Do not add a name-only install card or a guessed hosted MCP endpoint.

## Added read adapters (0.2.0)

| ID | Retained source shape | Fixed operation | Qualification gaps |
| --- | --- | --- | --- |
| microsoft-defender | Graph `value[]` | GET `/v1.0/security/alerts_v2?$top=100` | Graph global cloud only, operator bearer provisioned; no OAuth issuance or nextLink traversal |
| crowdstrike-falcon | `resources[]` alert objects | POST `/alerts/entities/alerts/v2` with 1–100 operator-selected composite IDs | Alerts:READ token supplied; discovery, token refresh and government-cloud qualification pending |
| tenable-vm | JSON array of export vulnerabilities | GET existing `/vulns/export/{uuid}/chunks/{chunk}` | Export job supplied; no job creation, expired-chunk recovery or new scan |
| wazuh | Indexer `hits.hits[]._source` | POST `/wazuh-alerts*/_search` with fixed match_all, size100, timestamp desc | Operator-approved self-hosted origin, read-only index account and trusted TLS CA; real Wazuh deployment pending |

Examples (credential values never belong in these files):

```json
{"product":"microsoft-defender","origin":"https://graph.microsoft.com","tokenEnv":"DEFENDER_GRAPH_TOKEN"}
```

```json
{"product":"crowdstrike-falcon","origin":"https://api.crowdstrike.com","tokenEnv":"FALCON_READ_TOKEN","compositeIds":["OPERATOR_SELECTED_ID"]}
```

```json
{"product":"tenable-vm","origin":"https://cloud.tenable.com","accessKeyEnv":"TENABLE_ACCESS_KEY","secretKeyEnv":"TENABLE_SECRET_KEY","exportUuid":"12345678-1234-1234-1234-123456789012","chunkId":1}
```

```json
{"product":"wazuh","origin":"https://indexer.example.test:9200","approvedOrigin":"https://indexer.example.test:9200","usernameEnv":"WAZUH_READ_USER","passwordEnv":"WAZUH_READ_PASSWORD","caFile":"/private/operator-ca.pem"}
```

The Wazuh example host is a placeholder; replace both origin fields with the same authorized destination. It is intentionally self-hosted, so private-address destinations are valid only under the operator's established scope. Certificate verification stays enabled. Optional caFile installs an operator-selected trust anchor, never disables verification. Cortex/Trend retain the existing adapters. All network operations need `--allow-network`; environment variables must be injected into the MCP subprocess by the client's secure credential configuration.

Official contracts: [Graph alerts_v2](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0) (SecurityAlert.Read.All), [CrowdStrike Alerts](https://developer.crowdstrike.com/api-reference/collections/alerts/) (PostEntitiesAlertsV2, Alerts:READ), [Tenable chunk download](https://developer.tenable.com/reference/exports-vulns-download-chunk), [Wazuh Indexer alert queries](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html). Shapes/fields and regional endpoints still require representative tenant qualification. Vendor tokens/keys are pre-provisioned; the adapter never creates them.

## Asset and identity context (0.3.0)

| Product | Accepted source | Fixed read contract | Qualification boundary |
|---|---|---|---|
| runzero | JSON array of assets, required string id; optional addresses[]/os/last_seen | GET `/api/v1.0/export/org/assets.json` | Hosted console or operator-pinned self-hosted HTTPS origin; export-read credential supplied; entire response must fit2MiB/1000rows; no scan/query/sync API |
| okta-system-log | JSON array, required uuid; optional client.ipAddress/actor.id/published/displayMessage/severity | GET `/api/v1/logs` with explicit since/until, ASCENDING, limit1–1000 | OAuth bearer with okta.logs.read; zoned window at most31days; one page, manual after cursor only; standard okta.com/oktapreview.com/okta-emea.com tenant domains |
| censys-platform | `result.resource` host object with IP | GET `/v3/global/asset/host/{ip}?organization_id={uuid}` | PAT supplied; explicit organization to avoid implicit free-wallet selection; public IPv4/IPv6 only; no search/rescan/history API; no assumed host timestamp |

Synthetic names and addresses in examples are configuration placeholders. No customer credential is provided or read during fixture validation.

```json
{"product":"runzero","origin":"https://console.runzero.com","tokenEnv":"RUNZERO_EXPORT_TOKEN","credentialScope":"export-read"}
```

For self-hosted runZero, add `approvedOrigin` equal to the exact selected `https://hostname`, optionally `caFile` for an operator-trusted CA. This pins a destination, not proof of ownership or credential permissions. `credentialScope` is an operator declaration; the client cannot attest remote RBAC. Public vendor docs currently show inconsistent ET/XT prefixes for export tokens, so the adapter does not infer access rights from a token prefix. Use a provisioned read-only export credential confirmed in the tenant.

```json
{"product":"okta-system-log","origin":"https://example.okta.com","tokenEnv":"OKTA_LOGS_READ_BEARER","since":"2026-10-05T00:00:00Z","until":"2026-10-06T00:00:00Z","limit":100}
```

Optional `after` is a manually selected opaque cursor containing letters/digits/underscore/hyphen, at most2048characters. Custom Okta domains, SSWS credentials, OAuth issuance/refresh, arbitrary filters and automatic Link traversal are unavailable. The Link header is inspected only for next-link presence; its URL is neither retained in the receipt nor requested. A missing next-link is not proof of complete retention or tenant coverage.

```json
{"product":"censys-platform","origin":"https://api.platform.censys.io","tokenEnv":"CENSYS_PAT","ip":"8.8.8.8","organizationId":"12345678-1234-1234-1234-123456789012"}
```

The adapter requires an explicit entitlement-bearing organization ID and checks returned host IP against the selected IP. Authorized API reads can consume vendor credits. This integration is fixture-tested; it does not connect or authenticate to the vendor's hosted MCP. Its observations are exposed through Mithril's local stdio MCP instead.

### Coverage receipt v2 and correlation

Receipts retain the source digest plus `normalizerVersion` and `coverage`. The status is always `incomplete-or-unknown`; extent differentiates alert page, selected IDs, export chunk, index search, asset export, bounded log page and selected host. Network receipts include start/end, method/path/origin, response bytes/status, selected non-secret scope and continuation presence. Falcon selections record ID count and a selection digest to bound receipt size. Authorization headers and secret values are excluded. Receipts are unsigned local claims; changing both source and receipt remains possible. Legacy receipts retain unknown coverage. A failed HTTP request, timeout, oversized body or invalid schema does not generate a successful receipt or a clearance verdict.

`cybersecurity_correlate` / CLI `--operation correlate` accepts `runs` (1–16), `address` (IP), optional `limit` (1–200) and `offset` (0–16000). It returns byte-verified context observations with exact normalized IP overlap, source hash/row, namespaced vendor IDs and `identityConclusion: not-established`. It does not merge assets or map IPs out of earlier alert adapters. See [context correlation](context-correlation.md).

MCP `resources/list` and `resources/read` expose only `cybersecurity://contracts` and `cybersecurity://coverage`; arbitrary file/resource URIs are refused. Network-disabled servers list7local tools; explicit `--allow-network` adds bounded collect as tool8.

Official sources: [runZero API](https://help.runzero.com/docs/leveraging-the-api/), [runZero data formats](https://help.runzero.com/docs/data-formats/), [Okta bounded System Log queries](https://developer.okta.com/docs/reference/system-log-query/), [Okta System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/), [Censys host lookup](https://docs.censys.com/reference/v3-globaldata-asset-host), [Censys host dataset](https://docs.censys.com/docs/platform-host-dataset). All are contract references, not evidence of live qualification.

Axonius remains deferred: [official API v2 access instructions](https://docs.axonius.com/docs/axonius-rest-api) require access to developer.axonius.com and a service account. The public overview alone does not supply a verified query/schema/auth contract. No Axonius endpoint or export format is invented here.

## Investigation arguments

- search: `{"runs":["/private/run-a"],"query":"literal asset or CVE","limit":100,"offset":0}`
- timeline: `{"runs":["/private/run-a"],"limit":100,"offset":0}`
- compare: `{"before":"/private/run-a","after":"/private/run-b"}`
- export: `{"runs":["/private/run-a"],"output":"/private/new-export"}`

Runs are directories from this CLI. Up to16 unique runs; search/timeline return at most200 rows per call and support offset. Source digest/product/row accompany results. Timeline orders explicit zoned ISO or Tenable declared epoch-seconds; other numeric times remain unknown. Original times remain intact; submicrosecond ordering and clock skew are not resolved. Compare requires same product and unambiguous vendor-ID/asset pairs; it reports sampleNew/sampleAbsent/sampleChanged, never resolved vulnerabilities or eliminated threats. Tenant identity and comparable collection scope remain operator-confirmed. Export retains normalized claims, source hashes, pagination and gaps in a new private investigation.json; it does not copy original bytes, redact confidential fields or upload to Mithril. Original run directories are still needed to verify claims.
