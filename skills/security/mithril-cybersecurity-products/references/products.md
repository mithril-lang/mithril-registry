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

## Investigation arguments

- search: `{"runs":["/private/run-a"],"query":"literal asset or CVE","limit":100,"offset":0}`
- timeline: `{"runs":["/private/run-a"],"limit":100,"offset":0}`
- compare: `{"before":"/private/run-a","after":"/private/run-b"}`
- export: `{"runs":["/private/run-a"],"output":"/private/new-export"}`

Runs are directories from this CLI. Up to16 unique runs; search/timeline return at most200 rows per call and support offset. Source digest/product/row accompany results. Timeline orders explicit zoned ISO or Tenable declared epoch-seconds; other numeric times remain unknown. Original times remain intact; submicrosecond ordering and clock skew are not resolved. Compare requires same product and unambiguous vendor-ID/asset pairs; it reports sampleNew/sampleAbsent/sampleChanged, never resolved vulnerabilities or eliminated threats. Tenant identity and comparable collection scope remain operator-confirmed. Export retains normalized claims, source hashes, pagination and gaps in a new private investigation.json; it does not copy original bytes, redact confidential fields or upload to Mithril. Original run directories are still needed to verify claims.
