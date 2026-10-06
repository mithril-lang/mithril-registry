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
