# Data Catalog agent contract

## Trust boundary

The agent may read explicitly selected local source files and send their verified bytes to the Mithril API. Only the API owns the R2 binding. Only the trusted CI/backend materializer owns Basin Catalog credentials. The Registry owns discovery, instructions, declared permissions, compatibility, and artifact hashes.

The canonical endpoint is `https://api.mithril.fund`. Until its zone cutover is independently verified, the Registry may pin the exact Fund-owned `https://mithril-api.cloud-kotoba.workers.dev` endpoint. These are the only two admitted origins. Do not accept redirects or send the catalog bearer to any other origin. Bump the Registry package and remove the transitional hostname after cutover.

## Receipt states

| State | Meaning | May claim |
| --- | --- | --- |
| Request prepared | Local files were bounded and hashed | Local validation only |
| `staged-for-iceberg` | Immutable R2 objects and receipt metadata read back | API staging succeeded |
| Materializer marker and table read-back | Trusted materializer committed and verified row/table state | Iceberg sync succeeded |

An empty result, network timeout, HTTP error, missing marker, or absent read-back is unknown/failure, never success.

## Recovery

Historical Iceberg manifests are catalog state, not disposable cache files. If an overwrite cannot read a referenced manifest, use the allowlisted recovery tooling with source digest, backup, replacement and read-back evidence. Creating a fresh table or observing `added-records` does not prove that an old snapshot was recovered.

## MCP request

Clients send JSON-RPC 2.0 over Streamable HTTP with:

- `Authorization: Bearer <profile-scoped catalog token>`
- `Accept: application/json, text/event-stream`
- `Content-Type: application/json`
- `MCP-Protocol-Version: 2025-06-18`

Call `initialize`, then `tools/list`; treat the returned schema as authoritative. `mithril_catalog_ingest_batch` accepts the same object as REST. File bytes are base64 in MCP, so the Hermes plugin is preferable when publishing local paths.
