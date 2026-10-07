---
name: mithril-data-catalog
description: Publish authorized Mithril datasets through the API-mediated R2 and Iceberg staging path without giving agents Cloudflare credentials.
version: 1.0.0
author: Mithril
license: Apache-2.0
metadata:
  hermes:
    tags: [data, catalog, r2, iceberg, api, mcp, hermes]
    category: data
---

# Mithril Data Catalog

Use this skill when an authorized Mithril dataset must be staged for R2 Data Catalog / Iceberg materialization. Read the [contract](references/contract.md) before the first write in a workflow.

Prefer the installed `mithril_catalog_publish` plugin tool for local files. A generic MCP client may instead use the URL in the Registry MCP manifest and call `mithril_catalog_ingest_batch`. During the Fund account cutover that URL is the verified Fund-owned Worker endpoint; after DNS cutover it becomes `api.mithril.fund`. Both routes use the same API validator and content-addressed storage writer. Never call Cloudflare R2, S3, Wrangler, or Basin Catalog from an agent profile.

The credential is the profile-scoped `MITHRIL_CATALOG_API_TOKEN`. Keep it in the Hermes profile secret store or MCP credential store. Do not put it in a prompt, tool argument, generated file, job definition, repository, log, or chat. This bearer grants only catalog staging; it is not a Cloudflare token, inference token, browser session, or general pipeline credential.

Before publishing:

1. Confirm the dataset is one of `actor`, `adnetwork`, `attack`, `cwe`, `darkweb`, `epss`, `exchange-sec`, `humankind`, `kev`, `oss-sec`, or `pwned`.
2. Confirm the source and data rights, exact local root, generated time, expected files, row counts where known, and whether the dataset belongs to Mithril. Keep Kotoba-owned Yabai data on its separately governed Kotoba path.
3. Ensure each path is relative to the selected root and each file is at most 8 MiB; one batch is at most 32 files and 16 MiB decoded.
4. Call the plugin tool once. It computes bytes and SHA-256 locally, base64-encodes the bounded content, and sends it only to the exact allowlisted Mithril API endpoint configured for the current cutover state.
5. Record `dataset`, `batchId`, `generatedAt`, file digests and returned state. Do not record the bearer or base64 content.

A response with `state: staged-for-iceberg` proves R2 staging and metadata read-back only. It does not prove an Iceberg commit, materializer success, public availability, or queryability. Report materialization only after the trusted CI materializer and table read-back succeed.

Retry an identical request after a lost acknowledgement; batch identity is content-addressed. Do not change `generatedAt`, paths, row declarations, or bytes merely to force a retry. On an immutable conflict, digest mismatch, uncertain materializer state, or missing historical manifest, stop and reconcile retained evidence through the established recovery workflow. Never replace a manifest heuristically or infer success from an added-record count.

Installation does not authorize a dataset, schedule a job, materialize Iceberg, create a bucket, rotate credentials, or move data between Kotoba and Mithril accounts.
