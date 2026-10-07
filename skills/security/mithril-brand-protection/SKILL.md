---
name: mithril-brand-protection
description: Register company brand assets, match authorized supplied observations and track candidate reviews through Mithril REST or the bundled stdio MCP bridge.
version: 0.1.0
author: Mithril
license: Apache-2.0
metadata:
  hermes:
    tags: [brand, trademark, logo, character, evidence, monitoring, mcp]
    category: security
---

Use this skill for a company's private trademark/logo/character investigation. Matching identifies candidates, never a legal infringement verdict. Read [the API and capability contract](references/contract.md) when preparing requests.

Use the explicitly selected Mithril account and a token in `MITHRIL_BRAND_TOKEN` with `brand:read` and, for writes, `brand:write`. Do not put credentials in files, prompts or tool arguments. Existing case/security token scopes do not grant brand access. The API must have the brand schema and routes released before data operations work.

The self-contained Python stdio bridge is an MCP integration for agent clients:

```sh
python3 scripts/brand.py --mcp
# Add --allow-writes only for an authorized register/observe/review workflow.
```

It implements initialize, ping, tools/list and tools/call; read-only by default. Tools schemas are bundled in `scripts/tools.json`. The API performs actual authorization, byte checks and all domain operations. No hosted MCP entry is promoted into the Registry index until live qualification. Example client configuration uses an environment variable reference rather than a literal credential:

```json
{"mcpServers":{"mithril-brand":{"command":"python3","args":["/absolute/installed/skill/scripts/brand.py","--mcp"],"env":{"MITHRIL_BRAND_TOKEN":"<set securely in your client>"}}}}
```

For a one-off call:

```sh
python3 scripts/brand.py --tool brand_list
python3 scripts/brand.py --allow-writes --tool brand_observe --input /private/observation.json
```

Before saving, establish the company, asset, authorized-domain list, data-use permission, observation date and coverage from the user's task. Do not invent registration numbers, ownership proofs or permission. Original/observed image references must come from that account's existing evidence upload; the server hashes retained bytes. Name and exact image-byte matches do not establish copyright or trademark infringement; transformed images and OCR are outside current matching coverage.

Persist a UUID operationId with the request before transfer. On an uncertain outcome, inspect brand_get or retry exactly the same operationId and payload; do not regenerate it automatically. Review updates require the current expectedRevision. Refresh a conflict and prepare a new explicit edit; never silently advance its revision. Uploads themselves are not idempotent: reconcile uncertain uploads in the evidence list.

The bridge has a fixed API origin, rejects redirects and never fetches supplied target URLs. No crawler, marketplace credentials, source license, automated schedule, takedown or outbound message is granted by installation. CT/RDAP/DoH source ledger decisions remain independent; blocked/internal-only sources must not be republished. Report the collection gaps and distinguish source installation, endpoint release, synthetic tests and actual investigations.
