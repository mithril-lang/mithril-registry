# Mithril Forensics MCP

Connect an MCP client to `https://api.mithril.fund/v1/forensics/mcp` with a Mithril scoped bearer. All five tools need `cases:read`; importing additionally needs `cases:write`. Credentials stay in the client. Tools share the REST API's account boundary, byte-integrity checks, parsers and audit trail.

Upload an existing report through `/v1/evidence/file`, then call `forensics_import` using its returned ID and SHA-256. `forensics_list`, `forensics_get` and `forensics_verify` read retained analyses and inspect missing/corrupted evidence. `forensics_products` reports supported formats and connector qualification. Schemas are available from `tools/list` and the public `.well-known/mcp.json` source.

Volatility 3 JSON/JSONL and Velociraptor JSON/JSONL are structured imports; Autopsy supports CSV or opaque artifacts. Magnet AXIOM, Cellebrite, X-Ways and Trend Micro services currently support opaque report retention. Their proprietary APIs and licenses are not provided by this MCP server. Report contents and engine versions remain untrusted operator claims. No remote device acquisition executes. Empty reports and missing source bytes remain coverage gaps, never a clean verdict. This is not WORM custody or vendor attestation.

Imports create new retained records and are not idempotent. Inspect the ledger after an uncertain response instead of automatically retrying. Local connector scripts retain intent/output files and require explicit upload; they use the installed Volatility CLI or Velociraptor's existing-flow API. See the [API, connector and release runbook](https://github.com/mithril-lang/mithril-fund/blob/main/docs/design/forensics-api-mcp.md) for formats, limits, qualification and secret-handling boundaries.
