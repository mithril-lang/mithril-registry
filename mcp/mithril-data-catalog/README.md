# Mithril Data Catalog MCP

During the Fund account cutover, connect an MCP client to `https://mithril-api.cloud-kotoba.workers.dev/v1/internal/data-catalog/mcp` with the isolated catalog-ingest bearer. This is the Fund-owned Mithril API Worker, not direct R2 access. After the `api.mithril.fund` zone cutover is independently verified, the Registry will move the connection to `https://api.mithril.fund/v1/internal/data-catalog/mcp`. The server supports stateless Streamable HTTP and exposes one tool: `mithril_catalog_ingest_batch`.

The tool validates bounded files, verifies SHA-256 and byte length, writes immutable content-addressed objects through the Fund API's R2 binding, and returns a staging receipt. It never returns or accepts Cloudflare credentials and cannot create/delete buckets, alter Basin settings, delete objects, or invoke the trusted Iceberg materializer.

Send the bearer through the client's credential store. Browser cookies and ordinary `mf_` inference tokens are not credentials for this internal publisher. Never include the token in tool arguments. Initialize the connection and use `tools/list` for the authoritative schema.

`staged-for-iceberg` is not a materialization receipt. Confirm the separate trusted-CI materializer and table read-back before reporting an Iceberg sync as complete. Exact retries are content-addressed and safe; changed content is a new batch. See the [Skill contract](../../skills/data/mithril-data-catalog/references/contract.md) for ownership and recovery rules.
