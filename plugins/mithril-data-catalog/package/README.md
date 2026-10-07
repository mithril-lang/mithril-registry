# Mithril Data Catalog plugin

This standalone Hermes plugin registers `mithril_catalog_publish`. The tool reads only explicitly selected files below an absolute root, computes their SHA-256 locally, and sends a bounded batch to an exact allowlist containing the canonical `api.mithril.fund` ingress and the Fund-owned transitional Worker ingress.

Until the `api.mithril.fund` cutover is verified, configure:

```yaml
plugins:
  entries:
    mithril-data-catalog:
      settings:
        api_url: https://mithril-api.cloud-kotoba.workers.dev/v1/internal/data-catalog/ingest
```

Remove that setting after the Registry moves to the canonical URL. Redirects and every other origin are refused.

Store `MITHRIL_CATALOG_API_TOKEN` in each Hermes profile's secret store. The plugin resolves it through Hermes' profile-scoped secret API, so a multiplexed gateway cannot fall back to another profile's environment. The token never appears in tool arguments.

The tool refuses absolute child paths, traversal/symlink escape, redirects, duplicate files, unknown datasets, files over 8 MiB, batches over 16 MiB, and malformed receipts. It provides no Cloudflare, R2, bucket, Basin, deletion, or Iceberg materializer operation.

A successful tool result is an API staging receipt only. Use trusted materializer evidence before claiming an Iceberg sync.
