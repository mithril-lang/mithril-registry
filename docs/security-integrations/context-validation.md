# Security context integration validation

Validated locally on 2026-10-06 for Registry skill v0.3.0.

## Results

- `python3 -m unittest discover -s scripts -p 'test_*.py'`: 70 tests, 58 passed, 12 skipped. Existing Mithril runtime/executor-dependent checks remain skipped; they are not qualification evidence.
- Owned loopback HTTP fixtures exercise all three new collectors, request selection and receipt creation. Tests verify foreign continuation links are not followed, mismatched Censys hosts and malformed/oversized responses fail, and credentials are excluded from receipts.
- Investigation tests verify source digest checking, exact-IP matching, IPv6 canonicalization, unknown host time, legacy receipts and tampered coverage claims. IP overlap does not establish identity.
- Official `@modelcontextprotocol/sdk` 1.32.1 verifies stdio initialization, 10 products, 7 local tools, 2 resources, three imported/context-correlated observations and 8 tools with collection explicitly enabled. Network-disabled collection is refused. No vendor connection occurs in this SDK check.
- Registry index generation/check, existing plugin package consistency and `git diff --check` pass.

## Reproduction

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
node scripts/verify_context_mcp.mjs /path/to/node_modules/@modelcontextprotocol/sdk
python3 scripts/build_index.py --check
python3 scripts/package_plugin.py mithril-app --check
git diff --check
```

The Node SDK is a validation-only external dependency; the collector and local MCP server use Python's standard library. The SDK check creates synthetic temporary sources and removes them afterward.

## Qualification boundary

No customer tenant, vendor credential, paid Censys credit, scan or remediation was used. These are fixture/loopback-tested adapters, with real tenant permissions, entitlements, retention and response compatibility still unverified. No hosted MCP, installed Desktop release or production deployment is claimed. Coverage remains incomplete or unknown; unsigned local receipts do not establish custody or vendor authenticity.
