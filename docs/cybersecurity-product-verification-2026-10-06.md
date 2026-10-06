# Cybersecurity product support verification

Measured 2026-10-06 JST, Registry. This addition packages a standalone Python CLI, local stdio MCP and discoverable skill; it does not deploy a Worker or change vendor tenants.

- Three adapters: Cortex XDR supplied alert JSON plus basic-key fixed read POST; Trend Vision One supplied Workbench JSON plus bearer fixed read GET; Wiz supplied issue-page JSON only.
- Seven new tests cover byte/digest retention, private filesystem output, vendor claims/coverage, malformed/error payloads, exact vendor origins/fixed requests, an actual HTTP simulator with synthetic credentials, no nextLink following, network opt-in, redirect refusal and stdio MCP notification/write separation.
- Registry suite: 53 tests, 41 passed, 12 existing engine/provisioning tests skipped when operator engine checkouts are absent. Deterministic index and plugin artifact checks passed.
- Official MCP TypeScript SDK 1.32.1 independently connected to the real Python stdio subprocess: initialize, tools/list, cybersecurity_products and cybersecurity_import passed. Wiz synthetic source/receipt count was read back from disk. Network-enabled collection is tested using the simulator, not an actual vendor account.
- The Registry validator admits its required author/version/platforms frontmatter. Generic Codex skill-creator validation passed on the same entrypoint with those Registry-specific keys omitted in a temporary validation copy; source metadata remains in Registry format.

No production API credentials, licenses, representative tenant exports, vendor cloud calls or App/Desktop installation were used. `fixture-tested` must not be promoted to live qualification. APIs have one-page coverage and no remediation actions. Wiz's tenant schema and direct API remain unavailable; the supported JSON shape is an explicit adapter input contract.

New vendor support follows the contract and tests in `skills/security/mithril-cybersecurity-products/references/products.md`. Secrets stay in operator environments. Retained source files may contain sensitive vendor fields; they remain private local data and must not be attached to repository commits.
