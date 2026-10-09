# Mithril CEX Automatic Freeze Execution
Evaluates a deterministic automatic-freeze policy gate over a validated submission package and exchange account state. Returns an executable/no-action plan; the freeze itself is NOT executed by this tool.

## Execution model
- Artifact: mithril-lang/mithril-system-one @ a478c27050ac77d0cd841af07d4fe78b6ddb0f86
- Entry: `node bin/cex-freeze-execution.mjs` (stdin JSON -> stdout JSON)
- Deterministic, offline-verifiable: no live endpoint is called.
- The tool emits a receipt with a canonical digest and `executed:false`;
  actual exchange / authority / settlement actions require the owning profile
  to execute them against the live counterparty and return the acknowledgement.

## Registry linkage
- Solution contract: `mithril-exchange-asset-recovery-design` (solutions/exchange-asset-recovery.json)
- This tool covers exactly one `notProvided` capability of that contract; on merge the
  corresponding entry moves to `providedBy` with `executionStatus: deterministic-offline`.
