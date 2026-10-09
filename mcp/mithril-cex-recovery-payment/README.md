# Mithril CEX Recovery Payment Settlement
Builds a canonical recovery-payment settlement instruction with idempotency key and fee allocation. No funds move: settlement execution requires the owning profile to present the instruction to the settlement channel.

## Execution model
- Artifact: mithril-lang/mithril-system-one @ a478c27050ac77d0cd841af07d4fe78b6ddb0f86
- Entry: `node bin/cex-recovery-payment.mjs` (stdin JSON -> stdout JSON)
- Deterministic, offline-verifiable: no live endpoint is called.
- The tool emits a receipt with a canonical digest and `executed:false`;
  actual exchange / authority / settlement actions require the owning profile
  to execute them against the live counterparty and return the acknowledgement.

## Registry linkage
- Solution contract: `mithril-exchange-asset-recovery-design` (solutions/exchange-asset-recovery.json)
- This tool covers exactly one `notProvided` capability of that contract; on merge the
  corresponding entry moves to `providedBy` with `executionStatus: deterministic-offline`.
