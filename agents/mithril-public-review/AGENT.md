# Mithril Public Code Review (agent)

This surface composes the `mithril-public-review` skill, plugin, agent, workflow and MCP into the existing Mithril Agent/Desktop profile flow. Runtime artifact: [299937c](https://github.com/mithril-lang/mithril-system-one/tree/299937c2e6cb11d36fbdde1278db64723867096c). [Execution contract and installation](https://github.com/mithril-lang/mithril-system-one/blob/299937c2e6cb11d36fbdde1278db64723867096c/docs/public-code-review-bot.md).

Input: public `owner/repository` plus an exact 40-character commit. The tool verifies source provenance, parses a bounded JavaScript ESM child_process subset and executes `.mith` ontology policies. Result is always `review_incomplete`; candidates require human review. No target code execution, inference, private repository access, GitHub writes or disclosure.

The `mithril-public-code-review` bot profile uses English and api.mithril.fund for future conversations. Install it with the artifact's `scripts/install-public-review-profile.py --home /absolute/hermes/home --apply`; credentials belong to that profile and are configured separately. No active-profile switch, gateway startup or scheduled jobs occur. Deterministic tool readiness is verified; a live provider conversation is not.

Native Agent tested on macOS with 0.21.5+4485.g3da66ca.dirty. Linux compatibility is not qualified. MCP is local stdio 2025-06-18, not a hosted URL. Workflow runs exactly one immutable repository review and stops on failure/unknown without retries.
