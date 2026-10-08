# Mithril Public Code Review Registry integration

Five entries share ID `mithril-public-review`, version 0.1.0 and one immutable runtime artifact, `6f684875b0cb5300780d52ba8745caa3a604aaf6` in [mithril-system-one](https://github.com/mithril-lang/mithril-system-one/tree/6f684875b0cb5300780d52ba8745caa3a604aaf6).

- Skill: scope and evidence instructions.
- Plugin: opt-in native Agent `mithril_public_repo_review`, toolset `mithril_public_review`.
- Agent: one public commit review, plus packaged `mithril-public-code-review` profile metadata/config/SOUL/USER.
- Workflow: one bounded review, stop on failure/unknown, no automatic retries.
- MCP: the same read tool through local stdio 2025-06-18.

[Typed composition](../skills/security/mithril-public-review/integration.json) separates deterministic tool readiness from unqualified provider conversations, scheduled scans and GitHub writes. The Registry index exports the agent's `botProfile` descriptor. The existing Desktop/Agent profile picker remains the user flow; no separate public security dashboard or provider credential store is added.

## Install and use

Review the artifact, use Node 22+, then `npm ci --ignore-scripts`, `npm run setup:dynamic` and `python3 scripts/install-public-review-profile.py --home /absolute/hermes/home --apply` from its checkout. Select `mithril-public-code-review` in a new Agent/Desktop session. The installer creates independent files with private permissions and no keys, copied history, cron, channel or running gateway. The profile's future conversation provider is api.mithril.fund and requires its own credential; deterministic review does not.

Call `mithril_public_repo_review` with exactly `repository` (`owner/name`) and `commit` (40 lowercase hexadecimal characters). JSON stdin uses `bin/mithril-public-review.mjs --stdin`; MCP uses `bin/mithril-public-mcp.mjs`. [Full runtime contract](https://github.com/mithril-lang/mithril-system-one/blob/6f684875b0cb5300780d52ba8745caa3a604aaf6/docs/public-code-review-bot.md).

## Qualification on 2026-10-08

Native Agent `0.21.5+4485.g3da66ca.dirty` and the actual MCP SDK each successfully reviewed `mithril-lang/mithril-system-one` commit `b4489ce0e5a7680b5b2da9620841f16207bdfff4`. Acquisition checked 275 inventory entries and parsed 47 files, excluding 228. Seven child_process observations had unknown input paths, with zero candidates. Result was `review_incomplete`; all-unknown data produced a real compiler/graph receipt without asserting security facts. Controlled fixtures separately produced a direct CLI-to-shell policy candidate.

Native profile discovery A → isolated-other → A yielded tool visible → absent → visible. Local runtime qualification passed 48 unit + 3 Todo, 18 Python, 5 public-review, 6 security and 7 dynamic tests. Registry suite passed 124 tests (12 optional engine/environment tests skipped). Index freshness passed. GitHub Actions is not a qualification dependency. macOS is verified; Linux execution and installed Desktop click-through are not separately qualified.

No target code executes and no repository content goes to an LLM. This is a conservative ESM child_process subset, not general SAST, taint analysis, authentication verification, CVE analysis, environment inventory or exploit proof. Every result preserves incomplete scope; zero candidates never establishes safety. No provider key was copied and no live conversation, autonomous monitoring, remediation, GitHub posting or external disclosure was enabled.
