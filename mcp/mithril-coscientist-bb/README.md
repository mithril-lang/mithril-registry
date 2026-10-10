# Mithril Coscientist Bug Bounty Core

Deterministic planner-round ledger for bug-bounty challenges, registered as
an offline-verifiable stdio MCP entry.

## Input (stdin JSON)

`op` is one of `round`, `hypotheses` or `report` (default `report`).

- `goal` — non-empty string: the round's aim.
- `commands` — non-empty array, at most 12 per round, unique `ref` each.
  `kind` is one of `GOOGLE`, `PYTHON`, `DOCUMENTATION`, `EXPERIMENT`
  (the Coscientist command space, Boiko et al., Nature 2023).
  `EXPERIMENT` requires a registered `tool`
  (`mithril_public_repo_review`, `mithril_business_process_review`,
  `mithril_scap_review`, `mithril_dependency_upgrade`, `web_search`,
  `web_extract`, `terminal`, `read_file`, `git_ls_remote`, aliases).
  `GOOGLE`/`DOCUMENTATION`/`PYTHON` normalize to declarative bindings
  (`web_search`, `web_extract`, `execute_code`) executed by the owning
  Planner LLM / agent.
- `observations` — optional: `{digest, status: complete|partial|error,
  observedBytes <= 262144}`.
- `hypotheses` — optional (for `hypotheses`/`report`): array of
  `{hypothesisId, statement, experiments: [{commandRef, result:
  confirmed|refuted|unknown}]}`.

## Output (stdout JSON)

A single receipt `{tool, version, success, receipt|code, ...}`. Digests are
`sha256:` over canonical JSON; identical input yields an identical digest.

## Execution status

`deterministic-offline`. The tool never calls the network, never executes
target code, never probes a deployment and never submits a report. A
`submit_to_human` decision is a hand-off, not a submission.

## Limits

- 12 commands per round, 32 hypotheses, 256 KiB observation bytes.
- A confirmed hypothesis is a candidate for human review, not a confirmed
  vulnerability; zero confirmed hypotheses does not mean safe.
- The Planner LLM is external to this module; this entry validates and
  digests its command plan only.
