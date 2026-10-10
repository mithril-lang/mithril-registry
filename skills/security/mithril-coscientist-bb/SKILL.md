---
name: mithril-coscientist-bb
description: Run a deterministic Coscientist bug-bounty challenge round when the user asks to plan, advance or review a public bug-bounty finding using the GOOGLE/PYTHON/DOCUMENTATION/EXPERIMENT loop.
license: Apache-2.0
metadata:
  version: 0.1.0
  author: Mithril
  hermes:
    tags: [mithril, security, bug-bounty, coscientist, planner-loop]
---

# Mithril Coscientist bug-bounty round

Use when the user wants to run a bug-bounty challenge as a bounded
planner loop. Apply the Coscientist method (Boiko et al., Nature 2023): a
Planner LLM proposes a small command plan; deterministic modules execute and
observe; a hypothesis ledger advances; a human gate submits.

The deterministic core is the owning profile's `mithril_coscientist_bb`
(stdio MCP, or `node bin/mithril-coscientist-bb.mjs` on the reviewed
artifact commit). It is offline-verifiable: it validates and digests the
plan and advances the ledger. It does not call the network, execute target
code, probe a deployment or submit a report.

## Round vocabulary

`op` is `round`, `hypotheses` or `report` (default `report`).

- `goal` — the round's aim, one sentence.
- `commands` — non-empty, at most 12, unique `ref`. `kind` is one of
  `GOOGLE`, `PYTHON`, `DOCUMENTATION`, `EXPERIMENT`. `EXPERIMENT` names a
  registered tool; the others normalize to declarative bindings
  (`web_search`, `web_extract`, `execute_code`) run by the Planner/agent.
- `observations` — `{digest, status: complete|partial|error,
  observedBytes <= 262144}`.
- `hypotheses` — `{hypothesisId, statement, experiments: [{commandRef,
  result: confirmed|refuted|unknown}]}`.

## Loop

1. Planner proposes a `goal` plus commands. Prefer `EXPERIMENT` commands
   bound to `mithril_public_repo_review` (public repositories) and
   `mithril_dependency_upgrade` (lockfile recheck) for a public-repo lane;
   use `GOOGLE`/`DOCUMENTATION` for brief/scope discovery and `PYTHON`
   for budget or triage arithmetic.
2. Execute each `EXPERIMENT` in the owning profile. Record each result as
   `confirmed`, `refuted` or `unknown`. Do not fabricate an observation.
3. Submit `op:report` with the round plus hypotheses. A `confirmed`
   experiment sets the hypothesis `confirmed`; `submit_to_human` is the
   only hand-off. `continue` means run another round; `observe_more` means
   observations were not yet recorded.

## Limits and honesty

- A confirmed hypothesis is a candidate for human review, not a confirmed
  vulnerability; zero confirmed hypotheses does not mean safe.
- `unknown` results keep the hypothesis open; never retry an unknown
  outcome automatically.
- Digests are `sha256:` over canonical JSON; identical input yields an
  identical digest. Report the digest, command count and decision.
- No network, no target execution, no probe, no submission is performed by
  this skill; those belong to the experiment tools and the human gate.
