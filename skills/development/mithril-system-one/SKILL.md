---
name: mithril-system-one
description: Implement and verify supported Mithril coding tasks, ontology repairs and semantic refactors using the System One harness when the user wants a checked Mithril artifact.
license: Apache-2.0
metadata:
  version: 0.3.1
  author: Mithril
  hermes:
    tags: [mithril, coding, ontology, system-one, refactor]
---

# Mithril System One coding

Use the owning profile's `mithril_task` for a single task and `mithril_workflow`
for 1–3 distinct tasks. The same operations are available from the local MCP
`mithril_task_run` / `mithril_workflow_run`; use `mithril_task_list` to discover
supported tasks. A reviewed checkout and `npm run setup:dynamic` are required
for dynamic tasks. Installation and connection instructions are in the
[Registry runtime guide](https://github.com/mithril-lang/mithril-system-one/blob/f940459126490a81b86d6d3474e48205b7bdf9c2/docs/registry-runtime.md).

Choose `ontology` for the deterministic catalog planner, or `system-one` when
the user wants one model proposal via api.mithril.fund. The latter uses the owning
profile/process Mithril credential; never borrow another profile's token or place
one in prompts, exported MCP configuration or source files.

Supported tasks are create-report, repair-summary, migrate-directory, repair-shape,
repair-import, compact-refactor, dynamic-repair-inheritance,
dynamic-repair-validation and dynamic-refactor. Choose the task matching the
user's supported contract. Do not disguise an unsupported request as a supported
one. Proposed source is `.mith`; the existing compiler/reasoner establishes its
behavior. Dynamic cases execute OWL inference and SHACL validation over changing
inputs; they do not establish general browser mutation or arbitrary code execution.

Inspect `row.success`, `row.outcome_unknown`, trace checks and actual receipts.
Keep failed attempts in the result, stop on an unknown outcome and never retry
it automatically. Report task pass rate, measured time and token usage; billed
USD is unknown unless actually measured. These original tasks do not constitute
Artificial Analysis, SWE-bench or Terminal-Bench results.

Return the candidate source and verification evidence to the user's existing
Desktop/Web/Agent flow. Saving, GitHub commits and publication use that product's
existing authorization; invoking this skill or harness does not perform them.
