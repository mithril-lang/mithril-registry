# Mithril System One workflow

This executable finite workflow runs 1–3 distinct supported task IDs in order.
All inputs are checked before the first external call. Each task returns the same
Mithril candidate and compiler/runtime receipts as the agent. The workflow stops
on the first failure or unknown outcome and never retries.

Check out the immutable artifact commit in `manifest.json`, run
`npm run setup:dynamic`, and execute:

```sh
printf '%s' '{"task_ids":["dynamic-repair-inheritance","dynamic-repair-validation","dynamic-refactor"],"method":"ontology"}' |
  node /ABSOLUTE/REVIEWED/CHECKOUT/bin/mithril-workflow.mjs --stdin
```

Hermes exposes the same executor as `mithril_workflow`; MCP exposes
`mithril_workflow_run`. `system-one` uses at most one model proposal per task and
requires the owning host's Mithril API credential. This workflow does not install
schedules, save files, commit, publish, or grant ambient shell access.
