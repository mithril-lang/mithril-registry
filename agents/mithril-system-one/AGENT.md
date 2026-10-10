# Mithril System One Coding

**System One Coding** is the development method; **Mithril Semantic Loop** is its agent loop. The technical descriptor is **ontology-driven generation and verification**. These names describe the supported executor contract below.

This specialized bounded coding agent runs inspect → propose → apply → compile
→ independent verification using the shared harness. It accepts one supported
task and returns Mithril source plus actual receipts. It is not a general agent.

Check out `manifest.json`'s immutable Git artifact, run `npm run setup:dynamic`,
and send the task as JSON to its fixed entrypoint:

```sh
printf '%s' '{"task_id":"dynamic-refactor","method":"ontology"}' |
  node /ABSOLUTE/REVIEWED/CHECKOUT/bin/mithril-task.mjs agent --stdin
```

Use `system-one` only for an explicitly selected model proposal with the owning
profile/process's Mithril API credential. The ontology method uses deterministic
catalog rules. Both paths require real compiler/runtime admission and the same
independent contract. Unknown outcomes stop without retry. Results contain no
implicit save, GitHub or deployment action. The same executor is available via
the native Hermes plugin and the MCP registration; use either existing host path.
