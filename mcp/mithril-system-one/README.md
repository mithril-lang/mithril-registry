# Mithril System One MCP

A local stdio MCP server backed by the actual shared System One executor. This
entry has no hosted HTTP endpoint. Check out the immutable artifact commit in
`manifest.json`, run `npm run setup:dynamic`, then launch:

```sh
node /ABSOLUTE/REVIEWED/CHECKOUT/bin/mithril-mcp.mjs
```

Replace `${system_one_root}` in the manifest's argument with that local checkout.
The server supports MCP 2025-06-18 `initialize`, `notifications/initialized`,
`ping`, `tools/list`, `tools/call`. It offers `mithril_task_list`,
`mithril_task_run` and `mithril_workflow_run`. JSON-RPC uses newline-delimited
stdio; stdout contains only protocol messages. The protocol sequence and actual
dynamic task execution are tested in the harness's dynamic-runtime CI job.

`ontology` requires no inference token. `system-one` requires the owning process's
`MITHRIL_API_KEY`; supply it through the host's scoped credential store, not a
literal value in exported configuration. The dynamic compiler child receives no
inference credential. Listing tools makes no model/compiler call. Inputs cannot
choose arbitrary paths, commands or unknown task IDs. No Git, file-save or publish
effect is provided. A local MCP server cannot execute inside a remote Web browser;
connect it through an explicitly configured owner runtime.
