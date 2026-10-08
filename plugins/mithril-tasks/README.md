# Mithril System One plugin

Install the immutable artifact in `manifest.json` through the owning Hermes
profile's normal plugin manager. The package exposes `mithril_task` and
`mithril_workflow` in the `mithril_tasks` toolset.

```sh
hermes -p PROFILE plugins install https://github.com/mithril-lang/mithril-system-one/tree/main/adapters/hermes/mithril-tasks --ref caa9a2f2c8aa4448664ad333a7a4a0e26bbea85d --no-enable
hermes -p PROFILE config set plugins.entries.mithril-tasks.settings.system_one_root /ABSOLUTE/REVIEWED/CHECKOUT
hermes -p PROFILE plugins enable mithril-tasks --no-allow-tool-override
```

Check out the same artifact commit at the configured path and run
`npm run setup:dynamic`. Use a new chat to discover updated tools. No additional
profile, core tool override or global gateway restart is required. The existing
owning-profile Mithril credential is used only for explicit `system-one` calls.
Neither the plugin nor its Registry entry performs a save, commit or publication.
Actual native plugin verification uses Hermes 0.21.5 on macOS; Linux CI verifies
the executable task/MCP/workflow paths. Installed Desktop UI interaction is a
separate qualification, not established by those checks.
