# Mithril App for Hermes Desktop

Mithril App adds an ontology-authored coding workspace, bounded agent sessions,
profile Cron controls, and a governed Kanban dispatch lane to Hermes Desktop.

## Compatibility

- Hermes Agent and Hermes Desktop `>=0.21.4,<0.22`
- macOS and Linux
- The desktop bundle uses only `@hermes/plugin-sdk` and React imports admitted
  by the Hermes plugin validator.

The package includes a dashboard adapter for Hermes' bundled Kanban plugin.
Set `MITHRIL_CODING_REGISTRY` to an absolute JSON file path to override the
default `~/.hermes/mithril/coding-tool-registry-v1.json` workspace registry.

The registry file has this shape:

```json
{
  "format": "https://mithril.fund/profile/coding-tool-registry-v1",
  "profiles": [
    {"workspace": "/absolute/workspace", "tool-profile": "default"}
  ]
}
```

Download the versioned zip from Mithril Registry's GitHub release and verify
the SHA-256 in `plugins/mithril-app/manifest.json`. Extract its `mithril-app`
directory to `~/.hermes/plugins/mithril-app`, then run
`hermes plugins enable mithril-app`. Restart or reload Hermes Desktop so the
unified plugin's `desktop/plugin.js` is discovered.
