# Copilot Studio integration contract

Copilot Studio is a managed Microsoft service. The Registry owns portable definitions and integration contracts; it does not own or redistribute Studio's runtime. Keep GitHub Copilot model/ACP integration separate from Copilot Studio integration.

Two adapters are required for different use cases: an authoring adapter for local agent definitions and Dataverse synchronization, and an invocation adapter for conversations with a published Studio agent. This package supplies neither adapter and does not claim runtime invocation support.

For authoring, the official Power Platform CLI supports `pac copilot clone`, `pull`, `push`, `pack`, and `publish`. Clone/pull retrieve definition state, push changes the remote definition, pack creates a local solution package, and publish changes the live agent. A successful push is not publication. Always select the authenticated profile and explicit environment; do not rely on the CLI's ambient active organization. The host must verify CLI version, harness support and actual command behavior before execution.

The sample workflow inspects a definition, pushes reviewed changes and publishes after a separate concrete approval. Logical operation IDs in `integration.json` are host contracts, not CLI commands. The executor must bind them to tested commands, verify conflicts with remote state, and retain the exact definition commit/digest, environment, agent and publication receipt. A timeout during push/publish leaves an unknown result until reconciled.

MCP is an independently verified connection. Studio's ability to consume MCP tools does not mean a Studio agent is automatically an MCP server. An authoring MCP endpoint and a published-agent conversation endpoint are also different. Require a configured server, handshake and tool contracts instead of synthesizing a Studio URL.

Portable skill files may be uploaded to a compatible GitHub Copilot harness agent as `SKILL.md` or a packaged ZIP. Validate the target harness and resource support before claiming portability. A `.mith` or Mithril workflow is not native Studio YAML; translation is a future adapter responsibility with round-trip tests.

The `tenant`, `environment` and `agent` references must identify one explicitly chosen destination. Power Platform authentication stays in the host; the public Registry stores no tenant credentials or live agent content. Treat `studio:read`, `studio:write` and `studio:publish` as Mithril capabilities mapped by the adapter, not Microsoft OAuth scopes.

Official references, checked 2026-10-06: [Power Platform CLI copilot commands](https://learn.microsoft.com/en-us/power-platform/developer/cli/reference/copilot), [Studio Agent Skills](https://learn.microsoft.com/en-us/microsoft-copilot-studio/agents-experience/skills-overview), [Microsoft authoring plugin](https://github.com/microsoft/copilot-studio-plugin). These establish available integration mechanisms; no live Studio tenant was tested here.
