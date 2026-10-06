# Enterprise integration composition

Google Workspace and Copilot Studio share a composition contract in Mithril Registry. Version 0.1.0 ships a portable planning skill, ten typed component definitions, a deterministic catalog and an offline planner. It does not ship authenticated vendor execution, a new MCP server, a native plugin, Studio publication, or an App/Desktop installer change.

## Component responsibilities

Each provider has one component of each of the following kinds. A plugin composes the other four; a workflow depends on an agent; an agent depends on its skill and MCP binding. The dependency graph declares a capability union and is validated before a plan is generated.

| Kind | Definition owns | Runtime owns |
| --- | --- | --- |
| skill | Task instructions and provider references | Progressive loading through the existing skill system |
| mcp | User-configured binding and handshake requirements | MCP client, OAuth, verified tools and transport |
| agent | Behavior, skill/tool dependencies and declared permissions | Session, model, owner-scoped invocation and delegation |
| workflow | Operation order, effects, approvals and permissions | Durable jobs, step receipts, approval enforcement and reconciliation |
| plugin | The coherent composition of those four kinds | Host mounting, runtime compatibility and session activation |

`integration.json` uses `schemaVersion`, `version`, `providers` and `components`. Every component declares `id`, `kind`, `version`, `provider`, `execution`, `requires`, `permissions` and `description`. Provider records declare target fields, credential references, prerequisites and qualification. Workflow steps declare the operation, component, effect, permissions, preceding steps and approval mode. Permission labels are Mithril capability names, not vendor OAuth scopes.

## Registry and GitHub

The source of truth is `skills/productivity/mithril-enterprise-integrations/integration.json`. `scripts/build_index.py` validates it and generates `integrations.json`. The existing `index.json` contains only the actual planning skill with an additive `integration` reference. Design-only MCP/agent/workflow/plugin components are not advertised as installable extensions. Existing clients can keep reading the current four distribution types without an installer migration.

Review definition changes through GitHub PRs. A future installer must resolve the exact repository commit, verify the package checksum from `index.json`, and validate the composition digest from `integrations.json`. Each plan embeds component versions/digests and the complete definition digest; changing definitions or target references changes its plan digest. Digests do not provide author authenticity or grant permission. Do not resolve a mutable `main` reference at execution time.

Credentials, tenant data and runtime connection status stay outside Git. There is no automatic synchronization between a checked-in definition and a live service. The generated catalog always states `runtimeReady: false` in this release. Metadata cannot turn an unqualified provider into a verified one.

## Planning

The skill's `scripts/planner.py` runs with Python's standard library, reads local JSON, validates dependency and step DAGs, and prints a deterministic plan. It starts no subprocesses, calls no network, loads no credentials and performs no external writes. Registry generation imports the planner from this trusted repository source; generated catalogs are data for clients and must never be imported as code.

From the Registry checkout:

```sh
python3 scripts/build_index.py --check
python3 skills/productivity/mithril-enterprise-integrations/scripts/planner.py --component google-workspace-plugin
python3 skills/productivity/mithril-enterprise-integrations/scripts/planner.py --component copilot-studio-plugin
```

Optional context contains reference strings only. Google targets require `workspace` and `account`; Studio targets require `tenant`, `environment` and `agent`. For example:

```json
{
  "principal": "profile:review-example",
  "target": {"tenant": "example-tenant", "environment": "example-environment", "agent": "example-agent"}
}
```

Passing this file with `--context` removes missing-reference blockers. It never removes the execution-adapter and live-qualification blockers. These references are supplied assertions; the host must verify identity and ownership before use. Context rejects unknown fields, but is not a content-based secret scanner: never put a secret inside a permitted reference string.

## Host integration boundary

The next host implementation consumes the plan without changing model tool schemas or session prompts mid-conversation. Reuse Agent's existing skills, MCP discovery, plugin registration and owner-scoped connector lifecycle. In Web and Desktop, shared UI may display the same definition and readiness; Web authentication/API transport and Desktop IPC/credential access remain separate adapters. Do not let a renderer access credentials or inherit another session's target.

Readiness must be measured for the exact principal, provider, target, host runtime and package version. Distinguish discovered, installed, configured, authenticated, handshake-verified, enabled and qualified states. An install button or a successful catalog fetch is not a connected account. Mount/unmount affects future sessions unless an explicit cache-aware activation is supported by the host.

The executor must validate every operation against adapter-supported schemas and declared effects. An MCP tool list cannot grant additional permissions. Reject unsupported capabilities, provider substitutions, mismatched targets and missing authentication. Workflow payloads, limits and operation-specific fields are intentionally not executable schemas in this release; adding an executor requires those schemas and a concrete adapter.

## Provider adapters

Google Workspace reuses the existing Agent skill through `gws` or its Python adapter. The sample workflow reads Drive, creates a Docs document and sends reviewed Gmail content. Calendar, Sheets and Contacts can be added as separate operations with their own permission sets. No fallback to a different Google account is permitted.

Copilot Studio uses distinct authoring and conversation adapters. The authoring path can use Power Platform CLI to retrieve, edit, push and publish definitions; the conversation path must authenticate against the supported published-agent endpoint. Neither an ACP Copilot model provider nor Studio's MCP client is an implementation of the other path. The sample workflow models inspection, push and publish without fabricating an endpoint. Provider details and official references live in the packaged skill references.

`.mith` components can author a closed composition whose exported definitions match this contract. This release contains no `.mith` compiler/exporter changes and does not imply that Mithril workflow JSON is accepted by Studio. A later exporter must test versioned round trips and preserve permissions, operation effects and dependency identities.

## Execution and qualification

A future executor binds approval to the concrete payload digest, principal, target, operation effects, package version and reviewed plan digest. It records an immutable run ID and step receipts. Write/publish steps require explicit approval in these definitions. Reads remain bounded by the selected scope; workflow composition is not blanket authority.

Persist step state before invoking a vendor. If a side effect might have occurred before a timeout, record `unknown` and reconcile against the vendor before retrying. Retry policies must distinguish idempotent reads, document creation, mail sending, definition push and publication. Cancel prevents further steps and cannot imply undo of completed remote writes. Resume must recheck identity, target, approvals and plan digest.

Qualification requires authenticated tests of the selected operations, cross-profile isolation, tool handshake/schema checks, conflict handling, timeout reconciliation and recorded version provenance. Studio push and publication need independent receipts; Google retrieval, document creation and sending need independent receipts. None of these live checks occurred for this offline package.

## Validation

Tests cover both provider compositions, dependency ordering/cycles, missing dependencies, cross-provider authority, permission escalation, approval removal, workflow cycles, secret-field rejection, target-sensitive digests, fabricated MCP endpoints, catalog compatibility and the actual packaged CLI. Run `python3 -m unittest discover -s scripts -p 'test_enterprise_integrations.py' -v`; the existing CI also checks generated catalog freshness and runs the Registry suite.
