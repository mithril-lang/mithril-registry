---
name: mithril-enterprise-integrations
description: Design and validate Google Workspace and Copilot Studio compositions of skills, MCP bindings, agents, workflows and plugins; generate scoped plans without authenticating or executing external actions.
version: 0.1.0
author: Mithril
license: Apache-2.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [google-workspace, copilot-studio, integration, agents, workflows, plugins, mcp]
    category: productivity
---

# Mithril Enterprise Integrations

Use this package to review and plan enterprise integrations. The packaged Python planner runs locally with the standard library. The ten provider components are design contracts, not executable adapters or installable native plugins. Installing this skill does not connect an account, install an MCP server, or publish an agent.

1. Read the selected provider reference in full: [Google Workspace](references/google-workspace.md) or [Copilot Studio](references/copilot-studio.md).
2. Choose the requested component from `integration.json`. Skills contain reusable instructions, MCPs describe tool connections, agents bind behavior and capabilities, workflows order operations, and plugins compose the other four kinds.
3. Validate the definition with `python3 scripts/planner.py`. Generate a plan with `python3 scripts/planner.py --component google-workspace-plugin` or `--component copilot-studio-plugin`, relative to this skill directory.
4. When the user has supplied the destination, use `--context` with a local JSON file containing only a `principal` reference and `target` references. Google targets require `workspace` and `account`; Studio targets require `tenant`, `environment` and `agent`. Never put tokens, secrets or credential files in this context or Git.
5. Review dependency order, requested permissions, operation effects, prerequisites and `blockedBy`. A plan always has `executable: false` because this release does not ship execution adapters. Do not present the plan as a completed integration or run.
6. Hand the reviewed plan to the host implementation team. The host must bind authentication, verify runtime support and MCP handshakes, enforce owner/session isolation, and produce live qualification evidence before executing anything. A plan digest is an integrity reference, not a signature or authorization token.
7. For future write/publish execution, bind approval to the concrete payload, principal, destination and plan digest. These definitions record approval requirements; the planner neither gathers approvals nor executes their actions.

Git manages definitions and packages; credentials, connected state and execution receipts belong to the host. Reuse the existing Mithril Google Workspace implementation rather than introducing a parallel OAuth store. Copilot Studio authoring and published-agent invocation are separate capabilities.
