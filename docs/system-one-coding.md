# System One coding Registry integration

Five Registry surfaces share the public Mithril-specific coding harness at
`caa9a2f2c8aa4448664ad333a7a4a0e26bbea85d`:

| Type | Registry path | Execution |
| --- | --- | --- |
| Skill | `skills/development/mithril-system-one` | Host instructions for checked Mithril tasks |
| MCP | `mcp/mithril-system-one` | Local stdio; initialize/list/run/workflow |
| Agent | `agents/mithril-system-one` | One bounded inspect/propose/apply/compile/verify task |
| Workflow | `workflows/mithril-system-one` | 1–3 distinct tasks, sequential, stop on failure/unknown |
| Plugin | `plugins/mithril-tasks` | Native `mithril_task` and `mithril_workflow` |

Executable definitions carry the same immutable Git artifact, a fixed entrypoint
and required host configuration. `${system_one_root}` is resolved by the user to
a reviewed local checkout; it is not an uploaded device path. Dynamic tasks need
`npm run setup:dynamic`, which installs the pinned real Mithril/Kotoba runtime.
The default ontology method uses no model credential. Explicit System One calls
use api.mithril.fund with the owning profile/process credential. No credential is
stored in a Registry artifact or passed to the dynamic compiler process.

These surfaces return `.mith` source and independent checks. They cannot grant
arbitrary shell, file saves, GitHub access or publication. Existing Desktop/Web
components and transports remain the product's execution and publication owners.
A browser-only host cannot launch a local stdio MCP; it must connect through an
explicitly configured owning runtime. Agent/workflow registration is an executable
finite task capability, not a scheduler or general coding-agent claim.

## Verification on 2026-10-08

- The Skill passes the Agent Skills frontmatter validator and Registry checks.
- Registry unit tests reject mutable artifact refs, arbitrary commands and
  retrying unknown outcomes, and require all five surfaces to share one commit.
- The artifact's Linux dynamic-runtime CI tests the real MCP lifecycle, lists
  three tools, refuses an unsupported task and executes dynamic refactoring.
- The real workflow executes three dynamic tasks, each checked across eleven
  input snapshots, with the same compiler/reasoner and independent verifier.
- An independent Python MCP SDK client initializes the server and executes a
  dynamic task. Native Hermes 0.21.5 default-profile plugin discovery registers
  both tools; a two-task workflow executes through the actual native dispatcher.
- Installed Desktop interaction and browser execution of this local MCP are
  separate qualifications. Registry/source publication and production Discover
  publication must be reported separately.

Registry CI reads the manifest's exact artifact commit and runs its actual dynamic
integration tests, rather than substituting metadata checks for execution proof.
