# Google Workspace integration contract

The existing Mithril Agent `skills/productivity/google-workspace/` implementation provides OAuth refresh and Google API operations through `gws` or the Python adapter. Reuse it through a host adapter; this Registry package neither copies that implementation nor installs it from a sibling checkout.

The sample composition retrieves Drive material, prepares a Docs document, and sends a reviewed Gmail message. Its declared permissions are `google:drive.read`, `google:docs.write` and `google:gmail.send`; these are Mithril capability names, not literal OAuth scopes. The host maps each operation to its minimal Google API scopes and verifies the selected account. Calendar, Sheets and Contacts remain supported by the existing skill but are outside this sample workflow's grants.

The MCP component is a binding contract for a user-selected server, not a claim that Google or Mithril already hosts a server. The host must verify `initialize`, `tools/list`, tool input schemas, access modes and effects. A server advertising extra tools does not expand the composition's permissions. A Google CLI installation does not prove an MCP endpoint exists.

The `workspace` and `account` target references must resolve to the same authenticated identity. Credentials stay in the host's profile-scoped store. Do not use ambient credentials from another profile or silently substitute a personal Gmail account for the requested Workspace account.

The future executor must retain input/source identifiers and receipt hashes, redact content from routine logs, and distinguish local document drafts from remote document creation. Gmail send and Docs creation require the recorded approval boundary. If a request times out after a remote write, mark its outcome unknown and reconcile before retrying; email must not be blindly resent.

Git contains the definitions, instructions and tests. Runtime secrets, mail bodies, private documents and account tokens do not belong in the public Registry.

Official integration reference, checked 2026-10-06: [Google Workspace CLI](https://github.com/googleworkspace/cli). API coverage depends on the host's installed version and granted scopes; it is not qualified by this offline planner.
