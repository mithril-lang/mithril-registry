# Mithril Knowledge Contributions MCP

Console の `/knowledge/contributions` は説明専用です。投稿フォーム、非公開履歴、撤回・異議申立て、管理者の処理画面は提供しません。情報提供者の操作は次の MCP または認証済み REST API から行います。

- URL: `https://api.mithril.fund/v1/knowledge/mcp`
- Transport: stateless Streamable HTTP, POST only
- Protocol: `2025-06-18` (also accepts `2025-03-26`, `2025-11-25`)
- Headers: `Authorization: Bearer <Mithril API token>`, `Content-Type: application/json`, `Accept: application/json, text/event-stream`
- Browser cookies are not MCP credentials. Supply secrets through the client's credential store, never commit them into configuration.

| Tool | Scope | Effect |
| --- | --- | --- |
| `mithril_knowledge_history` | `knowledge:read` | Own paginated private history |
| `mithril_knowledge_contributor_summary` | `knowledge:read` | Own contribution/credit totals |
| `mithril_knowledge_submission_status` | `knowledge:read` | Own private record and review history |
| `mithril_knowledge_submit` | `knowledge:write` | Private evidence and consented public preview |
| `mithril_knowledge_withdraw` | `knowledge:write` | Queue public removal; retain earned credits |
| `mithril_knowledge_profile` | `knowledge:write` | Set own pseudonym and explicitly enable/disable public leaderboard participation |
| `mithril_knowledge_appeal` | `knowledge:write` | Private clarification; no additional reward |

Initialize the connection, then request `tools/list` for authoritative input schemas and scoped tool availability. `GET /v1/knowledge/program` reports reward intake availability. Save one stable `requestId` for a submission and reuse it after a lost acknowledgement. A changed package requires a new ID. Do not split or copy submissions to claim extra rewards.

Before `submit`, show the exact `publicPreview` and obtain explicit permission for public reading and reuse. Use the current consent version from the live input schema. Keep `privateNote` and `incidentKey` out of the public preview. Do not include passwords, identity documents, addresses or victim identities. Do not transmit private evidence or returned history to another service without explicit permission. Public copies can persist after withdrawal.

This client has no review, publication or credit-grant tool. Removing the human processing UI does not remove the existing administrator assurance, evidence/privacy, novelty, version-CAS, publication receipt/hash or idempotent ledger gates. Review authority remains separate from contributor tokens. The server dispatches publication and settlement after an authorized review; it never pays at submission.

The Registry owns discoverability, declared scopes and generated checksums; `api.mithril.fund` owns authentication, owner isolation, records and side effects. No extra DB, fallback service, local reviewer or automatic approval is introduced. Public Knowledge search/context and leaderboard stay separate from private contributions.

Fund 1.1.1 retains both REST and MCP alongside the explanation-only screens. REST supports `POST/GET /v1/knowledge/submissions`, `GET /v1/knowledge/submissions/:id`, and `POST /v1/knowledge/submissions/:id/withdraw` or `/appeal`. Existing session/Origin protection and scoped bearer authentication remain; both transports use the same owner, consent, idempotency and reward checks. Publish the compatible Fund API via its existing main-only CI before treating this Registry entry as production-qualified. Source tests and Registry validation do not prove authenticated live MCP operation.
