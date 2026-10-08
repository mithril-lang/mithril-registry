# Private Knowledge 1.0.0 contract

Origin: `https://api.mithril.fund` (fixed HTTPS, redirects refused).

| Operation | Method | Path |
| --- | --- | --- |
| graphs | GET | `/v1/knowledge/graphs` |
| provision account | POST | `/v1/knowledge/graphs/account` |
| provision organization | POST | `/v1/knowledge/graphs/organization` |
| search | GET | collection with `q`, `limit`, `cursor` |
| get | GET | collection plus `/:documentId` |
| put | PUT | collection plus `/:documentId` |
| delete | DELETE | collection plus `/:documentId` |

Account collection: `/v1/knowledge/private/account/documents`.
Organization collection:
`/v1/knowledge/private/organizations/:organizationId/documents`.
Provision organization sends `{organizationId}`; account sends `{}`.
PUT sends `{title,body,expectedRevision,operationId}`; DELETE sends
`{expectedRevision,operationId}`. Only the API determines the authorized graph.

Personal access is owner-only. Active org members read; owner/admin write.
Bodies live in the non-public `mithril-private-knowledge` R2 bucket; D1 retains
graph ownership, title, digest, pointer, revision and operation receipts.
Membership is rechecked around asynchronous R2 work. Responses are private,
no-store; the client does not cache or persist them.

The initial format is UTF-8 text (including JSON serialized as a string).
Title: 1–200 UTF-16 code units; body: at most 16,000; request/object: at most
64 KiB. Maximum 200 document IDs per graph, including tombstones. Search scans
one bounded page with normalized case-insensitive substring matching. No full
text index, binary storage, arbitrary Iceberg/Data Catalog SQL, historical-body
retrieval, permanent erasure or migration of existing private notes is included.
Revisions and unreachable R2 objects are retained.

R2 bytes are read back before a transactional revision compare-and-swap and
operation receipt. Exact retries return the original receipt. Reusing an
operation ID with different data or actor is rejected. A 409 is never permission
to overwrite; retain uncertain request data privately until reconciled.

Backend source/release: [Fund PR #786](https://github.com/mithril-lang/mithril-fund/pull/786).
Authenticated production verification on 2026-10-08:
[run 37728020539](https://github.com/mithril-lang/mithril-fund/actions/runs/37728020539)
verified create/read/search/update, revision conflict, receipt replay,
anonymous/account/org denial, member write denial and membership revocation.
Registry client tests independently verify routing, bounds, opt-in mutation and
secret-safe errors using synthetic transport. This does not claim installation
or authenticated execution in any particular Desktop/Hermes profile.
