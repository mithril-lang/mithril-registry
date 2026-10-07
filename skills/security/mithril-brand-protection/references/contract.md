# Company brand protection

Mithril's private brand workspace compares supplied observations with company assets, groups candidates across repeated observations, and preserves human review history. REST and Streamable HTTP MCP execute the same domain operations and scopes. No match is a legal infringement verdict.

## Implemented scope

- Account-owned company and brand profiles, with multiple trademark/logo/character assets, names, aliases, registration references, jurisdictions, official/authorized domains and optional original image evidence references.
- Authority is an operator declaration, explicitly `authorityVerified:false`. Existing `ownership_proofs` domain records are read for a registration-time snapshot; a verified domain is not trademark ownership. Registration does not mint ownership proofs or grant DAST/SAST permission.
- Supplied website, product, service and social observations: HTTPS URL, explicitly zoned observation time, text, image evidence references, source permission declaration and coverage/gaps. Target URLs are never fetched by the Worker.
- Signals: Unicode NFKC case-insensitive name substring, domain-label resemblance (equal or edit distance at most one from the first official-domain label of at least four characters), and image SHA-256 byte equality. These are reasons for review, not similarity confidence or brand infringement assertions. Full domain labels are used; public-suffix awareness, homograph detection, OCR, visual/perceptual/semantic similarity and transformed-image detection are not implemented. Matching is version 1 and profiles are immutable; create a new profile when its asset/authorized-domain policy changes.
- Official and authorized domains and their subdomains produce no candidates. This exclusion cannot detect unauthorized content hosted on those domains; authorized lists require care. Queries and fragments are not collapsed into the same target; fragments are rejected, queries retained.
- Candidate identity = SHA-256 of profile ID, asset ID and normalized full URL. All matched observations remain, including out-of-order reported times. Absence from a later supplied observation does not prove removal. Nonmatched observations remain in coverage history. A review marks investigating, authorized, dismissed, reported or resolved; reported/resolved are operator claims and do not send external communications. Reobservations retain review status; the timeline remains available for renewed review.
- Server timestamps separate from reported times. Operator-supplied text and source/time linkage remain unverified. Image/evidence references must belong to the same account and retained bytes must match their digests at import time. The endpoint never follows URLs or treats text as agent instructions. Existing evidence deletion/retention semantics remain; imported digests prove past byte equality, not permanent custody.
- Web navigation uses the new shared `@mithril/workspace/brand-react` surface; Web supplies authentication/upload transport. `brand` and `brand-react` are reusable by Desktop. Native Desktop attachment/installer publication is not part of this Web source integration.

## REST / MCP

Existing API authentication, suspension and browser Origin/CSRF policy apply. New least-privilege token scopes `brand:read` / `brand:write`; old case/security scopes confer no brand access. Session users have existing wildcard scopes.

| REST | MCP | Required scopes |
|---|---|---|
| GET /v1/brand/profiles | brand_list | brand:read |
| POST /v1/brand/profiles | brand_register | brand:read + brand:write |
| GET /v1/brand/profiles/:id | brand_get | brand:read |
| POST /v1/brand/observations | brand_observe | brand:read + brand:write |
| POST /v1/brand/reviews | brand_review | brand:read + brand:write |

`POST /v1/brand/mcp`: stateless JSON Streamable HTTP; accepts `application/json, text/event-stream`, MCP 2025-03-26/06-18/11-25; supports initialize, ping, tools/list, tools/call. A scoped bearer and allowed Origin are required; notifications cannot execute writes. Tools/list is scope filtered. GET/SSE sessions are unavailable.

Every write requires a UUID `operationId`. Persist it with the exact request before transfer; reuse it only for that request. Replays return the stored receipt; changed content returns 409. Profile ID is its operation ID. Candidate review requires `expectedRevision` (initially 0); insertion and revision admission are one SQLite statement. Conflict: refresh history and prepare a new explicit edit with the current revision. Never automatically change a conflict's revision or overwrite another review.

Upload original and observed images to existing `POST /v1/evidence/file?filename=...` (PNG/JPEG/WebP in the shared UI); pass returned `{id,sha256}`. Direct uploads also require existing `cases:write` scope; listing/reconciling evidence requires `cases:read`. Brand scopes never silently grant vault access. Upload itself is not idempotent: uncertain upload must be reconciled in the evidence list. No credential is retained in the workspace state. Owner changes clear profiles, pending edits and selected images; asynchronous results from a prior owner are discarded.

Register example:

```json
{"operationId":"11111111-1111-4111-8111-111111111111","company":"Example Inc.","brand":"Example","officialDomains":["example.com"],"authorizedDomains":[],"authority":"owner-or-authorized-agent","assets":[{"id":"22222222-2222-4222-8222-222222222222","kind":"trademark","name":"Example","aliases":[],"registration":"operator supplied registration number","jurisdiction":"JP"}]}
```

Observe example (brandId = registered profile ID):

```json
{"operationId":"33333333-3333-4333-8333-333333333333","brandId":"11111111-1111-4111-8111-111111111111","url":"https://examplf-shop.test/item","surface":"product","observedAt":"2026-10-07T12:00:00+09:00","text":"Example products","images":[],"evidence":[],"source":{"name":"operator export","permission":"authorized-private-use","coverage":"one supplied product listing; no marketplace-wide crawl"}}
```

Limits: streamed JSON request 32 KiB, 100 profiles/owner, 50 assets/profile, 1000 observations/profile and 5000 reviews/profile. SQLite triggers enforce caps for concurrent REST/MCP writes. Read-back is bounded by those same caps, with explicit coverage; this is an initial finite investigation workspace, not an unbounded archive. Missing schema returns unavailable and never silently creates a table or routes to another service. No new service binding, database, bucket, secret or commercial subscription.

## Discovery and monitoring integration plan

A collector must supply observations through this API with an existing owner-scoped token. The bundled Registry stdio MCP bridge can drive these operations from agents. Repeated explicitly authorized observations implement tracking; there is no hidden crawling schedule. A future monitor must pin company, sources, scopes, terms, budget, interval, cursor and missed-run/uncertain-run policy, record actual collection coverage and emit observations without autonomous review/takedown. Existing metered scheduling is required for AI operations.

The Phase 0 ledger `config/data-source-terms.json` remains authoritative for CT/RDAP/DoH. No external catalog is queried or republished by this release. Do not attach blocked or internal-only sources to a public API/dataset. Marketplace/social API credentials, search providers and licensed image-search sources must be independently provisioned and qualified, with explicit source authorization. A source's absence is unknown coverage, not a clean result.

Next capabilities require separate adapters/qualification: CT-assisted domain discovery; platform-approved product/social discovery; trademark-register verification; OCR and perceptual logo/character models with benchmark false positives and explicit model version; actual notification/takedown workflows with recipient/body review. Never label an exact-hash/name prototype a comprehensive brand-enforcement service.

## Release

Migration `0050_brand_protection.sql` is additive, file-specific and repeatable. Production `d1_migrations` is incomplete: never run `migrations apply`. Live worker/domain/bindings must be verified, with a scoped backup and fresh Time Travel bookmark before applying this single file, then schema read-back. Workspace API CI is deploy-only and automatically refuses missing/incompatible schema; do not bypass it. Follow existing current-clean-main CI with pre-release rollback and post-release authentication/tenant/MCP/UI smoke. This PR's local tests do not establish production release.

Registry initially ships a self-contained Skill and stdio bridge plus a pending hosted manifest outside the installable MCP index. Promote the hosted manifest only after live initialize/tools/list and scoped synthetic calls can be measured. Web publication and installed Desktop support are separate receipts.
