# Mithril Message Report

An executable, commit-pinned workflow client connecting user-selected message excerpts to the Fund gateway and the canonical Knowledge contribution service. Capacitor provides explicit paste, private classification, exact public-preview consent, contribution history/status and withdrawal. The CLI provides `classify`, `receipt`, `submit`, `status`, and `withdraw` actions. Installation starts no monitoring and grants no review authority.

## Acquisition and privacy

Use the selected excerpt from the user's own SMS, email or messenger. Remove unrelated personal data and credentials first. Current iOS/Android implementation is explicit paste. The iOS app cannot assume access to Messages or email inboxes; IdentityLookup filtering is a separate native extension capability. Android SMS handler/Play exceptions require separate qualification. This workflow requests no SMS, notifications, contacts or accessibility privileges and has no inbound share extension.

Classification uses bounded deterministic signals in the owning Fund API. It never follows links or calls an LLM. The private receipt records hosts, reason codes, verdict, date and a private input hash; raw excerpts are persisted only on separately consented contribution submission. `unknown` is not a clearance. `suspected_spam` is a candidate, not sender attribution or human approval. The existing macOS `mithril-message-spam-watch` remains a separate local acquisition/classification skill; its ledgers are not automatically uploaded to this workflow.

## Execution

Checkout `artifact.commit` from the manifest. Supply `MITHRIL_API_KEY` through the owning profile with `knowledge:write` for classify/submit/withdraw and `knowledge:read` for receipt/status. Missing credentials fail before network. Never put a token in stdin or the public preview.

Run `node bin/mithril-message-report.mjs --stdin` with one JSON action. Example classification (synthetic content):

```json
{"action":"classify","message":{"requestId":"4b15d50b-3d00-4ea1-8528-8f2a2814a73e","source":"sms","observedDate":"2026-10-11","text":"Verify your account at https://fake.example","consentToProcess":true}}
```

Submission requires the exact same `message`, a separately reviewed `publicPreview` with `summary`, the same `observedDate`, chosen domain/hash `indicators`, `consentVersion:"knowledge-public-v1-2026-10-01"`, and `consentToPublish:true`. Domain indicators must be observed in the message; phone indicators are refused. Do not publish original text, identities, accounts or unsupported accusations. Editing the public projection requires renewed consent.

Use `{"action":"status","id":"<report UUID>"}` or `receipt` for recovery. `withdraw` uses the same report UUID. The canonical contribution UUID is returned separately. Exactly one bounded HTTP operation is made per invocation. The origin is fixed, redirects refused, timeout 15 seconds, response limit 32 KiB. Unknown outcomes never retry automatically; retrieve state, then repeat only the exact original payload and UUID if needed. Never create a replacement UUID to recover uncertainty.

## Review and $1 AI credit

A submitted report enters the existing private Knowledge queue. An independent human reviewer verifies novelty, evidence, privacy and the exact public projection. Duplicate/split/copied contributions earn no extra entitlement. Confirmed public receipt/hash/version precedes the canonical atomic ledger/balance write for `1_000_000 micro-USD`. The workflow cannot review, publish, alter a budget or grant credit. Failed publication stays pending. Withdrawal requests monotonic public removal and retains honestly earned credit. External exports cannot be recalled.

## Qualification

Source and local tests establish the workflow/client contract. Production gateway, migration `0061_message_report_receipts.sql`, existing contribution schemas/publisher, authorized finite reward budget, full signed standalone API receipts, current-main publication, native signed store artifacts and physical-device QA remain separate release gates. No production reward is promised by Registry installation. Follow the Fund design/runbook `docs/design/mobile-message-report-workflow.md`.
