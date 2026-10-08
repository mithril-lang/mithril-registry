# Operation contract 0.1.0

CLI: `python3 scripts/sales.py --db PATH --owner OWNER --operation OP --input JSON`.
Input may instead come from stdin. Output is JSON. Errors exit 1. Input cap 64 KiB.
Create the workspace directory with mode 0700. Database permissions must be 0600.
Timestamps require a timezone and are normalized to UTC. No URL is fetched.
Canonical target: `https://www.linkedin.com/in/<profile>` without query/fragment; ASCII slugs only, normalized to lowercase.
`owner` is a local namespace selected by the trusted host, not an OAuth identity.

Every mutation requires UUID `operationId`. Lead/message IDs are the UUID of the
creation operation. Retrying the exact operation is idempotent. The operations
ledger and audit are local, transactional and not tamper-proof.

| Operation | Additional fields | Result/effect |
|---|---|---|
| lead | name, company, profileUrl, source, observedAt, outreachBasis, fitReason, authorizedInput:true | Private qualified candidate; basis is operator-supplied, not verified consent |
| draft | leadId, kind:dm/inmail/connection-note, senderProfileUrl, body, optional subject | Immutable payload with digest and revision; attachments unsupported |
| approve | messageId, digest, expectedRevision, actor matching owner, memberAction:approve-draft | Freeze exact draft for screen handoff |
| cancel | messageId, digest, expectedRevision, reason | Cancel draft/approved message; create a new draft to edit |
| handoff | messageId, digest, expectedRevision, actor matching owner, memberAction:prepare-screen-send | Editable screen send packet, handoffId, sent:false |
| receipt | messageId, digest, expectedRevision, handoffId, outcome:screen-observed-sent/not-sent/unknown, evidence, observedAt; actualBody for screen-observed-sent, optional actualSubject | Reported screen observation; unknown can only be resolved by evidence-backed receipt |
| reply | leadId, body, evidence, observedAt, optional optOut:true | Append supplied reply; no external ingestion. Opt-out suppresses contact |
| suppress | leadId, reason | Permanent local no-contact state; reconciliation of an existing handoff remains allowed |
| opportunity | leadId, expectedRevision, stage:qualified/replied/meeting/proposal/won/lost, evidence, optional nextReviewAt | Evidence-backed stage and review time |
| status | none | Private full workspace state, externalSendReady:false |
| followups | optional at | Due review tasks excluding suppressed, closed and unresolved contacts |

`revision` advances with message transitions; `digest` binds immutable owner,
recipient, senderProfileUrl, kind, subject, body, attachments and contentRevision. A stale revision
fails. Approval alone cannot transfer/send a message. At most one unresolved
handoff exists per recipient. A second draft/handoff is blocked until its outcome
is known. Suppression blocks drafts, approvals and handoffs, including already
approved ones. Recording a receipt never creates a new send authorization.
A `not-sent` outcome does not requeue; create and approve a new draft if appropriate.

Actual text may differ after the sender edits it in LinkedIn. Retain both the
approved draft and the reported actual text; no receipt claims byte equality.
No verified sender, provider message/thread ID, consent, response, meeting or conversion
is inferred from a URL or a workflow state. `inmail` describes a manual draft,
not a tested Sales Navigator subscription or API capability.
