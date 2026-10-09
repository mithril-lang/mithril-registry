# Submission and receipt tools

Run through `response.py --root PRIVATE_VAULT --tool NAME --input JSON` or the
installed stdio MCP. These are local operator records; they never contact an
institution or authenticate its response. Tool schemas: [tools.json](../scripts/tools.json).

## Bind a reviewed report

Import the exact selected/redacted submission text as an attachment, plus the
selected supporting material. `fraud_action_prepare` takes `caseId`,
`recipient:{name,officialUrl}`, `purpose`, `reporterRole`, `legalBasis`,
`routeVerifiedAt` (timestamp with timezone), `payloadEvidenceId` and nonempty
`supportingEvidenceIds`. The public HTTPS route cannot contain credentials,
query parameters or fragments. Verify it independently; syntax checks do not
certify official sites. Keep session/token URLs private.

The returned `actionId` hashes recipient, purpose, payload/support hashes, role,
legal basis and route verification. Identical input returns the same action;
changed input creates a new action. The payload must contain all disclosed
fields, not just a narrative excerpt. Retain the full reviewed confirmation-page
representation and attachments before sending. Changed fields require a revised
action before dispatch.

## Record a separate authorized connector's execution

`fraud_action_event` takes `caseId`, `actionId`, `state`, nonempty `evidenceIds`,
`note` with a source locator and `observedAt` with timezone. Every source must be
retained in this case. Immediately before external execution, record
`dispatch-started` with `approval:{authorized:true,actionId,basis,operator}` and
the retained authority record. This binds existing user authorization to the
exact action; it is not independently authenticated delegation. Record any
required form agreement separately. The caller uses its authorized connector.

| Current record | Next record |
| --- | --- |
| prepared / reconciled-not-submitted | dispatch-started |
| dispatch-started | submitted / unknown / acknowledged / reconciled-not-submitted |
| unknown | submitted / acknowledged / reconciled-not-submitted |
| submitted | acknowledged / under-review / frozen / declined / returned-and-reconciled |
| acknowledged | under-review / frozen / declined / returned-and-reconciled |
| under-review | under-review / frozen / declined / returned-and-reconciled |
| frozen | under-review / declined / returned-and-reconciled |
| declined / returned-and-reconciled | terminal; new requests are separate actions |

An unresolved dispatch blocks another action with the same recipient and purpose,
including changed payloads. Inspect completion pages and inbox before retrying
an interrupted call. `unknown` cannot automatically retry.
`reconciled-not-submitted` requires evidence of no submission; missing email
alone is insufficient. Writes use a case-wide advisory lock and exclusive event
files. This assumes all operators use the ledger; external actions can bypass it.

`submitted` needs retained completion evidence. `acknowledged` needs a matching
institution receipt/ticket checked against recipient, time and submitted content.
Preserve exact submitted content, completion text/screenshots and original email
independently. Provisional registration is not final registration; a generic
auto-reply is not formal complaint acceptance.

`frozen` and `returned-and-reconciled` also need positive decimal-string `amount`
and uppercase `currency`. A freeze needs an explicit institution decision. A
return needs the victim's received credit reconciled against previous payments.
Gross transfers, historical balances, requests and promises are not returns.
The tool checks references and numbers, not the truth of the operator's claims.

`fraud_action_status` reverifies action/evidence hashes and returns events,
`retryBlocked` and separate receipt/freeze/return flags. It does not sum amounts;
accounts, actions and currencies may overlap. Hash links are not signatures,
WORM storage or trusted timestamps; the OS user can alter the vault.

## Decode original email

Import RFC822 `.eml` bytes as an `attachment`. `fraud_receipt_decode` takes
`caseId` and `evidenceId`; it returns decoded headers and plain MIME text with
source charset and original hash. Python decodes ISO-2022-JP and other supported
email charsets. Do not replace originals with a connector's garbled summary.
Malformed MIME/unsupported encodings require manual review. HTML-only mail
has no plain-text result, which is a gap. `decoded-only` does not authenticate
the sender or confirm an institution's receipt.

## Agent handoff

Provide private vault location, action IDs, states, missing evidence and available
connector capabilities. Reverify inventory and reconcile previous receipts before
more disclosure. No public upload, unattended filing, telephone connector, e-Gov
login, live-chain provider or institution freeze/return adapter is installed.
