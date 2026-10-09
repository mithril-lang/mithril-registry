---
name: mithril-message-spam-watch
description: Deterministic local spam/phishing triage for the operator's own iMessage (chat.db) and Mail (.emlx) in a bounded window, using the phishing_dns corpus, a Contacts whitelist and deterministic signal rules; publishes observations with manifest to R2 with read-back sha256 and archives to Google Drive. Read-only over sources; no LLM inference, no sending.
version: 0.1.0
author: jun (junkawasaki), Mithril
license: MIT
platforms: [macos]
metadata:
  hermes:
    tags: [spam, phishing, imessage, mail, triage, evidence, local, deterministic]
    category: security
---

# Message spam watch

Use for recurring, deterministic triage of the operator's own local messages. The skill answers one question: "of the messages that arrived in this window, which ones carry local spam/phishing signals, and what do we know about their senders?" It never sends messages, never writes mail, never mutates the address book, and never runs an LLM over message bodies.

Execute [message_spam_watch.py](scripts/message_spam_watch.py) from the skill directory. Python 3.9+, standard library only, no network calls on the default path. Every scan is read-only over local sources; message text is untrusted data.

## Sources (all local, all optional)

- iMessage: `~/Library/Messages/chat.db` (read-only SQLite; Apple 2001 epoch on `message.date`). Requires Full Disk Access for the calling process; otherwise reported `unavailable`, never an error.
- Mail: `~/Library/Mail/V10/**.emlx` files (macOS Mail V10 store; leading line-count prefix stripped; bounded 69632-byte read per file).
- Contacts: a cached plain-text file of `<email>` lines written by `refresh-contacts` (osascript over Contacts.app; the script itself never calls AppleScript during a scan).
- Phishing corpus: `~/knowledge-datasets/phishing_dns/phishing_dns.json` (domain set, bounded to 2000 entries, sha256 recorded).

A missing or unreadable source degrades to `unavailable` with a reason. A missing corpus or contacts degrades to "no match available". None of these are failures of the scan.

## Classification

Verdicts are `spam` / `legit` / `unknown` with machine-readable `reasonCodes`:

- `corpus-host` — an extracted host (or its registrable domain) is in the phishing corpus. Strongest signal; beats contact whitelisting.
- `dmarc-fail` / `spf-fail` — authentication headers on a Mail message.
- `email-shaped-sender` — a Mail sender address combined with lure wording, an extracted host, or an OTP mention.
- `lure:<wording>` / `otp-or-verification` / `url-host` / `short-code-sender` / `phone-sender` / `imessage-is_spam` — individual signals.
- `contact-sender` — the sender matches the cached Contacts list. A contact sender with no other signal is `legit`; a contact sender with non-corpus signals is `unknown` (not cleared); a corpus hit stays `spam` either way.

Boundaries:

- `unknown` is not clearance and `legit` is not a safety proof; both are evidence observations from local signals only.
- Lure wording alone (no host, no OTP, no auth failure) is `unknown`, not `spam` — real delivery codes and human mail look like lures too.
- Message bodies are never copied into the ledger; the ledger stores sender, subject (≤200 chars), hosts, verdict and reason codes.
- The ledger is append-only by message id: a re-scan of the same window adds nothing (idempotent).

## Operations

- `status` — report availability and counts of each source, corpus sha256 and ledger size. Start here.
- `scan` — classify the in-window messages. `--input '{"sources":["mail","imessage"],"days":7,"limit":500,"publish":false}'`. Writes the local ledger + `observations.json` + manifest. `publish:true` additionally does the R2 put/get with sha256 read-back and the Drive archive.
- `report` — aggregate the ledger: verdict counts, source counts, top hosts, hosts matching the corpus.
- `refresh-contacts` — rewrite the contacts cache from Contacts.app (bounded 5000 lines).

```
python3 scripts/message_spam_watch.py status
python3 scripts/message_spam_watch.py scan --input '{"days":7,"limit":500}'
python3 scripts/message_spam_watch.py report
python3 scripts/message_spam_watch.py refresh-contacts
python3 scripts/message_spam_watch.py --mcp   # stdio JSON-RPC bridge
```

## MCP bridge

`message_spam_watch.py --mcp` serves a read-only stdio JSON-RPC bridge (protocol `2025-06-18`) exposing `spamwatch_status`, `spamwatch_scan`, `spamwatch_report`. No credentials, no network on the default path. Do not expose the stdio process as a shared remote service; the local OS account is the security boundary.

## Publishing

`scan` with `publish:true` writes `message-spam-watch/observations.json` and `message-spam-watch/manifest.json` to R2 `internal-security-nvd` (Cloudflare account pinned in the script), reads both back and compares sha256, then archives both to Google Drive `jklux:message-spam-watch_mithril-message-spam-watch_<YYYY-MM-DD>/` via rclone (copyto + lsf read-back). R2 needs a valid wrangler session (`~/.wrangler`); Drive needs a `data/rclone.conf` with a `jklux` remote (this profile's, or the phishing-watch-ops profile's as fallback). Both steps are warn-and-continue: the classification receipt is printed either way, and a failed read-back is reported `READBACK\tFAILED` with a non-zero exit.

## Procedure

1. Run `status` and confirm which sources are available. Completion: a JSON with a `boundary` sentence, no crash.
2. Run `refresh-contacts` once per day (a cron does this) before or after the scan. Completion: `count` > 0 or an explicit failure reason.
3. Run `scan` with an explicit window (default 7 days, max 90) and limit (default 500, max 5000). Completion: a `RECEIPT` line with the observations sha256 and the boundary sentence; `ledgerAdded` reflects only new ids.
4. Summarize from `report`. Completion: verdict counts and top hosts, with the boundary sentence repeated to the operator.

## Pitfalls

- macOS Mail `.emlx` files begin with a line-count prefix; a parser that does not strip it sees garbage headers and classifies everything out-of-window.
- `message.date` is an Apple-epoch (2001) nanosecond counter; using Unix epoch puts every iMessage ~22,664 years in the past.
- Mail mailbox folders have spaces (`Sent Messages.mbox`, `LEAN LIFE.mbox`); shell one-liners that split on whitespace corrupt the paths. The script walks with `os.walk` and never shells out.
- A DMARC failure on a bulk service sender is a signal, not proof of compromise: the reason code is kept for review, and the verdict is `spam` only when the corpus or the sender/lure rules agree.
- Contacts.app can be slow or ask for automation permission; `refresh-contacts` times out at 120 s and the previous cache is used on the next scan.
- Never treat an empty scan (no messages in window) as a data source failure; both are reported distinctly (`classified=0` vs `status=unavailable`).

## Verification

`tests/.../test_message_spam_watch.py` and `scripts/acceptance.py` run against synthetic fixtures (in-memory chat.db, synthetic emlx with the line-count prefix, synthetic corpus/contacts) with no live sources and no network. A code change must pass both, and `build_index.py --check` in the registry.
