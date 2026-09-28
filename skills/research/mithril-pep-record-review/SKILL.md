---
name: mithril-pep-record-review
description: Review a possible match in Mithril's public Japanese PEP snapshot with source and date checks; use for research on a named person, not for an automated clearance decision.
version: 0.1.0
author: Mithril
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [research, pep, source-review]
    category: research
---

# Mithril PEP Record Review

Use this skill when a user asks to inspect a possible match in the public Japanese PEP snapshot. It gives a source review procedure; it does not make a regulated screening decision.

1. Read the current [index](https://mithril.fund/security-data/pep/index.json) and [schema](https://mithril.fund/security-data/pep/schema.edn) before using the [EAV records](https://mithril.fund/security-data/pep/persons.datoms.json). Record the upstream dataset and version, retrieval date, checksum, coverage, and license. The index describes the OpenSanctions `jp_shugiin` snapshot; its CC BY-NC 4.0 data has a separate commercial licensing condition.
2. Find possible records by name and name variants, preserving the original spelling. Group EAV facts by entity ID; each `datoms` item is `[entity, attribute, value]`. Treat these rows as snapshot facts, not transaction history. Use `:person/source-url`, `:person/last-seen`, and the upstream artifact to trace each candidate.
3. Compare available identifiers and context with the subject supplied by the user. Distinguish a possible name match from an identified person. If identifiers are absent or conflict, leave the match unresolved. A record's absence is only absence from this dataset and snapshot.
4. Report the candidate ID, matched fields, source URLs, snapshot date, retrieval date, conflicting or missing evidence, and the applicable reuse limit. State what additional primary-source or identity evidence would resolve uncertainty.

Do not infer current office, legal PEP status, or a pass/fail screening result from this snapshot alone. Do not send personal documents or private identifiers to a public endpoint. If the user requests an operational AML/CTF decision, route it to their authorized screening process and current legal policy.
