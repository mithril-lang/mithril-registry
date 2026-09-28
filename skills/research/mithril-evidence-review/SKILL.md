---
name: mithril-evidence-review
description: Review public security evidence with source links and dated claims when a user asks for a Mithril security research summary.
version: 0.1.0
author: Mithril
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [research, security, evidence]
    category: research
---

# Mithril Evidence Review

Use this skill to summarize public security evidence for a user. It does not grant research authorization or access to private data.

1. State the question, subject, time window, and the type of evidence that would answer it.
2. Retrieve the relevant public records from their current source or documented Mithril public endpoint. Check the endpoint's present behavior before relying on it. Record source URL, publication or snapshot date, retrieval date, and any license or reuse limit.
3. Keep observations, source claims, and your inferences distinct. If a record is absent, say that it was not found in the checked sources; do not treat absence as clearance.
4. Link each material conclusion to its evidence. Note stale snapshots, conflicting sources, missing coverage, and whether the source is primary.
5. Return a concise finding, evidence table, uncertainty, and the next verification step when necessary. Do not describe a public-data review as identity verification, compliance certification, or permission to scan a target.

For a request that would scan a system, access nonpublic information, or submit data, first establish the applicable authorization and use a separately documented tool with an explicit scope. This skill itself performs no such action.
