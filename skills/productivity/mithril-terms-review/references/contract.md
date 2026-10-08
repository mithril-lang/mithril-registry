# Input, output and execution

Agent: `node ${system_one_root}/bin/mithril-terms-review.mjs --stdin`.
Workflow: same entrypoint with `--workflow`, input `{ "tasks": [ ... ] }`, maximum three services. No side effects; a failing task stops the entire run and no partial records are emitted.

Service input: `{ "service": {"name":"Fixture service","plan":"sample","jurisdiction":"unknown"}, "documents": [...] }`. Optional service `usage` describes actual use, not account identifiers. Each document contains `kind` (terms/privacy/pricing/cancellation/dpa), `url` (HTTPS without credentials/query/fragment), `retrievedAt` (UTC YYYY-MM-DDTHH:mm:ssZ), `language` (ja/en/other), `text` (maximum 262,144 UTF-8 bytes), `sha256` (exact UTF-8 digest), optional `effectiveDate` (YYYY-MM-DD). One document per kind; maximum five. URLs are provenance only; origin and applicability are not verified by the runtime.

Optional `previous` has the same document schema. Optional `assessments` has up to 50 entries: `dimension` (billing-exit/data-control/fairness/user-choice/transparency), `risk` (low/medium/high/unknown), `rationale`, `sourceSha256`, `start`, `end`. Positions are UTF-16 indices into the exact imported text. They validate citation boundaries, not the interpretation. Read the full context before supplying these records.

Output: source metadata/digests, rule candidates with line and source position, explicit coverage gaps, reviewer-supplied interpretations, version changes, unknown trust dimensions, and private-only publication status. No raw clause text is returned, but service metadata and rationales may be private. Limit 1,000 candidates per document; reaching that limit is a coverage gap. Negations and favorable clauses can match. No match never means safe.

Workflow order: private inventory → verify source/applicability → hash/import → full contextual risk review → compare versions → owner review → separately reviewed public projection. The packaged command handles import, candidate detection, interpretation validation and comparison. Acquisition/OCR, scheduling, private storage integration, Knowledge contribution submission and operational provider verification require host capabilities.

Reference implementation and tests: [System One](https://github.com/mithril-lang/mithril-system-one/blob/a0bbc5d229ec3445c7bca129dc45c7ed3444333a/docs/terms-review.md).

Risk meanings: high = a documented restriction with material impact for the declared use; medium = a conditional restriction requiring a practical mitigation; low = limited documented impact within the stated scope; unknown = insufficient context/evidence. These are contextual reviewer interpretations, not legal ratings or a company-wide score.
