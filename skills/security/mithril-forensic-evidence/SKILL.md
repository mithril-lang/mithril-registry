---
name: mithril-forensic-evidence
description: Package retained cybersecurity runs with signed manifests, verify original bytes independently, record local case custody and prepare source-linked report drafts for supervised forensic evaluation.
version: 0.1.0
author: Mithril
license: Apache-2.0
platforms: [linux, macos]
metadata:
  hermes:
    tags: [forensics, evidence, custody, signatures, verification, cases]
    category: security
---

# Forensic evidence

Use for authorized local evidence handling and agency evaluation. Execute [evidence.py](scripts/evidence.py) with a provisioned local policy and principal; read [the contract](references/contract.md) for inputs, trust and failure handling. Runtime is Python 3.10+ on POSIX with the locked cryptography dependency. No network calls or AI processing occur in this skill.

The operations are case-create, pack, verify, inventory, custody, checkpoint, transfer, hold, report and report-approve. MCP tools use the `evidence_` prefix and underscores in operation names. Tool discovery is role-filtered; execution checks both role and case. Import roots are granted per case. Do not expand a policy to resolve an access refusal without the operator's authorization.

Packing copies original source.json bytes and unsigned receipt claims, recomputes findings with the bundled cybersecurity normalizer, then signs the inventory. Use the independent [verify.py](scripts/verify.py) and an externally provisioned trusted public key when receiving a package. A key delivered inside a package is not a trust anchor. Signing asserts local packaging, not original vendor authenticity, lawful acquisition, tenant completeness or court admissibility. Coverage stays incomplete-or-unknown.

Custody entries are signed and hash-linked. Export checkpoints to a separately controlled record; when verifying use the checkpoint obtained from that channel, not a newly generated one from the workspace being checked. Without it a valid chain remains unanchored. Newer entries after a checkpoint remain explicitly unanchored. Transfer records do not attest recipient acceptance. Hold is recorded; this toolkit has no delete command and does not enforce filesystem retention.

Report drafts contain claims with original source hash, source row and evidence ID. They generate no conclusion. A different principal must record review; local principal names are operator claims, not authenticated identities. Check the actual source, collection limits and unknown times before approval. Markdown summaries intentionally omit untrusted evidence text; use a safe JSON viewer for the signed detail.

The local OS account is the security boundary. A user controlling the account, policy or signing key can bypass local role checks. Do not expose this stdio process as a shared remote service. Independent authentication, OS-separated users, encryption, immutable storage, trusted timestamps, HSM/revocation and agency acceptance are not supplied by this prototype. Preserve interrupted staging/unregistered output for manual reconciliation; do not declare a successful receipt when an operation fails.

For deployment and acceptance, follow [the agency evaluation kit](../../../docs/security-integrations/agency-evaluation.md) in the Registry checkout. The distribution contains that document at the same relative path. Run acceptance against synthetic data first and obtain agency approval before incident data, vendor credentials or external sharing.
