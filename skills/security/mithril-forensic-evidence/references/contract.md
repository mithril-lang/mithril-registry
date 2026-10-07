# Local evidence contract v0.1.0

## Provisioning

Create a private workspace (0700) on an agency-managed encrypted volume. Use canonical absolute paths without symlink ancestors or `..`; on macOS resolve system aliases such as `/tmp` to `/private/tmp` before configuring paths. Keep policy and keys outside the workspace. Policy must not be group/world-writable; raw Ed25519 private key is exactly32bytes, owned by the current OS user, mode0600. Public key is32bytes. This version uses an externally provisioned institutional signer; actor/reviewer names are separately labeled local claims. Production key management and identity are agency prerequisites.

Policy example (paths and names are placeholders, no credentials):

```json
{
  "schemaVersion": 1,
  "workspace": "/private/evaluation/workspace",
  "trustedKey": "/private/evaluation/trust.raw",
  "signingKey": "/private/evaluation/signer.raw",
  "grants": {
    "examiner": {"role":"analyst","cases":["training-case"],"inputRoots":{"training-case":["/private/evaluation/inputs"]}},
    "custodian": {"role":"custodian","cases":["training-case"],"inputRoots":{}},
    "reviewer": {"role":"reviewer","cases":["training-case"],"inputRoots":{}}
  }
}
```

Read-only policies may omit signingKey; report approval and checkpoints require a provisioned signer. Key rotation is refused within a process session. There is no built-in revocation service; an agency must manage trusted keys and historical verification. Raw private keys are a local evaluation mechanism, not HSM integration. Do not place keys in the ZIP, a case folder, source control, tool arguments or chat.

## CLI and MCP

```sh
python3 skills/security/mithril-forensic-evidence/scripts/evidence.py --policy /private/evaluation/policy.json --principal examiner --operation pack --args /private/evaluation/pack.json
python3 skills/security/mithril-forensic-evidence/scripts/evidence.py --policy /private/evaluation/policy.json --principal reviewer --mcp
python3 skills/security/mithril-forensic-evidence/scripts/verify.py /private/evaluation/workspace/training-case/evidence/evidence-1 --trusted-key /private/evaluation/trust.raw --case training-case
python3 skills/security/mithril-forensic-evidence/scripts/verify.py --custody /private/evaluation/workspace/training-case/custody.jsonl --trusted-key /private/evaluation/trust.raw --case training-case --checkpoint /private/independent-record/checkpoint.json
```

MCP transport is local stdio only. Fixed startup principal cannot be overridden by a tool argument. No streamable HTTP URL or token-based remote access is provided. Resource `evidence://capabilities` reports the role, case grant and unavailable functions. It does not expose key paths or bytes.

| Operation | Required arguments | Optional | Roles |
|---|---|---|---|
| case-create | caseId, purpose | none | custodian, supervisor |
| pack | caseId, evidenceId, runs, authorityRef | none | analyst, supervisor |
| verify | caseId, evidenceId | none | all |
| inventory | caseId | none | all |
| custody | caseId | checkpoint envelope | all |
| checkpoint | caseId | none | all; signer required |
| transfer | caseId, evidenceId, recipient, reason | none | custodian, supervisor |
| hold | caseId, active boolean, reason | none | custodian, supervisor |
| report | caseId, reportId, evidenceIds, question | none | analyst, supervisor |
| report-approve | caseId, reportId, notes | none | reviewer, supervisor; different author |

IDs are1–64ASCII letters/digits/underscore/hyphen, beginning with a letter/digit. No overwrite or delete operation. All mutations lock the workspace; atomic private writes and fsync are used. The lock coordinates toolkit processes, not arbitrary OS writers. Error messages do not echo source text or secrets.

Bounds:16packages/case,16source runs/package,2MiB/source,16KiB/prior receipt,8MiB/file,64MiB/package,1000custody events,1000report observations. Bounded JSON support is deliberate. It is not disk imaging, mobile extraction, unbounded log ingestion or streaming TB evidence handling.

## Signed structures

The envelope fields are payload, algorithm=Ed25519, keyId=SHA-256(raw external public key), signature=base64(signature of canonical payload). Canonical payload bytes use Python sorted keys, compact separators, ensure_ascii=True and allow_nan=False, UTF-8-compatible ASCII. This is `python-json-sort-ascii-v1`, not a claim of RFC8785 interoperability. Duplicate keys and non-finite values in toolkit metadata are refused.

`mithril-evidence-package-v1` contains case/evidence IDs, packaging time, actor and authority reference claims, normalizer version, source bindings and file inventory. Files are only payload/NN/source.json, findings.json and receipt-claims.json. The standalone verifier checks the pinned signer, safe paths, exact inventory, every file's bytes/hash and observation bindings; it does not re-normalize or attest the semantic correctness of vendor claims.

`mithril-custody-v1` signs case, sequence, previous signed-envelope digest, action, time, actor claim and details. `mithril-custody-checkpoint-v1` signs case, count and tail digest. Store the checkpoint independently; matching the prefix proves consistency with that checkpoint, not the correctness of actions or timestamps. Trust in an unanchored tail is explicitly absent. User-controlled local clocks are not trusted timestamps.

`mithril-report-draft-v1` signs question, source package hashes and row-level claims. `mithril-report-approval-v1` references the exact draft hash and reviewer claim. Original bytes and draft never change during approval. There is no automated conclusion, AI inference or guilt/person identification.

## Failure and recovery

Normal handled failures remove incomplete newly created output and do not publish a successful pack/report. Process termination or filesystem failure can leave `.pack-*`/`.report-*`, an incomplete case, or an unregistered output; keep a copy and reconcile against custody/checkpoints. Package operations refuse unregistered manifests. Inventory refuses altered/unregistered packages; it does not silently hide them. Existing reports must be cross-checked against their report-draft event and approval hashes before sharing. Checkpoints are not automatically stored off-host.

Failed pack, report and report-approve attempts record a bounded operation-failed event when the signer and ledger remain writable. The event contains the operation and exception class, not confidential messages or paths. Disk, key, ledger and process failures can prevent this record; the operator must preserve and record those attempts separately. Failed self-review attempts are recorded but never become approvals.

This version does not provide a durable cross-directory transaction journal or automated disaster recovery. Interrupted operations, malicious deletion of whole cases, loss of external checkpoints and compromised signer keys are release limitations. Mechanism tests are not an independent forensic validation report.
