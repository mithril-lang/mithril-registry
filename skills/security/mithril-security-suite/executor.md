# Security executor contract

The Registry supplies executable admission and pinned engines. Fund API supplies tenant authorization and durable D1 jobs. App and Desktop use the same shared Security UI; Desktop IPC keeps bearer tokens in the main process. The executor independently provisions target policy and resolves named environment credentials. A client can choose a target, never redefine it.

## Host policy

```json
{
  "schemaVersion": 1,
  "tenant": "USER_ID",
  "executorId": "sandbox-worker",
  "engineRoot": "/installed/mithril-engines",
  "api": {"origin": "http://127.0.0.1:8787", "tokenEnv": "MITHRIL_SECURITY_EXECUTOR_TOKEN"},
  "targets": [{
    "id": "azure-sandbox", "name": "Azure emulator", "provider": "azure", "mode": "sandbox",
    "endpoint": "http://127.0.0.1:45874",
    "credentials": {"AZURE_ACCESS_TOKEN": "MITHRIL_SANDBOX_AZURE_TOKEN"},
    "input": {"subscription": "00000000-0000-0000-0000-00000000dead"}
  }]
}
```

Cloud inputs require an explicit AWS account, region and finite services (`ec2`, `s3`, `iam`, `rds`, `kms`), Azure subscription(s), or GCP project(s). Every installed engine must be clean at the Registry catalog commit. The cloud host invokes that checkout's built first-party agent. Its EDN receipt is decoded as bounded data; tags, symbols, executable forms, duplicate keys and additional forms are refused. AWS signatures and Azure/GCP bearer authentication are exercised by the wire-compatible emulator. Sandbox credentials are public synthetic credentials from its seeded fixtures, never production credentials. Live mode uses provider endpoints with no arbitrary endpoint override and needs separate qualification; no live target is created by the package. Cloudflare is not an admitted connector yet.

A suite target has `provider: "suite"`, a normal `request` without tenant (the executor binds it), and optional operator `scope`. In sandbox mode every network endpoint must be 127.0.0.1. Add `authentication` to scope as an array of `{origin, header, env, expectedStatus, bodyContains}`. `header` is Authorization, Cookie or X-API-Key; the referenced environment value is the complete header value. The authenticated response must match both assertions. No login automation, cookie jar, redirect following, token refresh or unscoped discovery is implemented.

## Durable protocol

- `GET /v1/security`: `security:read`; owner target list and last 100 jobs.
- `POST /v1/security`: `security:run`; `{id,targetId,policyDigest}`. Operation ID is immutable and idempotent.
- `POST /v1/security/target`: `security:execute` bearer token only; descriptors expire after 600 seconds. No credential values or scope data are accepted.
- `POST /v1/security/claim`: executor token; `{executorId}`; atomic single claim returns a private lease.
- `POST /v1/security/complete`: executor token; `{id,lease,result}`. Results require the same owner, lease and bound target mode; identical acknowledgement retries succeed. A failed job uses `result:null`.

New scopes follow the existing passkey token issuance policy. Existing Desktop tokens are never silently upgraded. Browser cookies cannot acquire executor authority.

Policy fingerprints include executor identity and the entire host target policy, including credential reference names. Changed policy holds old queued jobs. Job leases expire after 300 seconds and become uncertain; they are never reassigned automatically. The local SQLite journal writes intent before any effects, stores normalized evidence digests and findings, and prevents replay after restart. Interrupted local intents require operator reconciliation; the cloud ledger exposes the expired lease as uncertain. The journal retains the lease until result acknowledgement, with owner-only file permissions. Keep it on a private persistent filesystem, not an ephemeral worker directory.

Receipts contain at most 128 deduplicated findings, a coverage gap count, sandbox/live mode, `coverage:partial` and `productionVerified:false`. Source files, HTTP response bodies, credential values and raw provider errors are not persisted or sent to the API. No remediation executes. Automated recurring schedules and login flows are future work.

## Verification

Start a provisioned polling host with `python3 runtime/executor.py HOST.json --journal /private/path/security.sqlite --serve`. Polling defaults to 30 seconds (5–60 allowed), keeps descriptors available and executes only explicitly queued jobs. A refusal exits the service for operator reconciliation; it never silently repeats scan effects.

Run the Registry unit suite with `MITHRIL_SECURITY_ENGINE_ROOT`, `MITHRIL_SECURITY_COMPILER_ROOT` and `MITHRIL_SECURITY_EMULATOR_ROOT` explicitly configured. The emulator is kotoba-lang/opencloud at `b9b9e3f23fda1da0879a074a3c4e166531342ef8`; tests require clean sources. `MITHRIL_SECURITY_DEPS_ROOT` selects the installed pinned public Kotoba dependency cache, defaulting to `~/.gitlibs/libs/io.github.kotoba-lang`. Startup is isolated from optional test-host dependencies. Optionally use `MITHRIL_SECURITY_EMULATOR_ENDPOINT` for an already started local emulator.

Fund's `test/security-jobs.test.ts` covers D1 isolation, API scopes/CSRF, atomic claims, policy drift, immutable completion and uncertain leases. Setting `MITHRIL_SECURITY_REGISTRY_ROOT` enables the actual authenticated HTTP-to-Registry-to-D1 integration test with synthetic source only. Desktop's cloud-workspace tests validate fixed IPC-facing routes and explicit scopes.
