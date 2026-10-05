# Request and engine contracts

Every request has exactly `schemaVersion: "1"`, an opaque `tenant` identifier,
and a nonempty `operations` array. Each operation has exactly `id` and `input`.
IDs are unique. Limits: 10 operations, 128 entries per array/object, 2 MiB
request and 64 KiB per source file. Unknown operation input fields are refused.

| ID | Input | Execution boundary |
| --- | --- | --- |
| vm | `components` or `sbom`, nonempty OSV `advisories`, optional `vex` | Pinned VM service; ecosystem ordering, CVSS, VEX and undecided results preserved |
| cspm | `resources`, or `provider`, `account`, optional `region`, `responses` | Pinned CSPM normalizers/posture/CIEM/path engine; no cloud API calls |
| dast | `responses: [{url,status,headers,body}]`, **or** `target`, optional boolean `active` | Pinned ZAP decision core; observed response mode or scoped GET host transport |
| sast | `files: [{path,content}]` | Python AST intraprocedural source-to-sink candidates; other languages unmeasured |
| sca | `files: [{path,content}]`, OSV `advisories`, optional `vex` | Pinned dependency parser and VM engine; no automatic feed or update PR |
| container | `extracted: {path: text}`, OSV `advisories`, optional `os-release`, `unreadable-layers`, `vex` | Pinned OCI filesystem inventory and VM engine; supplied final filesystem, no registry fetch or integrity claim |
| infra | `assets: [{id,settings}]`, nonempty boolean `baseline` | Explicit host setting comparison; absent observations remain unmeasured |
| network | `targets: ["tcp://127.0.0.1:8080"]` | Finite scoped TCP connects; timeout is unmeasured, refusal is closed, success is open |
| templates | `responses: [{url,headers}]`, optional `rules` | Curated `content-type-options` / `content-security-policy` response checks |
| iac | `files: [{path,content}]` | Terraform security-group JSON, Kubernetes Pod JSON, private-key / AWS access-ID candidates |

Host baseline keys: `sshPasswordAuthentication`, `rootLogin`, `firewallEnabled`,
`automaticUpdates`. Desired values are explicitly supplied, never inferred.

VM/CSPM object schemas are those of the installed pinned services. For example,
components use `{name,version,ecosystem}` and provider-neutral cloud resources
use `resource/id`, `resource/provider`, `resource/type`, `resource/config` and
optional `resource/relations`. Container `os-release` uses `os/id`, `os/version`.
HTTP header values may be strings or lists; names are case insensitive.

Example without external engines or network:

```json
{
  "schemaVersion": "1",
  "tenant": "example",
  "operations": [{
    "id": "sast",
    "input": {"files": [{"path": "app.py", "content": "import os\nx = input()\nos.system(x)\n"}]}
  }]
}
```

An independently maintained operator scope:

```json
{"endpoints":["tcp://127.0.0.1:8080","http://127.0.0.1:8080"],"active":false,"budget":32,"timeout":2}
```

Reports share `operation`, admitted Mithril `symbol`, tenant-bound finding
`id`, `rule`, `asset`, `severity`, `evidenceDigest`, `remediation`, `verdict`,
`gaps`, `summary`, `coverage` and `limitations`. Query values are excluded
from HTTP asset labels. CSPM keeps engine priority and attack-path summaries;
VM keeps suppression counts and names unparsed/undecided input. Finding IDs
are stable for the same tenant, operation, rule and location. All reports
remain `coverage: partial`. There is no implicit resolved status or automatic
remediation based on an absent finding.
