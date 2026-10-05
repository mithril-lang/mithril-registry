# Mithril security integration

The Registry distributes `mithril-security-suite` as a skill with executable
host adapters, not as an already deployed cloud scanner or a Desktop plugin.
`index.json` remains the distribution catalog. `security.json` is generated
from its package capability declaration and the compiled Mithril assembly.

## Responsibilities

```
reviewed .mith component sources
  -> Mithril inert Form reader / component admission / assembly composition
  -> compiled.json (source digests, compiler identity, closed exports)
  -> request admission (tenant, operation, finite bounds)
  -> first-party native checks / pinned installed core adapters
  -> common findings, evidence digests, coverage and gaps
```

VM, CSPM, DAST, SAST, SCA, container, host baseline, network inventory, HTTP
templates and IaC share a dependency on the evidence contract. They are
analyzers in the existing Mithril component vocabulary. `contract` is the
existing language capability used by these components; no arbitrary source
evaluation, language-core vocabulary change or model decision is introduced.
The composed catalog selects handlers from a closed host dispatch table.

VM/CSPM/ZAP/security-core retain their own rules and ownership. Registry ships
JSON host adapters and immutable engine identities, not private engine source.
The optional installed-engine root is operator-owned. Its four checkouts must
be clean and pinned; refusal never triggers a silent substitute or Kotoba API
proxy. Container inspection explicitly measures supplied extracted inventory;
upstream OCI fetch/layer verification remains a separate collector capability.

## App, Desktop and API integration

App Extensions can discover and install the skill through the existing index
contract. Consumers can read `security.json` for capability-level limitations.
They must display installation, engine availability and assessment verification
separately. This release does not imply that App automatically executes the CLI.

An authenticated API adapter should derive tenant identity from its principal,
not trust the CLI's caller label; store input/policy/engine digests and immutable
receipts under that owner, with retention and read authorization. Source bodies
and credentials need a separate private storage policy. A queue worker needs
an independently provisioned effect scope and must invoke the same admitted
operation catalog. Request input never supplies permissions or engine paths.
VM aggregation should retain operation/rule/location IDs and refuse to mark
absent findings resolved when coverage is partial. Cloud connectors, multi-user
storage, scheduling, billing and installed-client execution remain explicit
subsequent releases; no undeployed API endpoint is put in the install index.

## Maturity gates

| Stage | Required evidence |
| --- | --- |
| experimental | Validated executable package and declared limitations |
| local-conformance | Positive, negative and refusal tests through the actual host path; scoped loopback evidence for live effects |
| live-verified | Dated authorized real-provider/target receipts, exact engine and policy identity, declared coverage |
| production | Authenticated tenant isolation, persistent queue/receipts, timeouts/cancellation, recovery and deployment/installed-client verification |

Verification has its own values: `unverified`, `unit`, `local-conformance`,
`live-service`. A test file reference is structural evidence; passing CI and
dated test receipts establish whether it actually passed. The Registry builder
rejects missing evidence paths, unsupported maturity claims, source drift,
unknown exports, duplicate operation IDs and mutable engine revisions.

## Remaining maturity work by comparison area

* Infrastructure: authenticated OS inventory, broad protocol coverage and real fleet calibration.
* Web: authentication/session workflows, POST/JSON mutation, crawl scope and false-positive validation.
* Templates: reviewed known-vulnerability packs with independent safe fixtures; no Nuclei compatibility claim.
* Network: service/version identification and UDP under separate effect grants.
* SAST: scope-aware control/dataflow, interprocedural analysis and more language frontends.
* SCA: authorized feed freshness and explicit reviewed update proposals.
* Container: connect the existing registry/digest/layer collector, broaden package DB support and test live registries.
* IaC/secrets: more resource rules, HCL/YAML parsers and candidate validation without leaking values.
* CSPM: real read-only provider runs, scope coverage, graph integration and independent connector deployment.

## Reproduction

```
python3 scripts/compile_security.py --compiler-root /installed/mithril
python3 scripts/compile_security.py --compiler-root /installed/mithril --check
python3 -m unittest discover -s scripts -p 'test_*.py'
MITHRIL_SECURITY_ENGINE_ROOT=/installed/engine/checkouts python3 -m unittest discover -s scripts -p 'test_security_core.py'
python3 scripts/build_index.py
python3 scripts/build_index.py --check
```

`compiled.json` records the exact compiler file digests. Recompilation must
use reviewed compiler code; source digests establish artifact/source agreement,
not an independent proof of compiler correctness or RDF canonical identity.
