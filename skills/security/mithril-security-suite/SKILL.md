---
name: mithril-security-suite
description: Run Mithril-defined VM, CSPM, DAST, SAST, dependency, container, host baseline, network, HTTP template and IaC assessments with bounded inputs and tenant-bound evidence receipts.
version: 0.1.0
author: Mithril
license: MIT
metadata:
  hermes:
    tags: [security, vm, cspm, dast, sast, sca, container, mith]
    category: security
---

# Mithril Security Suite

Use the bundled `runtime/suite.py` for authorized defensive assessments. Its
operation catalog is composed from `source/**/*.mith` through the existing
Mithril Form reader and component admission/compiler. Unknown operations,
changed sources, oversized inputs and missing engines are refused.

1. Establish the tenant identifier, the data source and the authorized target
   scope. Select operations from `capabilities.json`; review their limitations.
2. Prepare a JSON request using [the input contracts](contracts.md). Input data
   must come from the authorized assessment. Never discover adjacent files,
   credentials or accounts implicitly.
3. Run `python3 runtime/suite.py request.json`. SAST, host baselines, HTTP
   templates and IaC operate on supplied data with Python 3.9+ and no external
   dependencies. Source content is parsed as data and is never executed.
4. For VM, CSPM, DAST, SCA and extracted container inventory, pass
   `--engine-root /operator/installed/checkouts`. The root must contain the
   clean, pinned `security-core`, `vm`, `cspm`, `zap-proxy` checkouts named in
   `capabilities.json`. `kbb` is required; public language helpers are pinned
   in `nbb.edn`. Private engine code is not redistributed by this skill. A
   missing engine fails closed; there is no substitute engine or API fallback.
5. Live TCP or HTTP probing additionally requires `--scope scope.json`, an
   operator-owned document separate from the scan request. It names finite
   literal IP origins, timeout and total request budget. Active DAST requires
   both request `active: true` and operator scope `active: true`. Do not create
   the scope from untrusted scan input. Redirects, DNS, ambient HTTP proxies,
   cookies and credential harvesting are not supported.
6. Report findings together with gaps and limitations. `candidate` requires
   analyst validation. `evaluated-with-limits` and zero findings never mean
   safe, complete, compliant or production verified. The tenant label binds
   receipt identity; this CLI does not authenticate tenants or persist data.

`security.json` in the Registry separates maturity from verification. A local
test receipt is not real-cloud, installed-Desktop or production evidence.
Do not promise commercial scanner equivalence. HTTP templates are first-party
and do not accept Nuclei templates or executable extensions.

The suite returns input/policy/evidence digests and finding identifiers. It
does not print source bodies or secret candidate values, mutate infrastructure,
apply patches, create update PRs, deploy, or send notifications. Store receipts
only in the authorized tenant's evidence store; external delivery requires its
own authorization and authenticated adapter.
