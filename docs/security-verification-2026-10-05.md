# Security Suite verification — 2026-10-05 JST

Local verification of the Registry's bundled 0.1.0 suite. No external service
or customer system was scanned. No claim of commercial-product equivalence,
Cloudflare deployment or installed Desktop execution is made.

The actual Mithril compiler composed all 10 operation components and their
shared evidence dependency. Recompilation matched `compiled.json`; a modified
component with an unknown export kind was refused by that same compiler.

The configured clean engine checkouts matched the immutable commits in
`capabilities.json`. Installed adapters were exercised through `kbb` subprocess
JSON input, not through replacement mock implementations. Tests covered VM
positive/negative version matching and missing versions; SCA actual manifest
parsing and unsupported formats; Debian container inventory; CSPM real rules,
resource IDs and path coverage; DAST distinct passive header findings and
active request planning/evidence. A real loopback HTTP server exercised the
Python host -> HTTP response -> installed ZAP core -> common receipt pipeline.

Native tests covered Python AST taint candidates, safe parameterized SQL,
subprocess argument vectors, unsupported languages and syntax; host baseline
missing observations; positive/negative/unknown HTTP templates; Terraform and
Kubernetes JSON; secret-value exclusion; stable tenant-separated finding IDs.

Scope tests exercised a real loopback TCP/HTTP server, out-of-scope targets,
credential-bearing URLs, DNS names, redirects, active permission, total request
budgets and timeout-as-unmeasured. All targets and pure operations are checked
before external effects. Source/compiled drift, missing engines, mutable engine
identity, excessive inputs and unsupported maturity claims were refused.

Command used for the 32 security-specific checks (installation paths generalized):

```
MITHRIL_SECURITY_ENGINE_ROOT=/installed/checkouts \
MITHRIL_SECURITY_COMPILER_ROOT=/installed/mithril \
python3 -m unittest discover -s scripts -p 'test_security*.py' -v
```

Result: 32 tests, zero failures, zero skips. Compiler source-file hashes are
recorded in `compiled.json`; private-engine identities are in the capability
declaration. The compiler checkout had unrelated existing modifications, but
the actual Form reader, component compiler and CLI files used here were read
without modification. Those unrelated changes were preserved.

Public CI runs the portable native/Registry checks. Installed private-engine
and actual compiler tests require their explicitly configured roots and are
skipped when those roots are absent. A skipped integration test is not a new
integration pass. Real provider, registry, authenticated tenant-storage and
production/installed-client qualification remain pending.

Full Registry validation: 40 tests passed with both installed roots configured, zero skips. Native and core sample requests also completed through the public CLI (9 operations); TCP probing was exercised separately against loopback. Local Python was 3.9.6. Existing plugin artifact regeneration and generated index checks passed.

## Provisioned executor and sandbox extension (0.1.1)

AWS, Azure and GCP collectors successfully authenticated against kotoba-lang/opencloud commit `b9b9e3f23fda1da0879a074a3c4e166531342ef8` on loopback and produced shared posture findings. Wrong Azure credentials failed the job instead of reporting a clean assessment. These are emulator conformance results, not real-account qualification. The checked-in security-core agent artifact is tracked by the pinned engine commit and remained clean.

Six executor tests passed without skips with the emulator and engine roots configured. They cover authenticated provider collection, denied credentials, origin-bound Web headers and authenticated page assertions, sandbox scope refusal, immutable policy binding, persistent SQLite intent/replay refusal, owner isolation and the data-only agent wire codec. Registry version and catalog checks were regenerated for 0.1.1.

Fund's four local D1/API tests passed without skips with the Registry checkout configured, including an actual bearer-authenticated HTTP executor run through claim, assessment and result persistence. The shared Security UI's two tests passed, covering explicit execution, lost acknowledgements and account-change isolation. Workspace 0.6.5 compiled successfully for the App/Desktop consumer artifact. No production cloud account, production D1 migration or external scan was used.

The final Registry regression run passed all 46 tests with zero skips, including the real installed core engines, Mithril compiler and all three cloud emulators. Desktop's 12 transport tests, node/renderer typechecks and lat checks passed. Fund's API/Web typechecks and shared package build passed.
