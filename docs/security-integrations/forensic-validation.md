# Forensic local evaluation validation receipt

Date:2026-10-07. Local qualification only. Dependency environment:Python3.12, cryptography50.0.2, cffi2.0.0, pycparser2.23, typing-extensions4.16.0. Dependency version was selected after checking the official cryptography changelog; this is not a complete vulnerability or native-dependency attestation.

## Observable validation

- New forensic/packaging tests:21 passed. They cover original-byte preservation, recomputed findings, independent verification, payload/manifest tamper, missing/extra files and registered packages, symlinks, path traversal, special files, wrong external trust, source mismatch, handled ledger failure, case/role/input-root refusal, external checkpoint truncation, event ordering, report references, self-review refusal, changed sources, hold limitations and deterministic packaging.
- Full Registry suite:111 tests,99 passed,12 existing runtime-dependent skips. Skipped checks are not represented as successful qualification.
- Synthetic acceptance:three source products, nine packaged files, separate report reviewer, four custody events, checkpoint prefix match and independent rejection after payload tamper. No vendor/customer connection. Temporary keys deleted.
- Official MCP SDK1.32.1:10 supervisor tools,5 reviewer tools,1 resource, three-source packaging/verification/report approval/checkpoint workflow. Role and cross-case refusal observed. No network.
- macOS arm64/Python3.12 wheel ZIP unpacked into a separate directory. A fresh venv installed all dependencies with `--no-index --require-hashes`; the packaged acceptance exercise succeeded.
- Registry index and existing plugin packaging are checked independently. Registry's extended Skill frontmatter is validated by build_index.py; the generic Codex quick validator does not accept Registry's author/version/platform fields.

CI definitions run Linux/macOS Python3.12 acceptance and offline packaging/install on pull requests and main. The CI result belongs to the exact PR commit; consult its checks rather than treating the existence of the workflow as a pass.

## Reproduction

```sh
python3 -m pip install -r requirements.txt -r skills/security/mithril-forensic-evidence/requirements.txt
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 skills/security/mithril-forensic-evidence/scripts/acceptance.py
MITHRIL_EVIDENCE_PYTHON=/absolute/python node scripts/verify_forensic_mcp.mjs /path/to/node_modules/@modelcontextprotocol/sdk
python3 scripts/build_index.py --check
python3 scripts/package_plugin.py mithril-app --check
git diff --check
```

The distribution inventory and wheel hashes cover packaged files and Python wheels. The SBOM does not enumerate cryptography's vendored Rust/OpenSSL components, Python or the OS; a full supply-chain assessment is still required for operational delivery. Distribution itself is checksum-addressed, not publisher-signed.

Unperformed:independent agency/lab qualification, live vendor permissions and completeness, authenticated multiuser isolation, trusted clock/timestamps, HSM/revocation, WORM, power-loss recovery, TB evidence ingestion, automatic redaction, customer contract/support acceptance or production deployment. Nothing in this receipt proves court admissibility.
