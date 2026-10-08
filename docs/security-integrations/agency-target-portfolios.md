# Agency solutions and contact profiles

International/multi-agency cooperation uses the separate [planned common contract](international-investigation.md) in `solutions/international-investigation.json`. National Cyber, Forensic Laboratory and Prosecution remain related roles; the contract does not upgrade their availability or alter executable grants. Fund pins this contract independently of the agency catalog snapshot, so adopting it does not silently adopt other profiles/catalog changes.

`solutions/agency.json` is the source of truth. The deterministic `solutions.json` and eleven role briefs in `solutions/agency/` separate personas, needs, inputs, current scope, gaps, Registry entries, contact IDs, blog audience and editorial briefs. `scripts/build_index.py --check` verifies all artifacts. The existing executable entry taxonomy and IDs remain stable; `index.json` adds `solutionCatalog` and per-entry `solutionIds`. A solution is a discovery grouping, not a tool/MCP/Skill grant.

Cyber, Forensic Laboratory and Prosecution expose only the supported JSON local evaluation components. Eight domain modules are planned. Video/financial/maritime/tax/customs needs are hypotheses awaiting practitioner interviews and input-format qualification. No current CCTV identity analysis, bank/communications parser, universal evidence archive, government adoption or admissibility is claimed. The external Forensics MCP remains a separate product contract.

## Local contact profiles

Run `python3 scripts/install_agency_profiles.py --home /absolute/hermes/home` to preview; add `--apply` to create 14 local profiles. No new dependencies are required. Profiles include SOUL.md, USER.md, Desktop profile-meta.json, Hermes profile.yaml and routing metadata; they opt out of the host gateway multiplexer. No credentials, channels, cron or active-profile changes are copied. Existing changed files and symlinks are refused; identical reruns are harmless. Configure an approved provider separately before conversation. These are Mithril consultation bots, not officials or forensic executors.

The shared Web/Desktop Bot profiles screen consumes a reviewed snapshot in mithril-fund and offers editable drafts with explicit save. Local native profiles and cloud profiles remain separate records. A live cloud account requires workspace authorization; profile creation does not confer it.

## Editorial separation

Each solution owns a distinct audience ID and unpublished article brief. Published incident background may be curated for cyber analysts, while victim worksheets retain victim targeting. Do not manufacture published article URLs or reuse victim advice as a police product claim. Public article publication and new customer-facing capability claims require their own review.

Update Registry first, regenerate/check artifacts and review the snapshot SHA in the consumer PR. Re-run consumer template/discovery/blog checks before shipping. The offline forensic evaluation kit remains a separate release; this catalog does not add new acquisition formats to it.
