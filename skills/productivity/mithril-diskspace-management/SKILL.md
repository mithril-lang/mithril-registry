---
name: mithril-diskspace-management
description: Measure and visualize disk space, investigate large folders, and build evidence-based cleanup plans for Mithril Desktop or local storage without automatically deleting files.
license: Apache-2.0
metadata:
  version: "1.3.0"
  author: Mithril
  hermes:
    category: productivity
    tags: [diskspace, storage, device-care, cleanup, maintenance]
    compatibility:
      platforms: [macos, linux, windows]
      runtime: Python 3.9+; local metadata-only analysis
---

# Disk space management

Use when the user requests capacity analysis, a storage map, cleanup planning or a measured check after maintenance. Installing this package grants no deletion authority.

## Execute inside Mithril Desktop

Requires Desktop 0.8.0-preview.47 or newer. Open Skills → Open cleanup Skill, or Device care → Storage → Install / run cleanup Skill. The native runner installs this Registry package into the selected profile if needed, validates `desktop-adapter.json`, and runs the fixed Device care capability. It does not execute arbitrary downloaded shell commands or grant cloud agents local filesystem authority.

The first operation freshly measures Desktop-generated temporary media. The result names this Skill/version and reports `nothing-eligible` or `awaiting-selection`. Select exact candidates, create a reviewed plan and confirm the native Cancel-by-default dialog. The executor rechecks identity, ownership, age and content, moves approved items to OS Trash and records before/after free space. Nothing is automatically removed. Cancelling, changed content, failed Trash moves and retained recovery files remain visible. A completed measurement is not a completed cleanup or verified reclamation.

The executable cleanup scope is Desktop-owned generated media only. Arbitrary folders, npm/Homebrew/browser caches, histories, repositories and application databases are not admitted by this adapter. They can be measured and reviewed through the metadata scripts below, but their native-owner cleanup adapters are not yet provided. The adapter descriptor selects the existing bounded native workflow; it cannot widen paths, actions or cleanup authority.

1. Establish the requested computer and folder. In Mithril Desktop, open Device care → Storage, then analyze home or select a folder with the native picker. Temporary-file analysis has a separate, narrower cleanup scope. Cancel an analysis when its scope is unnecessary.
2. Alternatively run `python3 scripts/audit.py --root /explicit/selected/folder` from this skill directory. The bundled standard-library tool reads filesystem metadata only, writes JSON to stdout and never deletes, uploads or reads file contents. Defaults: 20,000 entries, depth 16 and 15 seconds. Symlinks, other volumes and unavailable entries are excluded; limits mark partial coverage. Folder names and paths are private: keep output local unless the user requests sharing.
3. Read volume capacity and available space separately from measured folder totals. Logical size counts each pathname; allocated estimates count a hard-linked inode once. APFS clones, compression, snapshots and shared containers prevent exact attribution. Unknown capacity stays unknown. Partial charts omit unmeasured files; do not extrapolate them to the whole disk.
4. Inspect the largest group one level at a time using an explicit narrower folder. Desktop’s proportional treemap and breadcrumbs navigate the measured hierarchy; the ranked list includes tiny tiles. “Analyze this folder in detail” renews a bounded read-only measurement using a native report-bound folder identity. Partial coverage is still partial; selection grants no cleanup authority. Compare before/after measurements for the same volume, scope and bounds.
5. Make a candidate ledger: exact path, measured bytes, class (reclaimable / review-required / preserve / unverified), owner, evidence of active use or open files, regeneration command or verified recovery copy, proposed operation and user authorization. If evidence is missing, mark unverified. Age, a cache name or large size alone never proves disposability. Do not claim an open-file check from metadata analysis.
6. Preserve source repositories and worktrees, user documents, chat/history, models, credentials, quarantine/recovery vaults, snapshots and application databases by default. Prefer reusing installed dependencies and existing artifacts before generating duplicates. Propose app-native cache controls only after verifying their documented scope. Do not automate broad recursive deletion or empty Trash.
7. For Desktop-generated temporary media, use the app's candidate selection and concrete review plan. Native confirmation binds exact items, bytes and expiry; the executor revalidates identity and moves eligible files to OS Trash. Arbitrary analyzed folders remain read-only. Other mutations require the user's authorization for the concrete paths and recovery plan; this skill's script supplies no mutation command.
8. After authorized maintenance, remeasure available space and record failures, skipped items and recovery locations. Moving to Trash may reclaim nothing until explicitly emptied. Report measured free-space change independently from logical bytes moved. Keep unknown and partial results visible.

Return the measured capacity summary, bounded folder breakdown, candidate ledger and next concrete action. Distinguish an installed skill, a completed analysis and a confirmed cleanup. Never install software, change snapshots, stop services, send messages or publish paths as an implicit part of analysis.

## Growth diagnosis and cleanup review

Use `python3 scripts/diagnose.py --current /local/current.json --previous /local/previous.json` to compare explicitly saved audit JSON. Omit `--previous` for a first audit. This command reads measurement metadata only and prints a structured diagnosis and cleanup review ledger; it performs no filesystem mutations. Do not save private observations in a repository or upload them by default.

Growth is reported only for two complete observations with the same canonical root, volume identity and bounds, in increasing timestamp order. Partial, cancelled, mismatched and old schema observations yield `unverified`; never describe coverage changes as disk growth. Logical growth is not free-space loss. Root group aggregation can hide changes inside Other; narrow the scope before claiming a specific cause.

Path rules identify hypotheses (dependency copies, cache accumulation, log retention, model versions, downloads). They do not identify the writing process or establish active use. For dependencies inspect the actual lockfile and project owner; for logs verify writer and retention; for cache use the application’s documented control; for models verify active configuration; for downloads verify recovery. Preserve histories, source repositories, credentials, databases, backup, quarantine and recovery paths. A large `.hermes` is application data, not a blanket cache.

The ledger contains exact measured file paths and bytes, `preserve` or `review-required`, cause hypothesis, required owner/active-use/regeneration evidence, proposed next action and `authorization: pending`. Never promote a row to reclaimable until those checks are supported. The executable bundle audits, compares and generates the review plan. Desktop’s existing reviewed temporary-media executor is the supported cleanup adapter; cleanup of other applications remains a separately authorized owner-native action.

Follow [the cleanup evidence checklist](references/cleanup-review.md). Re-measure available space after the approved operation and distinguish recovery, moved bytes and actual reclaimed space.

## Incremental index and freshness

Desktop persists a bounded private directory-listing index and monitors at most 256 directories while open. Unchanged single-link regular files may reuse in-memory measurements for up to 60 seconds. Directory replacement, change notifications, watcher errors and expired leases require fresh checks. Restart preserves listings only: every child receives fresh metadata checks. Native notifications are hints and may be missed; “Analyze this folder in detail” forces a fresh bounded measurement. Read reuse/check counts and update time alongside coverage. A cached report never grants cleanup authority; the executor revalidates real files and content independently.

For repeated CLI audits add `--index /explicit/private/path/listings.json`. This explicitly creates a local 0600 file with atomic replacement, capped at 20,000 entries, 2,000 directories and 4 MiB. Store it outside the measured folder and source repositories. Unchanged directory identity/timestamps reuse its names without enumeration; every file still gets a fresh lstat because the CLI has no continuous watcher. Corrupt indexes fall back to normal analysis; partial directory listings are never persisted. No file contents are cached or uploaded. File-content changes do not reliably change directory timestamps, so never skip file metadata checks on that evidence alone.

Record current observation time separately from reused measurements. Reject Desktop observations with `index.reusedFiles > 0` when verifying growth or post-cleanup reclamation; perform fresh focused analysis first. Fresh CLI observations remain comparable even when listing enumeration was reused. Do not claim instant whole-disk synchronization, a lossless journal, or that a cached file has no active writer. Independent volume free-space measurements remain current metadata observations.
