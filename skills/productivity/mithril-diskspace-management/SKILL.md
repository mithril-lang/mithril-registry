---
name: mithril-diskspace-management
description: Measure and visualize disk space, investigate large folders, and build evidence-based cleanup plans for Mithril Desktop or local storage without automatically deleting files.
license: Apache-2.0
metadata:
  version: "1.0.0"
  author: Mithril
  hermes:
    category: productivity
    tags: [diskspace, storage, device-care, cleanup, maintenance]
    compatibility: Python 3.9+; local read-only analysis on macOS, Linux and Windows
---

# Disk space management

Use when the user requests capacity analysis, a storage map, cleanup planning or a measured check after maintenance. Installing this package grants no deletion authority.

1. Establish the requested computer and folder. In Mithril Desktop, open Device care → Storage, then analyze home or select a folder with the native picker. Temporary-file analysis has a separate, narrower cleanup scope. Cancel an analysis when its scope is unnecessary.
2. Alternatively run `python3 scripts/audit.py --root /explicit/selected/folder` from this skill directory. The bundled standard-library tool reads filesystem metadata only, writes JSON to stdout and never deletes, uploads or reads file contents. Defaults: 20,000 entries, depth 16 and 15 seconds. Symlinks, other volumes and unavailable entries are excluded; limits mark partial coverage. Folder names and paths are private: keep output local unless the user requests sharing.
3. Read volume capacity and available space separately from measured folder totals. Logical size counts each pathname; allocated estimates count a hard-linked inode once. APFS clones, compression, snapshots and shared containers prevent exact attribution. Unknown capacity stays unknown. Partial charts omit unmeasured files; do not extrapolate them to the whole disk.
4. Inspect the largest group one level at a time using an explicit narrower folder. Group selection in Desktop reveals details; it does not authorize cleanup. Compare before/after measurements for the same volume, scope and bounds.
5. Make a candidate ledger: exact path, measured bytes, class (reclaimable / review-required / preserve / unverified), owner, evidence of active use or open files, regeneration command or verified recovery copy, proposed operation and user authorization. If evidence is missing, mark unverified. Age, a cache name or large size alone never proves disposability. Do not claim an open-file check from metadata analysis.
6. Preserve source repositories and worktrees, user documents, chat/history, models, credentials, quarantine/recovery vaults, snapshots and application databases by default. Prefer reusing installed dependencies and existing artifacts before generating duplicates. Propose app-native cache controls only after verifying their documented scope. Do not automate broad recursive deletion or empty Trash.
7. For Desktop-generated temporary media, use the app's candidate selection and concrete review plan. Native confirmation binds exact items, bytes and expiry; the executor revalidates identity and moves eligible files to OS Trash. Arbitrary analyzed folders remain read-only. Other mutations require the user's authorization for the concrete paths and recovery plan; this skill's script supplies no mutation command.
8. After authorized maintenance, remeasure available space and record failures, skipped items and recovery locations. Moving to Trash may reclaim nothing until explicitly emptied. Report measured free-space change independently from logical bytes moved. Keep unknown and partial results visible.

Return the measured capacity summary, bounded folder breakdown, candidate ledger and next concrete action. Distinguish an installed skill, a completed analysis and a confirmed cleanup. Never install software, change snapshots, stop services, send messages or publish paths as an implicit part of analysis.
