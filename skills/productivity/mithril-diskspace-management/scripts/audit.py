#!/usr/bin/env python3
"""Bounded, metadata-only disk space audit. No cleanup operations."""
import argparse
import datetime
import json
import os
import stat
import time


def audit(root, max_entries=20000, max_depth=16, seconds=15):
    if max_entries < 1 or max_depth < 0 or seconds <= 0:
        raise ValueError("Bounds must be positive (depth may be zero)")
    root = os.path.abspath(root)
    base = os.lstat(root)
    if not stat.S_ISDIR(base.st_mode) or os.path.realpath(root) != root:
        raise ValueError("Select a real directory without symlink ancestors")
    capacity = available = None
    try:
        volume = os.statvfs(root)
        capacity = volume.f_frsize * volume.f_blocks
        available = volume.f_frsize * volume.f_bavail
    except (AttributeError, OSError):
        pass
    report = dict(schemaVersion=1, root=root, observedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), capacity=capacity, freeBytes=available, files=0, logicalBytes=0, allocatedBytes=0, skipped=0, partial=False, bounds=dict(entries=max_entries, depth=max_depth, seconds=seconds), groups=[], largest=[])
    queue = [(root, 0)]
    groups, seen = {}, set()
    visited, start = 0, time.monotonic()
    while queue and visited < max_entries and time.monotonic() - start < seconds:
        path, depth = queue.pop()
        visited += 1
        try:
            item = os.lstat(path)
            if stat.S_ISLNK(item.st_mode) or item.st_dev != base.st_dev or depth > max_depth:
                report["skipped"] += 1
                continue
            if stat.S_ISDIR(item.st_mode):
                if os.path.realpath(path) != path:
                    report["skipped"] += 1
                    continue
                with os.scandir(path) as children:
                    for child in children:
                        if visited + len(queue) >= max_entries or time.monotonic() - start >= seconds:
                            report["partial"] = True
                            break
                        queue.append((child.path, depth + 1))
            elif stat.S_ISREG(item.st_mode):
                parts = os.path.relpath(path, root).split(os.sep)
                key = "" if len(parts) == 1 else parts[0]
                group = groups.setdefault(key, dict(name=key, kind="folder" if key else "files", logicalBytes=0, allocatedBytes=0, files=0))
                inode = (item.st_dev, item.st_ino)
                allocated = getattr(item, "st_blocks", None)
                allocated = item.st_size if allocated is None else allocated * 512
                allocated = 0 if inode in seen else allocated
                seen.add(inode)
                for dest in (report, group):
                    dest["files"] += 1
                    dest["logicalBytes"] += item.st_size
                    dest["allocatedBytes"] += allocated
                report["largest"].append(dict(name=path, bytes=item.st_size))
                report["largest"].sort(key=lambda entry: entry["bytes"], reverse=True)
                del report["largest"][20:]
            else:
                report["skipped"] += 1
        except OSError:
            report["skipped"] += 1
    ordered = sorted(groups.values(), key=lambda entry: (-entry["logicalBytes"], entry["name"]))
    report["groups"] = ordered[:12]
    if len(ordered) > 12:
        report["groups"].append(dict(name="", kind="other", **{key: sum(group[key] for group in ordered[12:]) for key in ("files", "logicalBytes", "allocatedBytes")}))
    report["skipped"] += len(queue)
    report["partial"] = report["partial"] or bool(report["skipped"])
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--max-entries", type=int, default=20000)
    parser.add_argument("--max-depth", type=int, default=16)
    parser.add_argument("--seconds", type=float, default=15)
    args = parser.parse_args()
    try:
        result = audit(args.root, args.max_entries, args.max_depth, args.seconds)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
