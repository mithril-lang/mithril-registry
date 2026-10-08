#!/usr/bin/env python3
"""Bounded, metadata-only disk space audit. No cleanup operations."""
import argparse
import datetime
import json
import os
import stat
import time
from collections import deque


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
    report = dict(schemaVersion=1, root=root, volumeId=str(base.st_dev), observedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(), capacity=capacity, freeBytes=available, files=0, logicalBytes=0, allocatedBytes=0, skipped=0, partial=False, bounds=dict(entries=max_entries, depth=max_depth, seconds=seconds), groups=[], largest=[])
    queue = deque([(root, 0, None)])
    cursors = set()
    groups, seen = {}, set()
    visited, start = 1, time.monotonic()
    try:
      while queue and visited < max_entries and time.monotonic() - start < seconds:
        directory, depth, cursor = queue.popleft()
        try:
            if cursor is None:
                current = os.lstat(directory)
                if not stat.S_ISDIR(current.st_mode) or current.st_dev != base.st_dev or os.path.realpath(directory) != directory:
                    report["skipped"] += 1
                    continue
                cursor = os.scandir(directory)
                cursors.add(cursor)
            exhausted = False
            for _ in range(32):
                if visited >= max_entries or time.monotonic() - start >= seconds:
                    break
                try:
                    child = next(cursor)
                except StopIteration:
                    exhausted = True
                    break
                path = child.path
                visited += 1
                try:
                    item = os.lstat(path)
                except OSError:
                    report["skipped"] += 1
                    continue
                if stat.S_ISLNK(item.st_mode) or item.st_dev != base.st_dev or depth + 1 > max_depth:
                    report["skipped"] += 1
                    continue
                if stat.S_ISDIR(item.st_mode):
                    if len(queue) >= 128 or os.path.realpath(path) != path:
                        report["skipped"] += 1
                        continue
                    queue.append((path, depth + 1, None))
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
            if exhausted:
                cursor.close()
                cursors.discard(cursor)
            else:
                queue.append((directory, depth, cursor))
        except OSError:
            report["skipped"] += 1
            if cursor is not None:
                cursor.close()
                cursors.discard(cursor)
    finally:
        for cursor in cursors:
            cursor.close()
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
