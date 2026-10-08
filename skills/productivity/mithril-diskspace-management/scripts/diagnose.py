#!/usr/bin/env python3
"""Compare local metadata audits and produce a cleanup review ledger. Never deletes."""
import argparse
import datetime
import json
import math
import os
import re


def category(path):
    value = path.replace("\\", "/").lower()
    if re.search(r"quarantine|recovery|credentials|\.git(?:/|$)|\.hermes|backup|\.sqlite|\.db$", value):
        return "protected"
    for name, pattern in (
        ("dependencies", r"(?:^|/)(?:node_modules|\.npm|\.yarn|vendor|\.venv)(?:/|$)"),
        ("cache", r"(?:^|/)(?:cache|caches|\.cache)(?:/|$)"),
        ("logs", r"(?:^|/)logs?(?:/|$)|\.log$"),
        ("models", r"\.(?:gguf|safetensors|pt|onnx)$|(?:^|/)models?(?:/|$)"),
        ("downloads", r"(?:^|/)downloads(?:/|$)|\.(?:zip|dmg|iso)$"),
    ):
        if re.search(pattern, value):
            return name
    return "unknown"


def compare(current, previous):
    unavailable = dict(state="unverified", reason="Comparable complete observations are required", groups=[])
    if not previous or any(report.get("partial", True) for report in (current, previous)):
        return unavailable
    keys = ("schemaVersion", "root", "volumeId", "bounds")
    if any(key not in current or key not in previous or current[key] != previous[key] for key in keys):
        return unavailable
    try:
        for report in (current, previous):
            metrics = [report["logicalBytes"]] + [g["logicalBytes"] for g in report["groups"]]
            if not all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in metrics):
                return unavailable
        before = datetime.datetime.fromisoformat(previous["observedAt"])
        after = datetime.datetime.fromisoformat(current["observedAt"])
        if before.tzinfo is None or after.tzinfo is None or before >= after:
            return unavailable
        old = {(g["kind"], g["name"]): g["logicalBytes"] for g in previous["groups"]}
        new = {(g["kind"], g["name"]): g["logicalBytes"] for g in current["groups"]}
        # Top-N membership shifts cannot prove named group growth or disappearance.
        common = old.keys() & new.keys()
        deltas = [dict(kind=k[0], name=k[1], logicalDelta=new[k] - old[k]) for k in common if k[0] != "other"]
        deltas.sort(key=lambda g: (-g["logicalDelta"], g["name"]))
        result = dict(state="comparable", logicalDelta=current["logicalBytes"] - previous["logicalBytes"], groups=deltas, limitation="Only shared named groups; Other and top-N membership changes are not attributed")
        free = (current.get("freeBytes"), previous.get("freeBytes"))
        result["freeSpaceDelta"] = free[0] - free[1] if all(isinstance(v, (int, float)) and math.isfinite(v) and v >= 0 for v in free) else None
        return result
    except (KeyError, ValueError, TypeError):
        return unavailable


def diagnose(current, previous=None):
    root = current["root"]
    ledger = []
    for item in current.get("largest", [])[:20]:
        path = item["name"]
        # Imported measurements are data, never commands or authority over another root.
        if not os.path.isabs(path) or os.path.commonpath([root, path]) != os.path.normpath(root):
            continue
        hint = category(path)
        ledger.append(dict(path=path, measuredBytes=item["bytes"], classification="preserve" if hint == "protected" else "review-required", causeHypothesis=hint, evidence="path only", owner="unverified", activeUse="unverified", regenerationOrRecovery="unverified", nextAction="Preserve; verify owner-native retention" if hint == "protected" else "Verify owner, active use and regeneration/recovery before proposing an exact action", authorization="pending"))
    return dict(schemaVersion=1, root=root, observedAt=current.get("observedAt"), coverage="partial" if current.get("partial", True) else "complete", growth=compare(current, previous), cleanupReview=ledger, mutationSupported=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True)
    parser.add_argument("--previous")
    args = parser.parse_args()
    try:
        with open(args.current, encoding="utf-8") as source:
            current = json.load(source)
        previous = None
        if args.previous:
            with open(args.previous, encoding="utf-8") as source:
                previous = json.load(source)
        result = diagnose(current, previous)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
