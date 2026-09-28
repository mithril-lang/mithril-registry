#!/usr/bin/env python3
"""Validate skill packages and build a deterministic Hermes-style catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
REQUIRED = ("name", "description", "version", "author", "license")


def frontmatter(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    parts = content.split("---\n", 2)
    if len(parts) != 3 or parts[0] != "" or not parts[2].strip():
        raise ValueError(f"{path}: missing frontmatter or body")
    data = yaml.safe_load(parts[1])
    if not isinstance(data, dict):
        raise ValueError(f"{path}: frontmatter must be a map")
    return data


def package_checksum(folder: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in folder.rglob("*") if path.is_file())
    for path in files:
        rel = path.relative_to(folder).as_posix().encode()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return "sha256:" + digest.hexdigest()


def build() -> tuple[dict, dict]:
    entries = []
    seen = set()
    for path in sorted(SKILLS.glob("*/*/SKILL.md")):
        category, folder_name = path.relative_to(SKILLS).parts[:2]
        data = frontmatter(path)
        for field in REQUIRED:
            if not isinstance(data.get(field), str) or not data[field].strip():
                raise ValueError(f"{path}: invalid {field}")
        if not NAME.fullmatch(data["name"]) or data["name"] != folder_name:
            raise ValueError(f"{path}: name must match the folder")
        if not NAME.fullmatch(category) or not VERSION.fullmatch(data["version"]):
            raise ValueError(f"{path}: invalid category or version")
        if data["name"] in seen:
            raise ValueError(f"{path}: duplicate name")
        seen.add(data["name"])
        metadata = data.get("metadata", {}).get("hermes", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"{path}: metadata.hermes must be a map")
        tags = metadata.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ValueError(f"{path}: tags must be strings")
        entries.append({
            "id": data["name"],
            "type": "skill",
            "category": category,
            "name": data["name"],
            "version": data["version"],
            "description": data["description"],
            "tags": tags,
            "author": data["author"],
            "license": data["license"],
            "path": path.parent.relative_to(ROOT).as_posix(),
            "icon": None,
            "checksum": package_checksum(path.parent),
            "compatibility": metadata.get("compatibility"),
            "acceptsFunding": False,
        })
    if not entries:
        raise ValueError("registry must contain at least one validated package")
    entries.sort(key=lambda entry: (entry["type"], entry["category"], entry["id"]))
    index = {"schemaVersion": "1", "count": len(entries), "entries": entries}
    counts = {}
    for entry in entries:
        counts[entry["category"]] = counts.get(entry["category"], 0) + 1
    categories = {"schemaVersion": "1", "types": [{
        "type": "skill", "count": len(entries),
        "categories": [{"name": name, "count": count} for name, count in sorted(counts.items())],
    }]}
    return index, categories


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, value in zip(("index.json", "categories.json"), build()):
        target = ROOT / name
        expected = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            if not target.exists() or target.read_text(encoding="utf-8") != expected:
                raise SystemExit(f"{name} is stale; run python3 scripts/build_index.py")
        else:
            target.write_text(expected, encoding="utf-8")
    print("Registry validated; catalog is current.")


if __name__ == "__main__":
    main()
