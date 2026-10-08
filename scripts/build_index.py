#!/usr/bin/env python3
"""Validate skill packages and build a deterministic Hermes-style catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml
import security_catalog
import integration_catalog
import solution_catalog

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
MANIFEST_TYPES = ("mcp", "tool", "plugin", "agent", "workflow")
MANIFEST_DIRS = {"mcp": "mcp", "tool": "tools", "plugin": "plugins", "agent": "agents", "workflow": "workflows"}
NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
REQUIRED = ("name", "description", "version", "author", "license")


def require_https(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: expected an HTTPS URL")
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError(f"{field}: expected an HTTPS URL without credentials")
    return value


def executable_artifact(data: dict, path: Path) -> None:
    artifact = data.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("format") != "git":
        raise ValueError(f"{path}: executable requires a Git artifact")
    require_https(artifact.get("url"), f"{path}: artifact.url")
    if not re.fullmatch(r"[0-9a-f]{40}", str(artifact.get("commit", ""))):
        raise ValueError(f"{path}: executable requires a full lowercase Git commit")
    entry = artifact.get("entry")
    if not isinstance(entry, str) or not re.fullmatch(r"bin/[a-z0-9-]+\.mjs", entry):
        raise ValueError(f"{path}: invalid fixed entrypoint")
    if data.get("command") != "node" or not isinstance(data.get("args"), list) or not data["args"]:
        raise ValueError(f"{path}: executable requires Node arguments")
    if data["args"][0] != "${system_one_root}/" + entry or any(
        not isinstance(arg, str) or not re.fullmatch(r"[a-z0-9-]+", arg)
        for arg in data["args"][1:]
    ):
        raise ValueError(f"{path}: arguments must bind the fixed entrypoint")
    if data.get("env", {}) != {"MITHRIL_API_KEY": "optional-owning-profile-reference"}:
        raise ValueError(f"{path}: only a scoped optional credential reference is allowed")


def manifest(path: Path, expected_type: str) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schemaVersion") != "1" or data.get("type") != expected_type:
        raise ValueError(f"{path}: invalid schemaVersion or type")
    for field in ("id", "category", *REQUIRED):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError(f"{path}: invalid {field}")
    if not NAME.fullmatch(data["id"]) or path.parent.name != data["id"]:
        raise ValueError(f"{path}: id must match the folder")
    if not NAME.fullmatch(data["category"]) or not VERSION.fullmatch(data["version"]):
        raise ValueError(f"{path}: invalid category or version")
    require_https(data.get("source"), f"{path}: source")
    if not isinstance(data.get("tags"), list) or not all(isinstance(tag, str) for tag in data["tags"]):
        raise ValueError(f"{path}: tags must be strings")
    if not isinstance(data.get("permissions"), list) or not data["permissions"] or not all(isinstance(p, str) for p in data["permissions"]):
        raise ValueError(f"{path}: permissions must be nonempty strings")
    if expected_type == "mcp":
        if data.get("transport") not in ("streamable-http", "stdio") or data.get("protocolVersion") != "2025-06-18":
            raise ValueError(f"{path}: unsupported MCP transport or protocol")
        if data["transport"] == "stdio":
            executable_artifact(data, path)
            if "url" in data:
                raise ValueError(f"{path}: stdio has no hosted URL")
        else:
            require_https(data.get("url"), f"{path}: url")
        if not isinstance(data.get("authentication"), dict) or data["authentication"].get("mode") != "per-tool":
            raise ValueError(f"{path}: authentication must describe per-tool access")
        tools = data.get("tools")
        if not isinstance(tools, list) or not tools:
            raise ValueError(f"{path}: tools must be nonempty")
        names = set()
        for tool in tools:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
                raise ValueError(f"{path}: invalid tool name")
            if tool["name"] in names or tool.get("authentication") not in (("none", "process-env-optional") if data["transport"] == "stdio" else ("none", "personal-api-token", "tenant-service-account")) or tool.get("effect") not in ("read", "write", "inference"):
                raise ValueError(f"{path}: duplicate tool or invalid access/effect")
            names.add(tool["name"])
    elif expected_type == "tool":
        binding, http = data.get("catalog"), data.get("http")
        if not isinstance(binding, dict) or not all(isinstance(binding.get(k), str) and binding[k] for k in ("url", "name")):
            raise ValueError(f"{path}: tool needs an HTTP tool catalog binding")
        require_https(binding["url"], f"{path}: catalog.url")
        if not isinstance(http, dict) or http.get("method") != "GET" or not isinstance(http.get("query"), dict):
            raise ValueError(f"{path}: tool needs a GET HTTP fallback")
        require_https(http.get("url"), f"{path}: http.url")
        if data.get("authentication") != "none" or data.get("effect") != "read":
            raise ValueError(f"{path}: standalone tool catalog only admits public read operations")
        for schema_field in ("inputSchema", "outputSchema"):
            schema = data.get(schema_field)
            if not isinstance(schema, dict) or schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
                raise ValueError(f"{path}: invalid {schema_field}")
        if set(http["query"]) != set(data["inputSchema"].get("required", [])):
            raise ValueError(f"{path}: HTTP query parameters and required input differ")
    elif expected_type in ("agent", "workflow"):
        executable_artifact(data, path)
        execution = data.get("execution")
        if (data.get("executable") is not True or not isinstance(execution, dict)
                or execution.get("runtime") != "mithril-system-one" or execution.get("input") != "json-stdin"
                or type(execution.get("maxTasks")) is not int
                or not 1 <= execution["maxTasks"] <= (1 if expected_type == "agent" else 3)
                or execution.get("stopOnFailure") is not True or execution.get("retryUnknown") is not False):
            raise ValueError(f"{path}: executable requires a bounded stop-on-failure contract")
    else:
        artifact, compatibility = data.get("artifact"), data.get("compatibility")
        if not isinstance(artifact, dict) or artifact.get("format") not in ("zip", "git"):
            raise ValueError(f"{path}: plugin needs a zip or git artifact")
        require_https(artifact.get("url"), f"{path}: artifact.url")
        if artifact["format"] == "zip":
            if not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
                raise ValueError(f"{path}: artifact.sha256 must be lowercase SHA-256")
            if not isinstance(artifact.get("bytes"), int) or artifact["bytes"] <= 0:
                raise ValueError(f"{path}: artifact.bytes must be positive")
        elif not re.fullmatch(r"[0-9a-f]{40}", str(artifact.get("commit", ""))):
            raise ValueError(f"{path}: artifact.commit must be a full lowercase Git commit")
        clients = compatibility.get("clients") if isinstance(compatibility, dict) else None
        platforms = compatibility.get("platforms") if isinstance(compatibility, dict) else None
        if not isinstance(clients, list) or not clients or not all(
            isinstance(client, dict) and all(isinstance(client.get(k), str) and client[k] for k in ("name", "version", "tested"))
            for client in clients
        ):
            raise ValueError(f"{path}: plugin needs tested client compatibility")
        if not isinstance(platforms, list) or not platforms or not all(isinstance(item, str) for item in platforms):
            raise ValueError(f"{path}: plugin needs platforms")
        if artifact["format"] == "zip":
            package = path.parent / "package"
            required_files = [package / "plugin.yaml", package / "desktop" / "plugin.js", package / "README.md", package / "LICENSE"]
            if not all(item.is_file() and item.stat().st_size for item in required_files):
                raise ValueError(f"{path}: plugin package is incomplete")
            native = yaml.safe_load((package / "plugin.yaml").read_text(encoding="utf-8"))
            if native.get("name") != data["id"] or native.get("version") != data["version"]:
                raise ValueError(f"{path}: plugin.yaml identity does not match manifest")
        requirements = data.get("requirements", {})
        commands = requirements.get("commands") if isinstance(requirements, dict) else None
        if commands is not None and (
            not isinstance(commands, list)
            or not commands
            or not all(isinstance(command, str) and NAME.fullmatch(command) for command in commands)
        ):
            raise ValueError(f"{path}: requirements.commands must be command names")
        tools = data.get("tools")
        if tools is not None and (
            not isinstance(tools, list)
            or not tools
            or not all(isinstance(tool, str) and NAME.fullmatch(tool.replace("_", "-")) for tool in tools)
        ):
            raise ValueError(f"{path}: tools must be nonempty command names")
    return data


def frontmatter(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    parts = content.split("---\n", 2)
    if len(parts) != 3 or parts[0] != "" or not parts[2].strip():
        raise ValueError(f"{path}: missing frontmatter or body")
    data = yaml.safe_load(parts[1])
    if not isinstance(data, dict):
        raise ValueError(f"{path}: frontmatter must be a map")
    # Agent Skills stores extension metadata here; retain legacy top-level
    # Registry author/version fields for existing packages.
    metadata = data.get("metadata", {})
    if isinstance(metadata, dict):
        for key in ("version", "author"):
            if key not in data and key in metadata:
                data[key] = metadata[key]
    return data


def package_checksum(folder: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        path for path in folder.rglob("*")
        if path.is_file() and not {"__pycache__", ".nbb"}.intersection(path.parts) and path.suffix != ".pyc"
    )
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
        if ("skill", data["name"]) in seen:
            raise ValueError(f"{path}: duplicate name")
        seen.add(("skill", data["name"]))
        metadata = data.get("metadata", {}).get("hermes", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"{path}: metadata.hermes must be a map")
        tags = metadata.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise ValueError(f"{path}: tags must be strings")
        entry = {
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
            "installable": True,
        }
        if data['name'] == 'mithril-security-suite':
            security = security_catalog.build(ROOT)
            if security['version'] != data['version']:
                raise ValueError('security skill and capability versions differ')
            entry['security'] = {'catalog': 'security.json',
                                 'operations': [op['id'] for op in security['operations']]}
        if data['name'] == 'mithril-enterprise-integrations':
            integration = integration_catalog.build(ROOT)
            if integration['version'] != data['version']:
                raise ValueError('integration skill and definition versions differ')
            entry['integration'] = {
                'catalog': 'integrations.json', 'digest': integration['digest'],
                'runtimeReady': False,
                'kinds': sorted({node['kind'] for node in integration['definition']['components']}),
            }
        entries.append(entry)
    manifests = {type_: {} for type_ in MANIFEST_TYPES}
    for type_ in MANIFEST_TYPES:
        for path in sorted((ROOT / MANIFEST_DIRS[type_]).glob("*/manifest.json")):
            data = manifest(path, type_)
            key = (type_, data["id"])
            if key in seen:
                raise ValueError(f"{path}: duplicate id")
            seen.add(key)
            manifests[type_][data["id"]] = data
            entry = {
                "id": data["id"], "type": type_, "category": data["category"],
                "name": data["name"], "version": data["version"],
                "description": data["description"], "tags": data["tags"],
                "author": data["author"], "license": data["license"],
                "path": path.parent.relative_to(ROOT).as_posix(),
                "icon": None, "checksum": package_checksum(path.parent),
                "compatibility": None, "acceptsFunding": False,
                "permissions": data["permissions"],
                "installable": type_ != "tool",
            }
            if type_ == "mcp":
                entry["connection"] = {"transport": data["transport"], "authentication": data["authentication"]["mode"]}
                if data["transport"] == "stdio":
                    entry["connection"].update(command=data["command"], args=data["args"])
                    entry["artifact"] = data["artifact"]
                else:
                    entry["connection"]["url"] = data["url"]
            elif type_ == "tool":
                entry["connection"] = {"viaHttpCatalog": data["catalog"]}
            elif type_ in ("agent", "workflow"):
                entry.update(artifact=data["artifact"], execution=data["execution"],
                             requirements=data["requirements"], tools=data["tools"])
            else:
                entry["artifact"] = data["artifact"]
                entry["compatibility"] = data["compatibility"]
                if data.get("requirements"):
                    entry["requirements"] = data["requirements"]
                if data.get("tools"):
                    entry["tools"] = data["tools"]
            entries.append(entry)
    if not entries:
        raise ValueError("registry must contain at least one validated package")
    entries.sort(key=lambda entry: (entry["type"], entry["category"], entry["id"]))
    index = {"schemaVersion": "1", "count": len(entries), "entries": entries}
    counts = {}
    for entry in entries:
        key = (entry["type"], entry["category"])
        counts[key] = counts.get(key, 0) + 1
    categories = {"schemaVersion": "1", "types": [{
        "type": type_, "count": sum(count for (kind, _), count in counts.items() if kind == type_),
        "categories": [{"name": category, "count": count} for (kind, category), count in sorted(counts.items()) if kind == type_],
    } for type_ in ("skill", *MANIFEST_TYPES) if any(kind == type_ for kind, _ in counts)]}
    return index, categories


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    index, categories = build()
    solutions = solution_catalog.build(ROOT, [e['id'] for e in index['entries']])
    index['solutionCatalog'] = 'solutions.json'
    docs = ROOT / 'solutions/agency'
    if not args.check:
        docs.mkdir(parents=True, exist_ok=True)
    for solution in solutions['solutions']:
        target = docs / (solution['id'] + '.md')
        expected = solution_catalog.document(solution, solutions['botProfiles'])
        if args.check:
            if not target.exists() or target.read_text() != expected:
                raise SystemExit(f"{target.name} is stale; run scripts/build_index.py")
        else:
            target.write_text(expected)
    for entry in index['entries']:
        entry['solutionIds'] = [s['id'] for s in solutions['solutions'] if entry['id'] in s['registryEntries']]
    for name, value in (("index.json", index), ("categories.json", categories),
                        ("security.json", security_catalog.build(ROOT)),
                        ("integrations.json", integration_catalog.build(ROOT)),
                        ("solutions.json", solutions)):
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
