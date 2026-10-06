#!/usr/bin/env python3
"""Validate and plan enterprise compositions. Never authenticate or execute tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

KINDS = {"skill", "mcp", "agent", "workflow", "plugin"}
EFFECTS = {"read", "write", "publish"}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
PACKAGE = Path(__file__).resolve().parents[1]


def canonical_digest(value: object) -> str:
    content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


def strings(value: object, label: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{label}: expected a list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label}: expected nonempty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{label}: duplicates")
    return value


def validate(data: dict) -> dict[str, dict]:
    if not isinstance(data, dict) or data.get("schemaVersion") != "1":
        raise ValueError("integration schemaVersion must be 1")
    if not VERSION.fullmatch(str(data.get("version", ""))):
        raise ValueError("invalid integration version")
    if not isinstance(data.get("components"), list) or not data["components"]:
        raise ValueError("components must be nonempty")
    providers = data.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise ValueError("providers must be nonempty")
    for name, provider in providers.items():
        if not IDENTIFIER.fullmatch(name) or not isinstance(provider, dict):
            raise ValueError("invalid provider")
        strings(provider.get("targetFields"), f"{name}.targetFields", nonempty=True)
        strings(provider.get("credentialReferences"), f"{name}.credentialReferences", nonempty=True)
        strings(provider.get("prerequisites"), f"{name}.prerequisites", nonempty=True)
        if provider.get("qualification") != "not-verified":
            raise ValueError("provider qualification requires separate live evidence")
    nodes = {}
    for component in data["components"]:
        if not isinstance(component, dict):
            raise ValueError("component must be an object")
        key = component.get("id")
        if not isinstance(key, str) or not IDENTIFIER.fullmatch(key) or key in nodes:
            raise ValueError("invalid or duplicate component id")
        if component.get("kind") not in KINDS or component.get("provider") not in providers:
            raise ValueError(f"{key}: invalid kind or provider")
        if not VERSION.fullmatch(str(component.get("version", ""))):
            raise ValueError(f"{key}: invalid version")
        if component.get("execution") != "design-only":
            raise ValueError(f"{key}: executable adapters are not shipped in this package")
        if not isinstance(component.get("description"), str) or not component["description"].strip():
            raise ValueError(f"{key}: description required")
        strings(component.get("requires"), f"{key}.requires")
        strings(component.get("permissions"), f"{key}.permissions", nonempty=True)
        if component["kind"] == "mcp":
            binding = component.get("binding")
            if not isinstance(binding, dict) or binding.get("mode") != "user-configured":
                raise ValueError(f"{key}: MCP requires a user-configured binding")
            if "url" in binding or binding.get("verification") != ["initialize", "tools/list"]:
                raise ValueError(f"{key}: cannot advertise an unverified MCP endpoint")
        nodes[key] = component
    for key, node in nodes.items():
        for dependency in node["requires"]:
            if dependency not in nodes:
                raise ValueError(f"{key}: missing dependency {dependency}")
            if nodes[dependency]["provider"] != node["provider"]:
                raise ValueError(f"{key}: cross-provider dependency needs a separate explicit composition")
            if not set(nodes[dependency]["permissions"]) <= set(node["permissions"]):
                raise ValueError(f"{key}: dependency permissions not declared")
        if node["kind"] == "workflow":
            validate_steps(node, nodes)
        if node["kind"] == "plugin":
            kinds = {nodes[dep]["kind"] for dep in node["requires"]}
            if not {"skill", "mcp", "agent", "workflow"} <= kinds:
                raise ValueError(f"{key}: plugin must compose all four component kinds")
    ordered(nodes, list(nodes))
    return nodes


def ordered(nodes: dict[str, dict], roots: list[str]) -> list[str]:
    result, active, done = [], set(), set()

    def visit(key: str):
        if key in active:
            raise ValueError(f"dependency cycle at {key}")
        if key in done:
            return
        if key not in nodes:
            raise ValueError(f"unknown component {key}")
        active.add(key)
        for dependency in nodes[key]["requires"]:
            visit(dependency)
        active.remove(key)
        done.add(key)
        result.append(key)

    for root in roots:
        visit(root)
    return result


def validate_steps(workflow: dict, nodes: dict[str, dict]) -> None:
    steps = workflow.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"{workflow['id']}: steps must be nonempty")
    graph = {}
    closure = set(ordered(nodes, workflow["requires"]))
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError("step must be an object")
        key = step.get("id")
        if not isinstance(key, str) or not IDENTIFIER.fullmatch(key) or key in graph:
            raise ValueError("invalid or duplicate step id")
        if step.get("component") not in closure or nodes[step["component"]]["kind"] not in {"skill", "mcp"}:
            raise ValueError(f"{key}: step must use a declared skill or MCP dependency")
        if step.get("effect") not in EFFECTS or not isinstance(step.get("operation"), str) or not step["operation"].strip():
            raise ValueError(f"{key}: invalid operation or effect")
        if step.get("approval") != ("explicit" if step["effect"] in {"write", "publish"} else "none"):
            raise ValueError(f"{key}: write/publish steps require explicit approval")
        strings(step.get("permissions"), f"{key}.permissions", nonempty=True)
        if not set(step["permissions"]) <= set(nodes[step["component"]]["permissions"]):
            raise ValueError(f"{key}: operation permissions exceed component permissions")
        graph[key] = {"requires": strings(step.get("after"), f"{key}.after")}
    ordered(graph, list(graph))


def catalog(data: dict) -> dict:
    validate(data)
    return {"schemaVersion": "1", "version": data["version"], "digest": canonical_digest(data),
            "runtimeReady": False, "definition": data}


def plan(data: dict, selected: str, context: dict | None = None) -> dict:
    nodes = validate(data)
    order = ordered(nodes, [selected])
    context = {} if context is None else context
    if not isinstance(context, dict) or set(context) - {"principal", "target"}:
        raise ValueError("context accepts only principal and target; credentials must remain in the host")
    principal, target = context.get("principal"), context.get("target", {})
    if principal is not None and (not isinstance(principal, str) or not principal.strip()):
        raise ValueError("principal must be a nonempty reference")
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    provider_name = nodes[selected]["provider"]
    provider = data["providers"][provider_name]
    if set(target) - set(provider["targetFields"]):
        raise ValueError("unknown target fields; do not provide credentials")
    if any(not isinstance(value, str) or not value.strip() for value in target.values()):
        raise ValueError("target fields must be nonempty references")
    blocked = ["execution-adapter-not-shipped", "live-qualification-not-verified"]
    if not principal:
        blocked.append("principal-not-bound")
    blocked.extend(f"target-not-bound:{field}" for field in provider["targetFields"] if field not in target)
    components = [{**nodes[key], "digest": canonical_digest(nodes[key])} for key in order]
    proposal = {"schemaVersion": "1", "mode": "plan-only", "selected": selected,
                "provider": provider_name, "principal": principal, "target": target,
                "definitionDigest": canonical_digest(data), "components": components,
                "permissions": sorted({p for key in order for p in nodes[key]["permissions"]}),
                "credentialReferences": provider["credentialReferences"],
                "prerequisites": provider["prerequisites"], "blockedBy": blocked, "executable": False}
    return {**proposal, "planDigest": canonical_digest(proposal)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition", type=Path, default=PACKAGE / "integration.json")
    parser.add_argument("--component")
    parser.add_argument("--context", type=Path, help="JSON principal/target references only; no credentials")
    args = parser.parse_args()
    if args.context and not args.component:
        parser.error('--context requires --component')
    try:
        data = json.loads(args.definition.read_text())
        context = json.loads(args.context.read_text()) if args.context else None
        value = plan(data, args.component, context) if args.component else catalog(data)
    except (ValueError, OSError) as error:
        parser.exit(2, f"Integration definition rejected: {error}\n")
    print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
