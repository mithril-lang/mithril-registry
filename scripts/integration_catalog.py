"""Build the non-executable composition catalog from the shipped planning skill."""

import importlib.util
from pathlib import Path

PACKAGE_PATH = "skills/productivity/mithril-enterprise-integrations"


def load_planner(root: Path):
    spec = importlib.util.spec_from_file_location(
        "enterprise_planner", root / PACKAGE_PATH / "scripts/planner.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(root: Path) -> dict:
    import json

    package = root / PACKAGE_PATH
    data = json.loads((package / "integration.json").read_text())
    planner = load_planner(root)
    result = planner.catalog(data)
    for node in data["components"]:
        if node["kind"] == "skill":
            relative = node.get("instructions")
            if not isinstance(relative, str):
                raise ValueError(f"{node['id']}: skill instructions required")
            target = (package / relative).resolve()
            if not target.is_relative_to(package.resolve()) or not target.is_file():
                raise ValueError(f"{node['id']}: instructions must be packaged files")
    return {**result, "package": PACKAGE_PATH}
