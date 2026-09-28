#!/usr/bin/env python3
"""Build a reproducible zip for one registry plugin package."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    package = ROOT / "plugins" / args.plugin / "package"
    manifest = json.loads((ROOT / "plugins" / args.plugin / "manifest.json").read_text())
    output = args.output or ROOT / "dist" / f"{args.plugin}-{manifest['version']}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source in sorted(
            path for path in package.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        ):
            relative = Path(args.plugin) / source.relative_to(package)
            info = zipfile.ZipInfo(relative.as_posix(), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    data = output.read_bytes()
    result = {"path": str(output), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if args.check:
        artifact = manifest["artifact"]
        if artifact["bytes"] != result["bytes"] or artifact["sha256"] != result["sha256"]:
            raise SystemExit("plugin artifact metadata does not match the reproducible package")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
