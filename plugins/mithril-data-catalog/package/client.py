"""Bounded local-file client for the Mithril Data Catalog ingest API."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request


API_URL = "https://api.mithril.fund/v1/internal/data-catalog/ingest"
DATASETS = frozenset(("actor", "adnetwork", "attack", "cwe", "darkweb", "epss",
                      "exchange-sec", "humankind", "kev", "oss-sec", "pwned"))
CONTENT_TYPES = {
    ".csv": "text/csv",
    ".gz": "application/gzip",
    ".json": "application/json",
    ".parquet": "application/vnd.apache.parquet",
    ".zip": "application/zip",
}
MAX_FILE = 8 * 1024 * 1024
MAX_BATCH = 16 * 1024 * 1024


class CatalogClientError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise CatalogClientError("catalog API redirect refused")


def _generated_at(value) -> str:
    if value is None:
        raise CatalogClientError("generated_at is required for retry-stable batch identity")
    if not isinstance(value, str) or len(value) > 64:
        raise CatalogClientError("generated_at must be a bounded RFC3339 string")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CatalogClientError("generated_at must be RFC3339 with an offset") from exc
    if parsed.tzinfo is None:
        raise CatalogClientError("generated_at must include an offset")
    return value


def _payload(args: dict) -> dict:
    if not isinstance(args, dict):
        raise CatalogClientError("tool arguments must be an object")
    dataset = args.get("dataset")
    if dataset not in DATASETS:
        raise CatalogClientError("dataset is not in the Mithril catalog allowlist")
    root_value = args.get("root")
    if not isinstance(root_value, str) or not Path(root_value).is_absolute():
        raise CatalogClientError("root must be an absolute path")
    root = Path(root_value).resolve(strict=True)
    if not root.is_dir():
        raise CatalogClientError("root must be a directory")
    files = args.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 32:
        raise CatalogClientError("files must contain 1 through 32 entries")
    entries, total, seen = [], 0, set()
    for item in files:
        if not isinstance(item, dict) or set(item) - {"path", "rows"}:
            raise CatalogClientError("each file needs only path and optional rows")
        relative = item.get("path")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise CatalogClientError("file paths must be non-empty and relative")
        candidate = (root / relative).resolve(strict=True)
        try:
            remote = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise CatalogClientError("file resolves outside root") from exc
        if remote in seen or not candidate.is_file():
            raise CatalogClientError("files must be unique regular files")
        seen.add(remote)
        content = candidate.read_bytes()
        if not 0 < len(content) <= MAX_FILE:
            raise CatalogClientError("each file must contain 1 byte through 8 MiB")
        total += len(content)
        if total > MAX_BATCH:
            raise CatalogClientError("catalog batch exceeds 16 MiB")
        rows = item.get("rows")
        if rows is not None and (isinstance(rows, bool) or not isinstance(rows, int) or rows < 0):
            raise CatalogClientError("rows must be a non-negative integer")
        entry = {
            "path": remote,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "contentType": CONTENT_TYPES.get(candidate.suffix.lower(), "application/octet-stream"),
            "contentBase64": base64.b64encode(content).decode("ascii"),
        }
        if rows is not None:
            entry["rows"] = rows
        entries.append(entry)
    return {"dataset": dataset, "generatedAt": _generated_at(args.get("generated_at")), "files": entries}


def publish(args: dict, token: str, *, opener=None) -> str:
    if not token:
        raise CatalogClientError("MITHRIL_CATALOG_API_TOKEN is not configured for this profile")
    payload = _payload(args)
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "mithril-data-catalog-hermes-plugin/1.0",
        },
        method="POST",
    )
    transport = opener or urllib.request.build_opener(_NoRedirect())
    try:
        with transport.open(request, timeout=300) as response:
            receipt = json.load(response)
    except urllib.error.HTTPError as exc:
        raise CatalogClientError(f"catalog ingest failed with HTTP {exc.code}") from None
    except urllib.error.URLError:
        raise CatalogClientError("catalog ingest transport failed") from None
    if not isinstance(receipt, dict) or receipt.get("dataset") != payload["dataset"] \
            or receipt.get("state") != "staged-for-iceberg" \
            or not isinstance(receipt.get("batchId"), str):
        raise CatalogClientError("catalog ingest returned an invalid receipt")
    return json.dumps(receipt, separators=(",", ":"), sort_keys=True)
