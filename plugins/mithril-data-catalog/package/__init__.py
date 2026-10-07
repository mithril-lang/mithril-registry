"""Hermes tool registration for API-mediated Mithril catalog staging."""

from __future__ import annotations

SCHEMA = {
    "name": "mithril_catalog_publish",
    "description": (
        "Stage authorized local dataset files through api.mithril.fund. Returns an R2 staging "
        "receipt, not an Iceberg materialization receipt. Never use Cloudflare credentials."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": ["dataset", "root", "generated_at", "files"],
        "properties": {
            "dataset": {
                "type": "string",
                "enum": ["actor", "adnetwork", "attack", "cwe", "darkweb", "epss",
                         "exchange-sec", "humankind", "kev", "oss-sec", "pwned"],
            },
            "root": {"type": "string", "description": "Absolute authorized local root."},
            "generated_at": {"type": "string", "description": "Optional RFC3339 time with offset."},
            "files": {
                "type": "array",
                "minItems": 1,
                "maxItems": 32,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["path"],
                    "properties": {
                        "path": {"type": "string", "description": "Path relative to root."},
                        "rows": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
    },
}


def _token() -> str:
    from agent.secret_scope import get_secret

    return (get_secret("MITHRIL_CATALOG_API_TOKEN") or "").strip()


def _available() -> bool:
    return bool(_token())


def _handle(args: dict, api_url: str, **_kwargs) -> str:
    from .client import CatalogClientError, publish

    try:
        return publish(args, _token(), api_url=api_url)
    except CatalogClientError as error:
        import json

        return json.dumps({"error": {"code": "catalog_publish_failed", "message": str(error)}})


def register(ctx) -> None:
    api_url = ctx.get_config(
        "api_url",
        "https://mithril-api.cloud-kotoba.workers.dev/v1/internal/data-catalog/ingest",
    )
    ctx.register_tool(
        name="mithril_catalog_publish",
        toolset="mithril_data_catalog",
        schema=SCHEMA,
        handler=lambda args, **kwargs: _handle(args, api_url, **kwargs),
        check_fn=_available,
        description=SCHEMA["description"],
        emoji="🧊",
    )
