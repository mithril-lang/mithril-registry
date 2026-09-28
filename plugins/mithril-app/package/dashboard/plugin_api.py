"""Narrow facade over Hermes Kanban for the Mithril Desktop application."""

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from plugins.kanban.dashboard import plugin_api as kanban


router = APIRouter()
BOARD = "mithril-runtime"
REGISTRY_FORMAT = "https://mithril.fund/profile/coding-tool-registry-v1"
REGISTRY = Path(os.environ.get(
    "MITHRIL_CODING_REGISTRY",
    str(Path.home() / ".hermes" / "mithril" / "coding-tool-registry-v1.json"),
))


@router.get("/kanban/board")
async def board():
    return await kanban.get_board_endpoint(
        tenant=None,
        include_archived=False,
        board=BOARD,
        workflow_template_id=None,
        current_step_key=None,
    )


@router.post("/kanban/tasks")
def create_task(payload: kanban.CreateTaskBody):
    if payload.assignee != "mithril-runtime":
        raise HTTPException(status_code=400, detail="Mithril queue accepts only mithril-runtime")
    return kanban.create_task(payload, board=BOARD)


@router.get("/kanban/workspaces")
def workspaces():
    document = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if set(document) != {"format", "profiles"} or document["format"] != REGISTRY_FORMAT:
        raise HTTPException(status_code=500, detail="invalid Mithril coding tool registry")
    rows = document["profiles"]
    if not isinstance(rows, list) or any(set(row) != {"workspace", "tool-profile"} for row in rows):
        raise HTTPException(status_code=500, detail="invalid Mithril coding tool registry entries")
    values = [row["workspace"] for row in rows]
    if len(values) != len(set(values)) or any(not Path(value).is_absolute() for value in values):
        raise HTTPException(status_code=500, detail="Mithril workspaces must be unique absolute paths")
    return {"format": REGISTRY_FORMAT, "workspaces": values}
