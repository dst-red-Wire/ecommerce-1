#!/usr/bin/env python3
"""Classify safe PostgreSQL backend metadata without exposing state payloads."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def unknown() -> dict[str, Any]:
    return {"rowCount": None, "workspaceNames": [], "verdict": "UNKNOWN"}


def evaluate(observation: Any, phase: str) -> dict[str, Any]:
    if not isinstance(observation, dict):
        return unknown()
    identity = {
        "database": "terraform_backend",
        "user": "terraform_backend",
        "schema": "terraform_management",
        "table": "states",
        "schemaExists": True,
        "tableExists": True,
        "tableColumnsExact": True,
        "uniqueWorkspaceIndex": True,
    }
    if any(observation.get(key) != value for key, value in identity.items()):
        return unknown()
    row_count = observation.get("rowCount")
    names = observation.get("workspaceNames")
    if (
        not isinstance(row_count, int)
        or isinstance(row_count, bool)
        or row_count < 0
        or not isinstance(names, list)
        or len(names) != row_count
        or names != sorted(set(names))
        or any(not isinstance(name, str) or not re.fullmatch(r"[0-9A-Za-z_-]+", name) for name in names)
    ):
        return unknown()
    result: dict[str, Any] = {
        "rowCount": row_count,
        "workspaceNames": names,
        "verdict": "NON_EMPTY" if row_count else "EMPTY",
    }
    if phase == "post-init" and row_count:
        empty_rows = observation.get("emptyStateRowCount")
        if not isinstance(empty_rows, int) or isinstance(empty_rows, bool) or not 0 <= empty_rows <= row_count:
            return unknown()
        if row_count == 1 and names == ["default"] and empty_rows == 1:
            result["verdict"] = "EMPTY"
    return result


parser = argparse.ArgumentParser()
parser.add_argument("--input", type=Path, required=True)
parser.add_argument("--phase", choices=("preflight", "post-init"), required=True)
args = parser.parse_args()
try:
    parsed = json.loads(args.input.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    parsed = None
json.dump(evaluate(parsed, args.phase), sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
