#!/usr/bin/env python3
"""Exact-input budget/cache controller for Codex invocations.

This helper never calls an AI model and never grants CODE/SECURITY or merge
authority. It only decides whether an explicitly marked local result can be
reused for the exact current context key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/codex-token-budget.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def contract() -> dict[str, Any]:
    return load_json(CONTRACT)


def _under_context(path: Path) -> bool:
    root = (ROOT / ".context").resolve()
    target = path.resolve()
    return target == root or root in target.parents


def _result_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if not _under_context(path):
        raise ValueError("Codex cache results must remain under .context")
    return path


def _cache_path(cache_key: str) -> Path:
    cfg = contract()
    root = ROOT / str(cfg["context_cache"]["state_directory"])
    return root / f"{cache_key}.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_manifest(manifest: dict[str, Any]) -> None:
    cfg = contract()
    route = str(manifest.get("route") or "")
    maxima = cfg["context_level_max_bytes"]
    if route not in maxima:
        raise ValueError(f"unknown context route: {route}")
    actual = int(manifest.get("actual_bytes", -1))
    declared = int(manifest.get("max_bytes", -1))
    allowed = int(maxima[route])
    if actual < 0 or declared < 1 or actual > declared or declared > allowed:
        raise ValueError(
            f"context budget violation route={route} actual={actual} declared={declared} allowed={allowed}"
        )
    key = str(manifest.get("cache_key") or "")
    if len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
        raise ValueError("manifest cache_key must be a full SHA-256")
    pack_path = _result_path(str(manifest.get("pack_path") or ""))
    pack_sha = str(manifest.get("pack_sha256") or "")
    if not pack_path.is_file() or len(pack_sha) != 64 or _sha256(pack_path) != pack_sha:
        raise ValueError("context pack integrity mismatch")


def decide(manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    cache_key = str(manifest["cache_key"])
    marker_path = _cache_path(cache_key)
    result = {
        "cache_key": cache_key,
        "route": manifest["route"],
        "actual_bytes": int(manifest["actual_bytes"]),
        "estimated_input_tokens": int(manifest.get("estimated_input_tokens", 0)),
        "should_invoke_ai": True,
        "reason": "exact_input_cache_miss",
        "cached_result": "",
    }
    if not marker_path.is_file():
        return result
    try:
        marker = load_json(marker_path)
        result_path = _result_path(str(marker.get("result_path") or ""))
    except (OSError, ValueError, json.JSONDecodeError):
        return result
    if (
        marker.get("cache_key") == cache_key
        and marker.get("status") == "PASS"
        and result_path.is_file()
        and marker.get("result_sha256") == _sha256(result_path)
    ):
        result.update(
            {
                "should_invoke_ai": False,
                "reason": "exact_input_cache_hit",
                "cached_result": str(result_path.relative_to(ROOT)),
            }
        )
    return result


def mark(manifest_path: Path, result_value: str) -> Path:
    manifest = load_json(manifest_path)
    validate_manifest(manifest)
    result_path = _result_path(result_value)
    if not result_path.is_file():
        raise ValueError(f"result does not exist: {result_path}")
    cache_key = str(manifest["cache_key"])
    marker_path = _cache_path(cache_key)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "status": "PASS",
        "cache_key": cache_key,
        "head_sha": str(manifest.get("head_sha") or ""),
        "result_path": str(result_path.relative_to(ROOT)),
        "result_sha256": _sha256(result_path),
    }
    marker_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return marker_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--manifest", default=".context/codex-context.json")
    m = sub.add_parser("mark")
    m.add_argument("--manifest", default=".context/codex-context.json")
    m.add_argument("--result", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    if args.command == "decide":
        print(json.dumps(decide(manifest), sort_keys=True))
        return 0
    marker = mark(manifest, args.result)
    print(marker.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        raise SystemExit(1) from None
