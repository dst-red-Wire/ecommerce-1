#!/usr/bin/env python3
"""Deterministic guardrail for repeated Codex/Work pull-request review.

This controller never calls an AI model. It decides whether a model invocation is
justified from material state changes, persists ephemeral state under .context,
and records exact-SHA review cache markers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "contracts" / "review-budget.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def contract() -> dict[str, Any]:
    return load_json(CONTRACT_PATH)


def state_root() -> Path:
    return ROOT / contract()["state_directory"]


def pr_root(pr: int) -> Path:
    return state_root() / f"pr-{pr}"


def snapshot_path(pr: int) -> Path:
    return pr_root(pr) / "last-snapshot.json"


def cache_path(pr: int, head_sha: str, review_kind: str) -> Path:
    return pr_root(pr) / head_sha / f"{review_kind}.json"


def normalize_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    findings = sorted({str(item) for item in raw.get("unresolved_finding_ids", [])})
    checks = raw.get("checks", {}) or {}
    reviews = raw.get("reviews", {}) or {}
    return {
        "base_sha": str(raw.get("base_sha", "")),
        "head_sha": str(raw.get("head_sha", "")),
        "last_reviewed_sha": str(raw.get("last_reviewed_sha", "")),
        "unresolved_finding_ids": findings,
        "checks": {str(k): str(v) for k, v in sorted(checks.items())},
        "reviews": {str(k): str(v) for k, v in sorted(reviews.items())},
    }


def materially_completed(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    before = previous.get("reviews", {})
    after = current.get("reviews", {})
    terminal = {"COMPLETED", "APPROVED", "CHANGES_REQUESTED", "FAILED"}
    for key, value in after.items():
        if value in terminal and before.get(key) != value:
            return True
    return False


def decision(pr: int, current: dict[str, Any], review_kind: str, final_candidate: bool) -> dict[str, Any]:
    current = normalize_snapshot(current)
    if not current["head_sha"]:
        raise ValueError("head_sha is required")

    cached = cache_path(pr, current["head_sha"], review_kind).is_file()
    previous_path = snapshot_path(pr)
    previous = normalize_snapshot(load_json(previous_path)) if previous_path.is_file() else None

    should_invoke = False
    reason = "unchanged_status"
    depth = "FAST"

    if cached:
        reason = "exact_sha_cache_hit"
    elif final_candidate:
        should_invoke = True
        reason = "final_candidate"
        depth = "DEEP"
    elif previous is None:
        should_invoke = True
        reason = "initial_review"
        depth = "NORMAL"
    elif previous["head_sha"] != current["head_sha"]:
        should_invoke = True
        reason = "head_changed"
        depth = "NORMAL"
    else:
        old_findings = set(previous["unresolved_finding_ids"])
        new_findings = set(current["unresolved_finding_ids"])
        if new_findings - old_findings:
            should_invoke = True
            reason = "new_finding"
            depth = "NORMAL"
        elif materially_completed(previous, current):
            should_invoke = True
            reason = "review_completed"
            depth = "NORMAL"

    diff_base = current["last_reviewed_sha"] or (previous or {}).get("head_sha", "") or current["base_sha"]
    affected_command = ""
    diff_context_command = ""
    if diff_base and diff_base != current["head_sha"]:
        affected_command = f"make affected BASE={diff_base} HEAD={current['head_sha']}"
        diff_context_command = f"make diff-context BASE={diff_base}"

    result = {
        "should_invoke_ai": should_invoke,
        "reason": reason,
        "depth": depth,
        "pr": pr,
        "review_kind": review_kind,
        "base_sha": current["base_sha"],
        "head_sha": current["head_sha"],
        "diff_base_sha": diff_base,
        "unresolved_finding_ids": current["unresolved_finding_ids"],
        "cached_review_kinds": [review_kind] if cached else [],
        "affected_command": affected_command,
        "diff_context_command": diff_context_command,
    }

    root = pr_root(pr)
    root.mkdir(parents=True, exist_ok=True)
    previous_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def mark_cache(pr: int, head_sha: str, review_kind: str, source: str) -> Path:
    if not head_sha:
        raise ValueError("head_sha is required")
    path = cache_path(pr, head_sha, review_kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pr": pr,
        "head_sha": head_sha,
        "review_kind": review_kind,
        "source": source,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def summarize_log(path: Path) -> str:
    cfg = contract()
    max_lines = int(cfg["max_failure_summary_lines"])
    max_bytes = int(cfg["max_failure_summary_bytes"])
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()
    selected = lines[-max_lines:]
    text = "\n".join(selected)
    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        encoded = encoded[-max_bytes:]
        text = encoded.decode("utf-8", errors="replace")
    return text + ("\n" if text else "")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    decide = sub.add_parser("decide")
    decide.add_argument("--pr", type=int, required=True)
    decide.add_argument("--snapshot", type=Path, required=True)
    decide.add_argument("--review-kind", choices=["code", "security", "combined"], default="combined")
    decide.add_argument("--final-candidate", action="store_true")

    cache = sub.add_parser("cache")
    cache.add_argument("--pr", type=int, required=True)
    cache.add_argument("--head-sha", required=True)
    cache.add_argument("--review-kind", choices=["code", "security", "combined"], required=True)
    cache.add_argument("--source", default="verified-review")

    summary = sub.add_parser("summarize-log")
    summary.add_argument("--log", type=Path, required=True)

    args = parser.parse_args()
    if args.cmd == "decide":
        result = decision(args.pr, load_json(args.snapshot), args.review_kind, args.final_candidate)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.cmd == "cache":
        path = mark_cache(args.pr, args.head_sha, args.review_kind, args.source)
        print(path.relative_to(ROOT))
        return 0
    if args.cmd == "summarize-log":
        print(summarize_log(args.log), end="")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
