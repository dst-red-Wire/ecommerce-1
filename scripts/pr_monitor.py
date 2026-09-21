#!/usr/bin/env python3
"""Low-cost GitHub PR watcher that emits bounded ChatGPT review handoffs for meaningful deltas."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request

PROMPT_BUDGET_BYTES = 16 * 1024
GRAPHQL_QUERY = """query PRMonitor($owner:String!,$repo:String!,$number:Int!,$threadCursor:String){repository(owner:$owner,name:$repo){pullRequest(number:$number){state merged mergeable mergeStateStatus isDraft reviewDecision updatedAt headRefOid reviews(last:100){nodes{id state submittedAt author{login}}} reviewThreads(first:100,after:$threadCursor){pageInfo{hasNextPage endCursor} nodes{id isResolved comments(last:1){nodes{id updatedAt path line originalLine body author{login}}}}} commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{... on CheckRun{id name status conclusion} ... on StatusContext{id context state}}}}}}}}}}"""
THREADS_QUERY = """query PRMonitorThreads($owner:String!,$repo:String!,$number:Int!,$threadCursor:String!){repository(owner:$owner,name:$repo){pullRequest(number:$number){reviewThreads(first:100,after:$threadCursor){pageInfo{hasNextPage endCursor} nodes{id isResolved comments(last:1){nodes{id updatedAt path line originalLine body author{login}}}}}}}}"""


class TransientGitHubError(RuntimeError):
    """A polling error that should be retried without losing monitor state."""


def github_request(
    url: str,
    token: str,
    *,
    body: bytes | None = None,
    etag: str = "",
) -> tuple[int, Any, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ecommerce-pr-monitor/2",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if etag:
        headers["If-None-Match"] = etag
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST" if body else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read()), response.headers.get("ETag", etag)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, etag
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        rate_limited = exc.code == 403 and (exc.headers or {}).get("X-RateLimit-Remaining") == "0"
        if exc.code == 429 or exc.code >= 500 or rate_limited:
            raise TransientGitHubError(f"GitHub transient HTTP {exc.code}: {detail}") from exc
        raise RuntimeError(f"GitHub returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise TransientGitHubError(f"GitHub request failed transiently: {exc}") from exc


def _graphql_body(query: str, owner: str, repo: str, number: int, cursor: str | None = None) -> bytes:
    return json.dumps(
        {
            "query": query,
            "variables": {
                "owner": owner,
                "repo": repo,
                "number": number,
                "threadCursor": cursor,
            },
        }
    ).encode()


def _graphql_pr(payload: dict[str, Any], number: int) -> dict[str, Any]:
    if payload.get("errors"):
        raise RuntimeError(f"GitHub GraphQL error: {payload['errors']}")
    repository = (payload.get("data") or {}).get("repository") or {}
    pr = repository.get("pullRequest")
    if pr is None:
        raise RuntimeError(f"pull request #{number} not found")
    return pr


def paginate_review_threads(
    pr: dict[str, Any],
    *,
    owner: str,
    repo: str,
    number: int,
    token: str,
) -> dict[str, Any]:
    connection = pr.get("reviewThreads") or {}
    nodes = list(connection.get("nodes") or [])
    page_info = connection.get("pageInfo") or {}
    while page_info.get("hasNextPage"):
        cursor = page_info.get("endCursor")
        if not cursor:
            raise RuntimeError("review thread pagination omitted endCursor")
        _, payload, _ = github_request(
            "https://api.github.com/graphql",
            token,
            body=_graphql_body(THREADS_QUERY, owner, repo, number, cursor),
        )
        page_pr = _graphql_pr(payload, number)
        page = page_pr.get("reviewThreads") or {}
        nodes.extend(page.get("nodes") or [])
        page_info = page.get("pageInfo") or {}
    result = dict(pr)
    result["reviewThreads"] = {"nodes": nodes, "pageInfo": page_info}
    return result


def snapshot(pr: dict[str, Any], *, etag: str, timestamp: int) -> dict[str, Any]:
    nodes = (pr.get("commits") or {}).get("nodes") or []
    rollup = ((nodes[-1].get("commit") or {}).get("statusCheckRollup") or {}) if nodes else {}
    checks = {}
    for check in (rollup.get("contexts") or {}).get("nodes") or []:
        key = str(check.get("id") or check.get("name") or check.get("context"))
        checks[key] = str(check.get("conclusion") or check.get("status") or check.get("state") or "UNKNOWN")
    reviews = {
        str(review["id"]): {
            "state": review.get("state"),
            "submitted_at": review.get("submittedAt"),
            "author": (review.get("author") or {}).get("login"),
        }
        for review in ((pr.get("reviews") or {}).get("nodes") or [])
    }
    findings = {}
    for thread in (pr.get("reviewThreads") or {}).get("nodes") or []:
        if thread.get("isResolved"):
            continue
        comments = (thread.get("comments") or {}).get("nodes") or [{}]
        comment = comments[-1]
        findings[str(thread["id"])] = {
            "comment_id": comment.get("id"),
            "updated_at": comment.get("updatedAt"),
            "path": comment.get("path"),
            "line": comment.get("line"),
            "original_line": comment.get("originalLine"),
            "body": comment.get("body"),
            "author": (comment.get("author") or {}).get("login"),
        }
    return {
        "head_sha": pr.get("headRefOid"),
        "checks": checks,
        "review_decision": pr.get("reviewDecision"),
        "reviews": reviews,
        "open_findings_count": len(findings),
        "open_findings": findings,
        "mergeable": pr.get("mergeable"),
        "merge_state_status": pr.get("mergeStateStatus"),
        "is_draft": bool(pr.get("isDraft")),
        "state": pr.get("state"),
        "merged": bool(pr.get("merged")),
        "github_updated_at": pr.get("updatedAt"),
        "polled_at": timestamp,
        "etag": etag,
    }


MEANINGFUL = (
    "head_sha",
    "checks",
    "review_decision",
    "reviews",
    "open_findings_count",
    "open_findings",
    "mergeable",
    "merge_state_status",
    "is_draft",
    "state",
    "merged",
)
COLLECTION_KEYS = {"checks", "reviews", "open_findings"}


def meaningful(state: dict[str, Any]) -> dict[str, Any]:
    return {key: state.get(key) for key in MEANINGFUL}


def _collection_delta(before: Any, after: Any) -> dict[str, Any]:
    before_map = before if isinstance(before, dict) else {}
    after_map = after if isinstance(after, dict) else {}
    added = {key: after_map[key] for key in sorted(after_map.keys() - before_map.keys())}
    removed = {key: before_map[key] for key in sorted(before_map.keys() - after_map.keys())}
    modified = {
        key: {"before": before_map[key], "after": after_map[key]}
        for key in sorted(before_map.keys() & after_map.keys())
        if before_map[key] != after_map[key]
    }
    result = {}
    if added:
        result["added"] = added
    if removed:
        result["removed"] = removed
    if modified:
        result["modified"] = modified
    return result


def delta(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    result = {}
    current_meaningful = meaningful(current)
    for key, value in current_meaningful.items():
        before = previous.get(key)
        if before == value:
            continue
        if key in COLLECTION_KEYS:
            collection_change = _collection_delta(before, value)
            if collection_change:
                result[key] = collection_change
        else:
            result[key] = {"before": before, "after": value}
    return result


def changed_files(owner: str, repo: str, old: str, new: str, token: str) -> list[str]:
    if not old or not new or old == new:
        return []
    _, payload, _ = github_request(
        f"https://api.github.com/repos/{owner}/{repo}/compare/{old}...{new}",
        token,
    )
    return [item["filename"] for item in payload.get("files", []) if item.get("filename")]


def _truncate(value: Any, *, string_limit: int = 1000) -> Any:
    if isinstance(value, str):
        if len(value) <= string_limit:
            return value
        return value[: string_limit - 1] + "…"
    if isinstance(value, list):
        return [_truncate(item, string_limit=string_limit) for item in value]
    if isinstance(value, dict):
        return {key: _truncate(item, string_limit=string_limit) for key, item in value.items()}
    return value


def _encode_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def bounded_payload(payload: dict[str, Any], *, budget: int = PROMPT_BUDGET_BYTES) -> str:
    reduced = _truncate(copy.deepcopy(payload))
    encoded = _encode_payload(reduced)
    if len(encoded.encode()) <= budget:
        return encoded

    reduced["changed_files"] = list(reduced.get("changed_files") or [])[:50]
    reduced["previous_validated_verdict"] = _truncate(
        reduced.get("previous_validated_verdict") or "",
        string_limit=1200,
    )
    changes = reduced.get("delta") or {}
    for key in COLLECTION_KEYS:
        value = changes.get(key)
        if not isinstance(value, dict):
            continue
        compact = {}
        for change_kind in ("added", "removed", "modified"):
            items = value.get(change_kind)
            if isinstance(items, dict):
                compact[change_kind] = dict(list(items.items())[:12])
        changes[key] = compact
    encoded = _encode_payload(reduced)
    if len(encoded.encode()) <= budget:
        return encoded

    summary = {
        "pr": reduced.get("pr"),
        "previous_validated_verdict": _truncate(
            reduced.get("previous_validated_verdict") or "",
            string_limit=800,
        ),
        "current_head": reduced.get("current_head"),
        "changed_files": list(reduced.get("changed_files") or [])[:20],
        "delta_keys": sorted((reduced.get("delta") or {}).keys()),
        "delta_summary": {
            key: {
                kind: len(items) if isinstance(items, dict) else 0
                for kind, items in value.items()
            }
            for key, value in (reduced.get("delta") or {}).items()
            if key in COLLECTION_KEYS and isinstance(value, dict)
        },
        "truncated": True,
    }
    encoded = _encode_payload(summary)
    if len(encoded.encode()) > budget:
        raise RuntimeError("prompt budget is too small for the minimal PR delta")
    return encoded


def chatgpt_review_handoff(
    number: int,
    previous: dict[str, Any],
    current: dict[str, Any],
    changes: dict[str, Any],
    files: list[str],
) -> str:
    instruction = (
        "ChatGPT incremental exact-SHA PR review handoff. "
        "Do not reload PR history or repeat proven gates. "
        "Review only changed_files plus finding paths in delta, then issue CODE/SECURITY findings "
        "bound to current_head. No other AI reviewer is authorized.\n"
    )
    payload = {
        "pr": number,
        "delta": changes,
        "current_head": current.get("head_sha"),
        "changed_files": files,
    }
    encoded = bounded_payload(payload, budget=PROMPT_BUDGET_BYTES - len(instruction.encode()))
    return instruction + encoded


def next_interval(unchanged: int, minimum: int, maximum: int) -> int:
    if unchanged >= 8:
        target = 3600
    elif unchanged >= 4:
        target = 1800
    else:
        target = minimum
    return min(max(minimum, target), maximum)


def is_terminal(state: dict[str, Any], abandoned: bool) -> bool:
    return bool(state.get("merged")) or state.get("state") != "OPEN" or abandoned


def _write_state(state_path: Path, state: dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def poll_once(args: argparse.Namespace, state_path: Path, token: str) -> tuple[bool, int]:
    previous = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    status, payload, etag = github_request(
        "https://api.github.com/graphql",
        token,
        body=_graphql_body(GRAPHQL_QUERY, args.owner, args.repo, args.pr),
        etag=previous.get("etag", ""),
    )
    if status == 304:
        unchanged = int(previous.get("unchanged_polls", 0)) + 1
        updated = dict(previous)
        updated["unchanged_polls"] = unchanged
        updated["polled_at"] = int(time.time())
        _write_state(state_path, updated)
        print("NO_CHANGE", flush=True)
        return is_terminal(previous, args.abandoned), unchanged

    pr = _graphql_pr(payload, args.pr)
    pr = paginate_review_threads(
        pr,
        owner=args.owner,
        repo=args.repo,
        number=args.pr,
        token=token,
    )
    current = snapshot(pr, etag=etag, timestamp=int(time.time()))
    changes = delta(previous, current) if previous else {}
    unchanged = 0 if changes else int(previous.get("unchanged_polls", 0)) + 1
    current["unchanged_polls"] = unchanged

    if previous and changes:
        files = changed_files(
            args.owner,
            args.repo,
            previous.get("head_sha", ""),
            current.get("head_sha", ""),
            token,
        )
        handoff = chatgpt_review_handoff(args.pr, previous, current, changes, files)
        current["chatgpt_review_handoff"] = handoff
        print("CHATGPT_REVIEW_REQUIRED", flush=True)
        print(handoff, flush=True)
    else:
        print("NO_CHANGE", flush=True)

    # Persist only after all delta processing succeeds. A failed review is retried.
    _write_state(state_path, current)
    return is_terminal(current, args.abandoned), unchanged


def _state_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "unknown"


def default_state_path(owner: str, repo: str, number: int) -> Path:
    return Path(
        ".context/pr-monitor/"
        f"{_state_component(owner)}-{_state_component(repo)}-pr-{number}.json"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--interval", type=int, default=900)
    parser.add_argument("--max-interval", type=int, default=3600)
    parser.add_argument("--state")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--abandoned", action="store_true")
    args = parser.parse_args()
    if args.interval < 1 or args.max_interval < args.interval:
        parser.error("intervals must satisfy 1 <= --interval <= --max-interval")
    return args


def main() -> int:
    args = parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2
    state_path = Path(args.state) if args.state else default_state_path(args.owner, args.repo, args.pr)
    transient_failures = 0
    while True:
        try:
            terminal, unchanged = poll_once(args, state_path, token)
            transient_failures = 0
        except TransientGitHubError as exc:
            transient_failures += 1
            delay = min(
                max(args.interval, 60 * (2 ** min(transient_failures - 1, 6))),
                args.max_interval,
            )
            print(f"TRANSIENT_ERROR retry_in={delay}s: {exc}", file=sys.stderr, flush=True)
            if args.once:
                return 3
            time.sleep(delay)
            continue
        if terminal or args.once:
            return 0
        time.sleep(next_interval(unchanged, args.interval, args.max_interval))


if __name__ == "__main__":
    raise SystemExit(main())
