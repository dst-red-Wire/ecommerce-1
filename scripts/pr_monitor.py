#!/usr/bin/env python3
"""Low-cost GitHub PR watcher that emits bounded ChatGPT review handoffs for meaningful deltas."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from .exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        ExactPRBindingError,
        resolve_exact_open_pr,
        revalidate_exact_open_pr,
    )
    from .managed_gh import resolve_managed_gh
else:
    from exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        ExactPRBindingError,
        resolve_exact_open_pr,
        revalidate_exact_open_pr,
    )
    from managed_gh import resolve_managed_gh

ROOT = Path(__file__).resolve().parents[1]
PROMPT_BUDGET_BYTES = int(
    json.loads(
        (ROOT / "config/contracts/codex-token-budget.json").read_text(encoding="utf-8")
    )["review_handoff_max_bytes"]
)
GRAPHQL_QUERY = """query PRMonitor($owner:String!,$repo:String!,$number:Int!,$threadCursor:String,$commentCursor:String){repository(owner:$owner,name:$repo){owner{login} pullRequest(number:$number){state merged mergeable mergeStateStatus isDraft reviewDecision updatedAt headRefOid comments(first:100,after:$commentCursor){pageInfo{hasNextPage endCursor} nodes{id createdAt updatedAt authorAssociation body author{login}}} reviews(last:100){nodes{id state submittedAt author{login}}} reviewThreads(first:100,after:$threadCursor){pageInfo{hasNextPage endCursor} nodes{id isResolved comments(last:1){nodes{id updatedAt path line originalLine body author{login}}}}} commits(last:1){nodes{commit{statusCheckRollup{contexts(first:100){nodes{... on CheckRun{id name status conclusion} ... on StatusContext{id context state}}}}}}}}}}"""
COMMENTS_QUERY = """query PRMonitorComments($owner:String!,$repo:String!,$number:Int!,$commentCursor:String!){repository(owner:$owner,name:$repo){pullRequest(number:$number){comments(first:100,after:$commentCursor){pageInfo{hasNextPage endCursor} nodes{id createdAt updatedAt authorAssociation body author{login}}}}}}"""
THREADS_QUERY = """query PRMonitorThreads($owner:String!,$repo:String!,$number:Int!,$threadCursor:String!){repository(owner:$owner,name:$repo){pullRequest(number:$number){reviewThreads(first:100,after:$threadCursor){pageInfo{hasNextPage endCursor} nodes{id isResolved comments(last:1){nodes{id updatedAt path line originalLine body author{login}}}}}}}}"""


class TransientGitHubError(RuntimeError):
    """A polling error that should be retried without losing monitor state."""


class SupersededHeadError(RuntimeError):
    """The local PR checkout cannot safely follow the exact GitHub HEAD."""


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
            return (
                response.status,
                json.loads(response.read()),
                response.headers.get("ETag", etag),
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, None, etag
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        rate_limited = (
            exc.code == 403 and (exc.headers or {}).get("X-RateLimit-Remaining") == "0"
        )
        if exc.code == 429 or exc.code >= 500 or rate_limited:
            raise TransientGitHubError(
                f"GitHub transient HTTP {exc.code}: {detail}"
            ) from exc
        raise RuntimeError(f"GitHub returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise TransientGitHubError(f"GitHub request failed transiently: {exc}") from exc


def _graphql_body(
    query: str,
    owner: str,
    repo: str,
    number: int,
    cursor: str | None = None,
    comment_cursor: str | None = None,
) -> bytes:
    return json.dumps(
        {
            "query": query,
            "variables": {
                "owner": owner,
                "repo": repo,
                "number": number,
                "threadCursor": cursor,
                "commentCursor": comment_cursor,
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
    result = dict(pr)
    result["_repository_owner_login"] = (repository.get("owner") or {}).get(
        "login"
    ) or ""
    return result


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


def paginate_comments(
    pr: dict[str, Any],
    *,
    owner: str,
    repo: str,
    number: int,
    token: str,
) -> dict[str, Any]:
    connection = pr.get("comments") or {}
    nodes = list(connection.get("nodes") or [])
    page_info = connection.get("pageInfo") or {}
    seen_cursors: set[str] = set()
    while page_info.get("hasNextPage"):
        cursor = page_info.get("endCursor")
        if not cursor or cursor in seen_cursors or len(seen_cursors) >= 99:
            raise RuntimeError("PR comment pagination is invalid or exceeds 100 pages")
        seen_cursors.add(cursor)
        _, payload, _ = github_request(
            "https://api.github.com/graphql",
            token,
            body=_graphql_body(
                COMMENTS_QUERY, owner, repo, number, comment_cursor=cursor
            ),
        )
        page_pr = _graphql_pr(payload, number)
        page = page_pr.get("comments") or {}
        nodes.extend(page.get("nodes") or [])
        if len(nodes) > 10_000:
            raise RuntimeError("PR comment pagination exceeds 10000 comments")
        page_info = page.get("pageInfo") or {}
    result = dict(pr)
    result["comments"] = {"nodes": nodes, "pageInfo": page_info}
    return result


CHATGPT_REVIEW_MARKER_RE = re.compile(
    r"<!--\s*chatgpt-exact-sha-review:v1\s+(\{[^\n]*\})\s*-->"
)


def _unique_marker_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate marker field")
        result[key] = value
    return result


def _latest_chatgpt_review(pr: dict[str, Any]) -> dict[str, Any]:
    head = str(pr.get("headRefOid") or "")
    owner = str(pr.get("_repository_owner_login") or "")
    latest: dict[str, tuple[str, int, dict[str, Any]]] = {}
    for index, comment in enumerate((pr.get("comments") or {}).get("nodes") or []):
        if (comment.get("author") or {}).get("login") != owner or not owner:
            continue
        lines = [
            line
            for line in str(comment.get("body") or "").splitlines()
            if "chatgpt-exact-sha-review:v1" in line
        ]
        if not lines:
            continue
        if len(lines) != 1:
            return {
                "head_sha": head,
                "verdict": "BLOCKED",
                "reason": "AMBIGUOUS_OWNER_MARKER",
            }
        match = CHATGPT_REVIEW_MARKER_RE.fullmatch(lines[0])
        try:
            proof = (
                json.loads(match.group(1), object_pairs_hook=_unique_marker_fields)
                if match
                else None
            )
        except ValueError:
            proof = None
        if (
            not isinstance(proof, dict)
            or set(proof)
            != {"provider", "kind", "head_sha", "status", "blocking_findings"}
            or proof.get("provider") != "ChatGPT"
            or proof.get("kind") not in {"code", "security"}
            or re.fullmatch(r"[0-9a-f]{40}", str(proof.get("head_sha") or "")) is None
            or type(proof.get("blocking_findings")) is not int
            or not (
                (proof.get("status") == "PASS" and proof["blocking_findings"] == 0)
                or (
                    proof.get("status") in {"BLOCKED", "FAIL"}
                    and proof["blocking_findings"] > 0
                )
            )
        ):
            return {
                "head_sha": head,
                "verdict": "BLOCKED",
                "reason": "INVALID_OWNER_MARKER",
            }
        if proof["head_sha"] != head:
            continue
        if (
            comment.get("authorAssociation") != "OWNER"
            or not isinstance(comment.get("createdAt"), str)
            or comment.get("createdAt") != comment.get("updatedAt")
        ):
            return {
                "head_sha": head,
                "verdict": "BLOCKED",
                "reason": "EDITED_OR_NONOWNER_MARKER",
            }
        kind = proof["kind"]
        key = (comment["createdAt"], index)
        value = {
            **proof,
            "created_at": key[0],
            "comment_id": comment.get("id"),
            "sequence": index,
        }
        if kind not in latest or key > latest[kind][:2]:
            latest[kind] = (key[0], key[1], value)
    code = latest.get("code", ("", "", {}))[2]
    security = latest.get("security", ("", "", {}))[2]
    if not code and not security:
        return {}
    ready = bool(
        code
        and security
        and code["status"] == "PASS"
        and security["status"] == "PASS"
        and (security["created_at"], security["sequence"])
        > (code["created_at"], code["sequence"])
    )
    return {
        "head_sha": head,
        "verdict": "READY" if ready else "BLOCKED",
        "code": code,
        "security": security,
    }


def _latest_owner_authorization(pr: dict[str, Any]) -> dict[str, Any]:
    owner = str(pr.get("_repository_owner_login") or "")
    number = pr.get("_number")
    head = str(pr.get("headRefOid") or "")
    if not owner or type(number) is not int:
        return {}
    scope = f"scope=pr-{number}"
    candidates = [
        item
        for item in ((pr.get("comments") or {}).get("nodes") or [])
        if (item.get("author") or {}).get("login") == owner
        and "/owner-authorization" in str(item.get("body") or "")
        and re.search(
            r"(?<!\S)" + re.escape(scope) + r"(?=\s|$)", str(item.get("body") or "")
        )
    ]
    if not candidates:
        return {}
    latest = max(
        enumerate(candidates),
        key=lambda pair: (str(pair[1].get("createdAt") or ""), pair[0]),
    )[1]
    expected = f"/owner-authorization approve {scope} sha={head}"
    valid = (
        latest.get("body") == expected
        and latest.get("authorAssociation") == "OWNER"
        and isinstance(latest.get("createdAt"), str)
        and latest.get("createdAt") == latest.get("updatedAt")
    )
    return {
        "status": "PASS" if valid else "BLOCKED",
        "head_sha": head,
        "comment_id": latest.get("id"),
    }


def snapshot(pr: dict[str, Any], *, etag: str, timestamp: int) -> dict[str, Any]:
    chatgpt_review = _latest_chatgpt_review(pr)
    owner_authorization = _latest_owner_authorization(pr)
    nodes = (pr.get("commits") or {}).get("nodes") or []
    rollup = (
        ((nodes[-1].get("commit") or {}).get("statusCheckRollup") or {})
        if nodes
        else {}
    )
    checks = {}
    for check in (rollup.get("contexts") or {}).get("nodes") or []:
        key = str(check.get("id") or check.get("name") or check.get("context"))
        checks[key] = str(
            check.get("conclusion")
            or check.get("status")
            or check.get("state")
            or "UNKNOWN"
        )
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
        "chatgpt_review": chatgpt_review,
        "owner_authorization": owner_authorization,
        "validated_verdict": (chatgpt_review.get("verdict") or ""),
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
    "chatgpt_review",
    "owner_authorization",
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
    added = {
        key: after_map[key] for key in sorted(after_map.keys() - before_map.keys())
    }
    removed = {
        key: before_map[key] for key in sorted(before_map.keys() - after_map.keys())
    }
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
    return [
        item["filename"] for item in payload.get("files", []) if item.get("filename")
    ]


def _truncate(value: Any, *, string_limit: int = 1000) -> Any:
    if isinstance(value, str):
        if len(value) <= string_limit:
            return value
        return value[: string_limit - 1] + "…"
    if isinstance(value, list):
        return [_truncate(item, string_limit=string_limit) for item in value]
    if isinstance(value, dict):
        return {
            key: _truncate(item, string_limit=string_limit)
            for key, item in value.items()
        }
    return value


def _encode_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def bounded_payload(
    payload: dict[str, Any], *, budget: int = PROMPT_BUDGET_BYTES
) -> str:
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
        "review_kind": reduced.get("review_kind"),
        "previous_validated_verdict": _truncate(
            reduced.get("previous_validated_verdict") or "",
            string_limit=800,
        ),
        "previous_head": reduced.get("previous_head"),
        "current_head": reduced.get("current_head"),
        "changed_files": list(reduced.get("changed_files") or [])[:20],
        "delta": {
            key: {
                kind: len(items) if isinstance(items, dict) else 0
                for kind, items in value.items()
            }
            for key, value in (reduced.get("delta") or {}).items()
            if key in COLLECTION_KEYS and isinstance(value, dict)
        },
        "exact_head_verified": bool(reduced.get("exact_head_verified")),
        "truncated": True,
    }
    encoded = _encode_payload(summary)
    while len(encoded.encode()) > budget and summary["changed_files"]:
        summary["changed_files"].pop()
        encoded = _encode_payload(summary)
    if len(encoded.encode()) <= budget:
        return encoded

    summary["previous_validated_verdict"] = ""
    encoded = _encode_payload(summary)
    if len(encoded.encode()) <= budget:
        return encoded
    raise RuntimeError("prompt budget is too small for the minimal PR delta")


def chatgpt_review_handoff(
    number: int,
    previous: dict[str, Any],
    current: dict[str, Any],
    changes: dict[str, Any],
    files: list[str],
    *,
    review_kind: str = "COMBINED",
) -> str:
    if review_kind not in {"CODE", "SECURITY", "COMBINED"}:
        raise ValueError(f"unsupported ChatGPT review kind: {review_kind!r}")
    prior_verdict = str(previous.get("validated_verdict") or "")
    reuse = (
        "Reuse the previous validated ChatGPT verdict and adjust only what this delta invalidates."
        if prior_verdict
        else "No previous validated ChatGPT verdict is available; review only this bounded delta."
    )
    review_instruction = (
        "Perform only the requested CODE review. "
        if review_kind == "CODE"
        else "Perform only the requested SECURITY review; exact-SHA CODE is already PASS. "
        if review_kind == "SECURITY"
        else "Perform the requested CODE/SECURITY review. "
    )
    instruction = (
        "ChatGPT incremental exact-SHA PR review handoff. "
        "Do not reload PR history or repeat proven gates. "
        f"{reuse} "
        f"{review_instruction}"
        "Read only changed_files plus finding paths in delta and issue findings "
        "bound to current_head. Return the compact UX summary as five lines: "
        "PR #<number>; HEAD : <old> → <new or unchanged>; CHANGEMENT : <delta>; "
        "VERDICT : READY | BLOCKED | WAITING; ACTION : <one next action>.\n"
    )
    payload = {
        "pr": number,
        "review_kind": review_kind,
        "previous_validated_verdict": prior_verdict,
        "delta": changes,
        "previous_head": previous.get("head_sha"),
        "current_head": current.get("head_sha"),
        "changed_files": files,
        "exact_head_verified": bool(current.get("exact_head_verified")),
    }
    encoded = bounded_payload(
        payload, budget=PROMPT_BUDGET_BYTES - len(instruction.encode())
    )
    return instruction + encoded


REPOSITORY = "dst-red-Wire/ecommerce-1"
MAX_HANDOFF_BYTES = min(PROMPT_BUDGET_BYTES, 8192)
MAX_CHANGED_FILES = 256
MAX_PATH_BYTES = 512
MAX_DELTA_COUNT = 1_000_000

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DELTA_COUNT_KEYS = frozenset(
    {
        "changed_file_count",
        "open_finding_count",
        "new_finding_count",
        "resolved_finding_count",
        "superseded_finding_count",
    }
)
_PRIOR_VERDICTS = frozenset({"CODE_PASS", "SECURITY_PASS", "READY"})


class ReviewHandoffError(ValueError):
    """The requested handoff is ambiguous, unsafe, or too large."""


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return _encode_payload(value).encode("utf-8")


def _require_sha(name: str, value: object) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ReviewHandoffError(f"{name} must be a full lowercase Git SHA")
    return value


def _changed_paths(value: object) -> list[str]:
    if type(value) not in (list, tuple) or not value or len(value) > MAX_CHANGED_FILES:
        raise ReviewHandoffError("changed_files must be a nonempty bounded sequence")
    seen: set[str] = set()
    paths: list[str] = []
    for path in value:
        if type(path) is not str:
            raise ReviewHandoffError("changed_files contains an unsafe path")
        try:
            byte_count = len(path.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ReviewHandoffError("changed_files contains invalid UTF-8") from exc
        if (
            not path
            or path != path.strip()
            or byte_count > MAX_PATH_BYTES
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or str(PurePosixPath(path)) != path
            or path in seen
        ):
            raise ReviewHandoffError(
                "changed_files contains an unsafe or duplicate path"
            )
        seen.add(path)
        paths.append(path)
    return sorted(paths)


def _delta_counts(value: object, changed_file_count: int) -> dict[str, int]:
    if value is None:
        supplied: dict[str, int] = {}
    elif type(value) is dict:
        supplied = value
    else:
        raise ReviewHandoffError("delta must contain counts only")
    if set(supplied) - _DELTA_COUNT_KEYS:
        raise ReviewHandoffError("delta contains non-count fields")
    counts = {"changed_file_count": changed_file_count}
    for key, count in supplied.items():
        if type(count) is not int or not 0 <= count <= MAX_DELTA_COUNT:
            raise ReviewHandoffError(
                "delta counts must be bounded nonnegative integers"
            )
        if key == "changed_file_count" and count != changed_file_count:
            raise ReviewHandoffError(
                "delta changed_file_count disagrees with changed_files"
            )
        counts[key] = count
    return counts


def build_handoff(
    repository: str,
    pr: int,
    review_kind: str,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    changed_files: list[str] | tuple[str, ...],
    qualification_status: str,
    qualification_evidence_digest: str,
    previous_validated_verdict: str | None = None,
    previous_head: str | None = None,
    delta: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build an integrity-bound metadata request after the caller verifies evidence.

    Only paths and numeric change counts are included; source, diff, comments,
    credentials, and executable instructions are outside this protocol.
    """
    if type(repository) is not str or repository != REPOSITORY:
        raise ReviewHandoffError("repository must be the canonical repository")
    if type(pr) is not int or not 1 <= pr <= 2_147_483_647:
        raise ReviewHandoffError("pr must be a positive GitHub PR number")
    if type(review_kind) is not str or review_kind not in {"CODE", "SECURITY"}:
        raise ReviewHandoffError("review_kind must be CODE or SECURITY")
    base = _require_sha("base_sha", base_sha)
    head = _require_sha("head_sha", head_sha)
    tree = _require_sha("tree_sha", tree_sha)
    if base == head:
        raise ReviewHandoffError("base_sha and head_sha must differ")
    if type(qualification_status) is not str or qualification_status != "PASS":
        raise ReviewHandoffError("verified exact qualification PASS is required")
    if (
        type(qualification_evidence_digest) is not str
        or _DIGEST.fullmatch(qualification_evidence_digest) is None
    ):
        raise ReviewHandoffError("qualification evidence digest must be SHA-256")
    paths = _changed_paths(changed_files)
    if previous_head is not None:
        _require_sha("previous_head", previous_head)
    if previous_validated_verdict is not None and (
        type(previous_validated_verdict) is not str
        or previous_validated_verdict not in _PRIOR_VERDICTS
        or previous_head is None
    ):
        raise ReviewHandoffError("previous verdict requires a validated prior head")
    if review_kind == "SECURITY" and (
        previous_validated_verdict != "CODE_PASS" or previous_head != head
    ):
        raise ReviewHandoffError("SECURITY handoff requires exact-head CODE PASS")

    payload: dict[str, Any] = {
        "schema_version": 1,
        "event": "CHATGPT_REVIEW_REQUIRED",
        "provider": "ChatGPT",
        "verdict_authority": False,
        "repository": repository,
        "pr": pr,
        "review_kind": review_kind,
        "base_sha": base,
        "head_sha": head,
        "tree_sha": tree,
        "exact_head_verified": True,
        "changed_files": paths,
        "qualification": {
            "status": "PASS",
            "evidence_digest": qualification_evidence_digest,
        },
        "previous_validated_verdict": previous_validated_verdict,
        "previous_head": previous_head,
        "delta": _delta_counts(delta, len(paths)),
    }
    payload["handoff_sha256"] = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if len(_canonical_bytes(payload)) > MAX_HANDOFF_BYTES:
        raise ReviewHandoffError("canonical handoff exceeds 8192 bytes")
    return payload


def _supports_color() -> bool:
    return (
        "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "") != "dumb"
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )


def _paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _supports_color() else text


def compact_status_lines(
    number: int,
    previous: dict[str, Any],
    current: dict[str, Any],
    changes: dict[str, Any],
) -> list[str]:
    old_head = str(previous.get("head_sha") or "none")
    new_head = str(current.get("head_sha") or "none")
    changed = ", ".join(sorted(changes)) or "aucun"
    verdict = str(current.get("validated_verdict") or "WAITING")
    if verdict == "READY":
        action = "continuer les gates qualification/fusion"
        verdict_color = "32"
    elif verdict == "BLOCKED":
        action = "review ChatGPT bornée sur le delta"
        verdict_color = "31"
    else:
        action = "review ChatGPT bornée sur le delta"
        verdict_color = "33"
    return [
        _paint(f"PR #{number}", "36"),
        _paint(f"HEAD : {old_head} → {new_head}", "34"),
        _paint(f"CHANGEMENT : {changed}", "33"),
        _paint(f"VERDICT : {verdict}", verdict_color),
        _paint(f"ACTION : {action}", "35"),
    ]


def _safe_exec_env() -> dict[str, str]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith(("GIT_", "PYTHON")):
            environment.pop(name, None)
    environment["PATH"] = os.defpath
    return environment


def _run(
    command: list[str], *, cwd: Path, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
        env=_safe_exec_env(),
    )


def _git_value(root: Path, *arguments: str) -> str:
    return _run(["git", *arguments], cwd=root).stdout.strip()


_TRUSTED_SOURCE_PATHS = (
    "scripts/pr_monitor.py",
    "scripts/pr_review_dispatch_transition.py",
    "scripts/chatgpt_review_dispatcher.py",
    "scripts/chatgpt_review_transport.py",
    "scripts/pr_review_convergence.py",
    "scripts/exact_pr_binding.py",
    "scripts/managed_gh.py",
)
_TRUSTED_BOOTSTRAP = (
    "import runpy,sys;"
    "from pathlib import Path;"
    "entry=Path(sys.argv[1]);"
    "sys.path.insert(0,str(entry.parent));"
    "sys.argv=sys.argv[1:];"
    'runpy.run_path(str(entry),run_name="__main__")'
)


def _trusted_roots(args: argparse.Namespace) -> tuple[Path, Path]:
    trusted_arg = getattr(args, "trusted_root", None)
    target_arg = getattr(args, "target_root", None)
    if trusted_arg is None or target_arg is None:
        raise RuntimeError("trusted monitor requires explicit trusted and target roots")
    trusted = Path(trusted_arg).resolve()
    target = Path(target_arg).resolve()
    if trusted != ROOT or trusted == target:
        raise RuntimeError(
            "trusted monitor must execute from a distinct exact-base checkout"
        )
    return trusted, target


def _verified_base_source(root: Path, base_sha: str, relative: str) -> Path:
    source = root / relative
    if (
        source.parent.is_symlink()
        or source.is_symlink()
        or not source.is_file()
        or source.resolve(strict=True) != source
    ):
        raise RuntimeError("trusted exact-base source is unavailable")
    try:
        committed = subprocess.run(
            ["git", "cat-file", "blob", f"{base_sha}:{relative}"],
            cwd=root,
            capture_output=True,
            check=True,
            timeout=30,
            env=_safe_exec_env(),
        ).stdout
        actual = source.read_bytes()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("trusted exact-base source is unavailable") from exc
    if actual != committed:
        raise RuntimeError("trusted exact-base source differs from Git")
    return source


def _trusted_adapter(args: argparse.Namespace, binding: ExactPRBinding) -> Path:
    trusted, _ = _trusted_roots(args)
    if binding.repository != REPOSITORY or binding.pr_number != args.pr:
        raise RuntimeError("trusted monitor exact PR binding differs")
    try:
        if _git_value(trusted, "rev-parse", "HEAD") != binding.base_sha or _git_value(
            trusted, "status", "--porcelain", "--untracked-files=all"
        ):
            raise RuntimeError("trusted monitor base checkout differs from GitHub")
        for relative in _TRUSTED_SOURCE_PATHS:
            _verified_base_source(trusted, binding.base_sha, relative)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("trusted monitor base checkout is unavailable") from exc
    return trusted / "scripts/pr_review_dispatch_transition.py"


def sync_exact_pr_head(args: argparse.Namespace, head_sha: str) -> None:
    """Fast-forward a clean local PR branch only to its revalidated GitHub HEAD."""
    if (
        f"{args.owner}/{args.repo}" != REPOSITORY
        or type(args.pr) is not int
        or args.pr < 1
        or type(head_sha) is not str
        or _SHA.fullmatch(head_sha) is None
    ):
        raise SupersededHeadError("SUPERSEDED: invalid exact PR HEAD binding")
    trusted_root, target_root = _trusted_roots(args)
    try:
        gh, _, _ = resolve_managed_gh(trusted_root)
        branch = _git_value(target_root, "branch", "--show-current")
        local_head = _git_value(target_root, "rev-parse", "HEAD")
        dirty = _git_value(
            target_root, "status", "--porcelain", "--untracked-files=all"
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SupersededHeadError("SUPERSEDED: local checkout is unavailable") from exc
    if not branch or dirty or _SHA.fullmatch(local_head) is None:
        raise SupersededHeadError("SUPERSEDED: local PR branch is not clean")
    try:
        binding = resolve_exact_open_pr(REPOSITORY, head_sha, branch, "main", gh=gh)
    except ExactPRBindingError as exc:
        if "GitHub API request failed" in str(exc):
            raise TransientGitHubError(
                "GitHub API unavailable before local synchronization"
            ) from exc
        raise SupersededHeadError(
            "SUPERSEDED: exact GitHub PR HEAD binding is unavailable"
        ) from exc
    if binding.pr_number != args.pr:
        raise SupersededHeadError("SUPERSEDED: GitHub PR number differs")
    _trusted_adapter(args, binding)

    def verify_github() -> None:
        try:
            if revalidate_exact_open_pr(binding, gh=gh) != binding:
                raise ExactPRBindingChanged("PR_CHANGED")
        except ExactPRBindingChanged as exc:
            if exc.reason == "HEAD_CHANGED":
                raise TransientGitHubError(
                    "exact GitHub PR HEAD changed during local synchronization"
                ) from exc
            raise SupersededHeadError(
                "SUPERSEDED: exact PR base or branch changed"
            ) from exc
        except ExactPRBindingError as exc:
            if "GitHub API request failed" in str(exc):
                raise TransientGitHubError(
                    "GitHub API unavailable during local synchronization"
                ) from exc
            raise SupersededHeadError(
                "SUPERSEDED: exact GitHub PR revalidation failed"
            ) from exc

    verify_github()
    if local_head == head_sha:
        return
    try:
        _run(["git", "fetch", "--no-tags", "origin", head_sha], cwd=target_root)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TransientGitHubError("git fetch failed for exact GitHub PR HEAD") from exc
    try:
        fetched = _git_value(target_root, "rev-parse", "FETCH_HEAD")
        if fetched != head_sha:
            raise SupersededHeadError("SUPERSEDED: fetched HEAD differs from GitHub")
        _run(
            ["git", "merge-base", "--is-ancestor", local_head, head_sha],
            cwd=target_root,
        )
        if (
            _git_value(target_root, "branch", "--show-current") != branch
            or _git_value(target_root, "rev-parse", "HEAD") != local_head
            or _git_value(target_root, "status", "--porcelain", "--untracked-files=all")
        ):
            raise SupersededHeadError(
                "SUPERSEDED: local checkout changed before fast-forward"
            )
        verify_github()
        _run(
            ["git", "-c", "core.hooksPath=/dev/null", "merge", "--ff-only", head_sha],
            cwd=target_root,
        )
        if (
            _git_value(target_root, "branch", "--show-current") != branch
            or _git_value(target_root, "rev-parse", "HEAD") != head_sha
            or _git_value(target_root, "status", "--porcelain", "--untracked-files=all")
        ):
            raise SupersededHeadError("SUPERSEDED: local fast-forward is not exact")
        verify_github()
    except subprocess.CalledProcessError as exc:
        raise SupersededHeadError(
            "SUPERSEDED: local PR branch cannot fast-forward to GitHub HEAD"
        ) from exc


@contextmanager
def exact_head_worktree(head_sha: str, *, repo_root: Path | None = None):
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise RuntimeError(f"invalid exact PR head SHA: {head_sha!r}")
    repo_root = ROOT if repo_root is None else Path(repo_root).resolve()
    with tempfile.TemporaryDirectory(prefix="pr-monitor-") as directory:
        worktree = Path(directory) / "repo"
        try:
            _run(["git", "fetch", "--no-tags", "origin", head_sha], cwd=repo_root)
        except subprocess.CalledProcessError as exc:
            raise TransientGitHubError(
                f"git fetch failed transiently for {head_sha}"
            ) from exc
        fetched = _run(["git", "rev-parse", "FETCH_HEAD"], cwd=repo_root).stdout.strip()
        if fetched != head_sha:
            raise RuntimeError(
                f"fetched head mismatch: expected {head_sha}, got {fetched}"
            )
        _run(
            ["git", "worktree", "add", "--detach", str(worktree), head_sha],
            cwd=repo_root,
        )
        try:
            yield worktree
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=repo_root,
                text=True,
                capture_output=True,
                check=False,
                env=_safe_exec_env(),
            )


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
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


MAX_TRANSIENT_RESUME_RETRIES = 3
TRANSIENT_DISPATCH_REASONS = frozenset(
    {"BLOCKED_EXTERNAL_REVIEW_TRANSPORT", "AWAITING_OWNER_MARKER"}
)


@dataclass(frozen=True, slots=True)
class ResumeOutcome:
    pending: bool
    transient_error: bool = False


def _record_resume_outcome(
    state: dict[str, Any],
    outcome: ResumeOutcome,
    *,
    prior_count: int,
) -> None:
    if type(prior_count) is not int or prior_count < 0:
        raise RuntimeError("monitor retry checkpoint is malformed")
    if outcome.transient_error:
        count = prior_count + 1
        state["resume_retry_count"] = count
        state["resume_pending"] = count < MAX_TRANSIENT_RESUME_RETRIES
        if not state["resume_pending"]:
            print("TRANSIENT_REVIEW_RETRY_EXHAUSTED", flush=True)
    else:
        state["resume_retry_count"] = 0
        state["resume_pending"] = outcome.pending


def _verified_resume_context(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path]:
    trusted, target = _trusted_roots(args)
    if f"{args.owner}/{args.repo}" != REPOSITORY or type(args.pr) is not int:
        raise RuntimeError("trusted monitor requires the canonical exact PR")
    try:
        head = _git_value(target, "rev-parse", "HEAD")
        branch = _git_value(target, "branch", "--show-current")
        dirty = _git_value(target, "status", "--porcelain", "--untracked-files=all")
        gh, _, _ = resolve_managed_gh(trusted)
        binding = resolve_exact_open_pr(REPOSITORY, head, branch, "main", gh=gh)
    except (
        OSError,
        ValueError,
        ExactPRBindingError,
        subprocess.CalledProcessError,
    ) as exc:
        raise RuntimeError("trusted monitor exact PR binding is unavailable") from exc
    if (
        _SHA.fullmatch(head) is None
        or not branch
        or dirty
        or binding.pr_number != args.pr
    ):
        raise RuntimeError("trusted monitor target PR checkout is not exact and clean")
    adapter = _trusted_adapter(args, binding)
    try:
        if revalidate_exact_open_pr(binding, gh=gh) != binding:
            raise RuntimeError("trusted monitor exact PR binding changed")
    except ExactPRBindingError as exc:
        raise RuntimeError("trusted monitor exact PR revalidation failed") from exc
    return trusted, target, adapter


def resume_trusted_transition(
    args: argparse.Namespace, *, poll_existing_only: bool = False
) -> ResumeOutcome:
    if getattr(args, "trusted_root", None) is None:
        return ResumeOutcome(False)
    trusted_root, target_root, adapter = _verified_resume_context(args)
    command = [
        sys.executable,
        "-I",
        "-c",
        _TRUSTED_BOOTSTRAP,
        str(adapter),
        "--trusted-root",
        str(trusted_root),
        "--target-root",
        str(target_root),
        "--pr",
        str(args.pr),
        "--json",
    ]
    authorization_binding = getattr(args, "owner_authorization_binding", None)
    if authorization_binding is not None:
        command += ["--owner-authorization-binding", authorization_binding]
    if poll_existing_only:
        command.append("--poll-existing-only")
    try:
        completed = subprocess.run(
            command,
            cwd=trusted_root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
            env=_safe_exec_env(),
        )
        result = json.loads(completed.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("trusted PR transition returned no valid JSON") from exc
    if not isinstance(result, dict) or result.get("pr") != args.pr:
        raise RuntimeError("trusted PR transition identity is invalid")
    dispatch = result.get("review_dispatch")
    submitted = (
        isinstance(dispatch, dict)
        and type(dispatch.get("submission_id")) is str
        and bool(dispatch["submission_id"])
    )
    if (
        isinstance(dispatch, dict)
        and dispatch.get("status") in {"REQUESTED", "RUNNING"}
        and not submitted
    ):
        raise RuntimeError("trusted transition omitted submitted review ID")
    exact_request = (
        completed.returncode == 0
        and result.get("state") == "CHATGPT_REVIEW_REQUIRED"
        and isinstance(dispatch, dict)
        and type(result.get("head_sha")) is str
        and _SHA.fullmatch(result["head_sha"]) is not None
        and dispatch.get("head_sha") == result["head_sha"]
        and dispatch.get("pr") == args.pr
    )
    active = (
        exact_request
        and submitted
        and dispatch.get("status") in {"REQUESTED", "RUNNING"}
    )
    transient = (
        exact_request
        and submitted
        and dispatch.get("status") == "BLOCKED"
        and dispatch.get("reason") in TRANSIENT_DISPATCH_REASONS
    )
    outcome = ResumeOutcome(bool(active or transient), bool(transient))
    print(
        f"TRUSTED_PR_LOOP state={result.get('state')} pending={outcome.pending}",
        flush=True,
    )
    return outcome


def _proof_events(previous: dict[str, Any], current: dict[str, Any]) -> list[str]:
    events: list[str] = []
    if previous.get("head_sha") != current.get("head_sha"):
        events.append("HEAD_CHANGED")
    before = previous.get("chatgpt_review") or {}
    after = current.get("chatgpt_review") or {}
    for kind in ("code", "security"):
        old = before.get(kind) if isinstance(before, dict) else None
        new = after.get(kind) if isinstance(after, dict) else None
        if (
            isinstance(new, dict)
            and new.get("status") == "PASS"
            and new.get("comment_id")
            and new.get("comment_id")
            != (old.get("comment_id") if isinstance(old, dict) else None)
        ):
            events.append(kind.upper() + "_MARKER_APPEARED")
    old_auth = previous.get("owner_authorization") or {}
    new_auth = current.get("owner_authorization") or {}
    if (
        isinstance(new_auth, dict)
        and new_auth.get("status") == "PASS"
        and new_auth.get("comment_id")
        and new_auth.get("comment_id")
        != (old_auth.get("comment_id") if isinstance(old_auth, dict) else None)
    ):
        events.append("OWNER_AUTH_APPEARED")
    return events


def poll_once(
    args: argparse.Namespace, state_path: Path, token: str, *, bootstrap: bool = False
) -> tuple[bool, int]:
    previous = (
        json.loads(state_path.read_text(encoding="utf-8"))
        if state_path.exists()
        else {}
    )
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
        if (
            getattr(args, "trusted_root", None)
            and not is_terminal(previous, args.abandoned)
            and (bootstrap or previous.get("resume_pending"))
        ):
            outcome = resume_trusted_transition(args, poll_existing_only=not bootstrap)
            _record_resume_outcome(
                updated,
                outcome,
                prior_count=(0 if bootstrap else previous.get("resume_retry_count", 0)),
            )
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
    pr = paginate_comments(
        pr, owner=args.owner, repo=args.repo, number=args.pr, token=token
    )
    pr["_number"] = args.pr
    current = snapshot(pr, etag=etag, timestamp=int(time.time()))
    current["exact_head_verified"] = bool(
        previous
        and current.get("head_sha") == previous.get("head_sha")
        and previous.get("exact_head_verified")
    )
    changes = delta(previous, current) if previous else {}
    unchanged = 0 if changes else int(previous.get("unchanged_polls", 0)) + 1
    current["unchanged_polls"] = unchanged

    handoff_changes = {
        key: value
        for key, value in changes.items()
        if key not in {"chatgpt_review", "owner_authorization"}
    }
    if previous and handoff_changes:
        if not current["exact_head_verified"]:
            worktree_root = (
                _trusted_roots(args)[1]
                if getattr(args, "trusted_root", None) is not None
                else ROOT
            )
            with exact_head_worktree(
                str(current.get("head_sha") or ""), repo_root=worktree_root
            ):
                pass
            current["exact_head_verified"] = True
        files = changed_files(
            args.owner,
            args.repo,
            previous.get("head_sha", ""),
            current.get("head_sha", ""),
            token,
        )
        handoff = chatgpt_review_handoff(
            args.pr, previous, current, handoff_changes, files
        )
        current["chatgpt_review_handoff"] = handoff
        print("CHATGPT_REVIEW_REQUIRED", flush=True)
        for line in compact_status_lines(args.pr, previous, current, changes):
            print(line, flush=True)
        print("CHATGPT_REVIEW_HANDOFF " + handoff, flush=True)
    else:
        print("NO_CHANGE", flush=True)

    events = _proof_events(previous, current) if previous else []
    for event in events:
        print(event, flush=True)
    current["resume_retry_count"] = previous.get("resume_retry_count", 0)
    if getattr(args, "trusted_root", None) and not is_terminal(current, args.abandoned):
        if "HEAD_CHANGED" in events:
            sync_exact_pr_head(args, current["head_sha"])
        if bootstrap or events or previous.get("resume_pending"):
            outcome = resume_trusted_transition(
                args, poll_existing_only=not (bootstrap or events)
            )
            _record_resume_outcome(
                current,
                outcome,
                prior_count=(
                    0 if bootstrap or events else previous.get("resume_retry_count", 0)
                ),
            )
        else:
            current["resume_pending"] = False
    else:
        current["resume_pending"] = False
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
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--target-root", type=Path)
    parser.add_argument("--owner-authorization-binding")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--abandoned", action="store_true")
    args = parser.parse_args()
    if args.interval < 1 or args.max_interval < args.interval:
        parser.error("intervals must satisfy 1 <= --interval <= --max-interval")
    if (args.trusted_root is None) != (args.target_root is None):
        parser.error("--trusted-root and --target-root must be supplied together")
    if args.owner_authorization_binding and args.trusted_root is None:
        parser.error("owner authorization binding requires trusted mode")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.trusted_root is not None:
            _trusted_roots(args)
    except RuntimeError as exc:
        print(f"BLOCKED_AUTHORITY {exc}", file=sys.stderr, flush=True)
        return 2
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if not token:
        try:
            gh = resolve_managed_gh(ROOT)[0] if args.trusted_root is not None else "gh"
            result = subprocess.run(
                [gh, "auth", "token"],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
                env=_safe_exec_env(),
            )
            if result.returncode == 0:
                token = result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not token:
        print("GitHub authentication is unavailable", file=sys.stderr)
        return 2
    state_path = (
        Path(args.state)
        if args.state
        else (_trusted_roots(args)[1] if args.trusted_root is not None else ROOT)
        / default_state_path(args.owner, args.repo, args.pr)
    )
    transient_failures = 0
    bootstrap = True
    while True:
        try:
            terminal, unchanged = poll_once(
                args, state_path, token, bootstrap=bootstrap
            )
            bootstrap = False
            transient_failures = 0
        except SupersededHeadError as exc:
            print(str(exc), file=sys.stderr, flush=True)
            return 2
        except TransientGitHubError as exc:
            transient_failures += 1
            delay = min(
                max(args.interval, 60 * (2 ** min(transient_failures - 1, 6))),
                args.max_interval,
            )
            print(
                f"TRANSIENT_ERROR retry_in={delay}s: {exc}", file=sys.stderr, flush=True
            )
            if args.once:
                return 3
            time.sleep(delay)
            continue
        except RuntimeError as exc:
            print(f"BLOCKED_AUTHORITY {exc}", file=sys.stderr, flush=True)
            return 2
        if terminal or args.once:
            return 0
        time.sleep(next_interval(unchanged, args.interval, args.max_interval))


if __name__ == "__main__":
    raise SystemExit(main())
