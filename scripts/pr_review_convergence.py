"""External-event convergence around the trusted exact-base PR controller.

This module observes GitHub and executes only a rerun supplied by the trusted
controller. It never creates CODE, SECURITY, or merge authority.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

if __package__:
    from .chatgpt_review_dispatcher import github_owner_marker_lookup
    from .exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        revalidate_exact_open_pr,
    )
else:
    from chatgpt_review_dispatcher import github_owner_marker_lookup
    from exact_pr_binding import (
        ExactPRBinding,
        ExactPRBindingChanged,
        revalidate_exact_open_pr,
    )


class ReviewConvergenceError(RuntimeError):
    """An exact-PR transition cannot safely continue."""


def _current_binding(
    binding: ExactPRBinding,
    *,
    gh: str,
    revalidator: Callable[..., ExactPRBinding],
) -> None:
    try:
        current = revalidator(binding, gh=gh)
    except ExactPRBindingChanged as exc:
        raise ReviewConvergenceError("SUPERSEDED: exact PR binding changed") from exc
    if current != binding:
        raise ReviewConvergenceError("SUPERSEDED: exact PR binding changed")


def _proof(
    binding: ExactPRBinding,
    kind: str,
    *,
    gh: str,
    marker_lookup: Callable[..., Mapping[str, Any] | None],
) -> Mapping[str, Any]:
    proof = marker_lookup(binding, kind, gh=gh)
    owner = binding.repository.split("/", 1)[0]
    if (
        not isinstance(proof, Mapping)
        or proof.get("provider") != "ChatGPT"
        or proof.get("kind") != kind
        or proof.get("head_sha") != binding.head_sha
        or proof.get("repository") != binding.repository
        or proof.get("pr") != binding.pr_number
        or proof.get("status") != "PASS"
        or type(proof.get("blocking_findings")) is not int
        or proof["blocking_findings"] != 0
        or proof.get("author_login") != owner
        or proof.get("owner_login") != owner
        or proof.get("created_at") != proof.get("updated_at")
        or proof.get("is_latest_for_kind") is not True
        or type(proof.get("comment_id")) is not int
        or proof["comment_id"] < 1
    ):
        raise ReviewConvergenceError("exact owner review marker is unavailable")
    return proof


def _review_proofs(
    binding: ExactPRBinding,
    *,
    gh: str,
    marker_lookup: Callable[..., Mapping[str, Any] | None],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    code = _proof(binding, "code", gh=gh, marker_lookup=marker_lookup)
    security = _proof(binding, "security", gh=gh, marker_lookup=marker_lookup)
    if (security["created_at"], security["comment_id"]) <= (
        code["created_at"],
        code["comment_id"],
    ):
        raise ReviewConvergenceError("SECURITY owner marker predates CODE")
    return code, security


def rerun_after_review_marker(
    controller: Mapping[str, Any],
    binding: ExactPRBinding,
    *,
    trusted_root: Path,
    target_root: Path,
    gh: str,
    marker_lookup: Callable[..., Mapping[str, Any] | None] = github_owner_marker_lookup,
    revalidator: Callable[..., ExactPRBinding] = revalidate_exact_open_pr,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    """Execute the exact trusted rerun argv after independent GitHub proof reads.

    The trusted argv intentionally has no JSON flag. The caller can run its
    normal JSON transition afterwards to read the controller's new decision.
    """
    request = controller.get("review_request")
    dispatch = controller.get("review_dispatch")
    if (
        controller.get("state") != "CHATGPT_REVIEW_REQUIRED"
        or not isinstance(request, Mapping)
        or not isinstance(dispatch, Mapping)
        or dispatch.get("status") != "PASS"
        or dispatch.get("reason") != "OWNER_MARKER_VERIFIED"
        or dispatch.get("verdict_authority") is not False
        or request.get("verdict_authority") is not False
        or request.get("repository") != binding.repository
        or request.get("pr") != binding.pr_number
        or request.get("base") != binding.base
        or request.get("base_sha") != binding.base_sha
        or request.get("head_branch") != binding.head_branch
        or request.get("head_sha") != binding.head_sha
        or controller.get("head_sha") != binding.head_sha
        or controller.get("pr") != binding.pr_number
        or dispatch.get("head_sha") != binding.head_sha
        or dispatch.get("pr") != binding.pr_number
        or dispatch.get("kind") != request.get("review_kind")
    ):
        raise ReviewConvergenceError("trusted review transition is not exact")
    kind = request.get("review_kind")
    if kind not in {"CODE", "SECURITY"}:
        raise ReviewConvergenceError("trusted review kind is invalid")
    rerun = request.get("rerun")
    argv = rerun.get("argv") if isinstance(rerun, Mapping) else None
    expected = [
        sys.executable,
        str(trusted_root.resolve() / "scripts/repository_delivery.py"),
        "trusted-pr-transition",
        "--target-root",
        str(target_root.resolve()),
        "--pr",
        str(binding.pr_number),
    ]
    if (
        not isinstance(rerun, Mapping)
        or rerun.get("controller_source") != "exact-pr-base-sha"
        or rerun.get("after_valid_marker") is not True
        or argv != expected
    ):
        raise ReviewConvergenceError("trusted rerun argv is invalid")
    _current_binding(binding, gh=gh, revalidator=revalidator)
    current = _proof(binding, kind.lower(), gh=gh, marker_lookup=marker_lookup)
    if kind == "SECURITY":
        _code, security = _review_proofs(binding, gh=gh, marker_lookup=marker_lookup)
        if security["comment_id"] != current["comment_id"]:
            raise ReviewConvergenceError("SECURITY marker changed before rerun")
    _current_binding(binding, gh=gh, revalidator=revalidator)
    try:
        completed = runner(
            argv,
            cwd=target_root.resolve(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewConvergenceError("trusted exact-base rerun unavailable") from exc
    return completed.returncode


def _gh_json(gh: str, arguments: list[str], *, input_text: str | None = None) -> Any:
    try:
        result = subprocess.run(
            [gh, "api", *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewConvergenceError("GitHub API unavailable") from exc
    if result.returncode or len(result.stdout) > 2_000_000:
        raise ReviewConvergenceError("GitHub API failed or exceeded its budget")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise ReviewConvergenceError("GitHub API returned malformed JSON") from exc


def _comments(binding: ExactPRBinding, gh: str) -> list[dict[str, Any]]:
    pages = _gh_json(
        gh,
        [
            "--paginate",
            "--slurp",
            f"repos/{binding.repository}/issues/{binding.pr_number}/comments?per_page=100",
        ],
    )
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ReviewConvergenceError("GitHub PR comments are malformed")
    comments = [item for page in pages for item in page]
    if any(not isinstance(item, dict) for item in comments):
        raise ReviewConvergenceError("GitHub PR comment is malformed")
    return comments


_UAC_RE = re.compile(
    r"/owner-authorization approve scope=pr-([1-9][0-9]*) sha=([0-9a-f]{40})\Z"
)


def _latest_owner_uac(
    binding: ExactPRBinding, comments: list[dict[str, Any]]
) -> dict[str, Any] | None:
    owner = binding.repository.split("/", 1)[0]
    scope = f"scope=pr-{binding.pr_number}"
    candidates: list[tuple[str, int, dict[str, Any]]] = []
    for item in comments:
        user = item.get("user")
        if not isinstance(user, dict) or user.get("login") != owner:
            continue
        body = item.get("body")
        if not isinstance(body, str):
            raise ReviewConvergenceError("owner PR comment body is malformed")
        if "/owner-authorization" not in body or scope not in body:
            continue
        created = item.get("created_at")
        updated = item.get("updated_at")
        comment_id = item.get("id")
        if (
            not isinstance(created, str)
            or not isinstance(updated, str)
            or type(comment_id) is not int
            or comment_id < 1
        ):
            raise ReviewConvergenceError("owner authorization metadata is malformed")
        candidates.append((created, comment_id, item))
    if not candidates:
        return None
    latest = max(candidates, key=lambda value: (value[0], value[1]))[2]
    match = _UAC_RE.fullmatch(str(latest["body"]))
    if (
        match is None
        or int(match.group(1)) != binding.pr_number
        or latest.get("created_at") != latest.get("updated_at")
        or latest.get("author_association") != "OWNER"
    ):
        raise ReviewConvergenceError("latest owner authorization is invalid or edited")
    return latest


def publish_owner_authorization(
    controller: Mapping[str, Any],
    binding: ExactPRBinding,
    *,
    gh: str,
    marker_lookup: Callable[..., Mapping[str, Any] | None] = github_owner_marker_lookup,
    revalidator: Callable[..., ExactPRBinding] = revalidate_exact_open_pr,
    github_api: Callable[..., Any] = _gh_json,
    comments_reader: Callable[[ExactPRBinding, str], list[dict[str, Any]]] = _comments,
    authorization_binding: str | None = None,
) -> dict[str, Any]:
    """Publish only the exact UAC requested by the trusted controller.

    A valid existing UAC is reused after a crash. A bot or an edited comment
    never becomes owner authority. The next trusted pr-loop verifies it again.
    """
    authorization = controller.get("owner_authorization")
    code = controller.get("code_review")
    security = controller.get("security_review")
    expected = (
        f"/owner-authorization approve scope=pr-{binding.pr_number} "
        f"sha={binding.head_sha}"
    )
    if (
        controller.get("state") != "OWNER_AUTH_REQUIRED"
        or controller.get("owner_authorization_required") is not True
        or controller.get("head_sha") != binding.head_sha
        or controller.get("pr") != binding.pr_number
        or not isinstance(authorization, Mapping)
        or authorization.get("command") != expected
        or authorization.get("status") not in {"MISSING", "SUPERSEDED"}
        or not isinstance(code, Mapping)
        or not isinstance(security, Mapping)
        or any(
            proof.get("status") != "PASS"
            or proof.get("head_sha") != binding.head_sha
            or type(proof.get("blocking_findings")) is not int
            or proof["blocking_findings"] != 0
            for proof in (code, security)
        )
    ):
        raise ReviewConvergenceError("trusted controller did not authorize exact UAC")
    if authorization_binding != f"{binding.pr_number}:{binding.head_sha}":
        return {"status": "AWAITING_OWNER_MARKER", "published": False}
    _current_binding(binding, gh=gh, revalidator=revalidator)
    code_marker, security_marker = _review_proofs(
        binding, gh=gh, marker_lookup=marker_lookup
    )
    if (
        code.get("comment_id") != code_marker["comment_id"]
        or security.get("comment_id") != security_marker["comment_id"]
    ):
        raise ReviewConvergenceError(
            "review evidence changed before owner authorization"
        )
    existing = _latest_owner_uac(binding, comments_reader(binding, gh))
    if existing is not None and existing["body"] == expected:
        return {"status": "PASS", "published": False, "comment_id": existing["id"]}
    user = github_api(gh, ["user"])
    owner = binding.repository.split("/", 1)[0]
    if not isinstance(user, dict) or user.get("login") != owner:
        return {"status": "AWAITING_OWNER_MARKER", "published": False}
    _current_binding(binding, gh=gh, revalidator=revalidator)
    response = github_api(
        gh,
        [
            "--method",
            "POST",
            f"repos/{binding.repository}/issues/{binding.pr_number}/comments",
            "--input",
            "-",
        ],
        input_text=json.dumps({"body": expected}, separators=(",", ":")),
    )
    if not isinstance(response, dict) or response.get("body") != expected:
        raise ReviewConvergenceError(
            "owner authorization publication was not confirmed"
        )
    _current_binding(binding, gh=gh, revalidator=revalidator)
    latest = _latest_owner_uac(binding, comments_reader(binding, gh))
    if (
        latest is None
        or latest.get("body") != expected
        or latest.get("id") != response.get("id")
    ):
        raise ReviewConvergenceError(
            "published UAC is not the latest immutable owner proof"
        )
    return {"status": "PASS", "published": True, "comment_id": latest["id"]}


def reconcile_post_rerun(
    binding: ExactPRBinding,
    *,
    gh: str,
    github_api: Callable[..., Any] = _gh_json,
) -> dict[str, Any]:
    """Read GitHub after a trusted rerun; a local rc is never merge proof."""
    try:
        payload = github_api(
            gh, [f"repos/{binding.repository}/pulls/{binding.pr_number}"]
        )
    except ReviewConvergenceError:
        return {"status": "UNKNOWN", "merge_sha": None}
    if not isinstance(payload, dict):
        return {"status": "UNKNOWN", "merge_sha": None}
    head = payload.get("head")
    base = payload.get("base")
    if (
        type(payload.get("number")) is not int
        or payload["number"] != binding.pr_number
        or not isinstance(head, dict)
        or not isinstance(base, dict)
        or not isinstance(head.get("repo"), dict)
        or not isinstance(base.get("repo"), dict)
        or head["repo"].get("full_name") != binding.repository
        or base["repo"].get("full_name") != binding.repository
        or head.get("ref") != binding.head_branch
        or base.get("ref") != binding.base
    ):
        return {"status": "UNKNOWN", "merge_sha": None}
    if head.get("sha") != binding.head_sha:
        return {"status": "SUPERSEDED", "merge_sha": None}
    merged = payload.get("merged")
    merged_at = payload.get("merged_at")
    if merged is True and isinstance(merged_at, str) and merged_at:
        merge_sha = payload.get("merge_commit_sha")
        if (
            not isinstance(merge_sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", merge_sha) is None
        ):
            return {"status": "UNKNOWN", "merge_sha": None}
        return {"status": "MERGED", "merge_sha": merge_sha}
    if merged is False and merged_at is None and payload.get("state") == "open":
        if payload.get("draft") is False and base.get("sha") == binding.base_sha:
            return {"status": "OPEN", "merge_sha": None}
        return {"status": "SUPERSEDED", "merge_sha": None}
    return {"status": "UNKNOWN", "merge_sha": None}
