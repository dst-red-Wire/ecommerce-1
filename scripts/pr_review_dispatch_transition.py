#!/usr/bin/env python3
"""Run the exact-base PR controller, then dispatch its review handoff.

This target-checkout adapter never decides a review or a merge. The controller
executed from ``trusted_root`` remains the only local delivery authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__:
    from .chatgpt_review_dispatcher import (
        ReviewDispatchError,
        canonical_structured_handoff,
        dispatch_review_request,
        dispatch_status,
        github_owner_marker_lookup,
    )
    from .exact_pr_binding import (
        CANONICAL_REPOSITORY,
        ExactPRBinding,
        ExactPRBindingError,
        resolve_exact_open_pr,
        revalidate_exact_open_pr,
    )
    from .managed_gh import resolve_managed_gh
else:
    from chatgpt_review_dispatcher import (
        ReviewDispatchError,
        canonical_structured_handoff,
        dispatch_review_request,
        dispatch_status,
        github_owner_marker_lookup,
    )
    from exact_pr_binding import (
        CANONICAL_REPOSITORY,
        ExactPRBinding,
        ExactPRBindingError,
        resolve_exact_open_pr,
        revalidate_exact_open_pr,
    )
    from managed_gh import resolve_managed_gh


ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_REQUEST_KEYS = frozenset(
    {
        "event",
        "state",
        "provider",
        "review_kind",
        "pr",
        "head_sha",
        "handoff",
        "handoff_bytes",
        "handoff_sha256",
        "expected_marker",
        "rerun",
        "verdict_authority",
    }
)
_ENRICHED_KEYS = frozenset(
    {"schema_version", "repository", "base", "base_sha", "head_branch"}
)


class ReviewTransitionError(RuntimeError):
    """The trusted output or exact PR binding is unavailable or contradictory."""


def _managed_gh() -> str:
    try:
        binary, _, _ = resolve_managed_gh(ROOT)
    except ValueError as exc:
        raise ReviewTransitionError(str(exc)) from exc
    return binary


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise ReviewTransitionError("cannot verify exact local Git checkout")
    return result.stdout.strip()


def _trusted_transition(
    trusted_root: Path,
    target_root: Path,
    pr_number: int,
    *,
    dry_run: bool,
) -> tuple[int, dict[str, Any]]:
    wrapper = trusted_root / "scripts/repository_delivery.py"
    if trusted_root == target_root or not wrapper.is_file():
        raise ReviewTransitionError("distinct exact-base trusted wrapper is required")
    command = [
        sys.executable,
        "-I",
        str(wrapper),
        "trusted-pr-transition",
        "--target-root",
        str(target_root),
        "--pr",
        str(pr_number),
        "--json",
    ]
    if dry_run:
        command.append("--dry-run")
    result = subprocess.run(
        command,
        cwd=target_root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise ReviewTransitionError(
            "exact-base controller did not emit one valid JSON result"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 2
        or type(payload.get("pr")) is not int
        or payload["pr"] != pr_number
        or payload.get("output_contract") != "PASS"
    ):
        raise ReviewTransitionError("exact-base controller result contract is invalid")
    return result.returncode, payload


def _request_from_controller(
    controller: dict[str, Any],
    binding: ExactPRBinding,
) -> dict[str, Any]:
    """Add identity fields without changing the trusted handoff or marker."""
    qualification = controller.get("qualification")
    original = controller.get("review_request")
    if (
        controller.get("state") != "CHATGPT_REVIEW_REQUIRED"
        or controller.get("pr") != binding.pr_number
        or controller.get("head_sha") != binding.head_sha
        or controller.get("head_branch") != binding.head_branch
        or controller.get("base") != binding.base
        or not isinstance(qualification, dict)
        or qualification.get("status") != "PASS"
        or qualification.get("head_sha") != binding.head_sha
        or qualification.get("base_sha") != binding.base_sha
        or not isinstance(original, dict)
        or not _SOURCE_REQUEST_KEYS.issubset(original)
        or set(original) - _SOURCE_REQUEST_KEYS - _ENRICHED_KEYS
    ):
        raise ReviewTransitionError(
            "trusted controller review state is not exact and complete"
        )
    for key, value in (
        ("schema_version", 1),
        ("repository", binding.repository),
        ("base", binding.base),
        ("base_sha", binding.base_sha),
        ("head_branch", binding.head_branch),
    ):
        if key in original and original[key] != value:
            raise ReviewTransitionError(f"trusted review request has conflicting {key}")
    if (
        original.get("event") != "CHATGPT_REVIEW_REQUIRED"
        or original.get("state") != "CHATGPT_REVIEW_REQUIRED"
        or original.get("provider") != "ChatGPT"
        or original.get("verdict_authority") is not False
        or original.get("pr") != binding.pr_number
        or original.get("head_sha") != binding.head_sha
        or original.get("review_kind") not in {"CODE", "SECURITY"}
        or type(original.get("handoff_bytes")) is not int
        or not isinstance(original.get("handoff"), str)
        or not isinstance(original.get("handoff_sha256"), str)
        or _DIGEST.fullmatch(original["handoff_sha256"]) is None
        or original["handoff_bytes"] != len(original["handoff"].encode("utf-8"))
        or hashlib.sha256(original["handoff"].encode("utf-8")).hexdigest()
        != original["handoff_sha256"]
    ):
        raise ReviewTransitionError("trusted controller review request is malformed")
    if (
        controller.get("review_kind", original["review_kind"])
        != original["review_kind"]
    ):
        raise ReviewTransitionError("trusted controller review kind conflicts")
    if original["review_kind"] == "SECURITY":
        code = controller.get("code_review")
        if (
            not isinstance(code, dict)
            or code.get("status") != "PASS"
            or code.get("head_sha") != binding.head_sha
            or code.get("blocking_findings") != 0
        ):
            raise ReviewTransitionError("SECURITY dispatch requires exact CODE PASS")
    request = {
        **original,
        "schema_version": 1,
        "repository": binding.repository,
        "base": binding.base,
        "base_sha": binding.base_sha,
        "head_branch": binding.head_branch,
    }
    if "compatibility_digest" in qualification and "handoff" not in controller:
        raise ReviewTransitionError("trusted controller omitted structured handoff")
    if "handoff" in controller:
        try:
            handoff = canonical_structured_handoff(
                controller["handoff"],
                binding,
                qualification_digest=qualification.get("compatibility_digest"),
            )
        except ReviewDispatchError as exc:
            raise ReviewTransitionError(
                "trusted structured handoff is malformed"
            ) from exc
        if controller["handoff"]["review_kind"] != request["review_kind"]:
            raise ReviewTransitionError(
                "trusted structured handoff review kind conflicts"
            )
        encoded = handoff.encode("utf-8")
        request.update(
            handoff=handoff,
            handoff_bytes=len(encoded),
            handoff_sha256=hashlib.sha256(encoded).hexdigest(),
        )
    return request


def dispatch_controller_result(
    controller: dict[str, Any],
    *,
    pr_number: int,
    target_root: Path,
    dry_run: bool = False,
    transport: Any = None,
    resolver: Callable[..., ExactPRBinding] = resolve_exact_open_pr,
    dispatcher: Callable[..., dict[str, Any]] = dispatch_review_request,
    marker_lookup: Callable[..., Any] = github_owner_marker_lookup,
    binding: ExactPRBinding | None = None,
) -> dict[str, Any]:
    """Dispatch a trusted review request while keeping its verdict external."""
    if controller.get("state") != "CHATGPT_REVIEW_REQUIRED":
        return controller
    if type(pr_number) is not int or pr_number < 1:
        raise ReviewTransitionError("PR number must be positive")
    if _git(target_root, "status", "--porcelain", "--untracked-files=all"):
        raise ReviewTransitionError(
            "target PR checkout must remain clean before dispatch"
        )
    source_sha = _git(target_root, "rev-parse", "HEAD")
    branch = _git(target_root, "branch", "--show-current")
    qualification = controller.get("qualification")
    base_sha = (
        qualification.get("base_sha") if isinstance(qualification, dict) else None
    )
    if (
        _SHA.fullmatch(source_sha) is None
        or source_sha != controller.get("head_sha")
        or branch != controller.get("head_branch")
        or not isinstance(base_sha, str)
        or _SHA.fullmatch(base_sha) is None
    ):
        raise ReviewTransitionError(
            "local checkout differs from trusted review identity"
        )
    gh = _managed_gh()
    if binding is None:
        binding = resolver(
            CANONICAL_REPOSITORY,
            source_sha,
            branch,
            str(controller.get("base") or ""),
            base_sha,
            gh=gh,
        )
    elif revalidate_exact_open_pr(binding, gh=gh) != binding:
        raise ReviewTransitionError("exact PR binding changed before dispatch")
    if binding.pr_number != pr_number:
        raise ReviewTransitionError(
            "resolved exact PR number differs from requested PR"
        )
    request = _request_from_controller(controller, binding)
    if "handoff" in controller:
        tree_sha = _git(target_root, "show", "-s", "--format=%T", "HEAD")
        if controller["handoff"]["tree_sha"] != tree_sha:
            raise ReviewTransitionError(
                "structured handoff tree differs from exact HEAD"
            )
    controller["review_request"] = request
    if dry_run:
        controller["review_dispatch"] = {
            "status": "NOT_REQUESTED",
            "provider": "ChatGPT",
            "kind": request["review_kind"],
            "pr": binding.pr_number,
            "head_sha": binding.head_sha,
            "handoff_sha256": request["handoff_sha256"],
            "transport": "DRY_RUN",
            "verdict_authority": False,
        }
        return controller
    lookup = (
        (lambda bound, kind: marker_lookup(bound, kind, gh=gh))
        if marker_lookup is github_owner_marker_lookup
        else marker_lookup
    )
    record = dispatcher(
        request,
        binding=binding,
        transport=transport,
        owner_marker_lookup=lookup,
        binding_revalidator=lambda bound: revalidate_exact_open_pr(bound, gh=gh),
    )
    if not isinstance(record, dict) or record.get("verdict_authority") is not False:
        raise ReviewTransitionError(
            "dispatcher returned invalid non-authoritative state"
        )
    status = record.get("state")
    if status not in {
        "NOT_REQUESTED",
        "REQUESTED",
        "RUNNING",
        "PASS",
        "FAIL",
        "BLOCKED",
        "SUPERSEDED",
    }:
        raise ReviewTransitionError("dispatcher returned an unsupported request state")
    controller["review_dispatch"] = {
        "status": status,
        "reason": str(record.get("reason") or ""),
        "provider": "ChatGPT",
        "kind": request["review_kind"],
        "pr": binding.pr_number,
        "head_sha": binding.head_sha,
        "handoff_sha256": request["handoff_sha256"],
        "dispatch_identity": record.get("identity"),
        "outbox_path": record.get("outbox_path"),
        "transport": "EXTERNAL" if transport is not None else "UNAVAILABLE",
        "verdict_authority": False,
    }
    if (
        status == "BLOCKED"
        and record.get("reason") == "BLOCKED_EXTERNAL_REVIEW_TRANSPORT"
    ):
        controller["state"] = "BLOCKED_EXTERNAL_REVIEW_TRANSPORT"
        controller["next_action"] = "CONNECT_EXTERNAL_CHATGPT_REVIEW_TRANSPORT"
        controller.setdefault("blockers", []).append(
            "ChatGPT review transport is unavailable; exact handoff is ready in review_request"
        )
    return controller


def _preflight_owner_markers(target_root: Path, pr_number: int) -> ExactPRBinding:
    """Block edited or malformed owner markers before the trusted controller runs."""
    if _git(target_root, "status", "--porcelain", "--untracked-files=all"):
        raise ReviewTransitionError("target PR checkout must remain clean")
    source_sha = _git(target_root, "rev-parse", "HEAD")
    branch = _git(target_root, "branch", "--show-current")
    gh = _managed_gh()
    binding = resolve_exact_open_pr(
        CANONICAL_REPOSITORY, source_sha, branch, "main", gh=gh
    )
    if binding.pr_number != pr_number:
        raise ReviewTransitionError(
            "resolved exact PR number differs from requested PR"
        )
    for kind in ("code", "security"):
        github_owner_marker_lookup(binding, kind, gh=gh)
    return binding


def transition(
    trusted_root: Path,
    target_root: Path,
    pr_number: int,
    *,
    dry_run: bool = False,
    transport: Any = None,
    preflight: Callable[[Path, int], ExactPRBinding] = _preflight_owner_markers,
) -> tuple[int, dict[str, Any]]:
    """Advance one bounded trusted transition, repeating only after a real marker."""
    trusted_root = trusted_root.resolve()
    target_root = target_root.resolve()
    previous_kind = ""
    binding = preflight(target_root, pr_number)
    for attempt in range(3):
        if attempt and preflight(target_root, pr_number) != binding:
            raise ReviewTransitionError("exact PR binding changed during transition")
        rc, controller = _trusted_transition(
            trusted_root,
            target_root,
            pr_number,
            dry_run=dry_run,
        )
        qualification = controller.get("qualification")
        if (
            not dry_run
            and rc == 0
            and controller.get("state") == "CHATGPT_REVIEW_REQUIRED"
            and isinstance(qualification, dict)
            and qualification.get("source") == "executed"
        ):
            # The exact-base controller's first handoff includes source=executed.
            # A later rerun would say source=reused and change the handoff digest.
            # Let the controller produce its stable handoff before any dispatch.
            if preflight(target_root, pr_number) != binding:
                raise ReviewTransitionError(
                    "exact PR binding changed while stabilizing review request"
                )
            initial_identity = (
                controller.get("pr"),
                controller.get("head_sha"),
                controller.get("head_branch"),
                controller.get("base"),
                controller.get("review_kind"),
            )
            rc, settled = _trusted_transition(
                trusted_root, target_root, pr_number, dry_run=False
            )
            settled_qualification = settled.get("qualification")
            if (
                rc != 0
                or settled.get("state") != "CHATGPT_REVIEW_REQUIRED"
                or (
                    settled.get("pr"),
                    settled.get("head_sha"),
                    settled.get("head_branch"),
                    settled.get("base"),
                    settled.get("review_kind"),
                )
                != initial_identity
                or not isinstance(settled_qualification, dict)
                or settled_qualification.get("status") != "PASS"
                or settled_qualification.get("source") != "reused"
            ):
                raise ReviewTransitionError(
                    "exact-base review handoff did not stabilize after qualification"
                )
            controller = settled
        if rc or controller.get("state") != "CHATGPT_REVIEW_REQUIRED":
            return rc, controller
        result = dispatch_controller_result(
            controller,
            pr_number=pr_number,
            target_root=target_root,
            dry_run=dry_run,
            transport=transport,
            binding=binding,
        )
        dispatch = result.get("review_dispatch", {})
        if dispatch.get("status") == "PASS":
            kind = str(dispatch.get("kind") or "")
            if kind == previous_kind:
                raise ReviewTransitionError(
                    "trusted controller did not accept the owner marker"
                )
            previous_kind = kind
            continue
        if dispatch.get("status") == "FAIL":
            result["state"] = f"{dispatch.get('kind')}_FAILED"
            result["next_action"] = "RESOLVE_CHATGPT_FINDINGS"
            return 1, result
        return (
            1 if result.get("state") == "BLOCKED_EXTERNAL_REVIEW_TRANSPORT" else 0
        ), result
    raise ReviewTransitionError("bounded review transition did not converge")


def _print_result(result: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return
    print(f"PR #{result.get('pr')} HEAD {result.get('head_sha') or 'unknown'}")
    print(f"STATE {result.get('state') or 'BLOCKED'}")
    dispatch = result.get("review_dispatch")
    if isinstance(dispatch, dict):
        print(
            f"REVIEW_DISPATCH {dispatch.get('status')} "
            f"kind={dispatch.get('kind')} identity={dispatch.get('dispatch_identity') or 'none'}"
        )
    request = result.get("review_request")
    if isinstance(request, dict) and request.get("handoff"):
        print("CHATGPT_REVIEW_HANDOFF " + str(request["handoff"]))
    authorization = result.get("owner_authorization")
    if result.get("state") == "OWNER_AUTH_REQUIRED" and isinstance(authorization, dict):
        print(str(authorization.get("command") or ""))
    for blocker in result.get("blockers", []):
        print("BLOCKER " + str(blocker))


def review_dispatch_status(
    target_root: Path,
    pr_number: int,
    kind: str,
) -> dict[str, Any]:
    """Read exact-PR outbox state without assigning any review authority."""
    if type(pr_number) is not int or pr_number < 1 or kind not in {"CODE", "SECURITY"}:
        raise ReviewTransitionError(
            "status requires a positive PR and CODE or SECURITY"
        )
    source_sha = _git(target_root, "rev-parse", "HEAD")
    branch = _git(target_root, "branch", "--show-current")
    gh = _managed_gh()
    binding = resolve_exact_open_pr(
        CANONICAL_REPOSITORY, source_sha, branch, "main", gh=gh
    )
    if binding.pr_number != pr_number:
        raise ReviewTransitionError(
            "resolved exact PR number differs from requested PR"
        )
    return dispatch_status(binding, kind, gh=gh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--target-root", type=Path, default=ROOT)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--kind", choices=("CODE", "SECURITY"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.status:
            if args.kind is None or args.dry_run:
                raise ReviewTransitionError(
                    "status requires --kind and disallows --dry-run"
                )
            result = review_dispatch_status(args.target_root, args.pr, args.kind)
            rc = 0
        else:
            if args.trusted_root is None or args.kind is not None:
                raise ReviewTransitionError(
                    "transition requires --trusted-root and no --kind"
                )
            rc, result = transition(
                args.trusted_root,
                args.target_root,
                args.pr,
                dry_run=args.dry_run,
            )
    except (
        OSError,
        ValueError,
        ReviewTransitionError,
        ExactPRBindingError,
        ReviewDispatchError,
    ) as exc:
        rc = 1
        result = {
            "schema_version": 2,
            "pr": args.pr,
            "state": "BLOCKED",
            "next_action": "REVALIDATE_EXACT_PR",
            "merge_ready": False,
            "merge_result": "NOT_ATTEMPTED",
            "blockers": [str(exc)],
            "review_dispatch": {"status": "BLOCKED", "verdict_authority": False},
        }
    _print_result(result, json_output=args.json)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
