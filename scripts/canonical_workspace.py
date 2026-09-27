#!/usr/bin/env python3
"""Fail-closed, machine-readable canonical Git workspace check."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import yaml


def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(cwd), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def _normalized_remote(
    remote: str, repository: str, *, allow_local: bool
) -> str | None:
    """Return non-secret repository evidence for an allowed remote."""
    value = remote.strip()
    if allow_local and value.startswith(("/", "./", "file://")):
        return "local-checkout"
    if value == f"git@github.com:{repository}.git":
        return value
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    allowed_hosts = {"github.com"}
    if allow_local:
        allowed_hosts.add("gitea.ecommerce.local")
    if (
        parsed.scheme != "https"
        or host not in allowed_hosts
        or port is not None
        or parsed.path != f"/{repository}.git"
        or parsed.query
        or parsed.fragment
    ):
        return None
    return f"https://{host}/{repository}.git"


def _validated_remotes(
    working: Path, repository: str, *, allow_local: bool
) -> dict | None:
    fetch_urls = _git(working, "remote", "get-url", "--all", "origin").splitlines()
    push_urls = _git(
        working, "remote", "get-url", "--push", "--all", "origin"
    ).splitlines()
    if not fetch_urls or not push_urls:
        return None
    fetch = [
        _normalized_remote(url, repository, allow_local=allow_local)
        for url in fetch_urls
    ]
    push = [
        _normalized_remote(url, repository, allow_local=allow_local)
        for url in push_urls
    ]
    if any(url is None for url in (*fetch, *push)):
        return None
    return {"fetch": fetch, "push": push}


def check(
    script_root: Path | None = None,
    cwd: Path | None = None,
    execution_scope: str | None = None,
) -> dict:
    source = script_root or Path(__file__).resolve().parents[1]
    working = cwd or Path.cwd()
    result: dict = {"status": "FAIL"}
    try:
        policy = yaml.safe_load(
            (source / "architecture.lock.yaml").read_text(encoding="utf-8")
        )
        contract = policy["repository_governance"]["canonical_workspace"]
        expected = contract["canonical_path"]
        repository = contract["repository"]
        scope_environment = contract["execution_scope_environment"]
        noncanonical_scopes = set(contract["noncanonical_execution_scopes"])
        publication_scopes = set(contract["publication_scopes"])
        scope = (
            execution_scope
            if execution_scope is not None
            else os.environ.get(scope_environment, "")
        ).strip().lower() or "local"
        if contract["status"] != "enforced" or contract["fail_closed"] is not True:
            raise ValueError("policy is not enforced")
        if scope != "local" and scope not in noncanonical_scopes:
            return {**result, "reason": "UNSUPPORTED_EXECUTION_SCOPE"}
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
        return {**result, "reason": "POLICY_UNAVAILABLE"}
    result["canonical_root"] = expected
    result["execution_scope"] = scope
    result["publication_allowed"] = scope in publication_scopes
    try:
        raw_root = _git(working, "rev-parse", "--show-toplevel")
        actual = str(Path(raw_root).resolve(strict=True))
        git_dir = str(
            Path(_git(working, "rev-parse", "--absolute-git-dir")).resolve(strict=True)
        )
    except (OSError, subprocess.CalledProcessError):
        return {**result, "reason": "GIT_ROOT_UNAVAILABLE"}
    result["actual_workspace"] = actual
    result["realpath"] = actual
    try:
        remotes = _validated_remotes(working, repository, allow_local=scope == "ci")
        if remotes is None:
            return {**result, "reason": "WRONG_REPOSITORY"}
        result["repository_remotes"] = remotes
        if scope == "local" and actual != expected:
            return {
                **result,
                "reason": "NON_CANONICAL_WORKSPACE",
                "expected": expected,
                "actual": actual,
            }
        lexical = os.environ.get("PWD", "") if scope == "local" else ""
        if (
            lexical
            and Path(lexical).resolve() == working.resolve()
            and lexical != expected
        ):
            return {
                **result,
                "reason": "WORKSPACE_SYMLINK_MISMATCH",
                "expected": expected,
                "actual": lexical,
            }
        required_root = expected if scope == "local" else actual
        if (
            raw_root != required_root
            or git_dir != str(Path(required_root) / ".git")
            or not Path(git_dir).is_dir()
        ):
            return {
                **result,
                "reason": "WORKSPACE_SYMLINK_MISMATCH",
                "expected": expected,
                "actual": raw_root,
            }
        blocks = [
            line
            for line in _git(working, "worktree", "list", "--porcelain").splitlines()
            if line.startswith("worktree ")
        ]
        result["worktree_count"] = len(blocks)
        if len(blocks) != 1 or blocks[0] != f"worktree {required_root}":
            return {**result, "reason": "MULTIPLE_WORKTREES"}
        result["git_head"] = _git(working, "rev-parse", "HEAD")
        result["git_branch"] = _git(working, "branch", "--show-current")
    except (OSError, subprocess.CalledProcessError):
        return {**result, "reason": "GIT_ROOT_UNAVAILABLE"}
    return {**result, "status": "PASS", "repository": repository}


def main() -> int:
    result = check()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
