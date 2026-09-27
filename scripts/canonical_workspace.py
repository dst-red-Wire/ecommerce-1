#!/usr/bin/env python3
"""Fail-closed, machine-readable canonical Git workspace check."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml


def _git(cwd: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(cwd), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def check(script_root: Path | None = None, cwd: Path | None = None) -> dict:
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
        if contract["status"] != "enforced" or contract["fail_closed"] is not True:
            raise ValueError("policy is not enforced")
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError):
        return {**result, "reason": "POLICY_UNAVAILABLE"}
    result["canonical_workspace"] = expected
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
        remote = _git(working, "remote", "get-url", "origin")
        result["repository_remote"] = remote
        accepted = {
            f"https://github.com/{repository}.git",
            f"git@github.com:{repository}.git",
        }
        if remote not in accepted:
            return {**result, "reason": "WRONG_REPOSITORY"}
        if actual != expected:
            return {
                **result,
                "reason": "NON_CANONICAL_WORKSPACE",
                "expected": expected,
                "actual": actual,
            }
        lexical = os.environ.get("PWD", "")
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
        if (
            raw_root != expected
            or git_dir != str(Path(expected) / ".git")
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
        if len(blocks) != 1 or blocks[0] != f"worktree {expected}":
            return {**result, "reason": "MULTIPLE_WORKTREES"}
        result["head"] = _git(working, "rev-parse", "HEAD")
        result["branch"] = _git(working, "branch", "--show-current")
    except (OSError, subprocess.CalledProcessError):
        return {**result, "reason": "GIT_ROOT_UNAVAILABLE"}
    return {**result, "status": "PASS", "repository": repository}


def main() -> int:
    result = check()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
