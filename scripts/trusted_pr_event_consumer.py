#!/usr/bin/env python3
"""Default-branch event adapter for the exact-base trusted PR transition.

This is forge transport, not CI: signed Tekton evidence must already exist.
The adapter never executes PR-head code and never manufactures review authority.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPOSITORY = "dst-red-Wire/ecommerce-1"
ORIGIN = "https://github.com/dst-red-Wire/ecommerce-1.git"
SHA = re.compile(r"[0-9a-f]{40}\Z")
OWNER_COMMAND = re.compile(r"/owner-authorization (?:approve|revoke) scope=pr-[1-9][0-9]* sha=[0-9a-f]{40}\Z")
REVIEW_MARKER = re.compile(r"<!--\s*chatgpt-exact-sha-review:v1\s+\{[^<>]*\}\s*-->")
EVENT_ACTIONS = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})
HEAD_EXEC_ENV_KEYS = frozenset({"PATH", "LANG", "LC_ALL", "TZ", "PYTHONIOENCODING"})
GITHUB_ENV_KEYS = HEAD_EXEC_ENV_KEYS | {"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPOSITORY"}
EVIDENCE_ENV_KEYS = HEAD_EXEC_ENV_KEYS | {
    "CI_EVIDENCE_REPOSITORY", "CI_EVIDENCE_COSIGN_PUBLIC_KEY",
    "CI_EVIDENCE_CERTIFICATE_IDENTITY", "CI_EVIDENCE_CERTIFICATE_OIDC_ISSUER",
    "DOCKER_CONFIG",
}


class Blocked(Exception):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Blocked(reason)


def phase_env(keys: frozenset[str]) -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in keys}


def head_exec_env() -> dict[str, str]:
    return phase_env(HEAD_EXEC_ENV_KEYS)


def trusted_github_env() -> dict[str, str]:
    env = phase_env(GITHUB_ENV_KEYS)
    require(bool(env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")), "GitHub credential unavailable")
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY, "GitHub repository mismatch")
    return env


def evidence_env() -> dict[str, str]:
    env = phase_env(EVIDENCE_ENV_KEYS)
    require(bool(env.get("CI_EVIDENCE_REPOSITORY")), "evidence repository unavailable")
    require(bool(env.get("CI_EVIDENCE_COSIGN_PUBLIC_KEY")) or bool(env.get("CI_EVIDENCE_CERTIFICATE_IDENTITY") and env.get("CI_EVIDENCE_CERTIFICATE_OIDC_ISSUER")), "evidence verifier unavailable")
    return env


@contextmanager
def scoped_environment(env: dict[str, str]):
    previous = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(env)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def run(args: list[str], *, cwd: Path | None = None, env: dict[str, str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise Blocked(f"command failed: {args[0]} {args[1] if len(args) > 1 else ''}")
    return result


def github(path: str) -> dict:
    return json.loads(run(["gh", "api", path], env=trusted_github_env()).stdout)


def verify_webhook(raw: bytes, signature: str, secret: str) -> None:
    require(bool(secret) and len(secret) >= 32, "webhook secret unavailable")
    require(signature.startswith("sha256=") and len(signature) == 71, "invalid webhook signature")
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    require(hmac.compare_digest(signature, expected), "webhook signature mismatch")


def authenticated_event_pr(raw: bytes, signature: str, event_name: str) -> int | None:
    secret = os.environ.pop("TRUSTED_PR_WEBHOOK_SECRET", "")
    try:
        verify_webhook(raw, signature, secret)
    finally:
        del secret
    return event_pr(event_name, json.loads(raw))


def event_pr(event_name: str, payload: dict) -> int | None:
    require(payload.get("repository", {}).get("full_name") == REPOSITORY, "wrong event repository")
    if event_name == "pull_request":
        if payload.get("action") not in EVENT_ACTIONS:
            return None
        value = payload.get("pull_request", {}).get("number")
    elif event_name == "issue_comment":
        if payload.get("action") != "created" or not payload.get("issue", {}).get("pull_request"):
            return None
        comment = payload.get("comment") or {}
        if comment.get("user", {}).get("login") != "dst-red-Wire":
            return None
        body = (comment.get("body") or "").strip()
        if not (OWNER_COMMAND.fullmatch(body) or REVIEW_MARKER.search(body)):
            return None
        value = payload.get("issue", {}).get("number")
    else:
        return None
    require(type(value) is int and value > 0, "invalid PR number")
    return value


def live_binding(number: int) -> tuple[str, str]:
    repo = github(f"repos/{REPOSITORY}")
    pr = github(f"repos/{REPOSITORY}/pulls/{number}")
    require(repo.get("full_name") == REPOSITORY and repo.get("default_branch") == "main", "repository identity changed")
    require(pr.get("number") == number and pr.get("state") == "open" and pr.get("draft") is False, "PR not eligible")
    require(pr.get("base", {}).get("ref") == "main" and pr.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY, "PR base mismatch")
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    require(bool(SHA.fullmatch(base)) and bool(SHA.fullmatch(head)), "invalid exact SHA")
    return base, head


def checkout_pair(root: Path, number: int, base: str, head: str) -> tuple[Path, Path]:
    shared = root / "source"
    run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--filter=blob:none", "--no-checkout", ORIGIN, str(shared)], env=head_exec_env(), timeout=300)
    run(["git", "-c", "core.hooksPath=/dev/null", "fetch", "--no-tags", "origin", f"refs/pull/{number}/head"], cwd=shared, env=head_exec_env())
    base_dir, head_dir = root / "base", root / "head"
    run(["git", "-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(base_dir), base], cwd=shared, env=head_exec_env())
    run(["git", "-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(head_dir), head], cwd=shared, env=head_exec_env())
    for path, expected in ((base_dir, base), (head_dir, head)):
        require(run(["git", "rev-parse", "HEAD"], cwd=path, env=head_exec_env()).stdout.strip() == expected, "checkout SHA mismatch")
        require(not run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=path, env=head_exec_env()).stdout.strip(), "dirty checkout")
        require(run(["git", "remote", "get-url", "origin"], cwd=path, env=head_exec_env()).stdout.strip() == ORIGIN, "checkout remote mismatch")
    require(subprocess.run(["git", "merge-base", "--is-ancestor", base, head], cwd=head_dir, env=head_exec_env(), capture_output=True).returncode == 0, "head not descended from base")
    return base_dir, head_dir


def trusted_delivery_module(base: Path):
    location = base / "scripts/repository_delivery.py"
    spec = importlib.util.spec_from_file_location("trusted_base_delivery", location)
    require(spec is not None and spec.loader is not None, "base delivery module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def no_credentials_env() -> dict[str, str]:
    return head_exec_env()


def prepare_qualification(base: Path, head_dir: Path, number: int, base_sha: str, head_sha: str) -> None:
    module = trusted_delivery_module(base)
    context = head_dir / ".context"
    with scoped_environment(evidence_env()):
        evidence = module.fetch_evidence(base, context, head_sha)  # Sigstore verification from exact-base code.
    audit = context / "performance" / f"{head_sha}.json"
    audit.parent.mkdir(parents=True, exist_ok=True)
    run([sys.executable, "-I", str(base / "scripts/performance_audit.py"), "--evidence", str(evidence), "--output", str(audit)], cwd=head_dir, env=head_exec_env())
    require(live_binding(number) == (base_sha, head_sha), "PR changed during qualification setup")


def transition(base: Path, head_dir: Path, number: int) -> dict:
    command = [sys.executable, "-I", str(base / "scripts/repository_delivery.py"), "trusted-pr-transition", "--target-root", str(head_dir), "--pr", str(number)]
    probe = subprocess.run([*command, "--dry-run", "--json"], cwd=base, env=trusted_github_env(), text=True, capture_output=True, timeout=180)
    try:
        state = json.loads(probe.stdout)
    except json.JSONDecodeError:
        raise Blocked("trusted dry-run produced no machine state") from None
    require(state.get("qualification", {}).get("status") == "PASS", "Tekton exact qualification unavailable")
    require(state.get("head_sha") == run(["git", "rev-parse", "HEAD"], cwd=head_dir, env=head_exec_env()).stdout.strip(), "trusted dry-run head mismatch")
    require(probe.returncode == 0, "trusted dry-run blocked")
    result = subprocess.run([*command, "--json"], cwd=base, env=trusted_github_env(), text=True, capture_output=True, timeout=300)
    try:
        final = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise Blocked("trusted transition produced no machine state") from None
    require(final.get("head_sha") == state["head_sha"], "trusted transition changed head")
    require(result.returncode == 0, "trusted transition blocked")
    return final


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--event-path", type=Path, required=True)
    parser.add_argument("--signature", required=True, help="GitHub X-Hub-Signature-256 header")
    args = parser.parse_args()
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "webhook repository mismatch")
    raw = args.event_path.read_bytes()
    number = authenticated_event_pr(raw, args.signature, args.event_name)
    if number is None:
        print("STATE=IGNORED_EVENT")
        return 0
    base_sha, head_sha = live_binding(number)
    with tempfile.TemporaryDirectory(prefix="trusted-pr-event-") as tmp:
        base, head_dir = checkout_pair(Path(tmp), number, base_sha, head_sha)
        prepare_qualification(base, head_dir, number, base_sha, head_sha)
        require(live_binding(number) == (base_sha, head_sha), "PR changed before trusted transition")
        result = transition(base, head_dir, number)
    print(json.dumps({"pr": number, "head_sha": head_sha, "state": result.get("state"), "next_action": result.get("next_action")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Blocked as exc:
        print("BLOCKED " + str(exc), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired):
        print("BLOCKED external authority unavailable", file=sys.stderr)
        raise SystemExit(1)
