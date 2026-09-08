from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

EVIDENCE_ARTIFACT_TYPE = "application/vnd.ecommerce1.ci-evidence.v1"
EVIDENCE_MEDIA_TYPE = "application/vnd.ecommerce1.ci-evidence.v1+json"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
REMOTE_STATUS_CONTEXT = "tekton/ecommerce-affected"


def _run(
    cmd: list[str], *, cwd: Path, check: bool = True, capture: bool = False, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(detail or f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def _output(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    return _run(cmd, cwd=cwd, env=env, capture=True).stdout


def require_command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"required command missing: {name}")
    return resolved


def evidence_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize actual work and conservative time saved by exact evidence reuse/promotion."""

    def reused(record: dict[str, Any]) -> bool:
        return bool(
            record.get("reused_from_sha")
            or record.get("promoted_from_worktree")
            or record.get("reused_from_worktree_tree_sha")
        )

    executed = [r for r in records if r.get("status") != "SKIP" and not reused(r)]
    reused_records = [r for r in records if reused(r)]
    skipped = [r for r in records if r.get("status") == "SKIP"]
    executed_seconds = round(sum(float(r.get("duration_seconds", 0.0) or 0.0) for r in executed), 3)
    saved_seconds = round(sum(float(r.get("source_duration_seconds", 0.0) or 0.0) for r in reused_records), 3)
    equivalent_full = round(executed_seconds + saved_seconds, 3)
    savings_percent = round((saved_seconds / equivalent_full) * 100.0, 1) if equivalent_full else 0.0
    return {
        "executed_gates": len(executed),
        "reused_gates": len(reused_records),
        "skipped_gates": len(skipped),
        "executed_seconds": executed_seconds,
        "estimated_saved_seconds": saved_seconds,
        "equivalent_full_seconds": equivalent_full,
        "estimated_savings_percent": savings_percent,
    }


def _evidence_repository() -> str:
    repository = os.environ.get("CI_EVIDENCE_REPOSITORY", "").strip()
    if not repository:
        raise RuntimeError("CI_EVIDENCE_REPOSITORY is required for remote evidence")
    if repository.startswith("oci://"):
        repository = repository[6:]
    if "://" in repository:
        raise RuntimeError("CI_EVIDENCE_REPOSITORY must be an OCI registry reference without URL scheme")
    return repository.rstrip("/")


def _evidence_ref(head_sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head_sha):
        raise RuntimeError(f"invalid full commit SHA: {head_sha}")
    return f"{_evidence_repository()}:sha-{head_sha}"


def _cosign_sign_blob(root: Path, evidence: Path, bundle: Path) -> None:
    cosign = require_command("cosign")
    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle)]
    key = os.environ.get("CI_EVIDENCE_COSIGN_KEY", "").strip()
    if key:
        cmd += ["--key", key]
    cmd.append(str(evidence))
    _run(cmd, cwd=root)


def _cosign_verify_blob(root: Path, evidence: Path, bundle: Path) -> None:
    cosign = require_command("cosign")
    cmd = [cosign, "verify-blob", str(evidence), "--bundle", str(bundle)]
    public_key = os.environ.get("CI_EVIDENCE_COSIGN_PUBLIC_KEY", "").strip()
    identity = os.environ.get("CI_EVIDENCE_CERTIFICATE_IDENTITY", "").strip()
    issuer = os.environ.get("CI_EVIDENCE_CERTIFICATE_OIDC_ISSUER", "").strip()
    if public_key:
        cmd += ["--key", public_key]
    elif identity and issuer:
        cmd += ["--certificate-identity", identity, "--certificate-oidc-issuer", issuer]
    else:
        raise RuntimeError(
            "evidence verification requires CI_EVIDENCE_COSIGN_PUBLIC_KEY or both "
            "CI_EVIDENCE_CERTIFICATE_IDENTITY and CI_EVIDENCE_CERTIFICATE_OIDC_ISSUER"
        )
    _run(cmd, cwd=root)


def publish_evidence(root: Path, evidence_path: Path) -> dict[str, str]:
    """Sign exact evidence then publish the evidence+Sigstore bundle as one OCI artifact."""
    oras = require_command("oras")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    head_sha = str(evidence.get("head_sha", ""))
    if evidence.get("status") != "PASS" or evidence.get("exact_commit_evidence") is not True:
        raise RuntimeError("only exact PASS evidence may be published")
    ref = _evidence_ref(head_sha)

    with tempfile.TemporaryDirectory(prefix="ci-evidence-publish-") as tmp:
        staging = Path(tmp)
        staged_evidence = staging / "evidence.json"
        bundle = staging / "evidence.sigstore.json"
        shutil.copy2(evidence_path, staged_evidence)
        _cosign_sign_blob(root, staged_evidence, bundle)
        proc = _run(
            [
                oras,
                "push",
                ref,
                "--artifact-type",
                EVIDENCE_ARTIFACT_TYPE,
                "--annotation",
                f"org.opencontainers.image.revision={head_sha}",
                f"{staged_evidence}:{EVIDENCE_MEDIA_TYPE}",
                f"{bundle}:{SIGSTORE_BUNDLE_MEDIA_TYPE}",
                "--format",
                "json",
            ],
            cwd=staging,
            capture=True,
        )
        descriptor = json.loads(proc.stdout)
    digest_ref = str(descriptor.get("reference") or descriptor.get("digest") or "")
    if digest_ref.startswith("sha256:"):
        digest_ref = ref.rsplit(":sha-", 1)[0] + "@" + digest_ref
    if "@sha256:" not in digest_ref:
        raise RuntimeError("ORAS did not return an immutable evidence digest reference")
    return {"tag_reference": ref, "digest_reference": digest_ref}


def fetch_evidence(root: Path, context: Path, head_sha: str) -> Path:
    """Pull and authenticate remote evidence before exposing it to incremental reuse."""
    oras = require_command("oras")
    ref = _evidence_ref(head_sha)
    with tempfile.TemporaryDirectory(prefix="ci-evidence-fetch-") as tmp:
        staging = Path(tmp)
        _run([oras, "pull", ref, "--output", str(staging)], cwd=root)
        evidence = staging / "evidence.json"
        bundle = staging / "evidence.sigstore.json"
        if not evidence.is_file() or not bundle.is_file():
            raise RuntimeError(f"remote evidence artifact is incomplete: {ref}")
        _cosign_verify_blob(root, evidence, bundle)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        if (
            payload.get("head_sha") != head_sha
            or payload.get("status") != "PASS"
            or payload.get("exact_commit_evidence") is not True
        ):
            raise RuntimeError(f"remote evidence is not exact PASS evidence for {head_sha}")
        destination = context / "evidence" / f"{head_sha}.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(evidence, destination)
    return destination


def _gitea_config() -> tuple[str, str, str] | None:
    api = os.environ.get("GITEA_API_URL", "").strip().rstrip("/")
    repository = os.environ.get("GITEA_REPOSITORY", "").strip().strip("/")
    token = os.environ.get("GITEA_TOKEN", "").strip()
    if not any((api, repository, token)):
        return None
    if not all((api, repository, token)):
        raise RuntimeError("GITEA_API_URL, GITEA_REPOSITORY and GITEA_TOKEN must be configured together")
    if not re.fullmatch(r"[^/]+/[^/]+", repository):
        raise RuntimeError("GITEA_REPOSITORY must use owner/repository form")
    return api, repository, token


def publish_gitea_status(
    head_sha: str, state: str, description: str, target_url: str = "", context: str = REMOTE_STATUS_CONTEXT
) -> bool:
    """Publish a status for the exact SHA. Returns False only when status publishing is unconfigured."""
    config = _gitea_config()
    if config is None:
        return False
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head_sha):
        raise RuntimeError(f"invalid full commit SHA for remote status: {head_sha}")
    if state not in {"pending", "success", "error", "failure", "warning", "skipped"}:
        raise RuntimeError(f"invalid Gitea status state: {state}")
    api, repository, token = config
    owner, repo = repository.split("/", 1)
    url = f"{api}/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/statuses/{head_sha}"
    payload = {"context": context, "description": description, "state": state}
    if target_url:
        payload["target_url"] = target_url
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 201:
                raise RuntimeError(f"Gitea status publish returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gitea status publish failed HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gitea status publish failed: {exc.reason}") from exc
    return True


def _git(root: Path, *args: str, check: bool = True) -> str:
    return _run(["git", *args], cwd=root, check=check, capture=True).stdout


def _object_sha_pattern(root: Path) -> re.Pattern[str]:
    algorithm = _git(root, "rev-parse", "--show-object-format").strip()
    if algorithm == "sha1":
        return re.compile(r"[0-9a-f]{40}")
    if algorithm == "sha256":
        return re.compile(r"[0-9a-f]{64}")
    raise RuntimeError(f"unsupported Git object format: {algorithm}")


def _bundle_branch(root: Path, bundle: Path, expected_head: str) -> str:
    if not bundle.is_file():
        raise RuntimeError(f"bundle not found: {bundle}")
    if not _object_sha_pattern(root).fullmatch(expected_head):
        raise RuntimeError("EXPECTED_HEAD must be a full lowercase commit SHA for this repository")
    _run(["git", "bundle", "verify", str(bundle)], cwd=root)
    lines = _output(["git", "bundle", "list-heads", str(bundle)], cwd=root).splitlines()
    matches: list[str] = []
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        if sha == expected_head and ref.startswith("refs/heads/"):
            matches.append(ref.removeprefix("refs/heads/"))
    if len(matches) != 1:
        raise RuntimeError(
            f"bundle must expose exactly one branch at EXPECTED_HEAD {expected_head}; found {matches or 'none'}"
        )
    branch = matches[0]
    if branch in {"main", "master"}:
        raise RuntimeError("bundle-deliver refuses a default-branch bundle")
    _run(["git", "check-ref-format", "--branch", branch], cwd=root)
    return branch


def _worktree_snapshot(root: Path) -> tuple[str, str, str]:
    branch = _git(root, "branch", "--show-current").strip()
    head = _git(root, "rev-parse", "HEAD").strip()
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    return branch, head, status


def bundle_deliver(
    root: Path, trusted_controller: Path, bundle: str, expected_head: str, title: str, base: str, python_executable: str
) -> int:
    """Deliver from an isolated clone without mutating refs/files in the caller worktree."""
    bundle_path = Path(bundle).expanduser().resolve()
    if not title.strip():
        raise RuntimeError("TITLE is required")
    if not base.strip():
        base = "main"
    before = _worktree_snapshot(root)
    branch = _bundle_branch(root, bundle_path, expected_head)
    origin = _git(root, "remote", "get-url", "origin").strip()
    if not origin:
        raise RuntimeError("origin remote is required")

    with tempfile.TemporaryDirectory(prefix="ecommerce-bundle-deliver-") as tmp:
        checkout = Path(tmp) / "checkout"
        _run(
            ["git", "clone", "--no-local", "--branch", branch, str(bundle_path), str(checkout)],
            cwd=Path(tmp),
        )
        actual_branch = _git(checkout, "branch", "--show-current").strip()
        actual_head = _git(checkout, "rev-parse", "HEAD").strip()
        if actual_branch != branch or actual_head != expected_head:
            raise RuntimeError(
                f"isolated bundle checkout mismatch: branch={actual_branch!r}, head={actual_head}; "
                f"expected branch={branch!r}, head={expected_head}"
            )
        if _git(checkout, "status", "--porcelain", "--untracked-files=all").strip():
            raise RuntimeError("isolated bundle checkout is unexpectedly dirty")
        _run(["git", "remote", "set-url", "origin", origin], cwd=checkout)

        # Execute the trusted controller from the caller checkout while cwd points at
        # the isolated clone. A bundle that modifies repoctl.py cannot weaken the
        # delivery controller used to validate and publish itself.
        trusted_env = os.environ.copy()
        trusted_env["REPOCTL_TRUSTED_CONTROLLER"] = str(trusted_controller)
        proc = _run(
            [
                python_executable,
                str(trusted_controller),
                "deliver",
                "--base",
                base,
                "--title",
                title,
            ],
            cwd=checkout,
            check=False,
            env=trusted_env,
        )
        if proc.returncode:
            return proc.returncode

    after = _worktree_snapshot(root)
    if after != before:
        raise RuntimeError("bundle-deliver mutated the caller worktree; refusing success")
    print(f"PASS bundle-deliver {branch} at {expected_head}; caller worktree unchanged")
    return 0


def compare_evidence(full_evidence: Path, incremental_evidence: Path) -> dict[str, Any]:
    """Compare measured gate durations from two real evidence documents."""
    full = json.loads(full_evidence.read_text(encoding="utf-8"))
    incremental = json.loads(incremental_evidence.read_text(encoding="utf-8"))
    if full.get("status") != "PASS" or incremental.get("status") != "PASS":
        raise RuntimeError("evidence comparison requires two PASS evidence documents")
    full_records = {str(r.get("gate")): r for r in full.get("gates", [])}
    inc_records = {str(r.get("gate")): r for r in incremental.get("gates", [])}
    names = sorted(set(full_records) | set(inc_records))
    gate_rows: list[dict[str, Any]] = []
    for name in names:
        before = full_records.get(name, {})
        after = inc_records.get(name, {})
        full_seconds = float(before.get("duration_seconds", 0.0) or 0.0)
        incremental_seconds = float(after.get("duration_seconds", 0.0) or 0.0)
        gate_rows.append(
            {
                "gate": name,
                "full_seconds": round(full_seconds, 3),
                "incremental_seconds": round(incremental_seconds, 3),
                "measured_delta_seconds": round(full_seconds - incremental_seconds, 3),
                "incremental_source": (
                    f"reused {after.get('reused_from_sha')}"
                    if after.get("reused_from_sha")
                    else ("skipped" if after.get("status") == "SKIP" else "executed")
                ),
            }
        )
    full_metrics = evidence_metrics(list(full_records.values()))
    inc_metrics = evidence_metrics(list(inc_records.values()))
    full_seconds = float(full_metrics["executed_seconds"])
    inc_seconds = float(inc_metrics["executed_seconds"])
    full_wall = full.get("metrics", {}).get("deliver_wall_seconds")
    inc_wall = incremental.get("metrics", {}).get("deliver_wall_seconds")
    return {
        "full_head_sha": full.get("head_sha"),
        "incremental_head_sha": incremental.get("head_sha"),
        "full_executed_seconds": full_seconds,
        "incremental_executed_seconds": inc_seconds,
        "full_total_gate_seconds": full_seconds,
        "incremental_total_gate_seconds": inc_seconds,
        "measured_time_saved_seconds": round(full_seconds - inc_seconds, 3),
        "measured_savings_percent": round(((full_seconds - inc_seconds) / full_seconds) * 100.0, 1)
        if full_seconds
        else 0.0,
        "full_deliver_wall_seconds": full_wall,
        "incremental_deliver_wall_seconds": inc_wall,
        "measured_deliver_time_saved_seconds": round(float(full_wall) - float(inc_wall), 3)
        if full_wall is not None and inc_wall is not None
        else None,
        "measured_deliver_savings_percent": round(((float(full_wall) - float(inc_wall)) / float(full_wall)) * 100.0, 1)
        if full_wall not in (None, 0, 0.0) and inc_wall is not None
        else None,
        "full_executed_gates": full_metrics["executed_gates"],
        "incremental_executed_gates": inc_metrics["executed_gates"],
        "incremental_reused_gates": inc_metrics["reused_gates"],
        "incremental_skipped_gates": inc_metrics["skipped_gates"],
        "gates": gate_rows,
    }


def _github_config() -> tuple[str, str, str] | None:
    api = os.environ.get("GITHUB_API_URL", "").strip().rstrip("/") or "https://api.github.com"
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip().strip("/")
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not repository and not token:
        return None
    if not repository or not token:
        raise RuntimeError("GITHUB_REPOSITORY and GITHUB_TOKEN must be configured together")
    if not re.fullmatch(r"[^/]+/[^/]+", repository):
        raise RuntimeError("GITHUB_REPOSITORY must use owner/repository form")
    return api, repository, token


def _publish_github_status(head_sha: str, state: str, description: str, target_url: str, context: str) -> None:
    config = _github_config()
    if config is None:
        raise RuntimeError("GitHub status publishing is not configured")
    api, repository, token = config
    owner, repo = repository.split("/", 1)
    url = f"{api}/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}/statuses/{head_sha}"
    payload = {"context": context, "description": description, "state": state}
    if target_url:
        payload["target_url"] = target_url
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 201:
                raise RuntimeError(f"GitHub status publish returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub status publish failed HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub status publish failed: {exc.reason}") from exc


def publish_remote_status(
    head_sha: str, state: str, description: str, target_url: str = "", context: str = REMOTE_STATUS_CONTEXT
) -> bool:
    """Publish to the single configured forge provider, always against the exact SHA."""
    has_gitea = _gitea_config() is not None
    has_github = _github_config() is not None
    if has_gitea and has_github:
        raise RuntimeError("configure exactly one remote CI status provider, not both Gitea and GitHub")
    if has_gitea:
        return publish_gitea_status(head_sha, state, description, target_url, context)
    if has_github:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head_sha):
            raise RuntimeError(f"invalid full commit SHA for remote status: {head_sha}")
        if state not in {"pending", "success", "error", "failure"}:
            # GitHub's commit-status API supports these four canonical states.
            state = "failure" if state in {"warning", "skipped"} else state
        _publish_github_status(head_sha, state, description, target_url, context)
        return True
    return False
