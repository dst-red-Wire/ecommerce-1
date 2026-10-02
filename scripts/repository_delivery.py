from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

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
    """Summarize execution, exact evidence reuse, and content-cache acceleration separately."""

    def reused(record: dict[str, Any]) -> bool:
        return bool(
            record.get("execution") == "parent-evidence"
            or record.get("reused_from_sha")
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

    nested_cache_gates = [r for r in executed if int(r.get("content_cache_hits", 0) or 0) > 0]
    content_cache_hits = sum(int(r.get("content_cache_hits", 0) or 0) for r in executed)
    content_cache_misses = sum(int(r.get("content_cache_misses", 0) or 0) for r in executed)
    execution_counts: dict[str, int] = {}
    for record in records:
        if record.get("status") == "SKIP":
            mode = "skipped"
        elif reused(record):
            mode = str(record.get("execution") or "parent-evidence")
        else:
            mode = str(record.get("execution") or "fresh")
        execution_counts[mode] = execution_counts.get(mode, 0) + 1

    return {
        "executed_gates": len(executed),
        "reused_gates": len(reused_records),
        "skipped_gates": len(skipped),
        "execution_counts": dict(sorted(execution_counts.items())),
        "content_cache_gates": len(nested_cache_gates),
        "content_cache_direct_gates": sum(1 for r in executed if r.get("execution") == "content-cache"),
        "content_cache_hits": content_cache_hits,
        "content_cache_misses": content_cache_misses,
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
    root_url = os.environ.get("GITEA_HTTPS_URL", "").strip().rstrip("/")
    configured_api = os.environ.get("GITEA_API_URL", "").strip().rstrip("/")
    derived_api = f"{root_url}/api/v1" if root_url else ""
    if configured_api and derived_api and configured_api != derived_api:
        raise RuntimeError("GITEA_API_URL contradicts GITEA_HTTPS_URL")
    api = configured_api or derived_api
    repository = os.environ.get("GITEA_REPOSITORY", "").strip().strip("/")
    token = os.environ.get("GITEA_TOKEN", "").strip()
    if not repository and not token:
        return None
    if not all((api, repository, token)):
        raise RuntimeError(
            "GITEA_HTTPS_URL (or GITEA_API_URL), GITEA_REPOSITORY and GITEA_TOKEN "
            "must be configured together"
        )
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
    """Read checkout metadata without inheriting owner identity or executable Git config."""
    checkout = root.resolve(strict=True)
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    prefix = [
        "/usr/bin/git", "--no-pager",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "-c", "protocol.ext.allow=never",
        "-c", f"core.worktree={checkout}",
        "-C", str(checkout),
    ]

    def read(*arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [*prefix, *arguments], cwd=checkout, env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("trusted Git metadata is unavailable") from exc

    if args and args[0] == "status":
        # A tracked .gitattributes can name a filter whose executable lives in
        # repository-local config. Git status may launch that filter on a dirty
        # checkout, even though the read will ultimately reject the checkout.
        external = read(
            "config", "--includes", "--name-only", "--get-regexp",
            r"^(filter\..*\.(clean|smudge|process)|diff\..*\.(command|textconv))$",
        )
        if external.returncode == 0:
            raise RuntimeError("external Git filters are forbidden during checkout validation")
        if external.returncode != 1:
            raise RuntimeError("trusted Git filter configuration is unavailable")

    result = read(*args)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or "trusted Git metadata check failed")
    return result.stdout


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


def _authenticated_gh_environment() -> dict[str, str]:
    """Keep owner GitHub auth while constraining Git spawned by the pinned CLI."""
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME") or pwd.getpwuid(os.getuid()).pw_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "credential.helper",
        "GIT_CONFIG_VALUE_2": "",
        "GIT_CONFIG_KEY_3": "protocol.ext.allow",
        "GIT_CONFIG_VALUE_3": "never",
    }
    for name in (
        "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GH_CONFIG_DIR",
        "XDG_CONFIG_HOME", "XDG_DATA_HOME", "ECOMMERCE_TOOL_HOME",
        "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
        "https_proxy", "http_proxy", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _github_repository(root: Path, gh: str) -> str:
    raw = _output(
        [gh, "repo", "view", "--json", "nameWithOwner"],
        cwd=root, env=_authenticated_gh_environment(),
    )
    try:
        repository = str(json.loads(raw or "{}").get("nameWithOwner") or "")
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub repository identity returned invalid JSON") from exc
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("GitHub repository identity is missing or invalid")
    return repository


def _github_pr_binding(root: Path, gh: str, repository: str, pr_number: int) -> dict[str, Any]:
    raw = _output(
        [gh, "api", f"repos/{repository}/pulls/{pr_number}"],
        cwd=root, env=_authenticated_gh_environment(),
    )
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub REST pull request binding returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("number") != pr_number:
        raise RuntimeError("GitHub REST pull request binding does not match the requested PR")
    base = value.get("base")
    head = value.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise RuntimeError("GitHub REST pull request base/head objects are missing")
    for side, payload in (("base", base), ("head", head)):
        if not re.fullmatch(r"[0-9a-f]{40}", str(payload.get("sha") or "")):
            raise RuntimeError(f"GitHub REST pull request {side}.sha is missing or invalid")
        if not isinstance(payload.get("ref"), str) or not payload["ref"]:
            raise RuntimeError(f"GitHub REST pull request {side}.ref is missing or invalid")
    if base["ref"] != "main":
        raise RuntimeError("trusted PR transition requires the main default branch")
    if value.get("state") not in {"open", "closed"}:
        raise RuntimeError(f"trusted PR transition refuses PR state {value.get('state')!r}")
    if value.get("state") == "closed" and not value.get("merged_at"):
        raise RuntimeError("trusted PR transition refuses a closed unmerged PR")
    if type(value.get("draft")) is not bool:
        raise RuntimeError("GitHub REST pull request draft flag is missing or invalid")
    head_repository = head.get("repo")
    if head_repository is not None and not isinstance(head_repository, dict):
        raise RuntimeError("GitHub REST pull request head repository is invalid")
    return {
        "number": pr_number,
        "state": "MERGED" if value.get("merged_at") else "OPEN",
        "draft": value["draft"],
        "base_sha": base["sha"],
        "head_sha": head["sha"],
        "head_repository": str((head_repository or {}).get("full_name") or ""),
    }


def _require_clean_sha(root: Path, expected_sha: str, label: str) -> None:
    if not root.is_dir():
        raise RuntimeError(f"{label} checkout does not exist: {root}")
    actual_sha = _git(root, "rev-parse", "HEAD").strip()
    if actual_sha != expected_sha:
        raise RuntimeError(
            f"{label} checkout SHA mismatch: expected {expected_sha}, got {actual_sha}"
        )
    if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise RuntimeError(f"{label} checkout must be clean at the exact SHA")


def trusted_pr_transition(
    trusted_root: Path,
    target_root: Path,
    pr_number: int,
    python_executable: str,
    *,
    dry_run: bool = False,
    json_output: bool = False,
) -> int:
    """Run the PR state machine exclusively from the PR's clean exact-base checkout."""
    trusted_root = trusted_root.resolve()
    target_root = target_root.resolve()
    if pr_number < 1:
        raise RuntimeError("PR number must be a positive integer")
    if trusted_root == target_root:
        raise RuntimeError("trusted base and target PR checkouts must be distinct")

    wrapper = Path(__file__).resolve()
    expected_wrapper = trusted_root / "scripts/repository_delivery.py"
    trusted_controller = trusted_root / "scripts/repoctl.py"
    if wrapper != expected_wrapper.resolve():
        raise RuntimeError("trusted PR wrapper must execute from its own trusted checkout")
    if not trusted_controller.is_file():
        raise RuntimeError("trusted exact-base repoctl.py is unavailable")

    from managed_gh import resolve_managed_gh

    gh, _version, _binary_sha256 = resolve_managed_gh(
        trusted_root, env=_authenticated_gh_environment()
    )
    trusted_repository = _github_repository(trusted_root, gh)
    binding = _github_pr_binding(trusted_root, gh, trusted_repository, pr_number)
    base_sha = str(binding["base_sha"])
    head_sha = str(binding["head_sha"])
    _require_clean_sha(trusted_root, base_sha, "trusted base")
    _require_clean_sha(target_root, head_sha, "target PR")

    target_repository = _github_repository(target_root, gh)
    if target_repository != trusted_repository or (
        binding["state"] == "OPEN" and binding["head_repository"] != trusted_repository
    ):
        raise RuntimeError(
            "target PR repository mismatch: expected "
            f"{trusted_repository}, got target={target_repository}, head={binding['head_repository']}"
        )
    # A stale PR head is a state for the trusted controller to reconcile. The
    # exact checkout and GitHub binding above remain mandatory before mutation.

    environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
            "REPOCTL_TRUSTED_CONTROLLER": str(trusted_controller.resolve()),
            "REPOCTL_TRUSTED_POLICY_ROOT": str(trusted_root),
            "REPOCTL_TRUSTED_BASE_SHA": base_sha,
            "REPOCTL_TRUSTED_TARGET_ROOT": str(target_root),
            "REPOCTL_TRUSTED_HEAD_SHA": head_sha,
            "REPOCTL_TRUSTED_PR_NUMBER": str(pr_number),
        }
    )
    command = [
        python_executable,
        "-I",
        str(trusted_controller.resolve()),
        "pr-loop",
        "--pr",
        str(pr_number),
    ]
    if dry_run:
        command.append("--dry-run")
    if json_output:
        command.append("--json")
    return _run(
        command,
        cwd=target_root,
        check=False,
        env=environment,
    ).returncode


_NATIVE_REPOSITORY = "dst-red-Wire/ecommerce-1"
_NATIVE_RUNNER_PATHS = (
    "scripts/windows/LabNativeBoot.ps1",
    "scripts/windows/LabNetworkSmoke.ps1",
    "scripts/windows/RockyImagePipeline.psm1",
    "scripts/windows/NativeVagrantSshSmoke.ps1",
    "scripts/windows/LabNetworkSeed.ps1",
    "scripts/windows/LabSshIdentity.ps1",
    "scripts/windows/local-services-seed-server.ps1",
)
_NATIVE_CONTROLLER_PATHS = (
    "scripts/repository_delivery.py",
    "scripts/repoctl.py",
    "scripts/exact_pr_binding.py",
    "scripts/managed_gh.py",
    "config/contracts/toolchain-lock.json",
)
_NATIVE_ACTIONS = {
    "Prepare": "lab-network-native-boot-prepare",
    "SelfTest": "lab-network-native-boot-self-test",
    "Reboot": "lab-network-native-boot-reboot",
    "Recover": "lab-network-native-boot-recover",
    "Verify": "lab-network-native-boot-authority-check",
}


def _native_child_environment() -> dict[str, str]:
    """Use only host identity, WSL interop and GitHub credentials at this gate."""
    account = pwd.getpwuid(os.getuid())
    environment = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    for name in (
        "XDG_RUNTIME_DIR", "WSL_DISTRO_NAME", "WSL_INTEROP",
        "GH_TOKEN", "GITHUB_TOKEN", "ECOMMERCE_TOOL_HOME",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _native_git_bytes(root: Path, *args: str, environment: dict[str, str]) -> bytes:
    if shutil.which("git", path=environment.get("PATH")) != "/usr/bin/git":
        raise RuntimeError("trusted native Git executable is unavailable")
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
            cwd=root, env=environment, stdin=subprocess.DEVNULL,
            capture_output=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("trusted native Git verification is unavailable") from exc
    if result.returncode:
        raise RuntimeError("trusted native Git verification failed")
    return result.stdout


def _native_git_text(root: Path, *args: str, environment: dict[str, str]) -> str:
    return _native_git_bytes(root, *args, environment=environment).decode("utf-8").strip()


def _native_checkout_root(root: Path, *, environment: dict[str, str]) -> Path:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise RuntimeError("trusted native checkout path is absent or redirected")
    if root.resolve(strict=True) != root:
        raise RuntimeError("trusted native checkout path is not canonical")
    top = _native_git_text(root, "rev-parse", "--show-toplevel", environment=environment)
    if top != str(root):
        raise RuntimeError("trusted native path is not a checkout root")
    return root


def _native_clean_checkout(
    root: Path, *, environment: dict[str, str], require_branch: bool = False
) -> tuple[str, str]:
    sha = _native_git_text(root, "rev-parse", "HEAD", environment=environment)
    branch = _native_git_text(
        root, "branch", "--show-current", environment=environment
    )
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise RuntimeError("trusted native checkout SHA is invalid")
    if (require_branch and not branch) or branch != branch.strip():
        raise RuntimeError("trusted native checkout branch is invalid")
    if _native_git_text(
        root, "status", "--porcelain=v1", "--untracked-files=all", environment=environment
    ):
        raise RuntimeError("trusted native checkout must be clean at the exact SHA")
    return sha, branch


def _native_ps1_crlf_policy(
    root: Path, sha: str, *, environment: dict[str, str]
) -> bool:
    attributes = _native_git_bytes(
        root, "show", f"{sha}:.gitattributes", environment=environment
    )
    return b"*.ps1 text eol=crlf" in attributes.splitlines()


def _native_git_file_bytes(
    root: Path, sha: str, relative: str, *, environment: dict[str, str]
) -> bytes:
    source = root / relative
    if (
        source.is_symlink() or not source.is_file()
        or source.resolve(strict=True) != source
        or not stat.S_ISREG(source.lstat().st_mode)
    ):
        raise RuntimeError(f"trusted native source is unsafe: {relative}")
    index = _native_git_text(
        root, "ls-files", "--stage", "--", relative, environment=environment
    )
    if not re.fullmatch(r"100(?:644|755) [0-9a-f]{40} 0\t" + re.escape(relative), index):
        raise RuntimeError(f"trusted native source is not a regular tracked file: {relative}")
    expected = _native_git_bytes(
        root, "show", f"{sha}:{relative}", environment=environment
    )
    raw = source.read_bytes()
    canonical = raw
    if source.suffix == ".ps1" and _native_ps1_crlf_policy(
        root, sha, environment=environment
    ):
        canonical = raw.replace(b"\r\n", b"\n")
        if b"\r" in canonical:
            raise RuntimeError(f"trusted native source has unsafe EOL: {relative}")
    if canonical != expected:
        raise RuntimeError(f"trusted native source differs from Git: {relative}")
    return raw


def _native_verify_base_tree(
    root: Path, sha: str, *, environment: dict[str, str]
) -> None:
    """Reject hidden substitutions in any exact-SHA checkout, including skip-worktree files."""
    tree = _native_git_bytes(
        root, "ls-tree", "-r", "-z", "--full-tree", sha, environment=environment
    )
    if not tree or not tree.endswith(b"\0"):
        raise RuntimeError("trusted native base Git tree is invalid")
    ps1_crlf = _native_ps1_crlf_policy(root, sha, environment=environment)
    for entry in tree.split(b"\0")[:-1]:
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, object_sha = metadata.split(b" ")
        except ValueError as exc:
            raise RuntimeError("trusted native base Git tree entry is invalid") from exc
        if (
            mode not in {b"100644", b"100755"} or kind != b"blob"
            or re.fullmatch(rb"[0-9a-f]{40}", object_sha) is None
        ):
            raise RuntimeError("trusted native base Git tree contains an unsafe entry")
        relative = Path(os.fsdecode(raw_path))
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise RuntimeError("trusted native base Git tree contains an unsafe path")
        source = root / relative
        if (
            source.is_symlink() or not source.is_file()
            or source.resolve(strict=True) != source
            or not stat.S_ISREG(source.lstat().st_mode)
        ):
            raise RuntimeError(f"trusted native base source is unsafe: {relative}")
        before = source.stat()
        raw = source.read_bytes()
        after = source.stat()
        if len(raw) != before.st_size:
            raise RuntimeError(f"trusted native base source changed during read: {relative}")
        # The committed .gitattributes checks PowerShell files out as CRLF.
        # Compare their canonical LF projection; all executable Python and
        # policy files must match their Git objects byte for byte.
        canonical = raw.replace(b"\r\n", b"\n") if ps1_crlf and relative.suffix == ".ps1" else raw
        if ps1_crlf and relative.suffix == ".ps1" and b"\r" in canonical:
            raise RuntimeError(f"trusted native base source has unsafe EOL: {relative}")
        digest = hashlib.sha1(
            b"blob " + str(len(canonical)).encode("ascii") + b"\0" + canonical
        ).hexdigest()
        if (
            digest.encode("ascii") != object_sha
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
               != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise RuntimeError(f"trusted native base source differs from Git: {relative}")


def _native_verify_controller(
    trusted_root: Path, *, environment: dict[str, str]
) -> tuple[str, Path, Path]:
    _native_checkout_root(trusted_root, environment=environment)
    wrapper = trusted_root / "scripts/repository_delivery.py"
    controller = trusted_root / "scripts/repoctl.py"
    if Path(__file__).resolve() != wrapper:
        raise RuntimeError("native UAC wrapper is not executing from its trusted checkout")
    if trusted_root / "scripts" != (trusted_root / "scripts").resolve(strict=True):
        raise RuntimeError("native UAC scripts directory is redirected")
    base_sha, _ = _native_clean_checkout(
        trusted_root, environment=environment
    )
    for relative in _NATIVE_CONTROLLER_PATHS:
        _native_git_file_bytes(
            trusted_root, base_sha, relative, environment=environment
        )
    _native_verify_base_tree(trusted_root, base_sha, environment=environment)
    if _native_clean_checkout(trusted_root, environment=environment)[0] != base_sha:
        raise RuntimeError("trusted native base changed during verification")
    return base_sha, wrapper, controller


def _native_runner_manifest(
    target_root: Path, head_sha: str, *, environment: dict[str, str]
) -> str:
    manifest = bytearray()
    for relative in sorted(_NATIVE_RUNNER_PATHS):
        source = _native_git_file_bytes(
            target_root, head_sha, relative, environment=environment
        )
        manifest.extend(relative.encode("utf-8"))
        manifest.extend(b"\0")
        manifest.extend(hashlib.sha256(source).hexdigest().encode("ascii"))
        manifest.extend(b"\n")
    return hashlib.sha256(manifest).hexdigest()



def _native_with_environment(callback, environment: dict[str, str], *args, **kwargs):
    """Run base GitHub tools without inheriting caller host or loader overrides."""
    previous = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(environment)
        return callback(*args, **kwargs)
    finally:
        os.environ.clear()
        os.environ.update(previous)

def trusted_native_uac(
    trusted_root: Path,
    target_root: Path,
    action: str,
    campaign_id: str,
    expected_vm_id: str,
    pr_number: int | None,
    python_executable: str,
    *,
    head_sha: str = "",
    base_sha: str = "",
    runner_manifest_sha256: str = "",
    qualification_sha256: str = "",
) -> int:
    """Delegate native UAC only from the clean exact-base controller."""
    if action not in _NATIVE_ACTIONS:
        raise RuntimeError("unsupported trusted native UAC action")
    if re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}", campaign_id or "") is None:
        raise RuntimeError("trusted native UAC campaign ID is invalid")
    if action in {"Prepare", "SelfTest", "Verify"}:
        if re.fullmatch(
            r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}",
            expected_vm_id or "",
        ) is None:
            raise RuntimeError("trusted native UAC expected VM ID is invalid")
    elif expected_vm_id:
        raise RuntimeError("trusted native UAC expected VM ID is only valid for Prepare/SelfTest/Verify")
    if action != "Recover" and (type(pr_number) is not int or pr_number < 1):
        raise RuntimeError("trusted native UAC requires a positive PR number")
    if action == "Recover" and pr_number is not None and (type(pr_number) is not int or pr_number < 1):
        raise RuntimeError("trusted native recovery PR hint is invalid")
    verify_fields = (head_sha, base_sha, runner_manifest_sha256, qualification_sha256)
    if action == "Verify":
        if (
            re.fullmatch(r"[0-9a-f]{40}", head_sha) is None
            or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None
            or re.fullmatch(r"[0-9a-f]{64}", runner_manifest_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", qualification_sha256) is None
        ):
            raise RuntimeError("trusted native Verify binding is invalid")
    elif any(verify_fields):
        raise RuntimeError("trusted native Verify binding is only valid for Verify")

    environment = _native_child_environment()
    actual_base_sha, wrapper, controller = _native_verify_controller(
        trusted_root, environment=environment
    )
    _native_checkout_root(target_root, environment=environment)
    if target_root == trusted_root:
        raise RuntimeError("native UAC target and exact-base checkouts must differ")
    environment.update({
        "REPOCTL_TRUSTED_NATIVE_UAC": "1",
        "REPOCTL_TRUSTED_WRAPPER": str(wrapper),
        "REPOCTL_TRUSTED_CONTROLLER": str(controller),
        "REPOCTL_TRUSTED_POLICY_ROOT": str(trusted_root),
        "REPOCTL_TRUSTED_BASE_SHA": actual_base_sha,
        "REPOCTL_TRUSTED_TARGET_ROOT": str(target_root),
    })
    command = [
        python_executable, "-I", str(controller), _NATIVE_ACTIONS[action],
        "--campaign-id", campaign_id,
    ]
    if action == "Recover":
        environment["REPOCTL_TRUSTED_NATIVE_RECOVERY"] = "1"
    else:
        from exact_pr_binding import resolve_exact_open_pr, revalidate_exact_open_pr
        from managed_gh import resolve_managed_gh

        actual_head_sha, head_branch = _native_clean_checkout(
            target_root, environment=environment, require_branch=True
        )
        _native_verify_base_tree(target_root, actual_head_sha, environment=environment)
        gh = _native_with_environment(resolve_managed_gh, environment, trusted_root)
        binding = _native_with_environment(
            resolve_exact_open_pr, environment, _NATIVE_REPOSITORY,
            actual_head_sha, head_branch, "main", actual_base_sha, gh=gh[0],
        )
        if binding.pr_number != pr_number:
            raise RuntimeError("native UAC target does not match the requested PR")
        manifest = _native_runner_manifest(
            target_root, actual_head_sha, environment=environment
        )
        if action == "Verify":
            if (
                actual_head_sha != head_sha or actual_base_sha != base_sha
                or manifest != runner_manifest_sha256
            ):
                raise RuntimeError("trusted native Verify binding changed during UAC")
            command += [
                "--expected-vm-id", expected_vm_id,
                "--qualification-sha256", qualification_sha256,
            ]
        elif action in {"Prepare", "SelfTest"}:
            command += ["--expected-vm-id", expected_vm_id, "--trusted-root", str(trusted_root)]
        _native_verify_base_tree(target_root, actual_head_sha, environment=environment)
        if (
            _native_verify_controller(trusted_root, environment=environment)[0] != actual_base_sha
            or _native_clean_checkout(target_root, environment=environment, require_branch=True)
               != (actual_head_sha, head_branch)
            or _native_runner_manifest(
                target_root, actual_head_sha, environment=environment
            ) != manifest
            or _native_with_environment(resolve_managed_gh, environment, trusted_root) != gh
            or _native_with_environment(
                revalidate_exact_open_pr, environment, binding, gh=gh[0]
            ) != binding
        ):
            raise RuntimeError("native UAC exact PR/controller/runner binding changed")
        environment.update({
            "REPOCTL_TRUSTED_HEAD_SHA": actual_head_sha,
            "REPOCTL_TRUSTED_PR_NUMBER": str(pr_number),
            "REPOCTL_TRUSTED_NATIVE_RUNNER_MANIFEST_SHA256": manifest,
        })
    try:
        result = subprocess.run(
            command, cwd=target_root, env=environment, stdin=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError("trusted native controller could not start") from exc
    return result.returncode



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
        trusted_env["ECOMMERCE_EXECUTION_SCOPE"] = "isolated-delivery"
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


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    transition = subparsers.add_parser("trusted-pr-transition")
    transition.add_argument("--target-root", required=True)
    transition.add_argument("--pr", required=True, type=int)
    transition.add_argument("--dry-run", action="store_true")
    transition.add_argument("--json", action="store_true")
    native = subparsers.add_parser("trusted-native-uac")
    native.add_argument("--target-root", required=True)
    native.add_argument("--action", choices=tuple(_NATIVE_ACTIONS), required=True)
    native.add_argument("--campaign-id", required=True)
    native.add_argument("--expected-vm-id", default="")
    native.add_argument("--pr", type=int)
    native.add_argument("--head-sha", default="")
    native.add_argument("--base-sha", default="")
    native.add_argument("--runner-manifest-sha256", default="")
    native.add_argument("--qualification-sha256", default="")
    args = parser.parse_args()
    try:
        if args.command == "trusted-native-uac":
            if not sys.flags.isolated:
                raise RuntimeError("trusted native UAC requires Python isolated mode (-I)")
            return trusted_native_uac(
                Path(__file__).resolve().parents[1],
                Path(args.target_root),
                args.action,
                args.campaign_id,
                args.expected_vm_id,
                args.pr,
                sys.executable,
                head_sha=args.head_sha,
                base_sha=args.base_sha,
                runner_manifest_sha256=args.runner_manifest_sha256,
                qualification_sha256=args.qualification_sha256,
            )
        if args.command == "trusted-pr-transition":
            return trusted_pr_transition(
                Path(__file__).resolve().parents[1],
                Path(args.target_root),
                args.pr,
                sys.executable,
                dry_run=args.dry_run,
                json_output=args.json,
            )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"BLOCKED {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
