#!/usr/bin/env python3
"""Publish a merged trusted runner image; never activate runner authority.

The image transport round trip is observable here. Formal runner activation
still requires an independent verifier of all three runtime proofs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPOSITORY = "dst-red-Wire/ecommerce-1"
ORIGIN_URL = "https://github.com/dst-red-Wire/ecommerce-1.git"
IMAGE_REPOSITORY = "harbor.ecommerce.local/ecommerce/runner-authority"
BASE_REFERENCE = (
    "docker.io/library/python:3.12-slim-bookworm@"
    "sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4"
)
SOURCE_PATHS = (
    "platform/runner/Containerfile",
    "scripts/runner_authority.py",
    "scripts/runner_budget.py",
    "scripts/runner_rbac.py",
    "config/contracts/qualification-execution-policy.yaml",
    "config/contracts/toolchain-lock.json",
)
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
FROM_RE = re.compile(r"^FROM ([^\s]+)$", re.MULTILINE)
PUSH_DIGEST_RE = re.compile(
    r"(?m)^.*\bdigest:\s*(sha256:[0-9a-f]{64})\s+size:\s*\d+\s*$"
)
INSPECT_DIGEST_RE = re.compile(r"(?m)^Digest:\s*(sha256:[0-9a-f]{64})\s*$")
CommandExecutor = Callable[
    [list[str], Path | None, int], subprocess.CompletedProcess[bytes]
]


class RuntimeBlocked(Exception):
    """A required independent runtime observation is absent or inconsistent."""


def _default_executor(
    command: list[str], cwd: Path | None, timeout: int
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    if command[0] == "git":
        for key in tuple(environment):
            if key.startswith("GIT_"):
                environment.pop(key)
        environment.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_NO_REPLACE_OBJECTS="1",
            GIT_TERMINAL_PROMPT="0",
        )
    elif command[0] == "gh":
        environment["GH_HOST"] = "github.com"
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _run(
    executor: CommandExecutor,
    command: list[str],
    *,
    label: str,
    cwd: Path | None = None,
    timeout: int = 30,
    max_output: int = 4_000_000,
) -> bytes:
    try:
        result = executor(command, cwd, timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeBlocked(f"{label} is unavailable") from exc
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise RuntimeBlocked(f"{label} failed")
    if len(result.stdout) > max_output:
        raise RuntimeBlocked(f"{label} output is oversized")
    return result.stdout


def _git(executor: CommandExecutor, root: Path, *args: str) -> bytes:
    return _run(
        executor,
        [
            "git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            *args,
        ],
        label="exact Git source check",
        cwd=Path("/"),
    )


def _sha(value: str, label: str) -> str:
    if SHA_RE.fullmatch(value) is None:
        raise RuntimeBlocked(f"{label} is not a full commit SHA")
    return value


def _digest(value: str, label: str) -> str:
    if DIGEST_RE.fullmatch(value) is None:
        raise RuntimeBlocked(f"{label} is not an immutable digest")
    return value


def _github_main(executor: CommandExecutor) -> str:
    raw = _run(
        executor,
        ["gh", "api", f"repos/{REPOSITORY}/git/ref/heads/main"],
        label="GitHub main observation",
        cwd=Path("/"),
        max_output=1_000_000,
    )
    try:
        payload = json.loads(raw)
        if (
            not isinstance(payload, dict)
            or payload.get("ref") != "refs/heads/main"
            or not isinstance(payload.get("object"), dict)
            or payload["object"].get("type") != "commit"
        ):
            raise ValueError("unexpected GitHub ref")
        return _sha(payload["object"].get("sha"), "GitHub main")
    except (TypeError, ValueError) as exc:
        raise RuntimeBlocked("GitHub main response is invalid") from exc


def _preflight(executor: CommandExecutor, root: Path) -> str:
    if not root.is_absolute() or root.is_symlink():
        raise RuntimeBlocked("checkout must be an absolute non-symlink directory")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RuntimeBlocked("checkout is unavailable") from exc
    if resolved != root or not root.is_dir():
        raise RuntimeBlocked("checkout path is redirected")
    if _git(executor, root, "rev-parse", "--show-toplevel").decode().strip() != str(
        root
    ):
        raise RuntimeBlocked("Git checkout root differs")
    if (
        _git(executor, root, "symbolic-ref", "--quiet", "--short", "HEAD")
        .decode()
        .strip()
        != "main"
    ):
        raise RuntimeBlocked("publisher requires checked-out main")
    if (
        _git(executor, root, "remote", "get-url", "origin").decode().strip()
        != ORIGIN_URL
    ):
        raise RuntimeBlocked("origin is not the canonical GitHub repository")
    if _git(executor, root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeBlocked("checkout is not clean")
    head = _sha(
        _git(executor, root, "rev-parse", "HEAD").decode().strip(), "local HEAD"
    )
    local_main = _sha(
        _git(executor, root, "rev-parse", "refs/remotes/origin/main").decode().strip(),
        "local origin/main",
    )
    remote_lines = (
        _git(executor, root, "ls-remote", "origin", "refs/heads/main")
        .decode()
        .splitlines()
    )
    if len(remote_lines) != 1:
        raise RuntimeBlocked("remote main is ambiguous")
    fields = remote_lines[0].split()
    if len(fields) != 2 or fields[1] != "refs/heads/main":
        raise RuntimeBlocked("remote main response is invalid")
    remote_main = _sha(fields[0], "remote main")
    github_main = _github_main(executor)
    if len({head, local_main, remote_main, github_main}) != 1:
        raise RuntimeBlocked("local HEAD, origin/main and observed GitHub main differ")
    return head


def _stage_source(
    executor: CommandExecutor, root: Path, sha: str, destination: Path
) -> dict[str, str]:
    digests: dict[str, str] = {}
    for relative in SOURCE_PATHS:
        entry = _git(executor, root, "ls-tree", "--full-tree", sha, "--", relative)
        match = re.fullmatch(
            rb"(100644|100755) blob [0-9a-f]{40,64}\t"
            + re.escape(relative.encode())
            + rb"\n",
            entry,
        )
        if match is None:
            raise RuntimeBlocked(
                f"approved source file is absent or not regular: {relative}"
            )
        data = _run(
            executor,
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                "show",
                f"{sha}:{relative}",
            ],
            label=f"approved source bytes for {relative}",
            cwd=Path("/"),
            max_output=2_000_000,
        )
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
        if relative != "platform/runner/Containerfile":
            digests[f"/opt/runner/{relative}"] = hashlib.sha256(data).hexdigest()
    return digests


def _inspect_digest(output: bytes, label: str) -> str:
    matches = INSPECT_DIGEST_RE.findall(output.decode("utf-8", errors="replace"))
    if len(matches) != 1:
        raise RuntimeBlocked(f"{label} digest is absent or ambiguous")
    return _digest(matches[0], label)


def _verify_base(executor: CommandExecutor, containerfile: Path) -> None:
    recipe = containerfile.read_text(encoding="utf-8")
    references = FROM_RE.findall(recipe)
    if references != [BASE_REFERENCE] or ":latest" in recipe:
        raise RuntimeBlocked("Containerfile base is not the reviewed immutable digest")
    observed = _inspect_digest(
        _run(
            executor,
            ["docker", "buildx", "imagetools", "inspect", BASE_REFERENCE],
            label="pinned base registry readback",
            timeout=60,
        ),
        "pinned base",
    )
    if observed != BASE_REFERENCE.rsplit("@", 1)[1]:
        raise RuntimeBlocked("pinned base registry digest differs")


def _local_image_config(executor: CommandExecutor, tag: str, sha: str) -> None:
    raw = _run(
        executor,
        ["docker", "image", "inspect", "--format", "{{json .Config}}", tag],
        label="locally built image inspection",
    )
    try:
        config = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeBlocked("locally built image configuration is invalid") from exc
    if (
        not isinstance(config, dict)
        or config.get("User") != "10001:10001"
        or not isinstance(config.get("Labels"), dict)
        or config["Labels"].get("org.opencontainers.image.revision") != sha
    ):
        raise RuntimeBlocked("local image user or source label differs")


def _push_digest(output: bytes) -> str:
    matches = set(PUSH_DIGEST_RE.findall(output.decode("utf-8", errors="replace")))
    if len(matches) != 1:
        raise RuntimeBlocked("Docker push did not report one immutable digest")
    return _digest(matches.pop(), "push expected")


def _pulled_digest(executor: CommandExecutor, reference: str) -> str:
    raw = _run(
        executor,
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", reference],
        label="pulled image RepoDigests inspection",
    )
    try:
        refs = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeBlocked("pulled RepoDigests are invalid") from exc
    if (
        not isinstance(refs, list)
        or reference not in refs
        or any(not isinstance(item, str) for item in refs)
    ):
        raise RuntimeBlocked("pulled RepoDigests lack the exact Harbor reference")
    observed = next(item for item in refs if item == reference)
    return _digest(observed.rsplit("@", 1)[1], "pulled image")


def _smoke(
    executor: CommandExecutor, reference: str, expected_files: dict[str, str]
) -> None:
    paths = json.dumps(sorted(expected_files))
    code = (
        "import hashlib,json,os; from pathlib import Path; "
        "from scripts import runner_authority,runner_budget,runner_rbac; "
        f"paths={paths}; "
        "print(json.dumps({'uid':os.getuid(),'digests':"
        "{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}}))"
    )
    raw = _run(
        executor,
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=10001:10001",
            "--pids-limit=32",
            "--memory=128m",
            "--cpus=1",
            "--entrypoint",
            "python3",
            reference,
            "-B",
            "-c",
            code,
        ],
        label="digest-pulled image smoke",
        timeout=60,
        max_output=1_000_000,
    )
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeBlocked("digest-pulled image smoke response is invalid") from exc
    if payload != {"uid": 10001, "digests": expected_files}:
        raise RuntimeBlocked("digest-pulled image bytes or non-root identity differ")


def publish_merged_runner(
    root: Path, executor: CommandExecutor = _default_executor
) -> dict[str, Any]:
    """Attempt image transport only; formal authority remains NOT_ACTIVE."""
    report: dict[str, Any] = {
        "status": "BLOCKED_RUNTIME",
        "runner_authority": "NOT_ACTIVE",
        "formal_proof": False,
        "image_transport_status": "BLOCKED_RUNTIME",
        "source_sha": None,
        "tag_reference": None,
        "digest_reference": None,
        "expected_digest": None,
        "registry_digest": None,
        "pulled_digest": None,
    }
    try:
        root = Path(root)
        sha = _preflight(executor, root)
        report["source_sha"] = sha
        tag = f"{IMAGE_REPOSITORY}:sha-{sha}"
        report["tag_reference"] = tag
        with tempfile.TemporaryDirectory(prefix="runner-image-approved-") as temporary:
            context = Path(temporary)
            expected_files = _stage_source(executor, root, sha, context)
            _verify_base(executor, context / "platform/runner/Containerfile")
            _run(
                executor,
                [
                    "docker",
                    "buildx",
                    "build",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "none",
                    "--provenance=false",
                    "--file",
                    str(context / "platform/runner/Containerfile"),
                    "--tag",
                    tag,
                    "--build-arg",
                    f"AUTHORITY_SOURCE_SHA={sha}",
                    "--load",
                    str(context),
                ],
                label="approved exact-SHA image build",
                timeout=900,
            )
            _local_image_config(executor, tag, sha)
            if _preflight(executor, root) != sha:
                raise RuntimeBlocked("GitHub main changed before Harbor push")
            expected = _push_digest(
                _run(
                    executor,
                    ["docker", "push", tag],
                    label="Harbor image push",
                    timeout=600,
                )
            )
            report["expected_digest"] = expected
            registry = _inspect_digest(
                _run(
                    executor,
                    ["docker", "buildx", "imagetools", "inspect", tag],
                    label="Harbor registry digest readback",
                    timeout=60,
                ),
                "Harbor registry",
            )
            report["registry_digest"] = registry
            if expected != registry:
                raise RuntimeBlocked("expected and Harbor registry digests differ")
            reference = f"{IMAGE_REPOSITORY}@{expected}"
            report["digest_reference"] = reference
            _run(
                executor,
                ["docker", "pull", reference],
                label="immutable Harbor digest pull",
                timeout=300,
            )
            pulled = _pulled_digest(executor, reference)
            report["pulled_digest"] = pulled
            if expected != pulled:
                raise RuntimeBlocked("expected and pulled RepoDigests differ")
            _smoke(executor, reference, expected_files)
            if _preflight(executor, root) != sha:
                raise RuntimeBlocked("GitHub main changed during image round trip")
        report["image_transport_status"] = "PASS"
        report["detail"] = (
            "expected=registry=pulled and image smoke passed; "
            "independent aggregate runtime proof verifier is unavailable"
        )
    except RuntimeBlocked as exc:
        report["detail"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - no unexpected error may issue PASS
        report["detail"] = f"publisher failed closed: {type(exc).__name__}"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish-after-merge", action="store_true", required=True)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args(argv)
    report = publish_merged_runner(args.root)
    print(json.dumps(report, sort_keys=True))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
