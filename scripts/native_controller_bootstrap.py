#!/usr/bin/env python3
"""Verify and install the exact-SHA offline controller payload inside Rocky."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


class BootstrapError(RuntimeError):
    pass


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise BootstrapError(f"controller bootstrap timed out: {command[0]}") from exc
    if result.returncode:
        detail = " ".join((result.stderr or result.stdout).split())[-1000:]
        raise BootstrapError(f"controller bootstrap failed: {command[0]}: {detail}")
    return result.stdout.strip()


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise BootstrapError(f"regular controller input required: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_payload(payload_root: Path, expected_sha: str) -> dict:
    if payload_root.is_symlink() or not payload_root.is_dir():
        raise BootstrapError("controller payload is absent or a symlink")
    document = json.loads((payload_root / "payload.json").read_text(encoding="utf-8"))
    if document.get("schema") != 1 or document.get("source_sha") != expected_sha:
        raise BootstrapError("controller payload source SHA is stale")
    if document.get("source_branch") != "feat/packer-dual-host-rocky-image-pipeline":
        raise BootstrapError("controller payload branch differs from the PR")
    files = document.get("files")
    if not isinstance(files, dict) or len(files) < 5:
        raise BootstrapError("controller payload manifest is incomplete")
    for required in ("source.bundle", "bootstrap.py", "oras", "assets/rpm-keys/rocky-10-public.asc"):
        if required not in files:
            raise BootstrapError(f"controller payload omits required input: {required}")
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise BootstrapError("controller payload manifest entry is invalid")
        if Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in Path(relative).parts):
            raise BootstrapError(f"controller payload path is unsafe: {relative}")
        path = payload_root / relative
        if not path.resolve().is_relative_to(payload_root.resolve()) or digest(path) != expected:
            raise BootstrapError(f"controller payload checksum differs: {relative}")
    return document


def bootstrap(payload_root: Path, destination: Path, expected_sha: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise BootstrapError("invalid exact source SHA")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if not re.search(r'(?m)^ID="?rocky"?$', os_release) or not re.search(r'(?m)^VERSION_ID="?10\.2"?$', os_release):
        raise BootstrapError("controller OS is not pinned Rocky Linux 10.2")
    if sys.version_info[:2] != (3, 12):
        raise BootstrapError("controller Python is not the Rocky 10.2 Python 3.12 runtime")
    if "virtualbox" not in Path("/sys/class/dmi/id/product_name").read_text(encoding="utf-8").lower():
        raise BootstrapError("controller is not a VirtualBox guest")
    payload = verify_payload(payload_root, expected_sha)
    if destination.is_symlink() or destination != Path("/home/qualifier/native-qualification"):
        raise BootstrapError("controller runtime root is outside the owned home")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)

    rpm_root = payload_root / "assets/gitea-rpms"
    key_root = payload_root / "assets/rpm-keys"
    rpms = sorted(rpm_root.glob("*.rpm"))
    if len(rpms) < 2 or not (key_root / "rocky-10-public.asc").is_file():
        raise BootstrapError("locked Git and SSH RPM closure is incomplete")
    run(["sudo", "-n", "rpm", "--import", str(key_root / "rocky-10-public.asc")], timeout=60)
    run([
        "sudo", "-n", "dnf", "-y", "--disablerepo=*",
        "--setopt=localpkg_gpgcheck=1", "--setopt=install_weak_deps=False",
        "install", *map(str, rpms),
    ], timeout=900)

    repo = destination / "repo"
    if repo.exists():
        if repo.is_symlink() or run(["git", "rev-parse", "HEAD"], cwd=repo, timeout=60) != expected_sha:
            raise BootstrapError("existing controller repository is stale")
    else:
        run([
            "git", "clone", "--no-checkout", "-b", payload["source_branch"],
            str(payload_root / "source.bundle"), str(repo),
        ], timeout=600)
        run(["git", "checkout", payload["source_branch"]], cwd=repo, timeout=120)
        if run(["git", "rev-parse", "HEAD"], cwd=repo, timeout=60) != expected_sha:
            raise BootstrapError("controller checkout differs from the exact SHA")
    if run(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, timeout=60) != payload["source_tree"]:
        raise BootstrapError("controller source tree differs from payload")

    environment = repo / ".venv/qualification"
    if not environment.is_dir():
        run(["python3", "-m", "venv", str(environment)], timeout=120)
    python = environment / "bin/python"
    run([
        str(python), "-m", "pip", "install", "--no-index", "--require-hashes",
        "--find-links", str(payload_root / "wheels"),
        "-r", str(repo / "config/python/requirements.lock"),
    ], timeout=900)
    toolchain = json.loads((repo / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8"))
    ansible_version = toolchain["versions"]["ANSIBLE_CORE_VERSION"]
    version_output = run([str(environment / "bin/ansible-playbook"), "--version"], timeout=30)
    if not version_output.startswith(f"ansible-playbook [core {ansible_version}]"):
        raise BootstrapError("controller Ansible version differs from the source lock")

    cache = repo / ".context/cache/local-services-vm"
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists() or cache.is_symlink():
        if not cache.is_symlink() or cache.resolve() != (payload_root / "assets").resolve():
            raise BootstrapError("controller asset cache has an unexpected owner")
    else:
        cache.symlink_to(payload_root / "assets", target_is_directory=True)
    binary = environment / "bin/oras"
    if not binary.exists():
        shutil.copy2(payload_root / "oras", binary)
        binary.chmod(0o700)
    import yaml

    qualification = yaml.safe_load((repo / "config/contracts/local-services-qualification.yaml").read_text(encoding="utf-8"))
    expected_binary = qualification["runtime"]["native_controller"]["oras_binary_sha256"]
    if digest(binary) != expected_binary:
        raise BootstrapError("controller ORAS binary digest differs from the native controller contract")
    if "Version: 1.3.3" not in run([str(binary), "version"], timeout=30):
        raise BootstrapError("controller ORAS version differs from the source lock")
    return {"source_sha": expected_sha, "source_tree": payload["source_tree"], "ansible_core": ansible_version}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    result = bootstrap(args.payload, args.destination, args.source_sha)
    print(json.dumps({"status": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
