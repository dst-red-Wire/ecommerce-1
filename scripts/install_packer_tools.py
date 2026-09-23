#!/usr/bin/env python3
"""Install and qualify centrally locked tools from a materialized Packer bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path


class ToolInstallError(RuntimeError):
    """Fail closed without executing network access."""


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def verify(entry: dict, artifact: Path) -> None:
    actual = digest(artifact)
    expected = entry["sha256"]
    if actual != expected:
        raise ToolInstallError(
            f"artifact={entry['file']} expected_version={entry['version']} "
            f"expected_sha256={expected} actual_sha256={actual}"
        )
    if entry["architecture"] != "amd64":
        raise ToolInstallError(
            f"artifact={entry['file']} expected architecture amd64, "
            f"got {entry['architecture']}"
        )


def _write_executable(source, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as output:
        shutil.copyfileobj(source, output)
    destination.chmod(0o755)


def install(entry: dict, artifact: Path) -> None:
    method = entry["install"]
    destination = Path("/usr/local/bin") / entry["binary"]
    if method["type"] == "binary":
        with artifact.open("rb") as source:
            _write_executable(source, destination)
    elif method["type"] == "archive":
        with tarfile.open(artifact, "r:*") as archive:
            member = archive.getmember(method["binary_relative"])
            if not member.isfile():
                raise ToolInstallError(
                    f"locked archive member is not a file: {member.name}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise ToolInstallError(
                    f"locked archive member is unreadable: {member.name}"
                )
            with source:
                _write_executable(source, destination)
    elif method["type"] == "rpm":
        subprocess.run(
            [
                "dnf",
                "-y",
                "--disablerepo=*",
                "--nogpgcheck",
                "install",
                os.fspath(artifact),
            ],
            check=True,
            timeout=300,
        )
    else:
        raise ToolInstallError(
            f"unsupported install type for {entry['name']}: {method['type']}"
        )


def qualify(entry: dict) -> None:
    result = subprocess.run(
        entry["version_command"],
        check=True,
        text=True,
        capture_output=True,
        timeout=30,
    )
    version_output = result.stdout + result.stderr
    if entry["version"] not in version_output:
        raise ToolInstallError(
            f"tool={entry['name']} expected_version={entry['version']} actual_version=unexpected"
        )
    qualification = entry.get("qualification")
    if qualification:
        if qualification.get("network") != "forbidden":
            raise ToolInstallError(
                f"tool={entry['name']} qualification network policy is not closed"
            )
        result = subprocess.run(
            qualification["command"],
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
            env={
                key: value
                for key, value in os.environ.items()
                if key not in {"GH_TOKEN", "GITHUB_TOKEN"}
            },
        )
        output = result.stdout + result.stderr
        missing = [
            value for value in qualification["stdout_contains"] if value not in output
        ]
        if missing:
            raise ToolInstallError(
                f"tool={entry['name']} missing capabilities: {missing}"
            )


def install_profile(bundle: Path, profile: str) -> None:
    root = bundle / "tools" / profile
    entries = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for entry in entries:
        artifact = root / entry["file"]
        verify(entry, artifact)
        install(entry, artifact)
        qualify(entry)


def qualify_rpm_profile(bundle: Path, profile: str) -> None:
    definition = json.loads(
        (bundle / "rpms" / profile / "manifest.json").read_text(encoding="utf-8")
    )
    packages = {entry["package"]: entry for entry in definition["packages"]}
    for package in definition["roots"]:
        entry = packages[package]
        expected = f"{entry['epoch']}:{entry['version']}-{entry['release']}.{entry['architecture']}"
        result = subprocess.run(
            ["rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", package],
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
        )
        actual = result.stdout.strip()
        if actual != expected:
            raise ToolInstallError(
                f"package={package} expected_version={expected} actual_version={actual}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--profile", choices=("base", "admin-qualification"))
    selection.add_argument(
        "--rpm-profile",
        choices=("base", "qemu-kvm", "admin-qualification"),
    )
    args = parser.parse_args()
    if args.profile:
        install_profile(args.bundle.resolve(), args.profile)
    else:
        qualify_rpm_profile(args.bundle.resolve(), args.rpm_profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
