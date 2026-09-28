#!/usr/bin/env python3
"""Enforce the canonical Windows workspace rule before repository operations."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_POLICY = {
    "status": "enforced",
    "execution": "wsl2",
    "repository_filesystem": "native-linux",
    "windows_mounts": "forbidden",
    "scope": "all-repository-operations",
}
NATIVE_FILESYSTEMS = frozenset({"ext4", "btrfs", "xfs"})


def workspace_error(
    root: Path = ROOT,
    *,
    platform: str | None = None,
    kernel_release: str | None = None,
    filesystem: str | None = None,
) -> str | None:
    """Return a reason when a Windows workstation uses an unsupported checkout."""
    try:
        policy = yaml.safe_load((root / "architecture.lock.yaml").read_text(encoding="utf-8"))
        actual = policy["repository_governance"]["windows_workspace"]
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        return "canonical Windows workspace policy is unavailable"
    if actual != EXPECTED_POLICY:
        return "canonical Windows workspace policy drift"

    current_platform = platform or sys.platform
    if current_platform == "win32":
        return "run repository operations in WSL2 from a native Linux checkout"
    if current_platform != "linux":
        return None

    try:
        release = kernel_release if kernel_release is not None else Path("/proc/sys/kernel/osrelease").read_text()
    except OSError:
        return "cannot identify the Linux kernel"
    if "microsoft" not in release.lower() and "wsl" not in release.lower():
        return None

    if filesystem is None:
        try:
            resolved = str(root.resolve())
            mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        except OSError:
            return "cannot identify the checkout filesystem"
        best_length = -1
        for line in mounts:
            before, separator, after = line.partition(" - ")
            if not separator:
                continue
            fields = before.split()
            details = after.split()
            if len(fields) < 5 or not details:
                continue
            mount_point = fields[4].replace(r"\040", " ")
            if resolved == mount_point or resolved.startswith(mount_point.rstrip("/") + "/"):
                if len(mount_point) > best_length:
                    best_length = len(mount_point)
                    filesystem = details[0]
        if filesystem is None:
            return "cannot identify the checkout filesystem"
    if filesystem not in NATIVE_FILESYSTEMS:
        return f"WSL2 checkout must use a native Linux filesystem; found {filesystem or 'unknown'}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    error = workspace_error()
    if error:
        if not args.quiet:
            print(f"FAIL workspace: {error}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"PASS native workspace {ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
