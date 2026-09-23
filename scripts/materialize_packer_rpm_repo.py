#!/usr/bin/env python3
"""Materialize the checksum-locked RPM input consumed by the Rocky Packer build."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path


class MaterializationError(ValueError):
    """Bounded failure without artifact content in diagnostics."""


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def download(url: str, destination: Path, expected: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ecommerce-packer-rpm-materializer/1"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output, length=1024 * 1024)
    if digest(destination) != expected:
        raise MaterializationError("downloaded artifact digest mismatch")


def materialize(lock_path: Path, output: Path) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("image") != "rocky-10.2-base" or lock.get("dependency_closure") != "complete":
        raise MaterializationError("invalid Rocky image package lock")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise MaterializationError("output must be a new path below an existing directory")
    entries = [*lock.get("rpm_signing_keys", []), *lock.get("packages", [])]
    if not entries:
        raise MaterializationError("empty Rocky image package lock")
    names = [entry.get("file") for entry in entries]
    if len(names) != len(set(names)) or any(not isinstance(name, str) or Path(name).name != name for name in names):
        raise MaterializationError("unsafe or duplicate locked filename")
    with tempfile.TemporaryDirectory(prefix=output.name + ".", dir=output.parent) as temporary:
        staging = Path(temporary)
        packages = staging / "packages"
        keys = staging / "keys"
        packages.mkdir()
        keys.mkdir()
        for entry in lock["rpm_signing_keys"]:
            download(entry["url"], keys / entry["file"], entry["sha256"])
        for entry in lock["packages"]:
            download(entry["url"], packages / entry["file"], entry["sha256"])
        evidence = {
            "image": lock["image"],
            "package_lock_sha256": digest(lock_path),
            "packages": len(lock["packages"]),
        }
        (staging / "evidence.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8",
        )
        os.replace(staging, output)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(materialize(args.lock.resolve(), args.output.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
