#!/usr/bin/env python3
"""Render non-secret Packer variables from the central machine-image contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml


def _digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _windows_path(path: Path) -> str:
    rendered = subprocess.check_output(
        ["wslpath", "-w", str(path)], text=True, timeout=15
    ).strip()
    if not re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", rendered):
        raise ValueError("Packer Windows staging path is not a local drive path")
    return rendered


def render(
    contract_path: Path,
    bundle: Path,
    build_public_key_file: Path,
    build_private_key_file: Path,
    output: Path,
    *,
    target_platform: str = "linux",
    artifact_dir: Path | None = None,
) -> None:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    image = contract["packer_image"]
    source = image["source"]
    if image["id"] != "rocky-10.2-base" or source.get("mutable_aliases") != "forbidden":
        raise ValueError("unsupported or mutable Packer image contract")
    checksum = str(source["sha256"])
    if len(checksum) != 64 or any(
        character not in "0123456789abcdef" for character in checksum
    ):
        raise ValueError("Packer ISO SHA256 is invalid")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("output must be a new path below an existing directory")
    iso = bundle / "iso" / source["iso"]
    required = (
        iso,
        bundle / "evidence.json",
        bundle / "rpms/base/SHA256SUMS",
        bundle / "tools/base/SHA256SUMS",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise ValueError(f"incomplete offline Packer bundle: {missing}")
    if _digest(iso) != checksum:
        raise ValueError("offline Packer ISO digest mismatch")
    if not build_public_key_file.is_file() or not build_private_key_file.is_file():
        raise ValueError("temporary Packer SSH key pair is incomplete")
    public_key = build_public_key_file.read_text(encoding="utf-8").strip()
    if (
        re.fullmatch(
            r"ssh-(?:ed25519|rsa) [A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9._@-]+)?",
            public_key,
        )
        is None
    ):
        raise ValueError("temporary Packer SSH public key is invalid")
    if target_platform == "windows":
        if artifact_dir is None or not artifact_dir.is_dir():
            raise ValueError("Windows Packer artifact directory must already exist")
        iso_path = _windows_path(iso.resolve())
        iso_url = "file:///" + iso_path.replace("\\", "/")
        bundle_path = _windows_path(bundle.resolve())
        private_key_path = _windows_path(build_private_key_file.resolve())
        artifact_path = _windows_path(artifact_dir.resolve())
    elif target_platform == "linux":
        if artifact_dir is None:
            artifact_dir = output.parent / "artifacts"
            artifact_dir.mkdir(exist_ok=True)
        iso_url = iso.resolve().as_uri()
        bundle_path = str(bundle.resolve())
        private_key_path = str(build_private_key_file.resolve())
        artifact_path = str(artifact_dir.resolve())
    else:
        raise ValueError(f"unsupported Packer target platform: {target_platform}")
    body = (
        f"iso_url      = {json.dumps(iso_url)}\n"
        f"iso_checksum = {json.dumps(checksum)}\n"
        f"offline_bundle_dir = {json.dumps(bundle_path)}\n"
        f"artifact_dir = {json.dumps(artifact_path)}\n"
        f"build_ssh_public_key = {json.dumps(public_key)}\n"
        f"build_ssh_private_key_file = {json.dumps(private_key_path)}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=output.name + ".",
        delete=False,
    ) as temporary:
        temporary.write(body)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--build-public-key-file", required=True, type=Path)
    parser.add_argument("--build-private-key-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--target-platform", choices=("linux", "windows"), default="linux"
    )
    parser.add_argument("--artifact-dir", type=Path)
    args = parser.parse_args()
    render(
        args.contract.resolve(),
        args.bundle.resolve(),
        args.build_public_key_file.resolve(),
        args.build_private_key_file.resolve(),
        args.output.resolve(),
        target_platform=args.target_platform,
        artifact_dir=args.artifact_dir.resolve() if args.artifact_dir else None,
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
