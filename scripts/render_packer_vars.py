#!/usr/bin/env python3
"""Render non-secret Packer variables from the central machine-image contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

import yaml


def _digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def render(
    contract_path: Path,
    bundle: Path,
    build_public_key_file: Path,
    build_private_key_file: Path,
    output: Path,
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
    body = (
        f"iso_url      = {json.dumps(iso.resolve().as_uri())}\n"
        f"iso_checksum = {json.dumps(checksum)}\n"
        f"offline_bundle_dir = {json.dumps(str(bundle.resolve()))}\n"
        f"build_ssh_public_key = {json.dumps(public_key)}\n"
        f"build_ssh_private_key_file = {json.dumps(str(build_private_key_file.resolve()))}\n"
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
    args = parser.parse_args()
    render(
        args.contract.resolve(),
        args.bundle.resolve(),
        args.build_public_key_file.resolve(),
        args.build_private_key_file.resolve(),
        args.output.resolve(),
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
