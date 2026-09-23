#!/usr/bin/env python3
"""Render non-secret Packer variables from the central machine-image contract."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import yaml


def render(contract_path: Path, output: Path) -> None:
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    image = contract["packer_image"]
    source = image["source"]
    if image["id"] != "rocky-10.2-base" or source.get("mutable_aliases") != "forbidden":
        raise ValueError("unsupported or mutable Packer image contract")
    checksum = str(source["sha256"])
    if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
        raise ValueError("Packer ISO SHA256 is invalid")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("output must be a new path below an existing directory")
    body = (
        f"iso_url      = {json.dumps(str(source['url']))}\n"
        f"iso_checksum = {json.dumps(checksum)}\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, prefix=output.name + ".", delete=False,
    ) as temporary:
        temporary.write(body)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    render(args.contract.resolve(), args.output.resolve())
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
