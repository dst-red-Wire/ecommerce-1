#!/usr/bin/env python3
"""Flip one byte in a staged fixture artifact and emit only its digests."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def mutate(path: Path, expected_parent: Path) -> dict[str, str]:
    expected_parent = expected_parent.resolve()
    resolved = path.resolve(strict=True)
    if expected_parent not in resolved.parents or not resolved.is_file():
        raise SystemExit("refuse mutating outside the staged fixture bundle")
    before = sha256(resolved)
    with resolved.open("r+b") as stream:
        stream.seek(-1, 2)
        final = stream.read(1)
        if not final:
            raise SystemExit("refuse mutating an empty artifact")
        stream.seek(-1, 2)
        stream.write(bytes((final[0] ^ 1,)))
    after = sha256(resolved)
    if before == after:
        raise SystemExit("artifact mutation did not change its digest")
    return {"after_sha256": after, "before_sha256": before}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("one staged artifact path is required")
    result = mutate(Path(sys.argv[1]), Path("/var/lib/ecommerce/bootstrap"))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
