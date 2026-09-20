#!/usr/bin/env python3
"""Remove only reconstructible local RKE2 import state before fixture restaging."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ALLOWED = (
    Path("/var/lib/rancher/rke2/agent/containerd"),
    Path("/var/lib/rancher/rke2/agent/images"),
)


def clean(paths: tuple[Path, ...], allowed: tuple[Path, ...] = ALLOWED) -> list[str]:
    normalized_allowed = {path.resolve(strict=False) for path in allowed}
    removed = []
    for path in paths:
        resolved = path.resolve(strict=False)
        if resolved not in normalized_allowed:
            raise ValueError("refuse removing non-reconstructible fixture state")
        if resolved.exists():
            shutil.rmtree(resolved)
            removed.append(str(resolved))
    return removed


def main() -> None:
    print(json.dumps({"removed": clean(ALLOWED)}, sort_keys=True))


if __name__ == "__main__":
    main()
