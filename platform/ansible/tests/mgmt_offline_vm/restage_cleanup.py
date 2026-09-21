#!/usr/bin/env python3
"""Remove only reconstructible local RKE2 import state before fixture restaging."""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

ALLOWED = (
    Path("/var/lib/rancher/rke2/agent/images"),
)


def clean(paths: tuple[Path, ...], allowed: tuple[Path, ...] = ALLOWED) -> list[str]:
    normalized_allowed = {Path(os.path.abspath(path)) for path in allowed}
    removed = []
    for path in paths:
        lexical = Path(os.path.abspath(path))
        if lexical not in normalized_allowed:
            raise ValueError("refuse removing non-reconstructible fixture state")
        for entry in (lexical, *lexical.parents):
            try:
                mode = entry.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                raise ValueError("refuse removing through a symbolic link")
        if lexical.exists():
            shutil.rmtree(lexical)
            removed.append(str(lexical))
    return removed


def main() -> None:
    print(json.dumps({"removed": clean(ALLOWED)}, sort_keys=True))


if __name__ == "__main__":
    main()
