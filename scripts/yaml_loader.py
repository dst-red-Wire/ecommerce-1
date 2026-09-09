"""Dependency-free YAML loading through the repository's required Ruby runtime."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any


def load_yaml(path: Path) -> Any:
    script = "d=YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false) || {}; print JSON.generate(d)"
    output = subprocess.check_output(
        ["ruby", "-ryaml", "-rjson", "-e", script, str(path)],
        text=True,
    )
    return json.loads(output)
