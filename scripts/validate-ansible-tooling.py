#!/usr/bin/env python3
"""Fail unless the active Python environment matches exact Ansible pins."""

from __future__ import annotations

import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements/ansible.txt"


def fail(message: str) -> None:
    raise SystemExit(f"Ansible tooling invalid: {message}")


if sys.version_info < (3, 12):
    fail("Python 3.12 or newer is required by the pinned ansible-core")

pins: dict[str, str] = {}
for line_number, raw_line in enumerate(
    REQUIREMENTS.read_text(encoding="utf-8").splitlines(), start=1
):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    match = re.fullmatch(r"([a-z0-9][a-z0-9-]*)==([A-Za-z0-9][A-Za-z0-9.+-]*)", line)
    if not match:
        fail(f"line {line_number} must be an exact package==version pin")
    package, version = match.groups()
    if package in pins:
        fail(f"duplicate package pin: {package}")
    pins[package] = version

for required_package in ("ansible-core", "ansible-lint"):
    if required_package not in pins:
        fail(f"missing exact pin for {required_package}")

for package, expected_version in pins.items():
    try:
        actual_version = importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        fail(f"{package} is not installed in {sys.prefix}")
    if actual_version != expected_version:
        fail(
            f"{package} version is {actual_version}, expected {expected_version} "
            f"from {REQUIREMENTS.relative_to(ROOT)}"
        )

dependency_check = subprocess.run(
    [sys.executable, "-m", "pip", "check"],
    cwd=ROOT,
    check=False,
    capture_output=True,
    text=True,
)
if dependency_check.returncode != 0:
    fail("the pinned environment has incompatible Python dependencies")

print(
    "Ansible tooling: valid "
    f"(ansible-core {pins['ansible-core']}, ansible-lint {pins['ansible-lint']})"
)
