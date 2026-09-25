#!/usr/bin/env python3
"""Fail closed on host interpolation and shell syntax before VM qualification."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WINDOWS_SOURCES = (
    (ROOT / "scripts/windows/native-vtx-cycle.ps1", "Invoke-VagrantSmokeCommand", 16),
    (ROOT / "scripts/windows/qualify-rocky-image.ps1", "Invoke-SmokeCommand", 10),
)


class GuestSmokePreflightError(RuntimeError):
    """A guest check cannot safely be sent to its intended shell."""


def _check_bash(command: str, owner: str) -> None:
    try:
        result = subprocess.run(
            ["bash", "-n", "-c", command],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuestSmokePreflightError(f"bash syntax preflight unavailable: {owner}") from exc
    if result.returncode:
        raise GuestSmokePreflightError(f"invalid guest shell syntax: {owner}: {result.stderr.strip()}")


def _windows_commands() -> list[tuple[str, str]]:
    commands: list[tuple[str, str]] = []
    literal = re.compile(r"-Command \(?'((?:''|[^'])*)'")
    for path, invocation, expected in WINDOWS_SOURCES:
        lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if invocation in line and "-Command " in line
        ]
        if len(lines) != expected:
            raise GuestSmokePreflightError(f"guest check inventory changed: {path.name}")
        for line in lines:
            owner = f"{path.name}:{invocation}"
            if '-Command ("rpm -q " + ($packages -join' in line:
                if path.name != "native-vtx-cycle.ps1" or not line.strip().endswith(
                    '-Command ("rpm -q " + ($packages -join \' \'))'
                ):
                    raise GuestSmokePreflightError(f"unexpected dynamic guest command: {owner}")
                commands.append((owner, "rpm -q bash"))  # Package names are allowlisted before use.
                continue
            match = literal.search(line)
            if match is None or '-Command "' in line:
                raise GuestSmokePreflightError(f"guest command is not a PowerShell literal: {owner}")
            command = match.group(1).replace("''", "'").replace("{0}", "34359738368")
            commands.append((owner, command))
    return commands


def _python_commands(path: Path, *, dict_name: str | None = None) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    commands: list[tuple[str, str]] = []
    found_dict = False
    for node in ast.walk(tree):
        if dict_name and isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and any(
            isinstance(target, ast.Name) and target.id == dict_name for target in node.targets
        ):
            found_dict = True
            try:
                checks = ast.literal_eval(node.value)
            except (ValueError, TypeError) as exc:
                raise GuestSmokePreflightError(f"guest checks are not literal: {path.name}") from exc
            if not isinstance(checks, dict) or len(checks) < 9:
                raise GuestSmokePreflightError(f"guest check inventory is incomplete: {path.name}")
            commands.extend((f"{path.name}:{name}", value) for name, value in checks.items())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ssh_command":
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    value = argument.value
                    if value.startswith(("rpm -qa --qf ", "cloud-init status --wait ")):
                        commands.append((f"{path.name}:ssh_command", value))
    if not commands or (dict_name and not found_dict):
        raise GuestSmokePreflightError(f"guest check inventory is absent: {path.name}")
    return commands


def validate_guest_smoke_commands() -> int:
    commands = _windows_commands()
    commands.extend(_python_commands(ROOT / "scripts/linux_image_pipeline.py", dict_name="checks"))
    commands.extend(_python_commands(ROOT / "scripts/local_services_qualification.py"))
    for owner, command in commands:
        if not isinstance(command, str):
            raise GuestSmokePreflightError(f"guest command is not text: {owner}")
        _check_bash(command, owner)
    return len(commands)


if __name__ == "__main__":
    try:
        count = validate_guest_smoke_commands()
    except GuestSmokePreflightError as exc:
        print(f"FAIL guest-smoke-preflight: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"PASS guest-smoke-preflight commands={count}")
