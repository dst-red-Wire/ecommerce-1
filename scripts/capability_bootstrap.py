#!/usr/bin/env python3
"""Capability-aware, dependency-scoped developer environment reconciliation."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/toolchain/capabilities.json"
VERSIONS = ROOT / "config/toolchain/versions.env"
STATES = {"PASS", "FAIL", "BLOCKED", "SKIP", "UNSUPPORTED"}


@dataclass(frozen=True)
class Result:
    state: str
    detail: str = ""


def load_versions(path: Path = VERSIONS) -> dict[str, str]:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if key in values:
                raise ValueError(f"duplicate version authority: {key}")
            values[key] = value
    return values


def load_contract(path: Path = CONTRACT) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalized_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str, str]:
    os_name = (system or platform.system()).lower()
    os_name = {"macos": "darwin"}.get(os_name, os_name)
    arch = (machine or platform.machine()).lower()
    arch = {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    context = os.environ.get("BOOTSTRAP_CONTEXT", "")
    if not context:
        release = platform.release().lower()
        context = "wsl2" if os_name == "linux" and "microsoft" in release else ("ci" if os.environ.get("CI") else "native")
    return os_name, arch, context


class Graph:
    def __init__(self, capabilities: list[dict]):
        self.items = {item["name"]: item for item in capabilities}
        if len(self.items) != len(capabilities):
            raise ValueError("duplicate capability")
        for name, item in self.items.items():
            dependencies = item.get("requires", []) + item.get("provision_requires", [])
            missing = set(dependencies) - self.items.keys()
            if missing:
                raise ValueError(f"{name}: missing dependencies: {', '.join(sorted(missing))}")

    def order(self) -> list[str]:
        marks: dict[str, int] = {}
        result: list[str] = []

        def visit(name: str, trail: list[str]) -> None:
            if marks.get(name) == 1:
                raise ValueError("capability cycle: " + " -> ".join(trail + [name]))
            if marks.get(name) == 2:
                return
            marks[name] = 1
            dependencies = self.items[name].get("requires", []) + self.items[name].get("provision_requires", [])
            for dependency in dependencies:
                visit(dependency, trail + [name])
            marks[name] = 2
            result.append(name)

        for name in self.items:
            visit(name, [])
        return result


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


class Auditor:
    def __init__(self, contract: dict, *, runner: Runner = default_runner, which: Callable[[str], str | None] = shutil.which):
        self.contract = contract
        self.graph = Graph(contract["capabilities"])
        self.runner = runner
        self.which = which
        self.versions = load_versions()

    def platform_result(self, os_name: str, arch: str) -> Result | None:
        if os_name not in self.contract["supported"]["os"]:
            return Result("UNSUPPORTED", f"os {os_name}")
        if arch not in self.contract["supported"]["arch"]:
            return Result("UNSUPPORTED", f"architecture {arch}")
        return None

    def check(self, item: dict) -> Result:
        if item.get("virtual"):
            return Result("PASS", "dependencies ready")
        command = item.get("command")
        argv = item.get("probe") or ([command, *item.get("version_args", [])] if command else [])
        resolved = self.which(command) if command else None
        managed = Path.home() / ".local" / "bin" / str(command)
        if command and item.get("provision") and managed.is_file():
            resolved = str(managed)
        if command and not resolved:
            return Result("FAIL", "tool absent")
        if command and argv and argv[0] == command:
            argv = [str(resolved), *argv[1:]]
        proc = self.runner(argv)
        detail = " ".join((proc.stdout or proc.stderr).strip().split())
        if proc.returncode:
            return Result("BLOCKED" if item.get("external_failure") else "FAIL", detail or f"exit {proc.returncode}")
        expected = self.versions.get(item.get("version_key", ""))
        version_file = item.get("version_file")
        if version_file:
            expected = (ROOT / version_file).read_text(encoding="utf-8").strip()
        if expected and expected not in detail:
            return Result("FAIL", f"wrong version: expected {expected}; got {detail or 'unknown'}")
        return Result("PASS", detail or "ready")

    def provision(self, item: dict) -> Result:
        spec = item.get("provision")
        if not spec:
            return self.check(item)
        if spec["type"] == "pip":
            version = self.versions["ANSIBLE_CORE_VERSION"]
            command = [sys.executable, "-m", "pip", "install", "--user", f"{spec['package']}=={version}"]
        else:
            command = ["ansible-playbook", "-i", "localhost,", "-c", "local", "platform/ansible/developer.yml", "-e", f"repo_root={ROOT}", "-e", f"ansible_python_interpreter={sys.executable}", "--tags", spec["tags"]]
        proc = self.runner(command)
        if proc.returncode:
            detail = " ".join((proc.stderr or proc.stdout).strip().split())[:300]
            return Result("BLOCKED", detail or f"provision exit {proc.returncode}")
        return self.check(item)

    def run(self, *, bootstrap: bool, os_name: str, arch: str) -> dict[str, Result]:
        platform_failure = self.platform_result(os_name, arch)
        results: dict[str, Result] = {}
        for name in self.graph.order():
            item = self.graph.items[name]
            if platform_failure:
                results[name] = platform_failure
                continue
            unmet = [dep for dep in item.get("requires", []) if results[dep].state != "PASS"]
            if unmet:
                results[name] = Result("SKIP", "requires " + ", ".join(unmet))
                continue
            result = self.check(item)
            if bootstrap and result.state == "FAIL" and item.get("provision"):
                unavailable = [dep for dep in item.get("provision_requires", []) if results[dep].state != "PASS"]
                result = Result("SKIP", "provision requires " + ", ".join(unavailable)) if unavailable else self.provision(item)
            results[name] = result
        return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("bootstrap", "env-check"))
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--os")
    parser.add_argument("--arch")
    args = parser.parse_args(argv)
    contract = load_contract(args.contract)
    auditor = Auditor(contract)
    os_name, arch, context = normalized_platform(args.os, args.arch)
    print(f"PLATFORM os={os_name} arch={arch} context={context}")
    results = auditor.run(bootstrap=args.mode == "bootstrap", os_name=os_name, arch=arch)
    for name, result in results.items():
        print(f"{result.state:<11} {name:<25} {result.detail}")
    return 0 if all(result.state == "PASS" for result in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
