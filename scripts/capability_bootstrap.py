#!/usr/bin/env python3
"""Capability-aware, dependency-scoped developer environment reconciliation."""

from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import re
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
CLASSIFICATIONS = {"managed", "seed-prerequisite", "platform-provided", "conditional"}
REQUIREMENTS = {"required-static", "optional-runtime"}
MANAGED_BIN_DIRS = (Path.home() / ".local" / "bin",)
COMMAND_WRAPPERS = {"require", "require_command"}
SEMVER = re.compile(r"(?<![0-9.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?![0-9A-Za-z.-])")


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


def validate_contract(contract: dict, versions: dict[str, str] | None = None) -> None:
    """Fail closed when a gate command is outside the explicit toolchain closure.

    Gate requirements are intentionally declarative. Trying to infer arbitrary
    subprocesses or shell fragments would create a misleading, incomplete parser.
    Tests and review keep this small authority aligned with executable gate paths.
    """
    versions = versions or load_versions()
    graph = Graph(contract["capabilities"])
    for name, item in graph.items.items():
        if item.get("requirement") not in REQUIREMENTS:
            raise ValueError(f"{name}: invalid or missing requirement")
    quality_names = ("ruff", "oxfmt", "oxlint")
    quality_items = [graph.items[name] for name in quality_names if name in graph.items]
    if len(quality_items) == len(quality_names):
        quality_tags = [item.get("provision", {}).get("tags") for item in quality_items]
        if len(set(quality_tags)) != len(quality_tags):
            raise ValueError("independent quality capabilities must use distinct provisioning tags")
    owners = contract.get("provision_owners", {})
    managed = {
        name for name, item in graph.items.items() if item.get("classification") == "managed" and item.get("provision")
    }
    if set(owners) != managed:
        missing = sorted(managed - set(owners))
        extra = sorted(set(owners) - managed)
        raise ValueError(f"provision owners must cover managed capabilities exactly; missing={missing}; extra={extra}")
    for capability, owner in owners.items():
        if capability not in graph.items:
            raise ValueError(f"provision owner references missing capability: {capability}")
        provision_type = graph.items[capability].get("provision", {}).get("type")
        if provision_type != owner:
            raise ValueError(f"{capability}: canonical provision owner is {owner}, not {provision_type or 'none'}")
    ansible_core = graph.items.get("ansible-core")
    if ansible_core:
        if ansible_core.get("classification") != "seed-prerequisite":
            raise ValueError("ansible-core: must be a runner prerequisite")
        if ansible_core.get("provision") or ansible_core.get("provision_requires") or ansible_core.get("isolated"):
            raise ValueError("ansible-core: runner prerequisite must not have a repository provisioner")
        required_entrypoints = {
            "ansible-playbook": "ansible-core",
            "ansible-galaxy": "ansible-core",
        }
        for entrypoint, provider in required_entrypoints.items():
            item = graph.items.get(entrypoint, {})
            if item.get("provider") != provider or provider not in item.get("requires", []):
                raise ValueError(f"{entrypoint}: must be bound to the ansible-core provider")
    for item in graph.items.values():
        if item.get("classification") == "seed-prerequisite" and (
            item.get("provision") or item.get("provision_requires") or item.get("isolated")
        ):
            raise ValueError(f"{item['name']}: runner prerequisite must not have a repository provisioner")
    command_aliases = contract.get("command_capabilities", {})
    external = {}
    for classification, key in (
        ("seed-prerequisite", "seed_prerequisites"),
        ("platform-provided", "platform_primitives"),
    ):
        for entry in contract.get(key, []):
            command = entry.get("command", "")
            if not command or not entry.get("justification"):
                raise ValueError(f"{key}: command and contractual justification are required")
            capability = graph.items.get(command)
            if key == "platform_primitives" and capability:
                capability_command = capability.get("command")
                probe = capability.get("probe") or []
                if capability_command != command or capability.get("any_of") or (probe and probe[0] != command):
                    raise ValueError(
                        f"primitive {command} collides with capability {command} that is not a direct executable check"
                    )
            if command in external:
                raise ValueError(f"command has multiple external classifications: {command}")
            external[command] = classification

    commands: dict[str, str] = {}
    for name, item in graph.items.items():
        classification = item.get("classification")
        if classification not in CLASSIFICATIONS:
            raise ValueError(f"{name}: invalid or missing classification")
        command = item.get("command")
        if command:
            commands[command] = name
        version_key = item.get("version_key")
        if version_key and not versions.get(version_key):
            raise ValueError(f"{name}: missing version authority {version_key}")
        for alternative in item.get("any_of", []):
            alternative_key = alternative.get("version_key")
            if not alternative.get("command") or not alternative_key or not versions.get(alternative_key):
                raise ValueError(f"{name}: alternative requires command and version authority")
        if "selection_policy" in item and (item["selection_policy"] != "first_available" or not item.get("any_of")):
            raise ValueError(f"{name}: invalid alternative selection policy")
        provision_authority = item.get("provision_authority")
        if provision_authority and not versions.get(provision_authority):
            raise ValueError(f"{name}: missing provision authority {provision_authority}")
        if (
            classification == "managed"
            and item.get("provision")
            and not (version_key or item.get("version_file") or item.get("provision_authority"))
        ):
            raise ValueError(f"{name}: provisioned capability has no version authority")
        if classification == "platform-provided" and not item.get("justification"):
            raise ValueError(f"{name}: platform-provided capability needs justification")
        checksum_key = item.get("checksum_key")
        if checksum_key:
            checksum = versions.get(checksum_key, "")
            if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum.lower()):
                raise ValueError(f"{name}: invalid checksum authority {checksum_key}")
        provider = item.get("provider")
        if provider:
            if provider not in graph.items:
                raise ValueError(f"{name}: missing provider capability {provider}")
            if provider not in item.get("requires", []):
                raise ValueError(f"{name}: provider {provider} must be a runtime dependency")
            if not graph.items[provider].get("command"):
                raise ValueError(f"{name}: provider {provider} has no executable")

    for command, capability in command_aliases.items():
        if capability not in graph.items:
            raise ValueError(f"command {command}: missing capability {capability}")
    known = set(commands) | set(command_aliases) | set(external)
    if not contract.get("gate_requirements"):
        raise ValueError("gate_requirements must not be empty")
    for gate, required in contract["gate_requirements"].items():
        if not required:
            raise ValueError(f"gate {gate}: requirements must not be empty")
        unknown = sorted(set(required) - known)
        if unknown:
            raise ValueError(f"gate {gate}: undeclared commands: {', '.join(unknown)}")

    declared = {command for required in contract["gate_requirements"].values() for command in required}
    for relative in contract.get("gate_sources", []):
        source = ROOT / relative
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=relative)
        discovered: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if function in COMMAND_WRAPPERS and node.args and isinstance(node.args[0], ast.Constant):
                discovered.add(str(node.args[0].value))
            if function in {"run", "output", "Popen"} and node.args and isinstance(node.args[0], ast.List):
                elements = node.args[0].elts
                if elements and isinstance(elements[0], ast.Constant) and isinstance(elements[0].value, str):
                    discovered.add(elements[0].value)
        missing = sorted(discovered - declared)
        if missing:
            raise ValueError(f"{relative}: executable commands absent from gate requirements: {', '.join(missing)}")


def normalized_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str, str]:
    os_name = (system or platform.system()).lower()
    os_name = {"macos": "darwin"}.get(os_name, os_name)
    arch = (machine or platform.machine()).lower()
    arch = {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    context = os.environ.get("BOOTSTRAP_CONTEXT", "")
    if not context:
        release = platform.release().lower()
        context = (
            "wsl2" if os_name == "linux" and "microsoft" in release else ("ci" if os.environ.get("CI") else "native")
        )
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


def profile_succeeded(results: dict[str, Result], contract: dict, profile: str) -> bool:
    graph = Graph(contract["capabilities"])
    required = {
        name for name, item in graph.items.items() if profile == "runtime" or item["requirement"] == "required-static"
    }
    required.update(primitive["command"] for primitive in contract.get("platform_primitives", []))
    return all(results[name].state == "PASS" for name in required)


class Auditor:
    def __init__(
        self, contract: dict, *, runner: Runner = default_runner, which: Callable[[str], str | None] = shutil.which
    ):
        self.contract = contract
        validate_contract(contract)
        self.graph = Graph(contract["capabilities"])
        self.runner = runner
        self.which = which
        self.versions = load_versions()
        self.resolved_executables: dict[str, str] = {}

    @staticmethod
    def installed_version(output: str, parser: str = "first_semver") -> str | None:
        """Parse the reported installed version, never an arbitrary substring."""
        if parser not in {"first_semver", "first_semver_release"}:
            raise ValueError(f"unsupported version parser: {parser}")
        match = SEMVER.search(output)
        if not match:
            return None
        version = match.group(1)
        return version.split("+", 1)[0] if parser == "first_semver_release" else version

    def resolve_all(self, command: str) -> list[str]:
        """Resolve commands without requiring a newly logged-in shell after provisioning."""
        candidates = []
        resolved = self.which(command)
        if resolved:
            candidates.append(resolved)
        for directory in MANAGED_BIN_DIRS:
            candidate = directory / command
            if candidate.is_file() and os.access(candidate, os.X_OK) and str(candidate) not in candidates:
                candidates.append(str(candidate))
        return candidates

    def resolve(self, command: str) -> str | None:
        candidates = self.resolve_all(command)
        return candidates[0] if candidates else None

    def resolve_repoctl_runtime(self, command: str) -> str | None:
        """Resolve using repoctl's managed-bin-prefixed effective PATH."""
        for directory in MANAGED_BIN_DIRS:
            candidate = directory / command
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return self.which(command)

    def provider_entrypoint(self, item: dict) -> str | None:
        """Resolve an entry point beside the executable that validated its provider."""
        provider = item.get("provider")
        if not provider:
            return None
        provider_executable = self.resolved_executables.get(provider)
        if not provider_executable:
            return None
        candidate = Path(provider_executable).parent / item["command"]
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None

    def platform_result(self, os_name: str, arch: str, item: dict | None = None) -> Result | None:
        if os_name not in self.contract["supported"]["os"]:
            return Result("UNSUPPORTED", f"os {os_name}")
        if arch not in self.contract["supported"]["arch"]:
            return Result("UNSUPPORTED", f"architecture {arch}")
        supported = (item or {}).get("platforms")
        if supported and f"{os_name}/{arch}" not in supported:
            return Result("UNSUPPORTED", f"{os_name}/{arch} has no contracted provisioner")
        return None

    def check(self, item: dict, capability_name: str | None = None) -> Result:
        if item.get("virtual"):
            return Result("PASS", "dependencies ready")
        alternatives = item.get("any_of", [])
        if alternatives:
            if item.get("selection_policy") == "first_available":
                for alternative in alternatives:
                    resolved = self.resolve_repoctl_runtime(alternative["command"])
                    if resolved:
                        return self.check(
                            {
                                **item,
                                **alternative,
                                "any_of": [],
                                "resolved_executable": resolved,
                            },
                            capability_name,
                        )
                return Result(
                    "FAIL", "alternatives absent: " + ", ".join(alternative["command"] for alternative in alternatives)
                )
            failures = []
            for alternative in alternatives:
                result = self.check({**item, **alternative, "any_of": []}, capability_name)
                if result.state == "PASS":
                    return result
                failures.append(f"{alternative['command']}: {result.detail}")
            return Result("FAIL", "; ".join(failures))
        command = item.get("command")
        argv = item.get("probe") or ([command, *item.get("version_args", [])] if command else [])
        provider = item.get("provider")
        if provider:
            provider_executable = self.resolved_executables.get(provider)
            provider_item = self.graph.items[provider]
            provider_command = (
                provider_executable if argv and argv[0] == provider_item["command"] else self.provider_entrypoint(item)
            )
            resolved_candidates = [provider_command] if provider_command else []
        elif item.get("isolated"):
            resolved_candidates = [
                str(candidate)
                for directory in MANAGED_BIN_DIRS
                if (candidate := directory / command).is_file() and os.access(candidate, os.X_OK)
            ]
        else:
            selected = item.get("resolved_executable")
            resolved_candidates = [selected] if selected else (self.resolve_all(command) if command else [])
        if (command or provider) and not resolved_candidates:
            if provider:
                detail = f"entry point absent from provider {provider}"
            elif item.get("classification") == "seed-prerequisite":
                detail = f"runner prerequisite missing: {capability_name or item.get('name', command)}"
            else:
                detail = "tool absent"
            state = "BLOCKED" if item.get("classification") == "seed-prerequisite" else "FAIL"
            return Result(state, detail)
        expected = self.versions.get(item.get("version_key", ""))
        version_file = item.get("version_file")
        if version_file:
            expected = (ROOT / version_file).read_text(encoding="utf-8").strip()
        candidates = resolved_candidates if argv and (provider or (command and argv[0] == command)) else [None]
        last = Result("FAIL", "tool absent")
        for resolved in candidates:
            candidate_argv = [str(resolved), *argv[1:]] if resolved else argv
            proc = self.runner(candidate_argv)
            detail = " ".join((proc.stdout or proc.stderr).strip().split())
            if proc.returncode:
                last = Result(
                    "BLOCKED" if item.get("external_failure") else "FAIL", detail or f"exit {proc.returncode}"
                )
            elif expected and self.installed_version(
                detail, item.get("version_parser", "first_semver")
            ) != expected.removeprefix("v"):
                installed = self.installed_version(detail, item.get("version_parser", "first_semver"))
                last = Result("FAIL", f"wrong version: expected {expected}; got {installed or detail or 'unknown'}")
            else:
                if capability_name and resolved:
                    self.resolved_executables[capability_name] = str(resolved)
                return Result("PASS", detail or "ready")
        return last

    def provision(self, item: dict) -> Result:
        spec = item.get("provision")
        if not spec:
            return self.check(item)
        if spec["type"] != "ansible":
            return Result("BLOCKED", f"unsupported repository provisioner: {spec['type']}")
        ansible_playbook = self.resolved_executables.get("ansible-playbook")
        playbook_capability = self.graph.items.get("ansible-playbook", {})
        if not playbook_capability.get("provider"):
            ansible_playbook = ansible_playbook or self.resolve("ansible-playbook")
        if not ansible_playbook:
            return Result("BLOCKED", "validated ansible-playbook provider is unavailable")
        command = [
            ansible_playbook,
            "-i",
            "localhost,",
            "-c",
            "local",
            "platform/ansible/developer.yml",
            "-e",
            f"repo_root={ROOT}",
            "-e",
            f"ansible_python_interpreter={sys.executable}",
            "-e",
            "resolved_executables=" + json.dumps(self.resolved_executables),
            "--tags",
            spec["tags"],
        ]
        proc = self.runner(command)
        if proc.returncode:
            detail = " ".join((proc.stderr or proc.stdout).strip().split())[:300]
            return Result("BLOCKED", detail or f"provision exit {proc.returncode}")
        return self.check(item, item["name"])

    def run(self, *, bootstrap: bool, os_name: str, arch: str, profile: str = "static") -> dict[str, Result]:
        if profile not in {"static", "runtime"}:
            raise ValueError(f"unknown capability profile: {profile}")
        results: dict[str, Result] = {}
        for name in self.graph.order():
            item = self.graph.items[name]
            platform_failure = self.platform_result(os_name, arch, item)
            if platform_failure:
                results[name] = platform_failure
                continue
            unmet = [dep for dep in item.get("requires", []) if results[dep].state != "PASS"]
            if unmet:
                results[name] = Result("SKIP", "requires " + ", ".join(unmet))
                continue
            result = self.check(item, name)
            if bootstrap and result.state == "FAIL" and item.get("provision"):
                unavailable = [dep for dep in item.get("provision_requires", []) if results[dep].state != "PASS"]
                result = (
                    Result("SKIP", "provision requires " + ", ".join(unavailable))
                    if unavailable
                    else self.provision(item)
                )
            results[name] = result
        for primitive in self.contract.get("platform_primitives", []):
            command = primitive["command"]
            if command not in results:
                platform_failure = self.platform_result(os_name, arch, primitive)
                results[command] = platform_failure or (
                    Result("PASS", "ready") if self.which(command) else Result("FAIL", "tool absent")
                )
        if profile == "static":
            for name, item in self.graph.items.items():
                result = results[name]
                if item["requirement"] == "optional-runtime" and result.state != "PASS":
                    results[name] = Result("SKIP", f"environmental: {result.state.lower()} - {result.detail}")
        return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("bootstrap", "env-check"))
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--os")
    parser.add_argument("--arch")
    parser.add_argument("--profile", choices=("static", "runtime"), default="static")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args(argv)
    contract = load_contract(args.contract)
    auditor = Auditor(contract)
    os_name, arch, context = normalized_platform(args.os, args.arch)
    print(f"PLATFORM os={os_name} arch={arch} context={context}")
    results = auditor.run(bootstrap=args.mode == "bootstrap", os_name=os_name, arch=arch, profile=args.profile)
    for name, result in results.items():
        print(f"{result.state:<11} {name:<25} {result.detail}")
    evidence = {
        "schema_version": 1,
        "mode": args.mode,
        "profile": args.profile,
        "platform": {"os": os_name, "arch": arch, "context": context},
        "results": {name: {"state": result.state, "detail": result.detail} for name, result in results.items()},
    }
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return 0 if profile_succeeded(results, contract, args.profile) else 1


if __name__ == "__main__":
    raise SystemExit(main())
