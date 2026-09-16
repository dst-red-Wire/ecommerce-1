#!/usr/bin/env python3
"""Capability-aware, dependency-scoped developer environment reconciliation."""

from __future__ import annotations

import argparse
import ast
import tempfile
import time
import contextlib
import hashlib
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
SEED_LOCK = ROOT / "config/python/requirements.lock"
LOCAL_SEED_VENV = ROOT / ".venv/qualification"
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
            elif item.get("expected_output") is not None and detail != str(item["expected_output"]):
                state = "BLOCKED" if item.get("external_failure") else "FAIL"
                last = Result(state, f"expected output {item['expected_output']}; got {detail or 'empty'}")
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
            if profile == "static" and item["requirement"] == "optional-runtime":
                results[name] = Result("SKIP", "optional runtime capability not required by static profile")
                continue
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
        return results


def seed_requirements(lock: str, environment: dict[str, str] | None = None) -> dict[str, str]:
    # pip is supplied by venv/ensurepip, before the locked closure is installed.
    # Its vendored PEP 508 parser avoids bootstrapping a dependency on packaging.
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name

    expected = {}
    for raw in lock.splitlines():
        if not raw or raw[0].isspace() or raw.startswith("#"):
            continue
        requirement = Requirement(raw.rstrip().removesuffix("\\").strip())
        if requirement.marker and not requirement.marker.evaluate(environment):
            continue
        pins = list(requirement.specifier)
        if len(pins) != 1 or pins[0].operator != "==":
            raise ValueError(f"seed requires an exact version: {requirement.name}")
        expected[canonicalize_name(requirement.name)] = pins[0].version
    return expected


# Reused from PR92 (46997184): trusted wheel authority and seed recovery.
def seed_wheels(directory: Path, lock: str, *, strict: bool = True) -> list[Path]:
    """Only lock-authorized wheel bytes can define the installed inventory."""
    from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
    from pip._vendor.packaging.tags import sys_tags

    if directory.is_symlink() or directory.resolve() != directory:
        raise ValueError("seed wheel reference escapes its cache")
    expected = seed_requirements(lock)
    hashes = {}
    name = None
    for line in lock.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            name = canonicalize_name(line.split("==", 1)[0])
            hashes[name] = set()
        elif name:
            hashes[name].update(re.findall(r"--hash=sha256:([0-9a-f]{64})", line))
    supported = set(sys_tags())
    selected = {}
    for wheel in sorted(directory.glob("*.whl")):
        try:
            name, version, _, tags = parse_wheel_filename(wheel.name)
            if name not in expected or str(version) != expected[name] or name in selected:
                raise ValueError("unexpected or duplicate seed wheel")
            if not tags & supported:
                raise ValueError("seed wheel is incompatible with this interpreter")
            if wheel.is_symlink() or hashlib.sha256(wheel.read_bytes()).hexdigest() not in hashes[name]:
                raise ValueError("seed wheel differs from locked digest")
            selected[name] = wheel
        except (OSError, ValueError):
            if strict:
                raise
    if set(selected) != set(expected):
        raise ValueError("locked seed wheel reference is incomplete")
    return list(selected.values())


def interpreter_seed_wheels() -> list[Path]:
    # ensurepip's bundled/distribution wheels belong to the trusted interpreter,
    # not to the mutable seed cache. They cover pip outside requirements.lock.
    import ensurepip

    if not hasattr(ensurepip, "_get_packages"):
        directory = getattr(ensurepip, "_WHEEL_PKG_DIR", None)
        candidates = sorted(Path(directory).glob("pip-*.whl")) if directory else []
        return candidates[-1:] or [
            Path(ensurepip.__file__).parent / "_bundled" / f"pip-{ensurepip.version()}-py3-none-any.whl"
        ]
    return [
        Path(package.wheel_path)
        if package.wheel_path
        else Path(ensurepip.__file__).parent / "_bundled" / package.wheel_name
        for package in ensurepip._get_packages().values()
    ]


def seed_launcher_matches(actual: bytes, expected: bytes) -> bool:
    """Ignore only distlib's two installation-time ZIP timestamp fields."""
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(expected)) as archive:
        offsets = (archive.getinfo("__main__.py").header_offset + 10, archive.start_dir + 12)
    normalized = bytearray(actual)
    for offset in offsets:
        normalized[offset : offset + 4] = expected[offset : offset + 4]
    return len(actual) == len(expected) and bytes(normalized) == expected


def seed_scaffold(root: Path) -> dict[Path, bytes | str]:
    """Rebuild venv-owned files with trusted stdlib, without executing the seed."""
    import venv

    with tempfile.TemporaryDirectory(prefix="seed-scaffold-") as temporary:
        reference = Path(temporary) / root.name
        builder = venv.EnvBuilder(with_pip=True, symlinks=os.name != "nt")
        context = builder.ensure_directories(str(reference))
        builder.create_configuration(context)
        builder.setup_python(context)
        builder.setup_scripts(context)
        expected = {}
        for path in reference.rglob("*"):
            relative = path.relative_to(reference)
            if path.is_symlink():
                expected[relative] = os.readlink(path).replace(str(reference), str(root))
            elif path.is_file():
                expected[relative] = path.read_bytes().replace(str(reference).encode(), str(root).encode())
        return expected


def validate_seed_payload(root: Path, wheels: Path, lock: str) -> bool:
    """Reconstruct payload authority from wheels, never from installed RECORD."""
    import base64
    import configparser
    import csv
    import io
    import marshal
    import zipfile
    from pip._internal.operations.install.wheel import PipScriptMaker

    try:
        if any(path.is_file() and not path.is_symlink() and path.stat().st_nlink != 1 for path in root.rglob("*")):
            return False
        interpreter_wheels = interpreter_seed_wheels()
        archives = seed_wheels(wheels, lock) + interpreter_wheels
        sites = list(root.glob("lib/python*/site-packages")) if os.name != "nt" else [root / "Lib/site-packages"]
        if len(sites) != 1:
            return False
        site = sites[0]
        scripts = root / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        expected = {}
        records = {}
        generated_scripts = set()
        for wheel in archives:
            owned = {}
            with zipfile.ZipFile(wheel) as archive:
                for member in archive.namelist():
                    if member.endswith("/"):
                        continue
                    parts = Path(member).parts
                    if not parts or member.startswith("/") or ".." in parts or "\\" in member:
                        return False
                    if parts[0].endswith(".data"):
                        scheme = {"purelib": site, "platlib": site, "scripts": scripts, "data": root}
                        if len(parts) < 3 or parts[1] not in scheme:
                            return False
                        path = scheme[parts[1]].joinpath(*parts[2:])
                    else:
                        path = site / member
                    data = archive.read(member)
                    if member.endswith(".dist-info/RECORD"):
                        record = path
                        continue
                    if path.parent == scripts and data.startswith((b"#!python\n", b"#!pythonw\n")):
                        data = b"#!" + str(python).encode() + b"\n" + data.split(b"\n", 1)[1]
                    owned[path] = data
                info = record.parent
                owned[info / "INSTALLER"] = b"pip\n"
                owned[info / "REQUESTED"] = b""
                entry = owned.get(info / "entry_points.txt")
                if entry:
                    parser = configparser.ConfigParser(interpolation=None)
                    parser.optionxform = str
                    parser.read_string(entry.decode())
                    maker = PipScriptMaker(None, str(scripts))
                    maker.executable = str(
                        scripts / Path(getattr(sys, "_base_executable", sys.executable)).resolve().name
                        if wheel in interpreter_wheels
                        else python
                    )
                    maker.variants = {""}
                    maker.clobber = True
                    maker.set_mode = False

                    # Generate expected entrypoint bytes in memory, with pip's
                    # own transformation; no writes or installation on reuse.
                    def capture_script(name, data):
                        path = Path(name)
                        owned[path] = data
                        generated_scripts.add(path)

                    maker._fileop.write_binary_file = capture_script
                    for group in ("console_scripts", "gui_scripts"):
                        for name, value in parser.items(group) if parser.has_section(group) else []:
                            if wheel in interpreter_wheels and name.startswith("pip"):
                                if name != "pip":
                                    continue
                                for command in (
                                    "pip",
                                    f"pip{sys.version_info.major}",
                                    f"pip{sys.version_info.major}.{sys.version_info.minor}",
                                ):
                                    maker.make(f"{command} = {value}")
                            else:
                                maker.make(f"{name} = {value}", options={"gui": group == "gui_scripts"})
                if expected.keys() & owned.keys():
                    return False
                expected.update(owned)
                records[record] = owned
        for path, data in expected.items():
            if path.is_symlink() or path.resolve() != path or not path.is_file():
                return False
            if os.name != "nt" and path in generated_scripts and not os.access(path, os.X_OK):
                return False
            actual = path.read_bytes()
            if os.name == "nt" and path in generated_scripts and path.suffix == ".exe":
                # distlib's Windows launcher embeds a ZIP with installation-time
                # DOS timestamps. Only those two timestamp fields may differ.
                if not seed_launcher_matches(actual, data):
                    return False
                # RECORD still must hash the actual, now authenticated wrapper.
                records[next(record for record, owned in records.items() if path in owned)][path] = actual
            elif actual != data:
                return False
        # Bytecode is installation/import output, not authority. Its code must
        # equal compilation of the wheel-authenticated source at this location.
        bytecode = set()
        for path in site.rglob("*.pyc"):
            import importlib.util

            source = Path(importlib.util.source_from_cache(str(path)))
            if source not in expected:
                return False
            optimization = re.search(r"\.opt-([012])\.pyc$", path.name)
            level = int(optimization[1]) if optimization else 0
            if path.is_symlink() or marshal.loads(path.read_bytes()[16:]) != compile(
                expected[source], str(source), "exec", dont_inherit=True, optimize=level
            ):
                return False
            bytecode.add(path)
        for record, owned in records.items():
            rows = list(csv.reader(io.StringIO(record.read_text())))
            seen = set()
            for relative, digest, size in rows:
                path = Path(os.path.abspath(site / relative))
                if path in seen:
                    return False
                seen.add(path)
                if path == record or path in bytecode:
                    if digest or size:
                        return False
                elif path in owned:
                    data = owned[path]
                    wanted = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
                    if digest != wanted or size != str(len(data)):
                        return False
                else:
                    return False
            if not set(owned).issubset(seen) or record not in seen:
                return False
        allowed = set(expected) | set(records) | bytecode
        for path in site.rglob("*"):
            if path.is_symlink():
                return False
            if path.is_dir():
                continue
            if path not in allowed:
                return False
        scaffold = seed_scaffold(root)
        for relative, trusted in scaffold.items():
            path = root / relative
            if isinstance(trusted, str):
                if not path.is_symlink() or os.readlink(path) != trusted:
                    return False
            elif path.is_symlink() or not path.is_file() or path.read_bytes() != trusted:
                return False
        if any(path not in expected and path.relative_to(root) not in scaffold for path in scripts.iterdir()):
            return False
        return True
    except (OSError, ValueError, KeyError, EOFError, zipfile.BadZipFile):
        return False


def copy_seed_reference(wheels: Path, destination: Path, lock: str) -> bool:
    """Recover a complete compatible closure without copying untrusted extras."""
    try:
        selected = seed_wheels(wheels, lock, strict=False)
    except (OSError, ValueError):
        return False
    for wheel in selected:
        shutil.copyfile(wheel, destination / wheel.name)
    return bool(seed_wheels(destination, lock))


def publish_seed_reference(candidate: Path, wheels: Path) -> None:
    """Replace the whole reference under the identity lock, restoring on failure."""
    previous = candidate.with_name(candidate.name + ".previous")
    if wheels.exists():
        os.replace(wheels, previous)
    try:
        os.replace(candidate, wheels)
    except BaseException:
        if previous.exists():
            os.replace(previous, wheels)
        raise
    if previous.is_dir():
        shutil.rmtree(previous)
    else:
        previous.unlink(missing_ok=True)


def check_seed_reference(wheels: Path, root: Path | None = None, *, copy_to: Path | None = None) -> bool:
    """Use base Python and ensurepip, even if the cached seed's pip is broken."""
    bootstrap = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
    try:
        result = subprocess.run(
            [
                bootstrap,
                "-I",
                "-S",
                "-c",
                "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "import capability_bootstrap as b; "
                "sys.path[:0] = [str(p) for p in b.interpreter_seed_wheels()]; "
                "lock = Path(sys.argv[2]).read_text(encoding='utf-8'); "
                "ok = b.copy_seed_reference(Path(sys.argv[3]), Path(sys.argv[5]), lock) if sys.argv[5] else "
                "b.validate_seed_payload(Path(sys.argv[4]), Path(sys.argv[3]), lock) "
                "if sys.argv[4] else bool(b.seed_wheels(Path(sys.argv[3]), lock)); "
                "sys.exit(0 if ok else 1)",
                str(ROOT / "scripts"),
                str(SEED_LOCK),
                str(wheels),
                str(root) if root else "",
                str(copy_to) if copy_to else "",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def seed_unlocked_distributions(lock_path: str) -> list[str]:
    import importlib.metadata as metadata
    from pip._vendor.packaging.utils import canonicalize_name

    expected = seed_requirements(Path(lock_path).read_text(encoding="utf-8"))
    # These are supplied by venv/ensurepip rather than the qualification lock.
    allowed = set(expected) | {"pip", "setuptools", "wheel"}
    installed: dict[str, list[str]] = {}
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name", "")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
            raise ValueError("invalid installed seed distribution name")
        canonical = canonicalize_name(name)
        installed.setdefault(canonical, []).append(distribution.version)
    if any(len(versions) != 1 for versions in installed.values()):
        raise ValueError("duplicate canonical seed distributions")
    return sorted(set(installed) - allowed)


def seed_pip_environment() -> dict[str, str]:
    """Pip must not inherit install destinations or mutable configuration."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("PIP_")}
    env["PIP_CONFIG_FILE"] = os.devnull
    return env


def validate_seed_lock(lock_path: str) -> bool:
    import importlib.metadata as metadata

    expected = seed_requirements(Path(lock_path).read_text(encoding="utf-8"))
    try:
        if any(metadata.version(name) != version for name, version in expected.items()):
            return False
    except metadata.PackageNotFoundError:
        return False
    try:
        if seed_unlocked_distributions(lock_path):
            return False
    except ValueError:
        return False
    return (
        subprocess.run(
            [sys.executable, "-I", "-m", "pip", "--isolated", "check"],
            env=seed_pip_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


class SeedGenerationBoundaryError(RuntimeError):
    """The seed cache cannot safely own its generation directory."""


def validate_seed_generation_root(generations: Path) -> None:
    try:
        invalid = generations.is_symlink() or generations.resolve() != generations
    except (OSError, RuntimeError) as exc:
        raise SeedGenerationBoundaryError("seed generation root cannot be resolved safely") from exc
    if invalid:
        raise SeedGenerationBoundaryError(
            "seed generation root is a symlink or escapes its expected identity/tool-home"
        )


def seed_environment() -> int:
    versions = load_versions()
    lock = SEED_LOCK.read_text(encoding="utf-8").lower()
    for package, key in (
        ("ansible-core", "ANSIBLE_CORE_VERSION"),
        ("pyyaml", "PYYAML_VERSION"),
    ):
        expected = versions[key]
        if not re.search(rf"^{re.escape(package)}=={re.escape(expected)}(?:\s|\\)", lock, re.MULTILINE):
            raise ValueError(f"{package}: lock does not match canonical {key}={expected}")
    identity_input = json.dumps(
        {
            "python": [platform.python_implementation(), f"{sys.version_info.major}.{sys.version_info.minor}"],
            "platform": normalized_platform()[:2],
            "lock_sha256": hashlib.sha256(SEED_LOCK.read_bytes()).hexdigest(),
            "installer": ["pip", "--require-hashes"],
        },
        sort_keys=True,
    ).encode()
    identity = hashlib.sha256(identity_input).hexdigest()
    tool_home = Path(os.environ.get("ECOMMERCE_TOOL_HOME", Path.home() / ".cache/ecommerce-1/qualification")).resolve()
    seed_root = tool_home / "python" / identity
    lock_path = tool_home / "locks" / f"python-{identity}.lock"
    wheels = tool_home / "python" / f"{identity}.wheels"
    validate_seed_generation_root(wheels)
    selector = seed_root.with_suffix(".current")
    generations = seed_root.with_suffix(".generations")
    validate_seed_generation_root(generations)
    metadata_path = seed_root / ".ecommerce-tool.json"
    python = seed_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    def valid() -> bool:
        if not python.is_file() or not metadata_path.is_file():
            return False
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata != {"identity": identity, "input": json.loads(identity_input)}:
                return False
            if not check_seed_reference(wheels, seed_root):
                return False
            proc = subprocess.run(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); "
                    "from capability_bootstrap import validate_seed_lock; "
                    "sys.exit(0 if validate_seed_lock(sys.argv[2]) else 1)",
                    str(ROOT / "scripts"),
                    str(SEED_LOCK),
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
            return proc.returncode == 0
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
            return False

    with identity_lock(lock_path):
        validate_seed_generation_root(generations)
        if selector.is_symlink():
            selected = selector.resolve()
            if selected.parent != generations:
                raise RuntimeError("seed generation selector escapes its identity")
            seed_root = selected
            metadata_path = seed_root / ".ecommerce-tool.json"
            python = seed_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if valid():
            print(f"REUSE qualification seed identity={identity[:16]}")
        else:
            print(f"PREPARE qualification seed identity={identity[:16]}")
            # Keep published generations in place: running consumers do not take
            # the writer lock, and venv shebangs must never change location.
            bootstrap = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
            probe = subprocess.run(
                [
                    bootstrap,
                    "-I",
                    "-c",
                    "import json,platform,sys; print(json.dumps([platform.python_implementation(), list(sys.version_info[:2])]))",
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            if json.loads(probe.stdout) != [platform.python_implementation(), list(sys.version_info[:2])]:
                raise RuntimeError("bootstrap interpreter does not match seed Python identity")
            validate_seed_generation_root(generations)
            generations.mkdir(parents=True, exist_ok=True)
            seed_root = Path(tempfile.mkdtemp(prefix="generation-", dir=generations))
            metadata_path = seed_root / ".ecommerce-tool.json"
            python = seed_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            temporary_selector = selector.with_name(f".{selector.name}.{os.getpid()}.tmp")
            try:
                subprocess.run([bootstrap, "-I", "-m", "venv", str(seed_root)], check=True)
                if not check_seed_reference(wheels):
                    with tempfile.TemporaryDirectory(dir=generations, prefix="wheels-") as download:
                        if not check_seed_reference(wheels, copy_to=Path(download)):
                            subprocess.run(
                                [
                                    str(python),
                                    "-I",
                                    "-m",
                                    "pip",
                                    "--isolated",
                                    "--cache-dir",
                                    str(tool_home / "downloads" / "pip"),
                                    "download",
                                    "--only-binary=:all:",
                                    "--require-hashes",
                                    "-r",
                                    str(SEED_LOCK),
                                    "--dest",
                                    download,
                                ],
                                check=True,
                                env=seed_pip_environment(),
                            )
                        if not check_seed_reference(Path(download)):
                            raise RuntimeError("downloaded seed wheel reference is invalid")
                        publish_seed_reference(Path(download), wheels)
                subprocess.run(
                    [
                        str(python),
                        "-I",
                        "-m",
                        "pip",
                        "--isolated",
                        "--cache-dir",
                        str(tool_home / "downloads" / "pip"),
                        "install",
                        "--no-index",
                        "--find-links",
                        str(wheels),
                        "--only-binary=:all:",
                        "--disable-pip-version-check",
                        "--require-hashes",
                        "-r",
                        str(SEED_LOCK),
                    ],
                    check=True,
                    env=seed_pip_environment(),
                )
                metadata_path.write_text(
                    json.dumps({"identity": identity, "input": json.loads(identity_input)}, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                if not valid():
                    raise RuntimeError("seed environment verification failed after installation")
                temporary_selector.unlink(missing_ok=True)
                temporary_selector.symlink_to(seed_root, target_is_directory=True)
                os.replace(temporary_selector, selector)
            except BaseException:
                # Only discard this unpublished candidate; published readers retain their paths.
                if not selector.is_symlink() or selector.resolve() != seed_root:
                    shutil.rmtree(seed_root)
                raise
            finally:
                temporary_selector.unlink(missing_ok=True)
        publish_checkout_reference(seed_root)
    ansible = seed_root / ("Scripts/ansible.exe" if os.name == "nt" else "bin/ansible")
    proc = subprocess.run([str(python), "-I", str(ansible), "--version"], check=True, text=True, capture_output=True)
    if versions["ANSIBLE_CORE_VERSION"] not in proc.stdout.splitlines()[0]:
        raise RuntimeError("seed Ansible version verification failed")
    print(
        f"PASS qualification seed ansible-core={versions['ANSIBLE_CORE_VERSION']} pyyaml={versions['PYYAML_VERSION']}"
    )
    return 0


@contextlib.contextmanager
def identity_lock(path: Path, timeout: float = 300.0):
    """Bounded cross-process lock; the caller must recheck after acquisition."""
    handle = path.open("a+", encoding="utf-8")
    deadline = time.monotonic() + timeout
    while True:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except (BlockingIOError, OSError):
            if time.monotonic() >= deadline:
                handle.close()
                raise TimeoutError(f"timed out waiting for {path}")
            time.sleep(0.1)
    try:
        yield
    finally:
        if os.name == "nt":
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def publish_checkout_reference(seed_root: Path) -> None:
    """Atomically point this checkout at its compatible immutable seed."""
    parent = LOCAL_SEED_VENV.parent
    for ancestor in (parent, *parent.parents):
        if ancestor.is_symlink() or (ancestor.exists() and not ancestor.is_dir()):
            raise SeedGenerationBoundaryError("seed checkout reference has an unsafe parent")
    parent.mkdir(parents=True, exist_ok=True)
    temporary = LOCAL_SEED_VENV.with_name(f".{LOCAL_SEED_VENV.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(seed_root, target_is_directory=True)
    if LOCAL_SEED_VENV.exists() and not LOCAL_SEED_VENV.is_symlink():
        shutil.rmtree(LOCAL_SEED_VENV)
    os.replace(temporary, LOCAL_SEED_VENV)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("seed", "bootstrap", "env-check"))
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--os")
    parser.add_argument("--arch")
    parser.add_argument("--profile", choices=("static", "runtime"), default="static")
    args = parser.parse_args(argv)
    if args.mode == "seed":
        try:
            return seed_environment()
        except SeedGenerationBoundaryError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            return 1
    contract = load_contract(args.contract)
    auditor = Auditor(contract)
    os_name, arch, context = normalized_platform(args.os, args.arch)
    print(f"PLATFORM os={os_name} arch={arch} context={context}")
    results = auditor.run(bootstrap=args.mode == "bootstrap", os_name=os_name, arch=arch, profile=args.profile)
    for name, result in results.items():
        print(f"{result.state:<11} {name:<25} {result.detail}")
    required = {
        name
        for name, item in auditor.graph.items.items()
        if args.profile == "runtime" or item["requirement"] == "required-static"
    }
    required.update(primitive["command"] for primitive in contract.get("platform_primitives", []))
    return 0 if all(results[name].state == "PASS" for name in required) else 1


if __name__ == "__main__":
    raise SystemExit(main())
