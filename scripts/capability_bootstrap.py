#!/usr/bin/env python3
"""Capability-aware, dependency-scoped developer environment reconciliation."""

from __future__ import annotations

import argparse
import configparser
import ast
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/toolchain/capabilities.json"
TOOLCHAIN_LOCK = ROOT / "config/contracts/toolchain-lock.json"
VERSIONS = ROOT / "config/toolchain/versions.env"  # native projection only
ANSIBLE_COLLECTIONS = ROOT / "platform/ansible/requirements.yml"
SEED_LOCK = ROOT / "config/python/requirements.lock"
SEED_VENV = ROOT / ".venv/qualification"

_MAX_REPOSITORY_DATA_BYTES = 16 * 1024 * 1024


def _repository_data_binding(path: Path) -> tuple[Path, str] | None:
    """Select only an existing wrapper binding; this reader grants no authority."""
    matches = []
    for root_key, sha_key in (
        ("REPOCTL_TRUSTED_POLICY_ROOT", "REPOCTL_TRUSTED_BASE_SHA"),
        ("REPOCTL_TRUSTED_TARGET_ROOT", "REPOCTL_TRUSTED_HEAD_SHA"),
    ):
        value = os.environ.get(root_key, "").strip()
        sha = os.environ.get(sha_key, "").strip()
        if bool(value) != bool(sha):
            # Native UAC validates a working tree before it has a PR HEAD;
            # its executable inputs still use the complete exact-base binding.
            if (
                value
                and not sha
                and root_key == "REPOCTL_TRUSTED_TARGET_ROOT"
                and os.environ.get("REPOCTL_TRUSTED_NATIVE_UAC") == "1"
            ):
                continue
            raise ValueError(
                "repository data binding requires both root and exact commit"
            )
        if not value:
            continue
        bound_root = Path(value)
        if not bound_root.is_absolute() or ".." in bound_root.parts:
            raise ValueError("repository data binding root is not canonical")
        if path.is_relative_to(bound_root):
            matches.append((bound_root, sha))
    # The trusted base can itself be a checkout below the target's .context/.
    if not matches:
        return None
    binding = max(matches, key=lambda item: len(item[0].parts))
    if not re.fullmatch(r"[0-9a-f]{40}", binding[1]):
        raise ValueError("repository data binding requires an exact commit")
    return binding


def _verify_repository_blob(
    path: Path, content: bytes, binding: tuple[Path, str]
) -> None:
    root, commit = binding
    relative = path.relative_to(root).as_posix()
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "PATH": "/usr/bin:/bin",
        }
    )
    try:
        result = subprocess.run(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                "ls-tree",
                "-z",
                commit,
                "--",
                relative,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("repository data exact Git blob lookup failed") from exc
    entries = result.stdout.split(b"\0")
    if result.returncode or len(entries) != 2 or entries[-1] != b"":
        raise ValueError("repository data is missing from the exact Git tree")
    metadata, separator, name = entries[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or name != relative.encode("utf-8")
        or len(fields) != 3
        or fields[0] not in (b"100644", b"100755")
        or fields[1] != b"blob"
    ):
        raise ValueError("repository data is not a regular file in the exact Git tree")
    object_id = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()
    if fields[2] != object_id.encode("ascii"):
        raise ValueError("repository data differs from its exact Git blob")


def read_repository_text(path: Path, *, root: Path | None = None) -> str:
    """Read bounded regular data without symlinks; bind trusted reads to Git bytes.

    Local bootstrap/working-tree checks may inspect edits. A trusted wrapper's
    target/base binding instead requires the bytes and mode in its exact commit.
    The same verified bytes are returned to the parser, never reopened by path.
    """
    candidate = Path(path).absolute()
    if ".." in candidate.parts:
        raise ValueError("repository data path contains traversal")
    if root is not None:
        boundary = Path(root).absolute()
        if ".." in boundary.parts or not candidate.is_relative_to(boundary):
            raise ValueError("repository data path escapes its root")
    # The caller's data root owns the namespace. A target-data read must not
    # silently become a base-data read merely because that checkout is nested.
    binding = _repository_data_binding(boundary if root is not None else candidate)
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise ValueError("repository data requires no-follow descriptor support")
    directory = descriptor = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(candidate.anchor, directory_flags)
        for part in candidate.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > _MAX_REPOSITORY_DATA_BYTES
        ):
            raise ValueError("repository data must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(_MAX_REPOSITORY_DATA_BYTES + 1)
        after = os.fstat(descriptor)
        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        if len(content) != before.st_size or identity(before) != identity(after):
            raise ValueError("repository data changed during read")
    except OSError as exc:
        raise ValueError(
            "repository data is unavailable, not regular, or contains a symlink"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
    # These Windows text projections have fixed CRLF checkout rules in the
    # repository's .gitattributes. Compare and parse their canonical LF bytes;
    # never invoke Git clean filters or normalize JSON/YAML/Python input bytes.
    if candidate.suffix in {".ps1", ".bat", ".cmd"}:
        content = content.replace(b"\r\n", b"\n")
    if binding is not None:
        _verify_repository_blob(candidate, content, binding)
    return content.decode("utf-8")


_RAW_TOOLCHAIN_LOCK = json.loads(read_repository_text(TOOLCHAIN_LOCK, root=ROOT))
_BOOTSTRAP_TOOLCHAIN_POLICY = _RAW_TOOLCHAIN_LOCK.get("capability_policy", {})

STATES = {"PASS", "FAIL", "BLOCKED", "SKIP", "UNSUPPORTED"}
CLASSIFICATIONS = set(_BOOTSTRAP_TOOLCHAIN_POLICY.get("classifications", []))
REQUIREMENTS = set(_BOOTSTRAP_TOOLCHAIN_POLICY.get("requirements", []))
SUPPORTED_REQUIREMENTS = frozenset({"required-static", "optional-runtime", "optional-tooling"})
MANAGED_PROVISION_TYPES = set(_BOOTSTRAP_TOOLCHAIN_POLICY.get("managed_provision_types", []))
_MANAGED_INSTALL_ROOT = _BOOTSTRAP_TOOLCHAIN_POLICY.get("managed_install_root", {})
_MANAGED_ROOT_ENVIRONMENT = _MANAGED_INSTALL_ROOT.get("environment", "ECOMMERCE_TOOL_HOME")
_MANAGED_ROOT_CONFIGURED = os.environ.get(_MANAGED_ROOT_ENVIRONMENT, "").strip()
_MANAGED_ROOT = (
    Path(_MANAGED_ROOT_CONFIGURED).expanduser()
    if _MANAGED_ROOT_CONFIGURED
    else Path(_MANAGED_INSTALL_ROOT.get("fallback", "~/.local")).expanduser()
)
MANAGED_BIN_DIRS = (_MANAGED_ROOT / _MANAGED_INSTALL_ROOT.get("bin_subdirectory", "bin"),)
COMMAND_WRAPPERS = {"require", "require_command"}
SEMVER = re.compile(r"(?<![0-9.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)(?![0-9A-Za-z.-])")


@dataclass(frozen=True)
class Result:
    state: str
    detail: str = ""


def _parse_versions_env(path: Path, *, root: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in read_repository_text(path, root=root).splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            if key in values:
                raise ValueError(f"duplicate version projection: {key}")
            values[key] = value.strip()
    return values


def load_toolchain_lock(path: Path = TOOLCHAIN_LOCK, *, root: Path | None = None) -> dict:
    contract = json.loads(read_repository_text(path, root=root))
    if (
        contract.get("architecture_authority") != "architecture.lock.yaml"
        or contract.get("scope") != "entire-repository"
        or contract.get("status") != "exact"
    ):
        raise ValueError("toolchain lock must inherit architecture.lock.yaml for the entire repository")

    versions = contract.get("versions")
    if not isinstance(versions, dict) or not versions:
        raise ValueError("toolchain lock versions must be a non-empty mapping")
    if any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or not key
        or not value
        for key, value in versions.items()
    ):
        raise ValueError("toolchain lock versions must use non-empty string keys and values")

    policy = contract.get("capability_policy")
    if not isinstance(policy, dict):
        raise ValueError("toolchain lock must declare capability_policy")
    if not policy.get("classifications") or not policy.get("requirements"):
        raise ValueError("toolchain lock capability policy must declare classifications and requirements")

    tools = contract.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ValueError("toolchain registry must contain approved repository tools")
    for name, tool in tools.items():
        version_ref = tool.get("version_ref")
        if version_ref not in versions or versions[version_ref].lower() == "latest":
            raise ValueError(f"{name}: missing exact central version")
        artifact = tool.get("artifact")
        install_type = tool.get("install", {}).get("type")
        rpm_package = install_type == "rpm-package" and tool.get("integrity") == "signed-rpm-package-lock"
        if rpm_package:
            if not str(tool.get("source", "")).startswith("https://"):
                raise ValueError(f"{name}: signed RPM package source must use HTTPS")
        else:
            if not isinstance(artifact, dict) or not str(artifact.get("url", "")).startswith("https://"):
                raise ValueError(f"{name}: deterministic HTTPS artifact is required")
            if "latest" in artifact["url"].lower():
                raise ValueError(f"{name}: floating artifact URL is forbidden")
        checksum_ref = tool.get("sha256_ref")
        integrity = tool.get("integrity")
        if checksum_ref is None and integrity not in {"go-checksum-database", "signed-rpm-package-lock"}:
            raise ValueError(f"{name}: artifact integrity authority is required")
        if checksum_ref is not None and not re.fullmatch(r"[0-9a-f]{64}", versions.get(checksum_ref, "")):
            raise ValueError(f"{name}: invalid central SHA256")
        if tool.get("platforms") not in (["linux/amd64"], ["windows/amd64"]):
            raise ValueError(f"{name}: unsupported platform contract")
        if not tool.get("install") or not tool.get("binary") or not tool.get("version_command"):
            raise ValueError(f"{name}: install and version verification contract is incomplete")
    rejected = contract.get("tool_lifecycle", {}).get("rejected", {})
    if "hyperfine" not in rejected:
        raise ValueError("hyperfine must remain rejected while qualification timing owns the capability")
    return contract


def _parse_ansible_collection_projection(
    path: Path | None = None, *, root: Path | None = None
) -> dict[str, str]:
    path = path or ANSIBLE_COLLECTIONS
    result: dict[str, str] = {}
    name: str | None = None
    for raw in read_repository_text(path, root=root).splitlines():
        if match := re.match(r"\s*-\s+name:\s*([\w.]+)\s*$", raw):
            if name is not None:
                raise ValueError(f"missing version for Ansible collection projection {name}")
            name = match.group(1)
        elif match := re.match(r"\s+version:\s*[\"']?([\w.-]+)[\"']?\s*$", raw):
            if name is None or name in result:
                raise ValueError("invalid Ansible collection projection")
            result[name] = match.group(1)
            name = None
    if name is not None or not result:
        raise ValueError("invalid or empty Ansible collection projection")
    return result


def validate_toolchain_projections(contract: dict | None = None, *, root: Path = ROOT) -> None:
    """Validate one repository tree with this controller's parser, never imported HEAD code."""
    lock = contract if contract is not None else load_toolchain_lock(root / "config/contracts/toolchain-lock.json", root=root)

    projected_versions = _parse_versions_env(root / "config/toolchain/versions.env", root=root)
    if projected_versions != lock["versions"]:
        raise ValueError("config/toolchain/versions.env drifted from central toolchain lock")

    projected_collections = _parse_ansible_collection_projection(root / "platform/ansible/requirements.yml", root=root)
    expected_collections = lock.get("ansible_collections", {})
    if projected_collections != expected_collections:
        raise ValueError("platform/ansible/requirements.yml drifted from central toolchain lock")

    projected_capabilities = load_contract(root / "config/toolchain/capabilities.json", root=root)
    expected_command_capabilities = lock.get("capability_policy", {}).get("command_capabilities", {})
    if projected_capabilities.get("command_capabilities", {}) != expected_command_capabilities:
        raise ValueError("config/toolchain/capabilities.json command_capabilities drifted from central toolchain lock")

    ansible_config = lock.get("native_tool_configs", {}).get("ansible", {})
    ansible_projection = root / str(ansible_config.get("projection", "platform/ansible/ansible.cfg"))
    parser = configparser.ConfigParser()
    parser.read_string(read_repository_text(ansible_projection, root=root))
    expected_sections = ansible_config.get("sections", {})
    actual_sections = {
        section: {key: value for key, value in parser.items(section)}
        for section in parser.sections()
    }
    normalized_expected_sections = {
        str(section): {str(key): str(value) for key, value in values.items()}
        for section, values in expected_sections.items()
    }
    if actual_sections != normalized_expected_sections:
        raise ValueError("platform/ansible/ansible.cfg drifted from central toolchain lock")

    bazel = lock.get("native_tool_configs", {}).get("bazel", {})
    version_ref = bazel.get("version_ref")
    expected_bazel = lock["versions"].get(version_ref) if isinstance(version_ref, str) else None
    if not expected_bazel or read_repository_text(root / ".bazelversion", root=root).strip() != expected_bazel:
        raise ValueError(".bazelversion drifted from central toolchain lock")

    expected_bazelrc = [str(line) for line in bazel.get("bazelrc_lines", [])]
    actual_bazelrc = [
        line.rstrip()
        for line in read_repository_text(root / ".bazelrc", root=root).splitlines()
        if line.strip()
    ]
    if actual_bazelrc != expected_bazelrc:
        raise ValueError(".bazelrc drifted from central toolchain lock")

    seed = read_repository_text(root / "config/python/requirements.lock", root=root).lower()
    roots = lock.get("language_contracts", {}).get("python", {}).get("seed_roots", {})
    for package, version_key in roots.items():
        expected = lock["versions"].get(version_key)
        if not expected:
            raise ValueError(f"seed root {package}: missing version key {version_key}")
        if not re.search(
            rf"^{re.escape(package.lower())}=={re.escape(expected.lower())}(?:\s|\\)",
            seed,
            re.MULTILINE,
        ):
            raise ValueError(f"{package}: seed lock drifted from central {version_key}={expected}")


def load_versions(path: Path | None = None) -> dict[str, str]:
    if path is not None:
        return _parse_versions_env(path)
    contract = load_toolchain_lock()
    validate_toolchain_projections(contract)
    return dict(contract["versions"])


def load_contract(path: Path = CONTRACT, *, root: Path | None = None) -> dict:
    return json.loads(read_repository_text(path, root=root))


def validate_contract(
    contract: dict,
    versions: dict[str, str] | None = None,
    *,
    root: Path = ROOT,
    allowed_requirements: list[str] | None = None,
) -> None:
    """Fail closed when a gate command is outside the explicit toolchain closure.

    Gate requirements are intentionally declarative. Trying to infer arbitrary
    subprocesses or shell fragments would create a misleading, incomplete parser.
    Tests and review keep this small authority aligned with executable gate paths.
    """
    versions = (
        versions
        if versions is not None
        else dict(load_toolchain_lock(root / "config/contracts/toolchain-lock.json", root=root)["versions"])
    )
    if allowed_requirements is not None and not isinstance(allowed_requirements, list):
        raise ValueError("toolchain capability requirements must be a list")
    declared_requirements = list(allowed_requirements) if allowed_requirements is not None else sorted(REQUIREMENTS)
    if (
        not declared_requirements
        or any(not isinstance(value, str) for value in declared_requirements)
        or len(declared_requirements) != len(set(declared_requirements))
        or not set(declared_requirements) <= SUPPORTED_REQUIREMENTS
    ):
        raise ValueError("toolchain declares an unsupported capability requirement")
    requirements = set(declared_requirements)
    graph = Graph(contract["capabilities"])
    for name, item in graph.items.items():
        if item.get("requirement") not in requirements:
            raise ValueError(f"{name}: invalid or missing requirement")
    ruff = graph.items.get("ruff")
    if (
        ruff
        and ruff.get("classification") == "managed"
        and ruff.get("provision", {}).get("tags") != "ruff"
    ):
        raise ValueError("ruff: managed provisioning must use the targeted ruff tag")
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
    # Optional agent tooling is declarative only. A real gate may neither
    # name it directly nor acquire it through a runtime dependency/provider.
    def uses_optional_tool(name: str, seen: set[str]) -> bool:
        if name in seen or name not in graph.items:
            return False
        seen.add(name)
        item = graph.items[name]
        if item.get("requirement") == "optional-tooling":
            return True
        dependencies = list(item.get("requires", []))
        if item.get("provider"):
            dependencies.append(item["provider"])
        return any(uses_optional_tool(dependency, seen) for dependency in dependencies)

    for gate, required in contract["gate_requirements"].items():
        if not required:
            raise ValueError(f"gate {gate}: requirements must not be empty")
        unknown = sorted(set(required) - known)
        if unknown:
            raise ValueError(f"gate {gate}: undeclared commands: {', '.join(unknown)}")

        for command in required:
            capability = commands.get(command) or command_aliases.get(command)
            if capability is None:
                if gate == "optional-agent-tooling":
                    raise ValueError(f"{gate}: {command} is not optional tooling")
                continue
            optional = uses_optional_tool(capability, set())
            if gate == "optional-agent-tooling" and not optional:
                raise ValueError(f"{gate}: {command} is not optional tooling")
            if gate != "optional-agent-tooling" and optional:
                raise ValueError(f"gate {gate}: optional tooling cannot enter a real gate: {command}")

    declared = {command for required in contract["gate_requirements"].values() for command in required}
    for relative in contract.get("gate_sources", []):
        source = root / relative
        tree = ast.parse(read_repository_text(source, root=root), filename=relative)
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
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join(
            [*(str(path) for path in MANAGED_BIN_DIRS), env.get("PATH", "")]
        )
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def templ_version_matches(stdout: str, stderr: str, expected: str) -> bool:
    """templ must report one exact v-prefixed version and no diagnostics."""
    return bool(expected) and stdout.strip() == f"v{expected}" and not stderr.strip()


def seed_path_is_private(path: Path, *, ancestor: bool = False) -> bool:
    """Reject replaceable seed paths before executing anything from the venv."""
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return False
    if os.name == "nt":
        return True
    owners = {os.geteuid(), 0} if ancestor else {os.geteuid()}
    if info.st_uid not in owners:
        return False
    if info.st_mode & 0o022:
        return bool(ancestor and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX)
    return not stat.S_ISREG(info.st_mode) or info.st_nlink == 1


def require_private_seed_path(path: Path) -> None:
    existing = []
    cursor = path
    while not cursor.exists() and cursor != cursor.parent:
        cursor = cursor.parent
    while True:
        existing.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    if not all(seed_path_is_private(item, ancestor=True) for item in existing):
        raise RuntimeError(f"unsafe seed path ancestry: {path}")
    if path.exists() and not seed_path_is_private(path):
        raise RuntimeError(f"unsafe qualification seed directory: {path}")


def seed_requirements_with_pip(python: Path, lock_text: str) -> dict[str, str]:
    """Parse active PEP 508 requirements using pip's vendored packaging parser."""
    program = r"""
import json, sys
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
expected = {}
for raw in sys.stdin.read().splitlines():
    text = raw.strip()
    if not text or text.startswith("#") or text.startswith("--") or text.startswith("\\"):
        continue
    if text.endswith("\\"):
        text = text[:-1].strip()
    if text.startswith("--hash="):
        continue
    req = Requirement(text)
    if req.marker and not req.marker.evaluate():
        continue
    pins = list(req.specifier)
    if len(pins) != 1 or pins[0].operator != "==":
        raise SystemExit(f"non-exact seed requirement: {req.name}")
    expected[canonicalize_name(req.name)] = pins[0].version
print(json.dumps(expected, sort_keys=True))
"""
    proc = subprocess.run(
        [str(python), "-I", "-c", program],
        input=lock_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(f"seed lock PEP 508 validation failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return json.loads(proc.stdout)


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
        if parser == "govulncheck":
            match = re.search(r"govulncheck@v([0-9]+(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z.-]+)?)", output)
            return match.group(1) if match else None
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
            elif command == "templ" and not templ_version_matches(proc.stdout, proc.stderr, expected or ""):
                last = Result("FAIL", f"wrong templ version: expected exact v{expected}")
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
            if item["requirement"] == "optional-tooling":
                results[name] = Result("SKIP", "optional tooling is provisioned only by its explicit task")
                continue
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


def seed_environment() -> int:
    versions = load_versions()
    lock_text = SEED_LOCK.read_text(encoding="utf-8")
    require_private_seed_path(SEED_VENV)
    python = SEED_VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        SEED_VENV.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-m", "venv", str(SEED_VENV)], check=True)
    require_private_seed_path(SEED_VENV)
    expected = seed_requirements_with_pip(python, lock_text)
    for package, key in (("ansible-core", "ANSIBLE_CORE_VERSION"), ("pyyaml", "PYYAML_VERSION")):
        canonical = versions[key]
        if expected.get(package) != canonical:
            raise ValueError(f"{package}: lock does not match canonical {key}={canonical}")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes", "-r", str(SEED_LOCK)],
        check=True,
    )
    subprocess.run([str(python), "-m", "pip", "check"], check=True)
    listed = subprocess.run(
        [str(python), "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
        check=True,
        text=True,
        capture_output=True,
    )
    installed = {item["name"].lower().replace("_", "-"): item["version"] for item in json.loads(listed.stdout)}
    for package, version in expected.items():
        if installed.get(package) != version:
            raise RuntimeError(f"seed package drift: {package} expected {version}, got {installed.get(package, 'missing')}")
    ansible = SEED_VENV / ("Scripts/ansible.exe" if os.name == "nt" else "bin/ansible")
    proc = subprocess.run([str(ansible), "--version"], check=True, text=True, capture_output=True)
    if versions["ANSIBLE_CORE_VERSION"] not in proc.stdout.splitlines()[0]:
        raise RuntimeError("seed Ansible version verification failed")
    print(
        f"PASS qualification seed ansible-core={versions['ANSIBLE_CORE_VERSION']} pyyaml={versions['PYYAML_VERSION']}"
    )
    return 0

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("seed", "bootstrap", "env-check"))
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--os")
    parser.add_argument("--arch")
    parser.add_argument("--profile", choices=("static", "runtime"), default="static")
    args = parser.parse_args(argv)
    if args.mode == "seed":
        return seed_environment()
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
        if item["requirement"] == "required-static"
        or (args.profile == "runtime" and item["requirement"] == "optional-runtime")
    }
    required.update(primitive["command"] for primitive in contract.get("platform_primitives", []))
    return 0 if all(results[name].state == "PASS" for name in required) else 1


if __name__ == "__main__":
    raise SystemExit(main())
