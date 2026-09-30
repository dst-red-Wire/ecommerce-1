#!/usr/bin/env python3
"""Read executable qualification definitions exclusively from an exact trusted base.

The target checkout may name capabilities and supply bounded scalar parameters.
It never supplies handlers, command argv, or a qualification policy to execute.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Mapping

import yaml


_POLICY_PATH = "config/contracts/qualification-execution-policy.yaml"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
_KEY = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
_PINNED_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}\Z")
_RESERVED_EXECUTABLE = frozenset({"handler", "command", "commands", "argv"})
_PARAMETER_TYPES = frozenset(
    {
        "positive-integer",
        "tcp-port",
        "nonempty-string",
        "repository-relative-path",
        "sha256-digest",
        "pinned-version",
        "virtualbox-backend",
    }
)
_MAX_POLICY_BYTES = 256_000
_MAX_POLICY_NODES = 50_000
_MAX_POLICY_DEPTH = 32
_MAX_CAPABILITIES = 128
_MAX_REQUESTED = 64
_MAX_PARAMETERS = 16
_MAX_PARAMETER_TEXT = 512


class TrustedQualificationPolicyError(ValueError):
    """The trusted-base policy or the untrusted capability request is invalid."""


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TrustedQualificationPolicyError(
            "exact checkout Git verification failed"
        ) from exc


def _git_text(root: Path, *arguments: str) -> str:
    result = _git(root, *arguments)
    if result.returncode:
        raise TrustedQualificationPolicyError("exact checkout Git verification failed")
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise TrustedQualificationPolicyError("Git identity is not UTF-8") from exc


def _canonical_root(value: Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise TrustedQualificationPolicyError(
            f"{label} must be an absolute non-symlink directory"
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise TrustedQualificationPolicyError(f"{label} is unavailable") from exc
    if resolved != path or not resolved.is_dir():
        raise TrustedQualificationPolicyError(f"{label} must be a canonical directory")
    if _git_text(resolved, "rev-parse", "--show-toplevel") != str(resolved):
        raise TrustedQualificationPolicyError(f"{label} is not a checkout root")
    return resolved


def _check_checkout(root: Path, expected_sha: str, label: str) -> None:
    if _git_text(root, "rev-parse", "HEAD") != expected_sha:
        raise TrustedQualificationPolicyError(f"{label} differs from the exact SHA")
    if _git_text(root, "status", "--porcelain", "--untracked-files=all"):
        raise TrustedQualificationPolicyError(f"{label} checkout is dirty")


def _read_exact_policy(trusted_root: Path) -> bytes:
    """Open every path component without following symlinks, then verify Git bytes."""
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory = None
    descriptor = None
    try:
        directory = os.open(trusted_root, directory_flags)
        for part in _POLICY_PATH.split("/")[:-1]:
            next_directory = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(_POLICY_PATH.split("/")[-1], file_flags, dir_fd=directory)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise TrustedQualificationPolicyError(
                "trusted policy path is not regular or contains a symlink"
            )
        if info.st_size < 1 or info.st_size > _MAX_POLICY_BYTES:
            raise TrustedQualificationPolicyError("trusted policy size exceeds bound")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(_MAX_POLICY_BYTES + 1)
        if len(content) != info.st_size:
            raise TrustedQualificationPolicyError("trusted policy changed during read")
    except OSError as exc:
        raise TrustedQualificationPolicyError(
            "trusted policy path is unavailable, not regular, or contains a symlink"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
    blob = _git(trusted_root, "show", f"HEAD:{_POLICY_PATH}")
    if blob.returncode or blob.stdout != content:
        raise TrustedQualificationPolicyError(
            "trusted policy differs from its exact Git blob"
        )
    return content


class _UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(
        self, node: yaml.nodes.MappingNode, deep: bool = False
    ) -> dict:
        if not isinstance(node, yaml.nodes.MappingNode):
            raise TrustedQualificationPolicyError("trusted policy mapping is invalid")
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise TrustedQualificationPolicyError(
                    "trusted policy keys must be strings"
                )
            if key in result:
                raise TrustedQualificationPolicyError(
                    "trusted policy has duplicate keys"
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _bounded_tree(value: object, *, depth: int = 0, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > _MAX_POLICY_DEPTH:
        raise TrustedQualificationPolicyError("trusted policy structure exceeds bound")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 200:
                raise TrustedQualificationPolicyError(
                    "trusted policy has an invalid key"
                )
            _bounded_tree(item, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        for item in value:
            _bounded_tree(item, depth=depth + 1, budget=budget)
    elif isinstance(value, str):
        if len(value) > 8192 or "\x00" in value:
            raise TrustedQualificationPolicyError(
                "trusted policy has an invalid scalar"
            )
    elif value is not None and type(value) not in (bool, int, float):
        raise TrustedQualificationPolicyError(
            "trusted policy has an unsupported YAML value"
        )


def _registry(policy: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    runtime = policy.get("runtime_orchestration")
    if not isinstance(runtime, Mapping):
        raise TrustedQualificationPolicyError("trusted runtime registry is missing")
    capabilities = runtime.get("capabilities")
    if not isinstance(capabilities, Mapping) or not capabilities:
        raise TrustedQualificationPolicyError(
            "trusted runtime capabilities are missing"
        )
    preflight = policy.get("work_item_preflight", {})
    if not isinstance(preflight, Mapping):
        raise TrustedQualificationPolicyError("trusted preflight registry is invalid")
    additional = preflight.get("additional_capabilities", {})
    if not isinstance(additional, Mapping):
        raise TrustedQualificationPolicyError(
            "trusted additional capabilities are invalid"
        )
    if len(capabilities) + len(additional) > _MAX_CAPABILITIES:
        raise TrustedQualificationPolicyError(
            "trusted capability registry exceeds bound"
        )
    if set(capabilities) & set(additional):
        raise TrustedQualificationPolicyError(
            "trusted capability registry has duplicate IDs"
        )
    combined = {**capabilities, **additional}
    for name, spec in combined.items():
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise TrustedQualificationPolicyError("trusted capability ID is invalid")
        if not isinstance(spec, Mapping):
            raise TrustedQualificationPolicyError(
                f"trusted capability {name} is invalid"
            )
        required = spec.get("required_parameters", [])
        types = spec.get("parameter_types", {})
        if (
            not isinstance(required, list)
            or len(required) > _MAX_PARAMETERS
            or any(
                not isinstance(key, str) or _KEY.fullmatch(key) is None
                for key in required
            )
            or len(required) != len(set(required))
            or not isinstance(types, Mapping)
            or set(types) != set(required)
            or any(kind not in _PARAMETER_TYPES for kind in types.values())
        ):
            raise TrustedQualificationPolicyError(
                f"trusted capability {name} parameter schema is invalid"
            )
    return combined


def load_trusted_execution_policy(
    trusted_root: Path,
    target_root: Path,
    base_sha: str,
    head_sha: str,
) -> dict:
    """Load policy bytes from a clean exact-base checkout, never from PR HEAD."""
    if not isinstance(base_sha, str) or _SHA.fullmatch(base_sha) is None:
        raise TrustedQualificationPolicyError("full exact base SHA required")
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        raise TrustedQualificationPolicyError("full exact head SHA required")
    base = _canonical_root(trusted_root, "trusted base")
    target = _canonical_root(target_root, "target head")
    if base == target:
        raise TrustedQualificationPolicyError(
            "trusted base and target head must be distinct"
        )
    _check_checkout(base, base_sha, "trusted base")
    _check_checkout(target, head_sha, "target head")
    if _git(target, "merge-base", "--is-ancestor", base_sha, head_sha).returncode:
        raise TrustedQualificationPolicyError(
            "trusted base is not an ancestor of target head"
        )
    raw = _read_exact_policy(base)
    try:
        policy = yaml.load(raw, Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, UnicodeError, TrustedQualificationPolicyError) as exc:
        raise TrustedQualificationPolicyError("trusted policy YAML is invalid") from exc
    if not isinstance(policy, dict):
        raise TrustedQualificationPolicyError("trusted policy must be a mapping")
    _bounded_tree(policy, budget=[_MAX_POLICY_NODES])
    if (
        policy.get("version") != 1
        or policy.get("kind") != "QualificationExecutionPolicy"
        or policy.get("status") != "enforced"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
    ):
        raise TrustedQualificationPolicyError("trusted policy envelope is invalid")
    _registry(policy)
    return policy


def _validate_parameter(kind: str, value: object, name: str) -> object:
    if kind in {"positive-integer", "tcp-port"}:
        limit = 65535 if kind == "tcp-port" else 2**31 - 1
        if type(value) is not int or not 1 <= value <= limit:
            raise TrustedQualificationPolicyError(f"{name} must be a bounded integer")
        return value
    if not isinstance(value, str) or not value or len(value) > _MAX_PARAMETER_TEXT:
        raise TrustedQualificationPolicyError(f"{name} must be a bounded string")
    if "\x00" in value or any(ord(character) < 32 for character in value):
        raise TrustedQualificationPolicyError(f"{name} contains a control character")
    if kind == "repository-relative-path":
        parts = PurePosixPath(value)
        if (
            parts.is_absolute()
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            raise TrustedQualificationPolicyError(
                f"{name} must be a repository-relative path"
            )
    elif kind == "sha256-digest" and _DIGEST.fullmatch(value) is None:
        raise TrustedQualificationPolicyError(f"{name} must be a SHA-256 digest")
    elif kind == "pinned-version" and _PINNED_VERSION.fullmatch(value) is None:
        raise TrustedQualificationPolicyError(f"{name} must be a pinned version")
    elif kind == "virtualbox-backend" and value not in {"NEM", "NATIVE_VTX"}:
        raise TrustedQualificationPolicyError(f"{name} must be an approved backend")
    return value


def validate_trusted_capability_requests(
    policy: Mapping[str, object],
    required_capabilities: list[str],
    capability_parameters: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    """Validate HEAD requests against trusted schemas without copying executable keys."""
    registry = _registry(policy)
    if (
        type(required_capabilities) is not list
        or len(required_capabilities) > _MAX_REQUESTED
        or any(
            not isinstance(name, str) or name not in registry
            for name in required_capabilities
        )
        or len(required_capabilities) != len(set(required_capabilities))
    ):
        raise TrustedQualificationPolicyError(
            "requested capabilities are unknown, duplicate, or unbounded"
        )
    parameters = capability_parameters if capability_parameters is not None else {}
    if not isinstance(parameters, Mapping) or set(parameters) - set(
        required_capabilities
    ):
        raise TrustedQualificationPolicyError(
            "unrequested capability parameters are forbidden"
        )
    validated: dict[str, dict[str, object]] = {}
    for name in required_capabilities:
        supplied = parameters.get(name, {})
        if not isinstance(supplied, Mapping) or len(supplied) > _MAX_PARAMETERS:
            raise TrustedQualificationPolicyError(
                f"{name} parameters are invalid or unbounded"
            )
        if any(
            not isinstance(key, str) or key.lower() in _RESERVED_EXECUTABLE
            for key in supplied
        ):
            raise TrustedQualificationPolicyError(
                f"{name} supplies executable policy fields"
            )
        schema = registry[name]
        required = schema.get("required_parameters", [])
        types = schema.get("parameter_types", {})
        if set(supplied) != set(required):
            raise TrustedQualificationPolicyError(
                f"{name} parameters differ from trusted schema"
            )
        validated[name] = {
            key: _validate_parameter(types[key], supplied[key], f"{name}.{key}")
            for key in required
        }
    return validated
