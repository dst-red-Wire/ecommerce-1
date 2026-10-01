#!/usr/bin/env python3
"""Read-only first-class preflight for one exact work item source identity.

The exact base owns the capability registry and executable probe parameters.
HEAD supplies capability IDs and bounded data only. Runtime probes reuse
runtime_orchestration.capture/preflight; prepare/restore are never called here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

import yaml

try:
    from . import runtime_orchestration as runtime
except ImportError:
    import runtime_orchestration as runtime


_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPACITY = frozenset({"cpu-capacity", "memory-capacity", "disk-capacity"})
_POLICY_PATH = "config/contracts/qualification-execution-policy.yaml"
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
_EXECUTABLE_PARAMETER_KEYS = frozenset(
    {
        "command",
        "commands",
        "handler",
        "operations",
        "requires",
        "parameters",
        "timeout_seconds",
        "output_regex",
        "environment",
        "env",
    }
)
_MAX_PARAMETER_INTEGER = 2**63 - 1
_MAX_PARAMETER_STRING = 4096
_MAX_PROOF_BYTES = 1024 * 1024
_CI_EVIDENCE_PATH = "config/contracts/ci-evidence.yaml"
_PRODUCER_PATH = "scripts/delivery_preflight.py"
_RUNTIME_PATH = "scripts/runtime_orchestration.py"


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_LITERAL_PATHSPECS="1")
    return environment


def _base_blob(root: Path, base_sha: str, relative: str) -> bytes:
    if _SHA.fullmatch(base_sha) is None:
        raise ValueError("full exact producer base SHA required")
    command = [
        "/usr/bin/git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(root),
    ]
    tree = subprocess.run(
        [*command, "ls-tree", "-z", base_sha, "--", relative],
        env=_git_environment(),
        capture_output=True,
        check=False,
        timeout=15,
    )
    metadata, separator, name = tree.stdout.partition(b"\t")
    fields = metadata.split()
    if (
        tree.returncode
        or not separator
        or name != relative.encode() + b"\0"
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
    ):
        raise ValueError("base producer input must be a regular Git blob: " + relative)
    blob = subprocess.run(
        [*command, "cat-file", "blob", fields[2].decode("ascii")],
        env=_git_environment(),
        capture_output=True,
        check=False,
        timeout=15,
    )
    if blob.returncode or len(blob.stdout) > 16 * 1024 * 1024:
        raise ValueError("base producer input is unavailable or too large")
    return blob.stdout


def _producer_fingerprint(root: Path, base_sha: str) -> dict:
    def digest(relative: str) -> str:
        return (
            "sha256:" + hashlib.sha256(_base_blob(root, base_sha, relative)).hexdigest()
        )

    return {
        "source": "exact-pr-base-sha",
        "path": _PRODUCER_PATH,
        "sha256": digest(_PRODUCER_PATH),
        "runtime_sha256": digest(_RUNTIME_PATH),
        "policy_sha256": digest(_POLICY_PATH),
    }


def _execution_authority(root: Path, base_sha: str, head_sha: str) -> str:
    if not any(
        key.startswith("REPOCTL_TRUSTED_") and value.strip()
        for key, value in os.environ.items()
    ):
        return "diagnostic"
    names = (
        "WRAPPER",
        "CONTROLLER",
        "POLICY_ROOT",
        "BASE_SHA",
        "TARGET_ROOT",
        "HEAD_SHA",
        "PR_NUMBER",
    )
    values = {
        name: os.environ.get("REPOCTL_TRUSTED_" + name, "").strip() for name in names
    }
    if (
        not all(values.values())
        or values["BASE_SHA"] != base_sha
        or values["HEAD_SHA"] != head_sha
        or values["TARGET_ROOT"] != str(root)
        or not values["PR_NUMBER"].isdigit()
        or int(values["PR_NUMBER"]) < 1
    ):
        raise ValueError("complete exact-base preflight execution binding required")
    trusted = Path(values["POLICY_ROOT"])
    if not trusted.is_absolute() or ".." in trusted.parts:
        raise ValueError("exact-base producer root is not canonical")
    if (
        Path(__file__).absolute() != trusted / _PRODUCER_PATH
        or Path(runtime.__file__).absolute() != trusted / _RUNTIME_PATH
        or values["CONTROLLER"] != str(trusted / "scripts/repoctl.py")
        or values["WRAPPER"] != str(trusted / "scripts/repository_delivery.py")
    ):
        raise ValueError("preflight is not executing its exact-base producer")
    try:
        from .capability_bootstrap import read_repository_text
    except ImportError:
        from capability_bootstrap import read_repository_text
    if (
        Path(read_repository_text.__globals__["__file__"]).absolute()
        != trusted / "scripts/capability_bootstrap.py"
    ):
        raise ValueError("preflight reader is not the exact-base dependency")
    for relative in (
        _PRODUCER_PATH,
        _RUNTIME_PATH,
        "scripts/repoctl.py",
        "scripts/repository_delivery.py",
        "scripts/capability_bootstrap.py",
    ):
        read_repository_text(trusted / relative, root=trusted)
    return "exact-base"


def _record_bytes(root: Path, path: Path) -> bytes:
    """Capture one bounded regular file through no-follow descriptors."""
    candidate = path if path.is_absolute() else root / path
    if ".." in candidate.parts or not candidate.is_relative_to(root):
        raise ValueError("preflight evidence path escapes repository")
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise ValueError("preflight evidence requires no-follow descriptor support")
    directory = descriptor = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(candidate.anchor, flags)
        for part in candidate.parts[1:-1]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_PROOF_BYTES:
            raise ValueError("preflight evidence must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(_MAX_PROOF_BYTES + 1)
        after = os.fstat(descriptor)

        def identity(info):
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if len(content) != before.st_size or identity(before) != identity(after):
            raise ValueError("preflight evidence changed during capture")
        return content
    except OSError as exc:
        raise ValueError(
            "preflight evidence missing, unsafe, or contains a symlink"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def load_base_policy(root: Path, expected_base_sha: str) -> dict:
    """Load registry bytes from the exact base, never the target worktree.

    Trusted wrappers bind their base checkout via the existing root/SHA pair.
    An ordinary local diagnosis reads the same immutable Git object directly;
    it creates no trusted execution or review authority.
    """
    if _SHA.fullmatch(expected_base_sha) is None:
        raise ValueError("full exact policy base SHA required")
    policy_root_value = os.environ.get("REPOCTL_TRUSTED_POLICY_ROOT", "").strip()
    bound_base = os.environ.get("REPOCTL_TRUSTED_BASE_SHA", "").strip()
    if any(
        key.startswith("REPOCTL_TRUSTED_") and value.strip()
        for key, value in os.environ.items()
    ):
        if not policy_root_value or bound_base != expected_base_sha:
            raise ValueError("trusted policy root and exact base binding required")
        policy_root = Path(policy_root_value)
        if not policy_root.is_absolute() or ".." in policy_root.parts:
            raise ValueError("trusted policy root must be canonical")
        try:
            from .capability_bootstrap import read_repository_text
        except ImportError:
            from capability_bootstrap import read_repository_text
        content = read_repository_text(policy_root / _POLICY_PATH, root=policy_root)
    else:
        content = _base_blob(root, expected_base_sha, _POLICY_PATH).decode("utf-8")
    policy = yaml.safe_load(content)
    if not isinstance(policy, dict):
        raise TypeError("base capability policy must be a mapping")
    return policy


def _validate_parameters(name: str, schema: object, supplied: object) -> None:
    if not isinstance(schema, Mapping) or not isinstance(supplied, Mapping):
        raise TypeError(f"{name}: capability schema and parameters must be mappings")
    required = schema.get("required_parameters", [])
    types = schema.get("parameter_types", {})
    if (
        not isinstance(required, list)
        or any(not isinstance(key, str) or not key for key in required)
        or len(required) != len(set(required))
        or not isinstance(types, Mapping)
        or set(types) != set(required)
        or any(kind not in _PARAMETER_TYPES for kind in types.values())
        or set(required) & _EXECUTABLE_PARAMETER_KEYS
    ):
        raise ValueError(f"{name}: base parameter schema invalid")
    if set(supplied) != set(required):
        raise ValueError(f"{name}: parameters differ from the base declaration")
    for key, value in supplied.items():
        kind = types[key]
        if kind == "positive-integer":
            if type(value) is not int or not 1 <= value <= _MAX_PARAMETER_INTEGER:
                raise ValueError(f"{name}.{key}: bounded positive integer required")
        elif kind == "tcp-port":
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError(f"{name}.{key}: TCP port required")
        else:
            if (
                not isinstance(value, str)
                or not value
                or len(value) > _MAX_PARAMETER_STRING
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in value
                )
            ):
                raise ValueError(f"{name}.{key}: bounded nonempty string required")
            if kind == "repository-relative-path" and (
                "\\" in value
                or PurePosixPath(value).is_absolute()
                or any(part in ("", ".", "..") for part in value.split("/"))
            ):
                raise ValueError(f"{name}.{key}: repository-relative path required")
            if kind == "sha256-digest" and _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{name}.{key}: SHA-256 digest required")
            if (
                kind == "pinned-version"
                and re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", value) is None
            ):
                raise ValueError(f"{name}.{key}: pinned version required")
            if kind == "virtualbox-backend" and value not in {"NEM", "NATIVE_VTX"}:
                raise ValueError(f"{name}.{key}: known backend required")


def _git(root: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            "/usr/bin/git",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=root,
        env=_git_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    return proc.returncode, proc.stdout.strip()


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _safe_file(root: Path, relative: str) -> Path | None:
    if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
        return None
    parts = PurePosixPath(relative)
    if (
        parts.is_absolute()
        or not relative
        or any(part in ("", ".", "..") for part in relative.split("/"))
    ):
        return None
    candidate = root.joinpath(*parts.parts)
    current = root
    for part in parts.parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _bounded_command(
    argv: list[str], timeout: int = 5
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv, check=False, text=True, capture_output=True, timeout=timeout
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _probe_special(
    root: Path, name: str, parameters: Mapping[str, object], head_sha: str
) -> tuple[bool, str]:
    """Only read host state or verify existing bytes. Never prepare a resource."""
    if name == "packer-runtime":
        version = parameters.get("version")
        if not isinstance(version, str) or not re.fullmatch(
            r"[0-9]+(?:\.[0-9]+){2}", version
        ):
            return False, "pinned Packer version required"
        proc = _bounded_command(["packer", "version"])
        return (
            proc is not None
            and proc.returncode == 0
            and bool(re.search(rf"\b{re.escape(version)}\b", proc.stdout)),
            "Packer version unavailable or differs from pin",
        )
    if name == "ssh-identity":
        relative = parameters.get("path")
        if not isinstance(relative, str):
            return False, "SSH identity path required"
        # The key may be outside the repository, but its contents are never read.
        path = Path(relative).expanduser()
        try:
            info = path.lstat()
        except OSError:
            return False, "SSH identity unavailable"
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0,
            "SSH identity ownership or permissions invalid",
        )
    if name == "network":
        host, port = parameters.get("host"), parameters.get("port")
        if (
            not isinstance(host, str)
            or not host
            or type(port) is not int
            or not 1 <= port <= 65535
        ):
            return False, "network host and port required"
        try:
            with socket.create_connection((host, port), timeout=3):
                return True, "network endpoint reachable"
        except OSError:
            return False, "network endpoint unavailable"
    if name == "toolchain-pinned":
        expected = parameters.get("sha256")
        path = _safe_file(root, "config/contracts/toolchain-lock.json")
        if (
            path is None
            or not isinstance(expected, str)
            or _DIGEST.fullmatch(expected) is None
        ):
            return False, "pinned toolchain digest required"
        if _digest(path) != expected:
            return False, "toolchain digest differs"
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False, "toolchain lock unreadable"

        def mutable(value: object) -> bool:
            if isinstance(value, dict):
                return any(mutable(item) for item in value.values())
            if isinstance(value, list):
                return any(mutable(item) for item in value)
            return isinstance(value, str) and value.strip().lower() in {
                "latest",
                "main",
                "master",
                "*",
            }

        return not mutable(document), "mutable toolchain version forbidden"
    if name == "artifact-available":
        relative, expected = parameters.get("path"), parameters.get("sha256")
        path = _safe_file(root, relative) if isinstance(relative, str) else None
        if (
            path is None
            or not isinstance(expected, str)
            or _DIGEST.fullmatch(expected) is None
        ):
            return False, "artifact path and digest required"
        return _digest(path) == expected, "artifact missing or digest mismatch"
    if name == "windows-admin":
        proc = _bounded_command(["cmd.exe", "/c", "whoami", "/groups"])
        return (
            proc is not None and proc.returncode == 0 and "S-1-16-12288" in proc.stdout,
            "elevated Windows token unavailable",
        )
    if name == "linux-admin":
        if os.geteuid() == 0:
            return True, "root identity available"
        proc = _bounded_command(["sudo", "-n", "true"])
        return (
            proc is not None and proc.returncode == 0,
            "noninteractive sudo unavailable",
        )
    if name == "virtualbox-backend":
        relative, expected, backend = (
            parameters.get("evidence_path"),
            parameters.get("sha256"),
            parameters.get("backend"),
        )
        path = _safe_file(root, relative) if isinstance(relative, str) else None
        if (
            path is None
            or not isinstance(expected, str)
            or _DIGEST.fullmatch(expected) is None
        ):
            return False, "backend probe evidence and digest required"
        if backend not in {"NEM", "NATIVE_VTX"} or _digest(path) != expected:
            return False, "backend proof digest or requested backend invalid"
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False, "backend proof unreadable"
        return (
            isinstance(evidence, dict)
            and evidence.get("status") == "PASS"
            and evidence.get("source_sha") == head_sha
            and evidence.get("virtualbox_backend") == backend
            and evidence.get("capture") == "PASS"
            and evidence.get("restore") == "PASS"
            and evidence.get("restore_verification") == "PASS",
            "exact source/backend and recovery proof required",
        )
    return False, "unknown preflight capability"


def run_preflight(
    root: Path,
    *,
    expected_head_sha: str,
    expected_base_sha: str,
    expected_branch: str,
    required_capabilities: list[str],
    capability_parameters: Mapping[str, Mapping[str, object]] | None = None,
    driver: runtime.CapabilityDriver | None = None,
    expected_head_tree_sha: str | None = None,
    expected_package_id: str | None = None,
    expected_package_digest: str | None = None,
    expected_issue: int | None = None,
    expected_milestone: str | None = None,
) -> dict:
    """Return PASS, BLOCKED_RUNTIME, or FAIL without any machine mutation."""
    parameters = capability_parameters if capability_parameters is not None else {}
    result = {
        "schema_version": 2,
        "status": "FAIL",
        "source_sha": expected_head_sha,
        "base_sha": expected_base_sha,
        "branch": expected_branch,
        "capacity": "FAIL",
        "environment": "FAIL",
        "required_capabilities": list(required_capabilities),
        "checks": {},
        "reason": "",
        "mutation_performed": False,
    }
    if any(
        not isinstance(value, str) or _SHA.fullmatch(value) is None
        for value in (expected_head_sha, expected_base_sha)
    ):
        result["reason"] = "full exact source and base SHA required"
        return result
    if (
        not isinstance(expected_branch, str)
        or not expected_branch
        or expected_branch in {"main", "master"}
    ):
        result["reason"] = "exact feature branch required"
        return result
    if (
        not isinstance(required_capabilities, list)
        or len(required_capabilities) > 128
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,127}", name) is None
            for name in required_capabilities
        )
        or len(required_capabilities) != len(set(required_capabilities))
        or not isinstance(parameters, Mapping)
    ):
        result["reason"] = "unique required capabilities list required"
        return result
    root = root.resolve()
    tree_code, tree_sha = _git(root, "rev-parse", expected_head_sha + "^{tree}")
    result["head_tree_sha"] = tree_sha
    if tree_code or (
        expected_head_tree_sha is not None and expected_head_tree_sha != tree_sha
    ):
        result["reason"] = "exact source tree mismatch"
        return result
    result.update(
        capability_parameters={
            name: dict(parameters.get(name, {}))
            for name in required_capabilities
            if isinstance(parameters.get(name, {}), Mapping)
        },
        work_package_id=expected_package_id,
        work_package_digest=expected_package_digest,
        work_item_issue=expected_issue,
        milestone=expected_milestone,
    )
    source_checks = {
        "tree": (_git(root, "rev-parse", "HEAD^{tree}"), tree_sha),
        "head": (_git(root, "rev-parse", "HEAD"), expected_head_sha),
        "base": (_git(root, "rev-parse", "origin/main"), expected_base_sha),
        "branch": (_git(root, "branch", "--show-current"), expected_branch),
        "worktree": (_git(root, "status", "--porcelain", "--untracked-files=all"), ""),
    }
    for name, ((code, observed), expected) in source_checks.items():
        result["checks"][name] = (
            "PASS" if code == 0 and observed == expected else "FAIL"
        )
    if any(result["checks"][name] != "PASS" for name in source_checks):
        result["reason"] = "source identity or clean worktree mismatch"
        return result
    try:
        policy = load_base_policy(root, expected_base_sha)
        runtime_policy = policy["runtime_orchestration"]
        additional = policy["work_item_preflight"]["additional_capabilities"]
        planner = runtime.RuntimePlanner(runtime_policy)
        if not isinstance(additional, dict):
            raise TypeError("additional capability registry invalid")
        allowed = set(planner.specs) | set(additional)
        if any(name not in allowed for name in required_capabilities):
            raise ValueError("unknown required capability")
        if set(parameters) - set(required_capabilities):
            raise ValueError("parameters for unrequested capability")
        schemas = {**runtime_policy["capabilities"], **additional}
        for name in required_capabilities:
            supplied = parameters.get(name, {})
            _validate_parameters(name, schemas[name], supplied)
        requests = [
            runtime.CapabilityRequest(name, parameters.get(name, {}))
            for name in required_capabilities
            if name in planner.specs
        ]
        plan = planner.resolve(requests)
        result["producer"] = _producer_fingerprint(root, expected_base_sha)
        result["execution_authority"] = _execution_authority(
            root, expected_base_sha, expected_head_sha
        )
        if driver is not None:
            result["execution_authority"] = "diagnostic"
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        subprocess.TimeoutExpired,
        yaml.YAMLError,
        runtime.RuntimePolicyError,
    ) as exc:
        result["reason"] = str(exc)
        return result
    probe = driver or runtime.BuiltinCapabilityDriver()
    blocked = []
    for capability in plan:
        try:
            state = probe.capture(capability)
            probe.preflight(capability, state)
            result["checks"][capability.spec.name] = "PASS"
        except runtime.RuntimeBlocked as exc:
            result["checks"][capability.spec.name] = "BLOCKED_RUNTIME"
            blocked.append(f"{capability.spec.name}: {exc}")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            result["checks"][capability.spec.name] = "FAIL"
            result["reason"] = (
                f"{capability.spec.name}: probe failed: {type(exc).__name__}"
            )
    for name in sorted(set(required_capabilities) & set(additional)):
        try:
            passed, reason = _probe_special(
                root, name, parameters.get(name, {}), expected_head_sha
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            passed, reason = False, f"probe error: {type(exc).__name__}"
        result["checks"][name] = "PASS" if passed else "BLOCKED_RUNTIME"
        if not passed:
            blocked.append(f"{name}: {reason}")
    for name, arguments, expected in (
        ("head", ("rev-parse", "HEAD"), expected_head_sha),
        ("tree", ("rev-parse", "HEAD^{tree}"), tree_sha),
        ("base", ("rev-parse", "origin/main"), expected_base_sha),
        ("branch", ("branch", "--show-current"), expected_branch),
        ("worktree", ("status", "--porcelain", "--untracked-files=all"), ""),
    ):
        code, observed = _git(root, *arguments)
        if code or observed != expected:
            result["checks"][name] = "FAIL"
            result["reason"] = "source identity changed during preflight"
    result["generated_at_epoch"] = int(time.time())
    statuses = list(result["checks"].values())
    capacity_names = set(required_capabilities) & _CAPACITY
    result["capacity"] = (
        "BLOCKED_RUNTIME"
        if any(
            result["checks"].get(name) == "BLOCKED_RUNTIME" for name in capacity_names
        )
        else "FAIL"
        if any(result["checks"].get(name) == "FAIL" for name in capacity_names)
        else "PASS"
    )
    environment_names = set(required_capabilities) - _CAPACITY
    result["environment"] = (
        "BLOCKED_RUNTIME"
        if any(
            result["checks"].get(name) == "BLOCKED_RUNTIME"
            for name in environment_names
        )
        else "FAIL"
        if any(result["checks"].get(name) == "FAIL" for name in environment_names)
        else "PASS"
    )
    if "FAIL" in statuses or result["reason"]:
        result["status"] = "FAIL"
    elif "BLOCKED_RUNTIME" in statuses:
        result["status"] = "BLOCKED_RUNTIME"
        result["reason"] = "; ".join(blocked)
    else:
        result["status"] = "PASS"
    return result


def _evidence_digest(payload: Mapping[str, object]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    )


def _evidence_directory(root: Path, *parts: str) -> Path:
    current = root.resolve()
    for part in parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symlink preflight evidence directory: {current}")
        current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError(
                f"preflight evidence directory is not a directory: {current}"
            )
    return current


def _atomic_evidence_write(destination: Path, content: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".preflight-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_preflight(root: Path, result: Mapping[str, object]) -> Path:
    """Persist a digest-bound snapshot, retaining every replaced version."""
    head = result.get("source_sha")
    if not isinstance(head, str) or _SHA.fullmatch(head) is None:
        raise ValueError("source_sha required")
    root = root.resolve()
    directory = _evidence_directory(root, ".context", "evidence", "preflight")
    destination = directory / f"{head}.json"
    if destination.is_symlink():
        raise ValueError("symlink preflight evidence file")
    payload = dict(result)
    payload.pop("evidence_digest", None)
    payload["evidence_digest"] = _evidence_digest(payload)
    content = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if destination.exists():
        if not destination.is_file():
            raise ValueError("preflight evidence path is not a regular file")
        previous = _record_bytes(root, destination)
        if previous == content:
            return destination
        previous_digest = hashlib.sha256(previous).hexdigest()
        history = _evidence_directory(
            root, ".context", "evidence", "preflight", "history", head
        )
        archive = history / f"{previous_digest}.json"
        if archive.is_symlink():
            raise ValueError("symlink preflight history file")
        if archive.exists():
            if not archive.is_file() or _record_bytes(root, archive) != previous:
                raise ValueError("preflight history digest collision")
        else:
            _atomic_evidence_write(archive, previous)
    _atomic_evidence_write(destination, content)
    return destination


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate preflight evidence key: {key}")
        value[key] = item
    return value


def _freshness_limit(root: Path, base_sha: str) -> int:
    policy = yaml.safe_load(_base_blob(root, base_sha, _CI_EVIDENCE_PATH))
    age = (
        policy.get("evidence", {}).get("maximum_local_age_seconds")
        if isinstance(policy, dict)
        else None
    )
    if type(age) is not int or age <= 0:
        raise ValueError("exact-base preflight freshness policy is invalid")
    return age


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite preflight evidence value: " + value)


def _verify_record(
    root: Path,
    content: bytes,
    *,
    expected_head_sha: str,
    expected_head_tree_sha: str,
    expected_base_sha: str,
    expected_branch: str,
    expected_package_id: str,
    expected_package_digest: str,
    expected_issue: int,
    expected_milestone: str,
    expected_capabilities: list[str],
    expected_capability_parameters: Mapping[str, Mapping[str, object]] | None,
    at_epoch: float,
) -> dict:
    for label, value in (
        ("head SHA", expected_head_sha),
        ("head tree SHA", expected_head_tree_sha),
        ("base SHA", expected_base_sha),
    ):
        if not isinstance(value, str) or _SHA.fullmatch(value) is None:
            raise ValueError(f"full exact {label} required")
    if (
        not isinstance(expected_branch, str)
        or not expected_branch
        or expected_branch in {"main", "master"}
        or not isinstance(expected_package_id, str)
        or not expected_package_id
        or not isinstance(expected_milestone, str)
        or not expected_milestone
        or type(expected_issue) is not int
        or expected_issue < 1
        or not isinstance(expected_package_digest, str)
        or _DIGEST.fullmatch(expected_package_digest) is None
    ):
        raise ValueError("complete work package and branch identity required")
    parameters = (
        expected_capability_parameters
        if expected_capability_parameters is not None
        else {}
    )
    if (
        not isinstance(expected_capabilities, list)
        or len(expected_capabilities) > 128
        or any(
            not isinstance(item, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,127}", item) is None
            for item in expected_capabilities
        )
        or len(expected_capabilities) != len(set(expected_capabilities))
        or not isinstance(parameters, Mapping)
        or set(parameters) - set(expected_capabilities)
    ):
        raise ValueError("unique expected capabilities and bounded parameters required")
    try:
        payload = json.loads(
            content,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("preflight evidence is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("preflight evidence must be a JSON object")  # noqa: TRY004
    declared_digest = payload.get("evidence_digest")
    if (
        not isinstance(declared_digest, str)
        or _DIGEST.fullmatch(declared_digest) is None
    ):
        raise ValueError("preflight evidence digest is missing or malformed")
    unsigned = {
        key: value for key, value in payload.items() if key != "evidence_digest"
    }
    if _evidence_digest(unsigned) != declared_digest:
        raise ValueError("preflight evidence digest mismatch")
    policy = yaml.safe_load(_base_blob(root, expected_base_sha, _POLICY_PATH))
    runtime_policy = policy["runtime_orchestration"]
    additional = policy["work_item_preflight"]["additional_capabilities"]
    planner = runtime.RuntimePlanner(runtime_policy)
    schemas = {**runtime_policy["capabilities"], **additional}
    normalized = {}
    for name in expected_capabilities:
        if name not in schemas:
            raise ValueError("unknown expected preflight capability")
        _validate_parameters(name, schemas[name], parameters.get(name, {}))
        normalized[name] = dict(parameters.get(name, {}))
    plan = planner.resolve(
        [
            runtime.CapabilityRequest(name, normalized[name])
            for name in expected_capabilities
            if name in planner.specs
        ]
    )
    expected = {
        "source_sha": expected_head_sha,
        "head_tree_sha": expected_head_tree_sha,
        "base_sha": expected_base_sha,
        "branch": expected_branch,
        "work_package_id": expected_package_id,
        "work_package_digest": expected_package_digest,
        "work_item_issue": expected_issue,
        "milestone": expected_milestone,
        "required_capabilities": expected_capabilities,
        "capability_parameters": normalized,
        "producer": _producer_fingerprint(root, expected_base_sha),
        "execution_authority": "exact-base",
    }
    for field, value in expected.items():
        if type(payload.get(field)) is not type(value) or _evidence_digest(
            {"value": payload[field]}
        ) != _evidence_digest({"value": value}):
            raise ValueError(f"preflight {field} differs from expected identity")
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 2
        or payload.get("status") != "PASS"
        or payload.get("capacity") != "PASS"
        or payload.get("environment") != "PASS"
        or payload.get("reason") != ""
        or payload.get("mutation_performed") is not False
    ):
        raise ValueError("preflight evidence is not a non-mutating PASS")
    generated = payload.get("generated_at_epoch")
    if (
        type(generated) is not int
        or generated <= 0
        or isinstance(at_epoch, bool)
        or not isinstance(at_epoch, (int, float))
        or not math.isfinite(at_epoch)
        or at_epoch <= 0
        or generated > at_epoch
        or at_epoch - generated > _freshness_limit(root, expected_base_sha)
    ):
        raise ValueError(
            "preflight evidence is stale, future-dated or has invalid freshness"
        )
    checks = payload.get("checks")
    required_checks = {
        "head",
        "tree",
        "base",
        "branch",
        "worktree",
        *expected_capabilities,
        *(capability.spec.name for capability in plan),
    }
    if (
        not isinstance(checks, dict)
        or not required_checks.issubset(checks)
        or any(
            not isinstance(key, str) or value != "PASS" for key, value in checks.items()
        )
    ):
        raise ValueError("preflight evidence checks are incomplete or not PASS")
    if _git(root, "rev-parse", expected_head_sha + "^{tree}") != (
        0,
        expected_head_tree_sha,
    ):
        raise ValueError("preflight historical head tree differs")
    if (
        _git(root, "merge-base", "--is-ancestor", expected_base_sha, expected_head_sha)[
            0
        ]
        != 0
    ):
        raise ValueError("preflight exact base is not an ancestor of HEAD")
    return payload


def _receipt(payload: dict, content: bytes, relative: str, *, historical: bool) -> dict:
    return {
        "status": "PASS",
        "producer": "scripts/delivery_preflight.py:run_preflight",
        "authority": "historical-preflight-verification"
        if historical
        else "current-preflight-verification",
        "head_sha": payload["source_sha"],
        "head_tree_sha": payload["head_tree_sha"],
        "base_sha": payload["base_sha"],
        "work_package_id": payload["work_package_id"],
        "work_package_digest": payload["work_package_digest"],
        "work_item_issue": payload["work_item_issue"],
        "milestone": payload["milestone"],
        "required_capabilities": payload["required_capabilities"],
        "capability_parameters": payload["capability_parameters"],
        "evidence_path": relative,
        "evidence_digest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "producer_fingerprint": _evidence_digest(payload["producer"]),
        "producer_identity": payload["producer"],
        "generated_at_epoch": payload["generated_at_epoch"],
        "historical_verification": "VERIFIED" if historical else "NOT_APPLICABLE",
        "payload": payload,
    }


def verify_preflight(
    root: Path,
    *,
    expected_head_sha: str,
    expected_base_sha: str,
    expected_branch: str,
    expected_package_id: str,
    expected_package_digest: str,
    expected_issue: int,
    expected_milestone: str,
    expected_capabilities: list[str],
    expected_head_tree_sha: str | None = None,
    expected_capability_parameters: Mapping[str, Mapping[str, object]] | None = None,
    expected_result: Mapping[str, object] | None = None,
) -> dict:
    """Verify one captured proof; merge callers bind the fresh BASE run result.

    A producer fingerprint identifies code, not execution. Passing the in-memory
    result of the trusted BASE run prevents a persisted self-declared PASS from
    substituting for that execution. Read-only bundle checks may omit it.
    """
    root = root.resolve(strict=True)
    if (
        not isinstance(expected_head_sha, str)
        or _SHA.fullmatch(expected_head_sha) is None
    ):
        raise ValueError("full exact head SHA required")
    relative = f".context/evidence/preflight/{expected_head_sha}.json"
    content = _record_bytes(root, root / relative)
    tree = (
        expected_head_tree_sha
        or _git(root, "rev-parse", expected_head_sha + "^{tree}")[1]
    )
    payload = _verify_record(
        root,
        content,
        expected_head_sha=expected_head_sha,
        expected_head_tree_sha=tree,
        expected_base_sha=expected_base_sha,
        expected_branch=expected_branch,
        expected_package_id=expected_package_id,
        expected_package_digest=expected_package_digest,
        expected_issue=expected_issue,
        expected_milestone=expected_milestone,
        expected_capabilities=expected_capabilities,
        expected_capability_parameters=expected_capability_parameters,
        at_epoch=time.time(),
    )
    if expected_result is not None:
        if not isinstance(expected_result, Mapping):
            raise ValueError("fresh BASE producer result must be a mapping")
        expected_unsigned = {
            key: value
            for key, value in expected_result.items()
            if key != "evidence_digest"
        }
        if _evidence_digest(expected_unsigned) != payload["evidence_digest"]:
            raise ValueError("preflight differs from fresh BASE producer result")
    for label, args, observed in (
        ("HEAD", ("rev-parse", "HEAD"), expected_head_sha),
        ("tree", ("rev-parse", "HEAD^{tree}"), tree),
        ("base", ("rev-parse", "origin/main"), expected_base_sha),
        ("branch", ("branch", "--show-current"), expected_branch),
        ("worktree", ("status", "--porcelain", "--untracked-files=all"), ""),
    ):
        if _git(root, *args) != (0, observed):
            raise ValueError(f"preflight current {label} differs from verified source")
    result = _receipt(payload, content, relative, historical=False)
    result["fresh_execution_verified"] = expected_result is not None
    return result


def verify_historical_preflight(
    root: Path,
    *,
    proof_path: str | Path,
    expected_sha256: str,
    expected_head_sha: str,
    expected_head_tree_sha: str,
    expected_base_sha: str,
    expected_branch: str,
    expected_package_id: str,
    expected_package_digest: str,
    expected_issue: int,
    expected_milestone: str,
    expected_capabilities: list[str],
    merge_epoch: float,
    expected_capability_parameters: Mapping[str, Mapping[str, object]] | None = None,
) -> dict:
    """Revalidate bytes anchored by the caller's verified signed post-merge bundle.

    The caller supplies the exact manifest digest and verified merge commit time.
    Current HEAD/branch are deliberately irrelevant to this historical proof.
    """
    root = root.resolve(strict=True)
    relative = f".context/evidence/preflight/{expected_head_sha}.json"
    path = Path(proof_path)
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError as exc:
            raise ValueError("historical preflight path escapes repository") from exc
    if path.as_posix() != relative or ".." in path.parts:
        raise ValueError("historical preflight must use the exact canonical proof path")
    if (
        not isinstance(expected_sha256, str)
        or _DIGEST.fullmatch(expected_sha256) is None
    ):
        raise ValueError("signed preflight byte digest required")
    content = _record_bytes(root, root / path)
    if "sha256:" + hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError("preflight bytes differ from signed bundle digest")
    payload = _verify_record(
        root,
        content,
        expected_head_sha=expected_head_sha,
        expected_head_tree_sha=expected_head_tree_sha,
        expected_base_sha=expected_base_sha,
        expected_branch=expected_branch,
        expected_package_id=expected_package_id,
        expected_package_digest=expected_package_digest,
        expected_issue=expected_issue,
        expected_milestone=expected_milestone,
        expected_capabilities=expected_capabilities,
        expected_capability_parameters=expected_capability_parameters,
        at_epoch=merge_epoch,
    )
    return _receipt(payload, content, relative, historical=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--capability", action="append", default=[])
    parser.add_argument("--parameters-json", default="{}")
    args = parser.parse_args(argv)
    try:
        parameters = json.loads(args.parameters_json)
        result = run_preflight(
            args.root,
            expected_head_sha=args.head_sha,
            expected_base_sha=args.base_sha,
            expected_branch=args.branch,
            required_capabilities=args.capability,
            capability_parameters=parameters,
        )
        write_preflight(args.root, result)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result = {"status": "FAIL", "reason": str(exc), "mutation_performed": False}
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result["status"] == "PASS"
        else 3
        if result["status"] == "BLOCKED_RUNTIME"
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
