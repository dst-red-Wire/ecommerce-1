#!/usr/bin/env python3
"""Read-only first-class preflight for one exact work item source identity.

The capability registry is QualificationExecutionPolicy. Runtime probes reuse
runtime_orchestration.capture/preflight; prepare/restore are never called here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Mapping

import yaml

try:
    from . import runtime_orchestration as runtime
except ImportError:
    import runtime_orchestration as runtime


_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPACITY = frozenset({"cpu-capacity", "memory-capacity", "disk-capacity"})


def _git(root: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=15,
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
    if parts.is_absolute() or not relative or any(part in ("", ".", "..") for part in relative.split("/")):
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


def _bounded_command(argv: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(argv, check=False, text=True, capture_output=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _probe_special(root: Path, name: str, parameters: Mapping[str, object], head_sha: str) -> tuple[bool, str]:
    """Only read host state or verify existing bytes. Never prepare a resource."""
    if name == "packer-runtime":
        version = parameters.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version):
            return False, "pinned Packer version required"
        proc = _bounded_command(["packer", "version"])
        return (
            proc is not None and proc.returncode == 0 and bool(re.search(rf"\b{re.escape(version)}\b", proc.stdout)),
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
            stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            "SSH identity ownership or permissions invalid",
        )
    if name == "network":
        host, port = parameters.get("host"), parameters.get("port")
        if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
            return False, "network host and port required"
        try:
            with socket.create_connection((host, port), timeout=3):
                return True, "network endpoint reachable"
        except OSError:
            return False, "network endpoint unavailable"
    if name == "toolchain-pinned":
        expected = parameters.get("sha256")
        path = _safe_file(root, "config/contracts/toolchain-lock.json")
        if path is None or not isinstance(expected, str) or _DIGEST.fullmatch(expected) is None:
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
            return isinstance(value, str) and value.strip().lower() in {"latest", "main", "master", "*"}
        return not mutable(document), "mutable toolchain version forbidden"
    if name == "artifact-available":
        relative, expected = parameters.get("path"), parameters.get("sha256")
        path = _safe_file(root, relative) if isinstance(relative, str) else None
        if path is None or not isinstance(expected, str) or _DIGEST.fullmatch(expected) is None:
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
        return proc is not None and proc.returncode == 0, "noninteractive sudo unavailable"
    if name == "virtualbox-backend":
        relative, expected, backend = (
            parameters.get("evidence_path"), parameters.get("sha256"), parameters.get("backend"),
        )
        path = _safe_file(root, relative) if isinstance(relative, str) else None
        if path is None or not isinstance(expected, str) or _DIGEST.fullmatch(expected) is None:
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
    policy: Mapping[str, object],
    driver: runtime.CapabilityDriver | None = None,
    base_ref: str = "origin/main",
) -> dict:
    """Return PASS, BLOCKED_RUNTIME, or FAIL without any machine mutation."""
    parameters = dict(capability_parameters or {})
    result = {
        "schema_version": 1,
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
    if any(not isinstance(value, str) or _SHA.fullmatch(value) is None for value in (expected_head_sha, expected_base_sha)):
        result["reason"] = "full exact source and base SHA required"
        return result
    if not isinstance(expected_branch, str) or not expected_branch or expected_branch in {"main", "master"}:
        result["reason"] = "exact feature branch required"
        return result
    if not isinstance(required_capabilities, list) or len(required_capabilities) != len(set(required_capabilities)):
        result["reason"] = "unique required capabilities list required"
        return result
    root = root.resolve()
    source_checks = {
        "head": (_git(root, "rev-parse", "HEAD"), expected_head_sha),
        "base": (_git(root, "rev-parse", base_ref), expected_base_sha),
        "branch": (_git(root, "branch", "--show-current"), expected_branch),
        "worktree": (_git(root, "status", "--porcelain", "--untracked-files=all"), ""),
    }
    for name, ((code, observed), expected) in source_checks.items():
        result["checks"][name] = "PASS" if code == 0 and observed == expected else "FAIL"
    if any(result["checks"][name] != "PASS" for name in source_checks):
        result["reason"] = "source identity or clean worktree mismatch"
        return result
    try:
        runtime_policy = policy["runtime_orchestration"]
        additional = policy["work_item_preflight"]["additional_capabilities"]
        planner = runtime.RuntimePlanner(runtime_policy)
        if not isinstance(additional, dict):
            raise ValueError("additional capability registry invalid")
        allowed = set(planner.specs) | set(additional)
        if any(name not in allowed for name in required_capabilities):
            raise ValueError("unknown required capability")
        if set(parameters) - set(required_capabilities):
            raise ValueError("parameters for unrequested capability")
        schemas = {**runtime_policy["capabilities"], **additional}
        for name in required_capabilities:
            supplied = parameters.get(name, {})
            if not isinstance(supplied, Mapping):
                raise ValueError(f"{name}: capability parameters must be a mapping")
            schema = schemas[name]
            required = schema.get("required_parameters", [])
            types = schema.get("parameter_types", {})
            if not isinstance(required, list) or not isinstance(types, dict):
                raise ValueError(f"{name}: parameter schema invalid")
            if set(supplied) != set(required):
                raise ValueError(f"{name}: required parameters differ from declaration")
            for key, value in supplied.items():
                kind = types.get(key)
                if kind == "positive-integer" and (type(value) is not int or value < 1):
                    raise ValueError(f"{name}.{key}: positive integer required")
                if kind == "tcp-port" and (type(value) is not int or not 1 <= value <= 65535):
                    raise ValueError(f"{name}.{key}: TCP port required")
                if kind in {"nonempty-string", "repository-relative-path"} and (not isinstance(value, str) or not value):
                    raise ValueError(f"{name}.{key}: nonempty string required")
                if kind == "repository-relative-path" and _safe_file(root, value) is None:
                    # An unavailable artifact/backend proof blocks runtime later;
                    # its path syntax still has to be safe here.
                    if (not isinstance(value, str) or "\\" in value or
                            PurePosixPath(value).is_absolute() or
                            any(part in ("", ".", "..") for part in value.split("/"))):
                        raise ValueError(f"{name}.{key}: repository-relative path required")
                if kind == "sha256-digest" and (not isinstance(value, str) or _DIGEST.fullmatch(value) is None):
                    raise ValueError(f"{name}.{key}: SHA-256 digest required")
                if kind == "pinned-version" and (not isinstance(value, str) or
                        re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", value) is None):
                    raise ValueError(f"{name}.{key}: pinned version required")
                if kind == "virtualbox-backend" and value not in {"NEM", "NATIVE_VTX"}:
                    raise ValueError(f"{name}.{key}: known backend required")
        requests = [
            runtime.CapabilityRequest(name, parameters.get(name, {}))
            for name in required_capabilities if name in planner.specs
        ]
        plan = planner.resolve(requests)
    except (KeyError, TypeError, ValueError, runtime.RuntimePolicyError) as exc:
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
            result["reason"] = f"{capability.spec.name}: probe failed: {type(exc).__name__}"
    for name in sorted(set(required_capabilities) & set(additional)):
        try:
            passed, reason = _probe_special(root, name, parameters.get(name, {}), expected_head_sha)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            passed, reason = False, f"probe error: {type(exc).__name__}"
        result["checks"][name] = "PASS" if passed else "BLOCKED_RUNTIME"
        if not passed:
            blocked.append(f"{name}: {reason}")
    statuses = list(result["checks"].values())
    capacity_names = set(required_capabilities) & _CAPACITY
    result["capacity"] = (
        "BLOCKED_RUNTIME" if any(result["checks"].get(name) == "BLOCKED_RUNTIME" for name in capacity_names)
        else "FAIL" if any(result["checks"].get(name) == "FAIL" for name in capacity_names)
        else "PASS"
    )
    environment_names = set(required_capabilities) - _CAPACITY
    result["environment"] = (
        "BLOCKED_RUNTIME" if any(result["checks"].get(name) == "BLOCKED_RUNTIME" for name in environment_names)
        else "FAIL" if any(result["checks"].get(name) == "FAIL" for name in environment_names)
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
    return "sha256:" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _evidence_directory(root: Path, *parts: str) -> Path:
    current = root.resolve()
    for part in parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symlink preflight evidence directory: {current}")
        current.mkdir(exist_ok=True)
        if not current.is_dir():
            raise ValueError(f"preflight evidence directory is not a directory: {current}")
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
        previous = destination.read_bytes()
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
            if not archive.is_file() or archive.read_bytes() != previous:
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
) -> dict:
    """Verify a persisted PASS against current source and work package identity."""
    for label, value in (
        ("head SHA", expected_head_sha), ("base SHA", expected_base_sha),
    ):
        if not isinstance(value, str) or _SHA.fullmatch(value) is None:
            raise ValueError(f"full exact {label} required")
    if (
        not isinstance(expected_branch, str) or not expected_branch
        or not isinstance(expected_package_id, str) or not expected_package_id
        or not isinstance(expected_milestone, str) or not expected_milestone
        or type(expected_issue) is not int or expected_issue < 1
        or not isinstance(expected_package_digest, str)
        or _DIGEST.fullmatch(expected_package_digest) is None
    ):
        raise ValueError("complete work package and branch identity required")
    if (
        not isinstance(expected_capabilities, list)
        or any(not isinstance(item, str) or not item for item in expected_capabilities)
        or len(expected_capabilities) != len(set(expected_capabilities))
    ):
        raise ValueError("unique expected capabilities required")
    root = root.resolve()
    relative = f".context/evidence/preflight/{expected_head_sha}.json"
    path = _safe_file(root, relative)
    if path is None:
        raise ValueError("exact-HEAD preflight evidence missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("preflight evidence is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("preflight evidence must be a JSON object")
    declared_digest = payload.get("evidence_digest")
    if not isinstance(declared_digest, str) or _DIGEST.fullmatch(declared_digest) is None:
        raise ValueError("preflight evidence digest is missing or malformed")
    unsigned = dict(payload)
    del unsigned["evidence_digest"]
    if _evidence_digest(unsigned) != declared_digest:
        raise ValueError("preflight evidence digest mismatch")
    expected = {
        "source_sha": expected_head_sha,
        "base_sha": expected_base_sha,
        "branch": expected_branch,
        "work_package_id": expected_package_id,
        "work_package_digest": expected_package_digest,
        "work_item_issue": expected_issue,
        "milestone": expected_milestone,
        "required_capabilities": expected_capabilities,
    }
    for field, value in expected.items():
        if type(payload.get(field)) is not type(value) or payload[field] != value:
            raise ValueError(f"preflight {field} differs from expected identity")
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or payload.get("status") != "PASS"
        or payload.get("capacity") != "PASS"
        or payload.get("environment") != "PASS"
        or payload.get("reason") != ""
        or payload.get("mutation_performed") is not False
    ):
        raise ValueError("preflight evidence is not a non-mutating PASS")
    checks = payload.get("checks")
    required_checks = {"head", "base", "branch", "worktree", *expected_capabilities}
    if (
        not isinstance(checks, dict)
        or not required_checks.issubset(checks)
        or any(not isinstance(key, str) or value != "PASS" for key, value in checks.items())
    ):
        raise ValueError("preflight evidence checks are incomplete or not PASS")
    for label, args, observed in (
        ("HEAD", ("rev-parse", "HEAD"), expected_head_sha),
        ("branch", ("branch", "--show-current"), expected_branch),
        ("worktree", ("status", "--porcelain", "--untracked-files=all"), ""),
    ):
        code, value = _git(root, *args)
        if code != 0 or value != observed:
            raise ValueError(f"preflight current {label} differs from verified source")
    if _git(root, "cat-file", "-e", expected_base_sha + "^{commit}")[0] != 0:
        raise ValueError("preflight exact base commit is missing")
    if _git(root, "merge-base", "--is-ancestor", expected_base_sha, expected_head_sha)[0] != 0:
        raise ValueError("preflight exact base is not an ancestor of HEAD")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--capability", action="append", default=[])
    parser.add_argument("--parameters-json", default="{}")
    parser.add_argument("--base-ref", default="origin/main")
    args = parser.parse_args(argv)
    try:
        parameters = json.loads(args.parameters_json)
        policy = yaml.safe_load((args.root / "config/contracts/qualification-execution-policy.yaml").read_text(encoding="utf-8"))
        result = run_preflight(
            args.root, expected_head_sha=args.head_sha, expected_base_sha=args.base_sha,
            expected_branch=args.branch, required_capabilities=args.capability,
            capability_parameters=parameters, policy=policy, base_ref=args.base_ref,
        )
        write_preflight(args.root, result)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result = {"status": "FAIL", "reason": str(exc), "mutation_performed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 3 if result["status"] == "BLOCKED_RUNTIME" else 1


if __name__ == "__main__":
    sys.exit(main())
