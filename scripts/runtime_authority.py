#!/usr/bin/env python3
"""Fail-closed producer authority for work-item runtime proofs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

try:
    from . import roadmap_sync, work_package
except ImportError:
    import roadmap_sync
    import work_package


_SHA = re.compile(r"^[0-9a-f]{40}$")
_ROADMAP_PATH = "config/contracts/roadmap-policy.yaml"
_LAB_PATH = roadmap_sync.m25_runtime_evidence.OUTPUT.as_posix()
_LAB_DECLARATION = {
    "path": _LAB_PATH, "environments": ["lab"], "proof_type": "lab-readiness",
}
_RUNTIME_FIELDS = {
    "schema_version", "status", "exact_commit_evidence", "runtime_execution",
    "head_sha", "head_tree_sha", "created_at_epoch", "milestone", "environment",
    "runtime_identity", "outcome",
}


def _fail(reason: str) -> dict:
    return {"status": "FAIL", "reason": reason}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True,
        check=False, timeout=15,
    )
    if result.returncode:
        raise ValueError(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate runtime evidence key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite runtime evidence number: {value}")


def _canonical_policy(root: Path) -> tuple[dict, dict]:
    lock = work_package._read_yaml(root / "architecture.lock.yaml")
    contracts = lock.get("machine_contracts")
    if not isinstance(contracts, dict) or contracts.get("roadmap_policy") != _ROADMAP_PATH:
        raise ValueError("RoadmapPolicy is not registered at its canonical path")
    policy = work_package._read_yaml(root / _ROADMAP_PATH)
    if (
        policy.get("version") != 1
        or policy.get("kind") != "RoadmapPolicy"
        or policy.get("status") != "enforced"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
    ):
        raise ValueError("canonical RoadmapPolicy identity is invalid")
    derivation = policy.get("status_derivation")
    if not isinstance(derivation, dict):
        raise ValueError("RoadmapPolicy status derivation is missing")
    contract = derivation.get("runtime_evidence_contract")
    if (
        not isinstance(contract, dict)
        or contract.get("schema_version") != 1
        or set(contract.get("required_fields", [])) != _RUNTIME_FIELDS
        or contract.get("accepted_status") != "PASS"
        or contract.get("accepted_outcome") != "PASS"
        or contract.get("m25_deployment_state") != "DEPLOYED"
        or contract.get("runtime_identity_required_fields") != ["kind", "id"]
        or type(derivation.get("evidence_max_age_seconds")) is not int
        or derivation["evidence_max_age_seconds"] != 86400
    ):
        raise ValueError("RoadmapPolicy runtime evidence contract is weakened")
    milestones = policy.get("milestones")
    matches = [
        item for item in milestones
        if isinstance(item, dict) and item.get("id") == "M2.5"
    ] if isinstance(milestones, list) else []
    if len(matches) != 1:
        raise ValueError("RoadmapPolicy M2.5 milestone is not unique")
    requirements = matches[0].get("requirements")
    declarations = requirements.get("runtime_evidence") if isinstance(requirements, dict) else None
    if not isinstance(declarations, list) or declarations.count(_LAB_DECLARATION) != 1:
        raise ValueError("canonical M2.5 lab runtime declaration is missing")
    return contract, _LAB_DECLARATION


def _safe_evidence_file(root: Path, relative: str) -> Path:
    if relative != _LAB_PATH:
        raise ValueError("runtime path has no registered producer validator")
    current = root
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("runtime evidence path contains a symlink")
    if not current.is_file() or not current.resolve().is_relative_to(root):
        raise ValueError("canonical runtime evidence file is missing or unsafe")
    if current.stat().st_size > 10_000_000:
        raise ValueError("runtime evidence file exceeds the bounded size")
    return current


def verify_runtime_proof(
    root: Path,
    milestone: str,
    head_sha: str,
    evidence_path: str,
    *,
    recovery_required: bool = False,
) -> dict:
    """Accept only producer-validated M2.5 lab proof at the current clean HEAD."""
    if type(recovery_required) is not bool:
        return _fail("recovery_required must be a boolean")
    if milestone != "M2.5":
        return _fail("runtime milestone has no registered producer validator")
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        return _fail("full exact runtime head SHA required")
    if not isinstance(evidence_path, str) or evidence_path != _LAB_PATH:
        return _fail("runtime path has no registered producer validator")
    if recovery_required:
        return _fail(
            "producer-verified capture, restore and restore verification are unavailable"
        )
    try:
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("runtime root is not a directory")
        contract, declaration = _canonical_policy(root)
        path = _safe_evidence_file(root, evidence_path)
        if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("runtime evidence repository root differs")
        if _git(root, "rev-parse", "HEAD") != head_sha:
            raise ValueError("runtime evidence HEAD differs from current checkout")
        if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
            raise ValueError("runtime evidence checkout is not clean")
        tree_sha = _git(root, "rev-parse", "HEAD^{tree}")
        before = path.read_bytes()
        evidence = json.loads(
            before.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(evidence, dict):
            raise ValueError("runtime evidence must be a JSON object")
        valid, detail = roadmap_sync._runtime_evidence_result(
            root, declaration, milestone, head_sha, tree_sha, contract,
            86400, datetime.now(timezone.utc),
        )
        if not valid:
            raise ValueError(detail)
        if path.read_bytes() != before:
            raise ValueError("runtime evidence changed during producer validation")
        if _git(root, "rev-parse", "HEAD") != head_sha or _git(
            root, "status", "--porcelain=v1", "--untracked-files=all"
        ):
            raise ValueError("runtime source changed during producer validation")
        return {
            "status": "PASS",
            "reason": "",
            "producer": "scripts/m25_runtime_evidence.py:validate",
            "proof_type": "lab-readiness",
            "milestone": milestone,
            "head_sha": head_sha,
            "head_tree_sha": tree_sha,
            "evidence_path": evidence_path,
            "evidence_digest": "sha256:" + hashlib.sha256(before).hexdigest(),
            "recovery": "NOT_REQUIRED",
        }
    except (
        OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError,
        subprocess.SubprocessError, UnicodeError,
    ) as exc:
        return _fail(str(exc))
