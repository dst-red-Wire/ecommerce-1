#!/usr/bin/env python3
"""Fail-closed producer authority for work-item runtime proofs."""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    from . import native_recovery_evidence, roadmap_sync, work_package
except ImportError:
    import native_recovery_evidence
    import roadmap_sync
    import work_package


_SHA = re.compile(r"^[0-9a-f]{40}$")
_ROADMAP_PATH = "config/contracts/roadmap-policy.yaml"
_EXECUTION_POLICY_PATH = "config/contracts/execution-properties-policy.yaml"
_NATIVE_RECOVERY_PATH = ".context/evidence/native-recovery/current.json"
_NATIVE_PRODUCER = "scripts/native_recovery_evidence.py:validate"
_RECOVERY_PHASES = ("capture", "restore", "restore_verification")
_LAB_PATH = roadmap_sync.m25_runtime_evidence.OUTPUT.as_posix()
_LAB_DECLARATION = {
    "path": _LAB_PATH,
    "environments": ["lab"],
    "proof_type": "lab-readiness",
}
_RUNTIME_FIELDS = {
    "schema_version",
    "status",
    "exact_commit_evidence",
    "runtime_execution",
    "head_sha",
    "head_tree_sha",
    "created_at_epoch",
    "milestone",
    "environment",
    "runtime_identity",
    "outcome",
}


def _fail(reason: str) -> dict:
    return {"status": "FAIL", "reason": reason}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
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


def _canonical_policy(root: Path, *, revision: str | None = None) -> tuple[dict, dict]:
    def policy_data(relative: str) -> dict:
        if revision is None:
            return work_package._read_yaml(root / relative)
        value = work_package.yaml.load(
            _git(root, "show", f"{revision}:{relative}"),
            Loader=work_package._UniqueKeyLoader,
        )
        if not isinstance(value, dict):
            raise TypeError("historical runtime policy is not a mapping")
        return value

    lock = policy_data("architecture.lock.yaml")
    contracts = lock.get("machine_contracts")
    if (
        not isinstance(contracts, dict)
        or contracts.get("roadmap_policy") != _ROADMAP_PATH
    ):
        raise ValueError("RoadmapPolicy is not registered at its canonical path")
    policy = policy_data(_ROADMAP_PATH)
    if (
        policy.get("version") != 1
        or policy.get("kind") != "RoadmapPolicy"
        or policy.get("status") != "enforced"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
    ):
        raise ValueError("canonical RoadmapPolicy identity is invalid")
    derivation = policy.get("status_derivation")
    if not isinstance(derivation, dict):
        raise TypeError("RoadmapPolicy status derivation is missing")
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
    matches = (
        [
            item
            for item in milestones
            if isinstance(item, dict) and item.get("id") == "M2.5"
        ]
        if isinstance(milestones, list)
        else []
    )
    if len(matches) != 1:
        raise ValueError("RoadmapPolicy M2.5 milestone is not unique")
    requirements = matches[0].get("requirements")
    declarations = (
        requirements.get("runtime_evidence") if isinstance(requirements, dict) else None
    )
    if not isinstance(declarations, list) or declarations.count(_LAB_DECLARATION) != 1:
        raise ValueError("canonical M2.5 lab runtime declaration is missing")
    return contract, _LAB_DECLARATION



def _native_recovery_policy(root: Path, *, revision: str | None = None) -> None:
    """Use the existing recovery semantics; the proof is not roadmap readiness."""
    def read(relative: str) -> dict:
        if revision is None:
            return work_package._read_yaml(root / relative)
        value = work_package.yaml.load(
            _git(root, "show", f"{revision}:{relative}"),
            Loader=work_package._UniqueKeyLoader,
        )
        if not isinstance(value, dict):
            raise TypeError("historical recovery policy is not a mapping")
        return value

    lock = read("architecture.lock.yaml")
    contracts = lock.get("machine_contracts")
    if (
        not isinstance(contracts, dict)
        or contracts.get("execution_properties_policy") != _EXECUTION_POLICY_PATH
    ):
        raise ValueError("ExecutionPropertiesPolicy is not registered at its canonical path")
    policy = read(_EXECUTION_POLICY_PATH)
    if (
        type(policy.get("version")) is not int
        or policy["version"] != 1
        or policy.get("kind") != "ExecutionPropertiesPolicy"
        or policy.get("status") != "enforced"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
    ):
        raise ValueError("canonical ExecutionPropertiesPolicy identity is invalid")
    properties = policy.get("properties")
    recovery = properties.get("recovery") if isinstance(properties, dict) else None
    required = {
        "capture_before_mutation": "required",
        "restore_on_failure": "required",
        "restore_verification": "required",
        "required_mutation_classes": [
            "local-virtualization", "bcd", "native-boot", "network",
            "infrastructure", "production", "credentials", "destructive-cleanup",
        ],
        "proof_fields": [f"recovery.{phase}" for phase in _RECOVERY_PHASES],
        "proof_success_status": "PASS",
        "proof": "capture-mutate-restore-verify",
    }
    if not isinstance(recovery, dict) or any(
        recovery.get(key) != value for key, value in required.items()
    ):
        raise ValueError("ExecutionPropertiesPolicy recovery contract is weakened")
    verification = properties.get("verification")
    failure = properties.get("failure")
    contract = policy.get("evidence_contract")
    if (
        not isinstance(verification, dict)
        or verification.get("runtime_evidence") != "required"
        or verification.get("declaration_only_proof") != "forbidden"
        or not isinstance(failure, dict)
        or any(failure.get(key) != "fail_closed" for key in (
            "unknown_state", "missing_evidence", "cannot_verify", "ambiguous_evidence",
        ))
        or not isinstance(contract, dict)
        or contract.get("static_status_forbidden") is not True
        or contract.get("unknown_or_missing") != "FAIL"
    ):
        raise ValueError("ExecutionPropertiesPolicy evidence contract is weakened")


def _native_recovery_metadata(
    evidence: dict, head_sha: str, tree_sha: str, *, historical: bool,
) -> None:
    if (
        type(evidence.get("schema_version")) is not int
        or evidence["schema_version"] != 1
        or evidence.get("status") != "PASS"
        or evidence.get("outcome") != "PASS"
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("runtime_execution") is not True
        or evidence.get("head_sha") != head_sha
        or evidence.get("head_tree_sha") != tree_sha
        or evidence.get("milestone") != "M2.5"
        or evidence.get("environment") != "host"
        or evidence.get("proof_type") != "native-host-recovery"
        or "recovery" in evidence
        or evidence.get("deployment_state") != "NOT_DEPLOYED"
        or type(evidence.get("paid_resources_created")) is not int
        or evidence["paid_resources_created"] != 0
    ):
        raise ValueError("native recovery evidence identity or outcome is invalid")
    identity = evidence.get("runtime_identity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"kind", "id"}
        or any(not isinstance(value, str) or not value for value in identity.values())
    ):
        raise ValueError("native recovery runtime identity is invalid")
    created = evidence.get("created_at_epoch")
    now = datetime.now(timezone.utc).timestamp()
    if (
        isinstance(created, bool) or not isinstance(created, (int, float))
        or not math.isfinite(created) or created <= 0 or created > now
        or (not historical and now - created > 86400)
    ):
        raise ValueError("native recovery timestamp is invalid or stale")


def _verify_native_runtime_proof(
    root: Path, head_sha: str, *, base_sha: str | None = None,
    head_tree_sha: str | None = None, evidence_digest: str | None = None,
    historical: bool = False,
) -> dict:
    """Dispatch only to this controller's registered host recovery producer."""
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        return _fail("full exact runtime head SHA required")
    if historical and (
        not all(isinstance(value, str) and _SHA.fullmatch(value)
                for value in (base_sha, head_tree_sha))
        or not isinstance(evidence_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest) is None
    ):
        return _fail("historical native recovery requires exact base, tree and evidence digest")
    try:
        root = Path(root).resolve(strict=True)
        if not root.is_dir() or Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("native recovery repository root differs")
        if not historical and (
            _git(root, "rev-parse", "HEAD") != head_sha
            or _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise ValueError("native recovery requires the clean exact HEAD")
        tree_sha = _git(root, "rev-parse", head_sha + "^{tree}")
        if historical and tree_sha != head_tree_sha:
            raise ValueError("historical native recovery tree differs from exact HEAD")
        _native_recovery_policy(root, revision=base_sha)
        path = _safe_evidence_file(root, _NATIVE_RECOVERY_PATH)
        if path.stat().st_nlink != 1:
            raise ValueError("native recovery evidence is hardlinked")
        before = path.read_bytes()
        digest = "sha256:" + hashlib.sha256(before).hexdigest()
        if historical and digest != evidence_digest:
            raise ValueError("historical native recovery bytes differ from bundled digest")
        evidence = json.loads(
            before.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(evidence, dict):
            raise TypeError("native recovery evidence must be a JSON object")
        _native_recovery_metadata(evidence, head_sha, tree_sha, historical=historical)
        if historical:
            _historical_producer_inputs(
                root, head_sha, relative_paths=_NATIVE_HISTORICAL_PRODUCER_INPUTS,
            )
        # Import resolution is anchored to this module's package, never the PR HEAD.
        # The producer independently reads protected observations and Git identities.
        verdict = native_recovery_evidence.validate(
            root, evidence, head_sha, tree_sha, historical=historical,
        )
        recovery = verdict.get("recovery") if isinstance(verdict, dict) else None
        if (
            not isinstance(verdict, dict)
            or verdict.get("status") != "PASS"
            or verdict.get("environment") != "host"
            or verdict.get("runtime_identity") != evidence["runtime_identity"]
            or not isinstance(recovery, dict)
            or set(recovery) != set(_RECOVERY_PHASES)
            or any(recovery.get(phase) != "PASS" for phase in _RECOVERY_PHASES)
        ):
            raise ValueError("native producer did not verify capture, restore and restore verification")
        if (
            _safe_evidence_file(root, _NATIVE_RECOVERY_PATH).stat().st_nlink != 1
            or path.read_bytes() != before
        ):
            raise ValueError("native recovery evidence changed during producer validation")
        if not historical and (
            _git(root, "rev-parse", "HEAD") != head_sha
            or _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise ValueError("native recovery source changed during producer validation")
        _native_recovery_policy(root, revision=base_sha)
        if historical:
            _historical_producer_inputs(
                root, head_sha, relative_paths=_NATIVE_HISTORICAL_PRODUCER_INPUTS,
            )
        return {
            "status": "PASS", "reason": "", "producer": _NATIVE_PRODUCER,
            "proof_type": "native-host-recovery", "milestone": "M2.5",
            "environment": "host", "head_sha": head_sha, "head_tree_sha": tree_sha,
            "evidence_path": _NATIVE_RECOVERY_PATH, "evidence_digest": digest,
            "runtime_identity": dict(verdict["runtime_identity"]),
            "recovery": {phase: recovery[phase] for phase in _RECOVERY_PHASES},
        }
    except (
        OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError,
        subprocess.SubprocessError, UnicodeError, work_package.yaml.YAMLError,
    ) as exc:
        return _fail(str(exc))

def _safe_evidence_file(root: Path, relative: str) -> Path:
    if relative not in {_LAB_PATH, _NATIVE_RECOVERY_PATH}:
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
    if evidence_path == _NATIVE_RECOVERY_PATH:
        return _verify_native_runtime_proof(root, head_sha)
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
            raise TypeError("runtime evidence must be a JSON object")
        valid, detail = roadmap_sync._runtime_evidence_result(
            root,
            declaration,
            milestone,
            head_sha,
            tree_sha,
            contract,
            86400,
            datetime.now(timezone.utc),
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
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RuntimeError,
        subprocess.SubprocessError,
        UnicodeError,
    ) as exc:
        return _fail(str(exc))


_HISTORICAL_PRODUCER_INPUTS = (
    "config/contracts/machine-image-lock.yaml",
    "config/contracts/qualification-execution-policy.yaml",
    "config/artifacts/rocky-10.2-base-packages.lock.json",
    "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json",
)


_NATIVE_HISTORICAL_PRODUCER_INPUTS = tuple(dict.fromkeys((
    *_HISTORICAL_PRODUCER_INPUTS,
    ".gitattributes",
    *(f"scripts/windows/{name}" for name in roadmap_sync.m25_runtime_evidence.NETWORK_RUNNER_FILES),
    "platform/vagrant/rocky-image-smoke/Vagrantfile",
)))


def _historical_producer_inputs(
    root: Path, head_sha: str, *,
    relative_paths: tuple[str, ...] = _HISTORICAL_PRODUCER_INPUTS,
) -> None:
    """Keep the producer's filesystem data identical to the historical Git tree."""
    ps1_crlf = any(Path(relative).suffix == ".ps1" for relative in relative_paths) and (
        "*.ps1 text eol=crlf" in _git(root, "show", f"{head_sha}:.gitattributes").splitlines()
    )
    for relative in relative_paths:
        current = root
        for component in Path(relative).parts:
            current /= component
            if current.is_symlink():
                raise ValueError("historical runtime producer input is a symlink")
        if not current.is_file() or current.stat().st_size > 16_000_000:
            raise ValueError("historical runtime producer input is unavailable")
        entry = _git(root, "ls-tree", head_sha, "--", relative).split()
        data = current.read_bytes()
        if ps1_crlf and current.suffix == ".ps1":
            data = data.replace(b"\r\n", b"\n")
            if b"\r" in data:
                raise ValueError("historical runtime producer input has unsafe PowerShell EOL")
        blob = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()
        if (
            len(entry) != 4
            or entry[0] not in {"100644", "100755"}
            or entry[1] != "blob"
            or entry[2] != blob
        ):
            raise ValueError(
                "historical runtime producer input differs from exact HEAD"
            )


def verify_historical_runtime_proof(
    root: Path,
    milestone: str,
    head_sha: str,
    evidence_path: str,
    *,
    base_sha: str,
    head_tree_sha: str,
    evidence_digest: str,
    recovery_required: bool = False,
) -> dict:
    """Revalidate retained producer evidence bound by a verified exact bundle.

    The caller verifies the bundle and its signed post-merge witness. Historical
    completion does not reapply a wall-clock expiry to already bound evidence.
    Source identity, protected producer observations and every digest still apply.
    """
    if type(recovery_required) is not bool:
        return _fail("recovery_required must be a boolean")
    if milestone == "M2.5" and evidence_path == _NATIVE_RECOVERY_PATH:
        return _verify_native_runtime_proof(
            root, head_sha, base_sha=base_sha, head_tree_sha=head_tree_sha,
            evidence_digest=evidence_digest, historical=True,
        )
    if recovery_required:
        return _fail(
            "producer-verified capture, restore and restore verification are unavailable"
        )
    if milestone != "M2.5" or evidence_path != _LAB_PATH:
        return _fail("runtime path or milestone has no registered producer validator")
    if not all(
        isinstance(value, str) and _SHA.fullmatch(value)
        for value in (base_sha, head_sha, head_tree_sha)
    ):
        return _fail("historical runtime requires exact base, HEAD and tree SHAs")
    if (
        not isinstance(evidence_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest) is None
    ):
        return _fail("historical runtime evidence digest is invalid")
    try:
        root = Path(root).resolve(strict=True)
        if Path(_git(root, "rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("historical runtime repository root differs")
        if _git(root, "rev-parse", head_sha + "^{tree}") != head_tree_sha:
            raise ValueError("historical runtime tree differs from exact HEAD")
        contract, declaration = _canonical_policy(root, revision=base_sha)
        path = _safe_evidence_file(root, evidence_path)
        before = path.read_bytes()
        if "sha256:" + hashlib.sha256(before).hexdigest() != evidence_digest:
            raise ValueError("historical runtime bytes differ from bundled digest")
        evidence = json.loads(
            before.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(evidence, dict):
            raise TypeError("historical runtime evidence must be a JSON object")
        created = evidence.get("created_at_epoch")
        if (
            isinstance(created, bool)
            or not isinstance(created, (int, float))
            or not math.isfinite(created)
            or created <= 0
            or created > datetime.now(timezone.utc).timestamp()
        ):
            raise ValueError("historical runtime timestamp is invalid")
        _historical_producer_inputs(root, head_sha)
        valid, reason = roadmap_sync._runtime_evidence_result(
            root,
            declaration,
            milestone,
            head_sha,
            head_tree_sha,
            contract,
            86400,
            datetime.fromtimestamp(math.ceil(created), timezone.utc),
        )
        if not valid:
            raise ValueError(reason)
        if path.read_bytes() != before:
            raise ValueError("historical runtime changed during producer validation")
        _historical_producer_inputs(root, head_sha)
        return {
            "status": "PASS",
            "reason": "",
            "producer": "scripts/m25_runtime_evidence.py:validate",
            "proof_type": "lab-readiness",
            "milestone": milestone,
            "head_sha": head_sha,
            "head_tree_sha": head_tree_sha,
            "evidence_path": evidence_path,
            "evidence_digest": evidence_digest,
            "runtime_identity": evidence["runtime_identity"],
            "recovery": "NOT_REQUIRED",
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RuntimeError,
        subprocess.SubprocessError,
        UnicodeError,
        work_package.yaml.YAMLError,
    ) as exc:
        return _fail(str(exc))
