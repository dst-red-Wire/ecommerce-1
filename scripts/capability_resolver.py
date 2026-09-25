#!/usr/bin/env python3
"""Deterministic, fail-closed resolution of repository tool capabilities.

The registry describes potential relationships only.  This resolver is the sole
place where repository discovery and exact-SHA runtime evidence are combined.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import qualification_cache


STATES = ("unsupported", "available", "configured", "verified", "proven")
RELATIONSHIPS = {
    "implements", "enforces", "verifies", "observes", "produces_evidence",
    "aggregates_evidence", "transports_evidence",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ResolutionError(ValueError):
    """An ambiguity or invalid claim which must fail closed."""


def _load(path: Path) -> dict[str, Any]:
    value = qualification_cache.psych_load(path)
    if not isinstance(value, dict):
        raise ResolutionError(f"{path}: expected a mapping")
    return value


def _head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode or not SHA.fullmatch(result.stdout.strip()):
        raise ResolutionError("source SHA is missing or is not an exact commit")
    return result.stdout.strip()


def toolchain_digest(root: Path) -> str:
    data = (root / "config/contracts/toolchain-lock.json").read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _assert_commit_bound(root: Path, source_sha: str, registry: dict[str, Any]) -> None:
    """Reject live-worktree inputs which differ from the claimed commit."""
    probe = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=root, text=True,
        capture_output=True, check=False,
    )
    if probe.returncode:
        return  # Synthetic fixture roots are bound by their explicit test SHA.
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=False,
    ).stdout.strip()
    if head != source_sha:
        raise ResolutionError("resolver source SHA is not the checked-out exact HEAD")
    relevant = {
        "config/contracts/tool-capabilities.yaml",
        "config/contracts/composed-capabilities.yaml",
        "config/contracts/toolchain-lock.json",
    }
    for entry in registry["tools"].values():
        relevant.update(str(probe["path"]) for probe in entry.get("discovery", []))
    dirty = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *sorted(relevant)],
        cwd=root, text=True, capture_output=True, check=False,
    )
    if dirty.returncode or dirty.stdout.strip():
        raise ResolutionError("resolver inputs differ from the claimed exact commit")


def _requirement_names(expression: object) -> set[str]:
    if isinstance(expression, str):
        return {expression}
    if not isinstance(expression, dict) or len(expression) != 1:
        raise ResolutionError("requirement expression must contain exactly one of all/any/not")
    operator, children = next(iter(expression.items()))
    if operator not in {"all", "any", "not"}:
        raise ResolutionError(f"unknown requirement operator: {operator}")
    if operator == "not":
        return _requirement_names(children)
    if not isinstance(children, list) or not children:
        raise ResolutionError(f"requirement operator {operator} requires a non-empty list")
    names: set[str] = set()
    for child in children:
        names.update(_requirement_names(child))
    return names


def _evaluate(expression: object, values: dict[str, str]) -> bool:
    if isinstance(expression, str):
        return values.get(expression) == "PASS"
    operator, children = next(iter(expression.items()))
    if operator == "not":
        return not _evaluate(children, values)
    results = [_evaluate(child, values) for child in children]
    return all(results) if operator == "all" else any(results)


def validate_registry(registry: dict[str, Any], composed: dict[str, Any]) -> None:
    if registry.get("version") != 1 or registry.get("kind") != "ToolCapabilityRegistry":
        raise ResolutionError("invalid ToolCapabilityRegistry identity")
    if registry.get("policy_ref") != "config/contracts/execution-properties-policy.yaml":
        raise ResolutionError("tool registry must reference the semantic policy")
    if set(registry.get("relationships", [])) != RELATIONSHIPS:
        raise ResolutionError("relationship taxonomy is incomplete or unknown")
    allowed_requirements = set(registry.get("requirement_vocabulary", []))
    scopes = set(registry.get("scopes", []))
    tools = registry.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ResolutionError("tool registry is empty")
    for tool, entry in tools.items():
        if not entry.get("version_ref") or not entry.get("capabilities"):
            raise ResolutionError(f"unknown or incomplete tool mapping: {tool}")
        if not isinstance(entry.get("discovery"), list) or not entry["discovery"]:
            raise ResolutionError(f"{tool}: configuration is not detectable")
        if not isinstance(entry.get("not_guaranteed"), list):
            raise ResolutionError(f"{tool}: not_guaranteed must be explicit")
        for capability, declaration in entry["capabilities"].items():
            if not isinstance(declaration.get("gate"), str) or not declaration["gate"]:
                raise ResolutionError(f"{tool}.{capability}: mandatory gate is absent")
            relationships = set(declaration.get("relationships", []))
            if not relationships or relationships - RELATIONSHIPS:
                raise ResolutionError(f"{tool}.{capability}: unknown relationship")
            declared_scopes = declaration.get("scopes", [])
            if not declared_scopes or set(declared_scopes) - scopes:
                raise ResolutionError(f"{tool}.{capability}: missing or ambiguous scope")
            names = _requirement_names(declaration.get("requires"))
            if names - allowed_requirements:
                raise ResolutionError(
                    f"{tool}.{capability}: unknown requirements {sorted(names - allowed_requirements)}"
                )
    if composed.get("version") != 1 or composed.get("kind") != "ComposedCapabilities":
        raise ResolutionError("invalid ComposedCapabilities identity")
    for name, declaration in composed.get("capabilities", {}).items():
        requirements = declaration.get("requires", {}).get("all")
        if not isinstance(requirements, list) or not requirements:
            raise ResolutionError(f"composed capability {name} has no all requirements")
        for item in requirements:
            tool = item.get("tool")
            capability = item.get("capability")
            if tool not in tools or capability not in tools[tool]["capabilities"]:
                raise ResolutionError(f"composed capability {name} references unknown tool/capability")
            if item.get("status") not in STATES:
                raise ResolutionError(f"composed capability {name} has unknown state")


def _configured(root: Path, discovery: list[dict[str, str]]) -> tuple[bool, list[str]]:
    relevant: list[str] = []
    for probe in discovery:
        path = root / probe["path"]
        if not path.exists():
            continue
        marker = probe.get("marker")
        if marker and (not path.is_file() or marker not in path.read_text(encoding="utf-8")):
            continue
        relevant.append(probe["path"])
    return bool(relevant), sorted(relevant)


def _evidence_files(path: Path | None) -> list[Path]:
    if path is None or not path.exists():
        return []
    return sorted(path.glob("*.json")) if path.is_dir() else [path]


def _read_evidence(path: Path | None) -> tuple[dict[tuple[str, str], dict[str, Any]], list[str]]:
    records: dict[tuple[str, str], dict[str, Any]] = {}
    errors: list[str] = []
    duplicates: set[tuple[str, str]] = set()
    for source in _evidence_files(path):
        try:
            payload = _load(source)
        except (OSError, json.JSONDecodeError, ResolutionError) as exc:
            errors.append(f"invalid_evidence:{source}:{exc}")
            continue
        items = payload.get("evidence", [payload])
        if not isinstance(items, list):
            errors.append(f"invalid_evidence:{source}:evidence must be a list")
            continue
        for record in items:
            if not isinstance(record, dict):
                errors.append(f"invalid_evidence:{source}:record must be a mapping")
                continue
            key = (str(record.get("tool", "")), str(record.get("capability", "")))
            if key in records or key in duplicates:
                errors.append(f"ambiguous_evidence:{key[0]}.{key[1]}")
                records.pop(key, None)
                duplicates.add(key)
            else:
                records[key] = record
    return records, errors


def resolve(
    root: Path,
    *,
    evidence_path: Path | None = None,
    source_sha: str | None = None,
    registry_path: Path | None = None,
    composed_path: Path | None = None,
) -> dict[str, Any]:
    registry = _load(registry_path or root / "config/contracts/tool-capabilities.yaml")
    composed = _load(composed_path or root / "config/contracts/composed-capabilities.yaml")
    validate_registry(registry, composed)
    lock = _load(root / "config/contracts/toolchain-lock.json")
    exact_sha = source_sha or _head(root)
    if not SHA.fullmatch(exact_sha):
        raise ResolutionError("source SHA must be an exact full SHA")
    _assert_commit_bound(root, exact_sha, registry)
    digest = toolchain_digest(root)
    active = lock.get("tool_lifecycle", {}).get("active", {})
    versions = lock.get("versions", {})
    evidence, evidence_errors = _read_evidence(evidence_path)
    for evidence_tool, evidence_capability in sorted(evidence):
        if evidence_tool not in registry["tools"]:
            evidence_errors.append(f"unknown_tool:{evidence_tool}")
        elif evidence_capability not in registry["tools"][evidence_tool]["capabilities"]:
            evidence_errors.append(
                f"unknown_capability:{evidence_tool}.{evidence_capability}"
            )
    output: dict[str, Any] = {
        "version": 1,
        "kind": "EffectiveCapabilities",
        "generated": True,
        "source_sha": exact_sha,
        "toolchain_digest": digest,
        "state_machine": list(STATES),
        "tools": {},
        "composed_capabilities": {},
        "capability_graph": {},
        "gaps": [],
        "unmapped_active_tools": [],
        "stale_evidence": [],
        "unknown_states": sorted(evidence_errors),
    }
    aliases = registry.get("toolchain_aliases", {})
    mapped_active = {alias for names in aliases.values() for alias in names}
    mapped_active.update(registry["tools"])
    mapped_active.update(registry.get("non_capability_tools", []))
    output["unmapped_active_tools"] = sorted(set(active) - mapped_active)
    output["unknown_states"].extend(
        f"unmapped_active_tool:{tool}" for tool in output["unmapped_active_tools"]
    )

    for tool in sorted(registry["tools"]):
        entry = registry["tools"][tool]
        active_names = aliases.get(tool, [tool])
        lifecycle = next((active[name] for name in active_names if name in active), None)
        version_ref = entry["version_ref"]
        repository_tool = entry.get("repository_tool") is True
        version = exact_sha if repository_tool else (versions.get(version_ref) if lifecycle is not None else None)
        detected = (repository_tool or lifecycle is not None) and isinstance(version, str) and bool(version) and version != "latest"
        configured, relevant = _configured(root, entry.get("discovery", []))
        configured = detected and configured
        tool_result = {
            "detection": {
                "status": "available" if detected else "unsupported",
                "version": version,
                "source": ("repository-source-sha" if repository_tool else f"config/contracts/toolchain-lock.json#{version_ref}") if detected else None,
                "configured": configured,
                "relevant_files": relevant,
            },
            "capabilities": {},
            "not_guaranteed": entry["not_guaranteed"],
        }
        for capability in sorted(entry["capabilities"]):
            declaration = entry["capabilities"][capability]
            record = evidence.get((tool, capability))
            names = sorted(_requirement_names(declaration["requires"]))
            values = record.get("requirements", {}) if isinstance(record, dict) else {}
            if not isinstance(values, dict):
                values = {}
            missing = [name for name in names if values.get(name) != "PASS"]
            state = "unsupported" if not detected else "available"
            if configured:
                state = "configured"
            evidence_ids: list[str] = []
            identity_errors: list[str] = []
            if record is not None:
                if record.get("source_sha") != exact_sha:
                    identity_errors.append("stale_or_foreign_evidence")
                if record.get("toolchain_digest") != digest:
                    identity_errors.append("toolchain_digest_mismatch")
                if not DIGEST.fullmatch(str(record.get("artifact_digest", ""))):
                    identity_errors.append("artifact_digest_missing_or_invalid")
                artifact_relative = Path(str(record.get("artifact_path", "")))
                artifact_root = Path(".context/evidence/artifacts")
                if (
                    artifact_relative.is_absolute()
                    or ".." in artifact_relative.parts
                    or artifact_relative.parts[:3] != artifact_root.parts
                ):
                    identity_errors.append("artifact_path_missing_or_unsafe")
                else:
                    artifact = root / artifact_relative
                    if not artifact.is_file() or artifact.is_symlink():
                        identity_errors.append("producer_artifact_missing")
                    else:
                        actual_artifact_digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
                        if actual_artifact_digest != record.get("artifact_digest"):
                            identity_errors.append("producer_artifact_digest_mismatch")
                if record.get("gate_id") != declaration["gate"] or record.get("gate") != "PASS":
                    identity_errors.append("required_gate_missing_or_failed")
                supplied_evidence_digest = str(record.get("evidence_digest", ""))
                digest_input = {key: value for key, value in record.items() if key != "evidence_digest"}
                expected_evidence_digest = "sha256:" + hashlib.sha256(
                    json.dumps(digest_input, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if supplied_evidence_digest != expected_evidence_digest:
                    identity_errors.append("evidence_digest_missing_or_invalid")
                unknown_values = sorted(set(values) - set(names))
                if unknown_values:
                    identity_errors.append("unknown_requirements:" + ",".join(unknown_values))
                observations = record.get("observations", {})
                if not isinstance(observations, dict):
                    observations = {}
                if (
                    values.get("second_apply_changes_zero") == "PASS"
                    and observations.get("second_apply_changes") != 0
                ):
                    identity_errors.append("second_apply_changed_nonzero")
                if values.get("valid_signature") == "PASS" and observations.get("signature_verified") is not True:
                    identity_errors.append("signature_not_verified")
                if values.get("provenance_attestation") == "PASS" and observations.get("attestation_verified") is not True:
                    identity_errors.append("attestation_not_verified")
                if identity_errors:
                    output["stale_evidence"].append(
                        {"tool": tool, "capability": capability, "reasons": identity_errors}
                    )
                elif configured:
                    state = "verified"
                    evidence_ids = [str(record.get("id", f"{tool}-{capability}"))]
                    if _evaluate(declaration["requires"], values):
                        state = "proven"
            result = {
                "status": state,
                "relationships": declaration["relationships"],
                "scopes": declaration["scopes"],
                "requirements": {name: values.get(name, "MISSING") for name in names},
                "gates": [declaration["gate"]] if isinstance(record, dict) else [],
                "evidence": evidence_ids,
                "missing": missing,
            }
            tool_result["capabilities"][capability] = result
            for scope in declaration["scopes"]:
                output["capability_graph"].setdefault(capability, []).append(
                    {"tool": tool, "scope": scope, "relationships": declaration["relationships"], "status": state}
                )
                if state != "proven":
                    output["gaps"].append(
                        {"capability": capability, "scope": scope, "tool": tool,
                         "reason": identity_errors[0] if identity_errors else (missing[0] if missing else state)}
                    )
        output["tools"][tool] = tool_result

    for name in sorted(composed["capabilities"]):
        declaration = composed["capabilities"][name]
        missing: list[str] = []
        for requirement in declaration["requires"]["all"]:
            actual = output["tools"][requirement["tool"]]["capabilities"][requirement["capability"]]["status"]
            if STATES.index(actual) < STATES.index(requirement["status"]):
                missing.append(f"{requirement['tool']}.{requirement['capability']}:{requirement['status']}")
        output["composed_capabilities"][name] = {
            "status": "proven" if not missing else "not_proven", "scopes": declaration["scopes"], "missing": missing
        }
        if missing and declaration.get("required") is True:
            output["unknown_states"].append(f"required_composed_capability_incomplete:{name}")
    output["gaps"] = sorted(output["gaps"], key=lambda item: (item["capability"], item["scope"], item["tool"]))
    output["stale_evidence"] = sorted(output["stale_evidence"], key=lambda item: (item["tool"], item["capability"]))
    return output


def filtered(payload: dict[str, Any], *, tool: str = "", property_name: str = "", status: str = "", scope: str = "") -> dict[str, Any]:
    clone = json.loads(json.dumps(payload))
    for tool_name in list(clone["tools"]):
        if tool and tool_name != tool:
            del clone["tools"][tool_name]
            continue
        capabilities = clone["tools"][tool_name]["capabilities"]
        for name in list(capabilities):
            item = capabilities[name]
            if property_name and name != property_name:
                del capabilities[name]
            elif status == "not-proven" and item["status"] == "proven":
                del capabilities[name]
            elif status and status != "not-proven" and item["status"] != status:
                del capabilities[name]
            elif scope and scope not in item["scopes"]:
                del capabilities[name]
    return clone


def write(payload: dict[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
