#!/usr/bin/env python3
"""Validate bounded work package declarations without claiming execution evidence."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "config/contracts/work-package-policy.yaml"
REQUIRED_FIELDS = (
    "id",
    "milestone",
    "tracker_issue",
    "work_item_issue",
    "objective",
    "scope",
    "dependencies",
    "acceptance",
    "execution",
    "review",
    "completion",
    "exit_criteria",
)
SCOPE_FIELDS = ("allowed_paths", "forbidden_paths")
ACCEPTANCE_FIELDS = (
    "contracts",
    "qualification_gates",
    "runtime_evidence",
    "tests",
    "qce_capabilities",
)
EXECUTION_FIELDS = ("preflight_required", "runtime_required", "recovery_required")
EXECUTION_OPTIONAL_FIELDS = ("required_capabilities", "capability_parameters")
REVIEW_FIELDS = ("code", "security")
COMPLETION_FIELDS = ("post_merge_verification",)
ID_PATTERN = r"^[a-z][a-z0-9._-]{2,79}$"


class WorkPackageError(ValueError):
    """A work package or its policy cannot be trusted."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict:
    result: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise WorkPackageError("YAML mapping keys must be scalar") from exc
        if duplicate:
            raise WorkPackageError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8")
        value = yaml.load(content, Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise WorkPackageError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkPackageError(f"{path} must contain a YAML mapping")
    return value


def load_policy(root: Path = ROOT) -> dict[str, Any]:
    """Load the registered policy and reject attempts to weaken its minima."""
    root = Path(root)
    value = _read_yaml(root / POLICY_PATH)
    expected_header = {
        "version": 1,
        "kind": "WorkPackagePolicy",
        "status": "enforced",
        "architecture_authority": "architecture.lock.yaml",
        "roadmap_authority": "config/contracts/roadmap-policy.yaml",
        "qualification_authority": "config/contracts/qualification-execution-policy.yaml",
    }
    if set(value) != set(expected_header) | {"validation"}:
        raise WorkPackageError(
            "WorkPackagePolicy has missing or unknown top-level fields"
        )
    for key, expected in expected_header.items():
        if type(value.get(key)) is not type(expected) or value[key] != expected:
            raise WorkPackageError(f"WorkPackagePolicy.{key} is invalid")

    validation = value.get("validation")
    expected = {
        "required_fields": list(REQUIRED_FIELDS),
        "scope_fields": list(SCOPE_FIELDS),
        "acceptance_fields": list(ACCEPTANCE_FIELDS),
        "execution_fields": list(EXECUTION_FIELDS),
        "execution_optional_fields": list(EXECUTION_OPTIONAL_FIELDS),
        "review_fields": list(REVIEW_FIELDS),
        "completion_fields": list(COMPLETION_FIELDS),
        "id_pattern": ID_PATTERN,
        "objective_max_length": 400,
        "path_grammar": "exact-or-bounded-subtree",
        "forbidden_paths_take_precedence": True,
        "minimum_subtree_prefix_segments": 2,
        "required_review": "required",
        "required_preflight": True,
        "required_post_merge_verification": True,
        "nonempty_acceptance": ["contracts", "qualification_gates", "tests"],
        "runtime_evidence_required_if_runtime": True,
        "evidence_status": "NOT_EVALUATED",
    }
    if not isinstance(validation, dict) or set(validation) != set(expected):
        raise WorkPackageError("WorkPackagePolicy.validation is incomplete or unknown")
    for key, required in expected.items():
        if type(validation[key]) is not type(required) or validation[key] != required:
            raise WorkPackageError(f"WorkPackagePolicy.validation.{key} is invalid")
    return value


def _mapping(
    value: object,
    label: str,
    fields: tuple[str, ...],
    errors: list[str],
    *,
    optional_fields: tuple[str, ...] = (),
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label} must be a mapping")
        return {}
    missing = sorted(set(fields) - set(value))
    unknown = sorted(map(str, set(value) - set(fields) - set(optional_fields)))
    if missing:
        errors.append(f"{label} missing fields: {', '.join(missing)}")
    if unknown:
        errors.append(f"{label} unknown fields: {', '.join(map(str, unknown))}")
    return value


def _nonempty_text(value: object, label: str, errors: list[str], *, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
        or any(ord(char) < 32 for char in value)
    ):
        errors.append(
            f"{label} must be nonempty single-line text of at most {limit} characters"
        )
        return ""
    return value


def _string_list(
    value: object,
    label: str,
    errors: list[str],
    *,
    nonempty: bool = False,
    limit: int = 200,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        errors.append(f"{label} must be {'a nonempty' if nonempty else 'a'} list")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        text = _nonempty_text(item, f"{label}[{index}]", errors, limit=limit)
        if text:
            result.append(text)
    if len(result) != len(set(result)):
        errors.append(f"{label} contains duplicates")
    return result


def _safe_path(
    value: object,
    label: str,
    errors: list[str],
    *,
    subtree: bool = False,
    allow_context: bool = False,
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        errors.append(f"{label} must be a repository-relative path")
        return ""
    if (
        value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(ord(char) < 32 for char in value)
    ):
        errors.append(f"{label} must be a repository-relative path")
        return ""
    parts = value.split("/")
    if (
        any(part in ("", ".", "..") for part in parts)
        or parts[0] == ".git"
        or (parts[0] == ".context" and not allow_context)
    ):
        errors.append(f"{label} contains unsafe path components")
        return ""
    if any(any(char in part for char in "*?[]") for part in parts) and (
        not subtree
        or parts[-1] != "**"
        or len(parts) < 3
        or any(any(char in part for char in "*?[]") for part in parts[:-1])
    ):
        errors.append(f"{label} has an unbounded or unsupported path pattern")
        return ""
    return value


def _patterns(
    value: object, label: str, errors: list[str], *, nonempty: bool
) -> list[str]:
    values = _string_list(value, label, errors, nonempty=nonempty)
    result = [
        path
        for index, raw in enumerate(values)
        if (path := _safe_path(raw, f"{label}[{index}]", errors, subtree=True))
    ]
    return result


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-3] + "/")
    return path == pattern


def _known_qce_capabilities(roadmap: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    groups = roadmap.get("qce_traceability", {}).get("capabilities", {})
    if isinstance(groups, dict):
        for items in groups.values():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and isinstance(item.get("id"), str):
                        result.add(item["id"])
    return result


def _validate_contract_path(path: str, root: Path, errors: list[str]) -> None:
    if not (
        path == "architecture.lock.yaml"
        or path.startswith(("config/contracts/", "config/infrastructure/"))
    ):
        errors.append(
            f"acceptance.contracts: {path} is outside canonical contract roots"
        )
        return
    candidate = root / path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        errors.append(f"acceptance.contracts: {path} does not exist")
        return
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        errors.append(f"acceptance.contracts: {path} is not a repository contract file")


def _validate_relations(
    package: Mapping[str, Any],
    roadmap: Mapping[str, Any],
    errors: list[str],
    *,
    expected_issue: int | None,
    expected_milestone: str | None,
) -> None:
    milestone = package.get("milestone")
    if not isinstance(milestone, str) or not milestone:
        errors.append("milestone must be a nonempty roadmap milestone ID")
        return
    if expected_milestone is not None and milestone != expected_milestone:
        errors.append("milestone does not match the requested milestone")
    items = roadmap.get("milestones")
    matches = (
        [
            item
            for item in items
            if isinstance(item, dict) and item.get("id") == milestone
        ]
        if isinstance(items, list)
        else []
    )
    if len(matches) != 1:
        errors.append(f"milestone {milestone} is not unique in RoadmapPolicy")
        return
    tracker = package.get("tracker_issue")
    if type(tracker) is not int or tracker <= 0:
        errors.append("tracker_issue must be a positive issue number")
    elif tracker != matches[0].get("tracker"):
        errors.append(
            f"tracker_issue does not match RoadmapPolicy milestone {milestone}"
        )
    issue = package.get("work_item_issue")
    if type(issue) is not int or issue <= 0:
        errors.append("work_item_issue must be a positive issue number")
    elif issue == tracker:
        errors.append("work_item_issue must differ from tracker_issue")
    if expected_issue is not None and issue != expected_issue:
        errors.append("work_item_issue does not match the requested issue")


def _validate_acceptance(
    acceptance: Mapping[str, Any],
    execution: Mapping[str, Any],
    root: Path,
    roadmap: Mapping[str, Any],
    qualification: Mapping[str, Any],
    errors: list[str],
) -> None:
    contracts = _string_list(
        acceptance.get("contracts"), "acceptance.contracts", errors, nonempty=True
    )
    for index, raw in enumerate(contracts):
        path = _safe_path(raw, f"acceptance.contracts[{index}]", errors)
        if path:
            _validate_contract_path(path, root, errors)

    gates = _string_list(
        acceptance.get("qualification_gates"),
        "acceptance.qualification_gates",
        errors,
        nonempty=True,
    )
    known_gates = qualification.get("gates")
    if not isinstance(known_gates, dict):
        errors.append("QualificationExecutionPolicy has no gate registry")
    else:
        for gate in gates:
            if gate not in known_gates:
                errors.append(f"acceptance.qualification_gates: unknown gate {gate}")

    tests = _string_list(
        acceptance.get("tests"), "acceptance.tests", errors, nonempty=True
    )
    for index, raw in enumerate(tests):
        path = _safe_path(raw, f"acceptance.tests[{index}]", errors)
        if path and not path.startswith("tests/"):
            errors.append(f"acceptance.tests: {path} must be under tests/")

    capabilities = _string_list(
        acceptance.get("qce_capabilities"), "acceptance.qce_capabilities", errors
    )
    known_capabilities = _known_qce_capabilities(roadmap)
    for capability in capabilities:
        if capability not in known_capabilities:
            errors.append(
                f"acceptance.qce_capabilities: unknown capability {capability}"
            )

    evidence = _string_list(
        acceptance.get("runtime_evidence"), "acceptance.runtime_evidence", errors
    )
    for index, raw in enumerate(evidence):
        path = _safe_path(
            raw, f"acceptance.runtime_evidence[{index}]", errors, allow_context=True
        )
        if path and (
            not path.startswith(".context/evidence/") or not path.endswith(".json")
        ):
            errors.append(
                f"acceptance.runtime_evidence: {path} must be a .context/evidence JSON path"
            )
    if execution.get("runtime_required") is True and not evidence:
        errors.append(
            "acceptance.runtime_evidence required when execution.runtime_required"
        )
    if execution.get("runtime_required") is False and evidence:
        errors.append(
            "execution.runtime_required is false but runtime evidence is required"
        )


PARAMETER_TYPES = {
    "positive-integer",
    "nonempty-string",
    "pinned-version",
    "sha256-digest",
    "tcp-port",
    "repository-relative-path",
    "virtualbox-backend",
}


def _validate_parameter_value(
    capability: str, name: str, value: object, kind: str, errors: list[str]
) -> None:
    label = f"execution.capability_parameters.{capability}.{name}"
    if kind == "positive-integer":
        valid = type(value) is int and value > 0
    elif kind == "tcp-port":
        valid = type(value) is int and 1 <= value <= 65535
    elif kind == "nonempty-string":
        valid = (
            isinstance(value, str)
            and bool(value)
            and value == value.strip()
            and not any(ord(char) < 32 for char in value)
        )
    elif kind == "pinned-version":
        valid = (
            isinstance(value, str)
            and re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+",
                value,
            )
            is not None
        )
    elif kind == "sha256-digest":
        valid = (
            isinstance(value, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
        )
    elif kind == "repository-relative-path":
        valid = bool(_safe_path(value, label, errors, allow_context=True))
        if not valid:
            return
    elif kind == "virtualbox-backend":
        valid = value in ("NEM", "NATIVE_VTX")
    else:
        errors.append(f"{label} uses unsupported parameter type {kind}")
        return
    if not valid:
        errors.append(f"{label} must match {kind}")


def _validate_capabilities(
    execution: Mapping[str, Any], qualification: Mapping[str, Any], errors: list[str]
) -> None:
    capabilities = _string_list(
        execution.get("required_capabilities", []),
        "execution.required_capabilities",
        errors,
    )
    runtime = qualification.get("runtime_orchestration")
    preflight = qualification.get("work_item_preflight")
    runtime_registry = (
        runtime.get("capabilities") if isinstance(runtime, dict) else None
    )
    extra_registry = (
        preflight.get("additional_capabilities")
        if isinstance(preflight, dict)
        else None
    )
    if not isinstance(runtime_registry, dict) or not isinstance(extra_registry, dict):
        errors.append("QualificationExecutionPolicy capability registries are invalid")
        return
    if set(runtime_registry) & set(extra_registry):
        errors.append("QualificationExecutionPolicy capability registries overlap")
        return
    definitions = {**runtime_registry, **extra_registry}
    parameters = execution.get("capability_parameters", {})
    if not isinstance(parameters, dict):
        errors.append("execution.capability_parameters must be a mapping")
        return
    for capability in sorted(parameters, key=str):
        if capability not in capabilities:
            errors.append(
                f"execution.capability_parameters: {capability} is not a required capability"
            )
    for capability in capabilities:
        definition = definitions.get(capability)
        if not isinstance(definition, dict):
            errors.append(
                f"execution.required_capabilities: unknown capability {capability}"
            )
            continue
        required = definition.get("required_parameters", [])
        types = definition.get("parameter_types", {})
        if (
            not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
            or len(set(required)) != len(required)
            or not isinstance(types, dict)
            or not all(
                isinstance(name, str) and kind in PARAMETER_TYPES
                for name, kind in types.items()
            )
            or not set(required) <= set(types)
        ):
            errors.append(
                f"QualificationExecutionPolicy metadata invalid for {capability}"
            )
            continue
        values = parameters.get(capability, {})
        if not isinstance(values, dict):
            errors.append(
                f"execution.capability_parameters.{capability} must be a mapping"
            )
            continue
        for name in sorted(set(required) - set(values)):
            errors.append(
                f"execution.capability_parameters.{capability}.{name} is required"
            )
        for name in sorted(set(values) - set(types), key=str):
            errors.append(
                f"execution.capability_parameters.{capability}.{name} is not declared"
            )
        for name in sorted(set(values) & set(types)):
            _validate_parameter_value(
                capability, name, values[name], types[name], errors
            )


def resolve_dependencies(
    package: Mapping[str, Any], *, root: Path = ROOT
) -> list[dict[str, Any]]:
    """Resolve canonical declarations in dependency order, without reading proofs."""
    if not isinstance(package, Mapping):
        raise WorkPackageError("dependencies: package must be a mapping")
    errors: list[str] = []
    requested = _string_list(package.get("dependencies"), "dependencies", errors)
    if errors:
        raise WorkPackageError("; ".join(errors))
    if not requested:
        return []
    root = Path(root)
    roadmap = _read_yaml(root / "config/contracts/roadmap-policy.yaml")
    milestones: dict[str, Mapping[str, Any]] = {}
    for item in roadmap.get("milestones", []):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise WorkPackageError("dependencies: invalid canonical milestone")
        if item["id"] in milestones:
            raise WorkPackageError("dependencies: ambiguous canonical milestone")
        milestones[item["id"]] = item

    def permitted_milestones(
        identifier: str, active: frozenset[str] = frozenset()
    ) -> set[str]:
        if identifier in active or identifier not in milestones:
            raise WorkPackageError("dependencies: unknown or cyclic milestone relation")
        allowed = {identifier}
        requirements = milestones[identifier].get("requires", [])
        if not isinstance(requirements, list) or any(
            not isinstance(value, str) for value in requirements
        ):
            raise WorkPackageError("dependencies: invalid milestone requirements")
        for required in requirements:
            allowed.update(permitted_milestones(required, active | {identifier}))
        return allowed

    registry = root / "config/work-packages"
    for component in (root, root / "config", registry):
        if component.is_symlink():
            raise WorkPackageError(
                "dependencies: canonical registry contains a symlink"
            )
    entries = sorted(registry.glob("*/*.yaml"))
    if len(entries) > 256:
        raise WorkPackageError(
            "dependencies: canonical registry exceeds package budget"
        )
    indexed: dict[str, dict[str, Any]] = {}
    issues: set[int] = set()
    for path in entries:
        if (
            path.parent.is_symlink()
            or path.is_symlink()
            or path.stat().st_size > 1_000_000
        ):
            raise WorkPackageError("dependencies: canonical package is unsafe")
        item = _read_yaml(path)
        identifier = item.get("id")
        relation_errors: list[str] = []
        _validate_relations(
            item,
            roadmap,
            relation_errors,
            expected_issue=None,
            expected_milestone=path.parent.name,
        )
        if (
            not isinstance(identifier, str)
            or re.fullmatch(ID_PATTERN, identifier) is None
            or path.stem != identifier
            or relation_errors
        ):
            raise WorkPackageError(
                "dependencies: canonical package relation is invalid"
            )
        if identifier in indexed or item["work_item_issue"] in issues:
            raise WorkPackageError(
                "dependencies: ambiguous package ID or work-item issue"
            )
        indexed[identifier] = item
        issues.add(item["work_item_issue"])
    identifier = package.get("id")
    if not isinstance(identifier, str) or re.fullmatch(ID_PATTERN, identifier) is None:
        raise WorkPackageError("dependencies: invalid source package ID")
    if identifier in indexed and indexed[identifier] != dict(package):
        raise WorkPackageError(
            "dependencies: source differs from its canonical declaration"
        )
    # The source may be a newly declared package, while dependencies must already
    # have unique canonical files. Never recursively call package validation.
    indexed[identifier] = dict(package)
    visited: set[str] = set()
    active: set[str] = set()
    ordered: list[dict[str, Any]] = []

    def visit(current_id: str) -> None:
        if current_id in active:
            raise WorkPackageError("dependencies: cyclic work-package relation")
        if current_id in visited:
            return
        current = indexed.get(current_id)
        if current is None:
            raise WorkPackageError(f"dependencies: unregistered package {current_id}")
        active.add(current_id)
        declaration_errors: list[str] = []
        declared = _string_list(
            current.get("dependencies"), "dependencies", declaration_errors
        )
        if declaration_errors:
            raise WorkPackageError("; ".join(declaration_errors))
        permitted = permitted_milestones(current.get("milestone"))
        for dependency in declared:
            if re.fullmatch(ID_PATTERN, dependency) is None:
                raise WorkPackageError("dependencies: invalid dependency identifier")
            candidate = indexed.get(dependency)
            if candidate is None:
                raise WorkPackageError(
                    f"dependencies: unregistered package {dependency}"
                )
            if candidate.get("milestone") not in permitted:
                raise WorkPackageError(
                    f"dependencies: milestone {candidate.get('milestone')} is not permitted "
                    f"for {current.get('milestone')}"
                )
            visit(dependency)
        active.remove(current_id)
        visited.add(current_id)
        if current_id != identifier:
            ordered.append(current)

    visit(identifier)
    return ordered


def validate_work_package(
    package: object,
    *,
    root: Path = ROOT,
    changed_paths: Iterable[str] | None = None,
    expected_issue: int | None = None,
    expected_milestone: str | None = None,
) -> list[str]:
    """Validate a declaration and optional changed paths; never validate evidence."""
    errors: list[str] = []
    root = Path(root)
    try:
        load_policy(root)
        roadmap = _read_yaml(root / "config/contracts/roadmap-policy.yaml")
        qualification = _read_yaml(
            root / "config/contracts/qualification-execution-policy.yaml"
        )
    except WorkPackageError as exc:
        return [str(exc)]
    item = _mapping(package, "work_package", REQUIRED_FIELDS, errors)
    if not item:
        return errors

    identifier = _nonempty_text(item.get("id"), "id", errors, limit=80)
    if identifier and re.fullmatch(ID_PATTERN, identifier) is None:
        errors.append("id must be a stable lowercase work package identifier")
    _validate_relations(
        item,
        roadmap,
        errors,
        expected_issue=expected_issue,
        expected_milestone=expected_milestone,
    )
    _nonempty_text(item.get("objective"), "objective", errors, limit=400)
    scope = _mapping(item.get("scope"), "scope", SCOPE_FIELDS, errors)
    allowed = _patterns(
        scope.get("allowed_paths"), "scope.allowed_paths", errors, nonempty=True
    )
    forbidden = _patterns(
        scope.get("forbidden_paths"), "scope.forbidden_paths", errors, nonempty=False
    )
    for pattern in sorted(set(allowed) & set(forbidden)):
        errors.append(f"scope pattern {pattern} is both allowed and forbidden")

    dependencies = _string_list(item.get("dependencies"), "dependencies", errors)
    for dependency in dependencies:
        if re.fullmatch(ID_PATTERN, dependency) is None or dependency == identifier:
            errors.append(f"dependencies: invalid or self-referential ID {dependency}")

    if dependencies and not any(error.startswith("dependencies") for error in errors):
        try:
            resolve_dependencies(item, root=root)
        except (WorkPackageError, OSError, TypeError, ValueError) as exc:
            errors.append(str(exc))

    execution = _mapping(
        item.get("execution"),
        "execution",
        EXECUTION_FIELDS,
        errors,
        optional_fields=EXECUTION_OPTIONAL_FIELDS,
    )
    for field in EXECUTION_FIELDS:
        if type(execution.get(field)) is not bool:
            errors.append(f"execution.{field} must be boolean")
    if execution.get("preflight_required") is not True:
        errors.append("execution.preflight_required must be true")
    if (
        execution.get("recovery_required") is True
        and execution.get("runtime_required") is not True
    ):
        errors.append("execution.recovery_required requires execution.runtime_required")
    _validate_capabilities(execution, qualification, errors)

    acceptance = _mapping(
        item.get("acceptance"), "acceptance", ACCEPTANCE_FIELDS, errors
    )
    _validate_acceptance(acceptance, execution, root, roadmap, qualification, errors)

    review = _mapping(item.get("review"), "review", REVIEW_FIELDS, errors)
    for field in REVIEW_FIELDS:
        if review.get(field) != "required":
            errors.append(f"review.{field} must be required")
    completion = _mapping(
        item.get("completion"), "completion", COMPLETION_FIELDS, errors
    )
    if completion.get("post_merge_verification") is not True:
        errors.append("completion.post_merge_verification must be true")

    _string_list(
        item.get("exit_criteria"), "exit_criteria", errors, nonempty=True, limit=500
    )

    if changed_paths is not None:
        if isinstance(changed_paths, (str, bytes)):
            errors.append(
                "scope.changed_paths must be a sequence of repository-relative paths"
            )
        else:
            for index, raw in enumerate(changed_paths):
                path = _safe_path(raw, f"scope.changed_paths[{index}]", errors)
                if not path:
                    continue
                if not any(_matches(path, pattern) for pattern in allowed):
                    errors.append(
                        f"scope.changed_paths: {path} is outside allowed_paths"
                    )
                if any(_matches(path, pattern) for pattern in forbidden):
                    errors.append(f"scope.changed_paths: {path} is forbidden")
    return errors


def work_package_status(
    package: object,
    *,
    root: Path = ROOT,
    changed_paths: Iterable[str] | None = None,
    expected_issue: int | None = None,
    expected_milestone: str | None = None,
) -> dict[str, Any]:
    """Return declaration status, explicitly excluding execution and proof claims."""
    paths = (
        changed_paths
        if isinstance(changed_paths, (str, bytes))
        else (None if changed_paths is None else list(changed_paths))
    )
    errors = validate_work_package(
        package,
        root=root,
        changed_paths=paths,
        expected_issue=expected_issue,
        expected_milestone=expected_milestone,
    )
    scope_errors = any(error.startswith(("scope.", "scope ")) for error in errors)
    return {
        "status": "INVALID" if errors else "VALID",
        "scope_status": (
            "NOT_CHECKED" if paths is None else "INVALID" if scope_errors else "VALID"
        ),
        "preflight_status": "NOT_EVALUATED",
        "acceptance_status": "NOT_EVALUATED",
        "runtime_status": "NOT_EVALUATED",
        "id": package.get("id") if isinstance(package, dict) else None,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate"])
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--changed-path", action="append", dest="changed_paths")
    parser.add_argument("--issue", type=int)
    parser.add_argument("--milestone")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        package = _read_yaml(args.package)
        result = work_package_status(
            package,
            changed_paths=args.changed_paths,
            expected_issue=args.issue,
            expected_milestone=args.milestone,
        )
    except WorkPackageError as exc:
        result = {
            "status": "INVALID",
            "scope_status": "NOT_CHECKED",
            "preflight_status": "NOT_EVALUATED",
            "acceptance_status": "NOT_EVALUATED",
            "runtime_status": "NOT_EVALUATED",
            "id": None,
            "errors": [str(exc)],
        }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result["status"])
        for error in result["errors"]:
            print(f"- {error}")
    return 0 if result["status"] == "VALID" else 2


if __name__ == "__main__":
    raise SystemExit(main())
