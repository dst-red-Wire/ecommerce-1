#!/usr/bin/env python3
"""Synchronize project roadmap status from the canonical policy and GitHub issue state."""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())

SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_cache


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(detail or f"command failed: {command}")
    return result


def load_yaml(relative: str) -> dict[str, Any]:
    value = qualification_cache.psych_load(ROOT / relative)
    if not isinstance(value, dict):
        raise RuntimeError(f"{relative} must be a YAML mapping")
    return value


def policy() -> dict[str, Any]:
    lock = load_yaml("architecture.lock.yaml")
    relative = lock.get("machine_contracts", {}).get("roadmap_policy")
    if not isinstance(relative, str) or not relative:
        raise RuntimeError("roadmap policy is not registered in architecture.lock.yaml")
    value = load_yaml(relative)
    if (
        value.get("version") != 1
        or value.get("kind") != "RoadmapPolicy"
        or value.get("status") != "enforced"
        or value.get("architecture_authority") != "architecture.lock.yaml"
        or value.get("document") != "docs/project/MASTER_EXECUTION_PLAN.md"
    ):
        raise RuntimeError("invalid roadmap policy header")

    rendering = value.get("rendering")
    milestones = value.get("milestones")
    if not isinstance(rendering, dict) or not isinstance(milestones, list) or not milestones:
        raise RuntimeError("roadmap policy must declare rendering and milestones")

    derivation = value.get("status_derivation")
    if (
        not isinstance(derivation, dict)
        or derivation.get("manual_status_override") != "forbidden"
        or derivation.get("qualification_base_ref") != "origin/main"
        or set(derivation.get("statuses", {}))
        != {"NOT_STARTED", "CONTRACTED", "PARTIAL", "IMPLEMENTED", "PROVEN", "BLOCKED"}
        or derivation.get("dependency_terminal_statuses") != ["DONE", "PROVEN"]
    ):
        raise RuntimeError("roadmap status derivation contract is invalid")
    projection = Path(str(derivation.get("projection_output", "")))
    if (
        projection.is_absolute()
        or ".." in projection.parts
        or projection.parts[:2] != (".context", "evidence")
        or projection.suffix != ".json"
    ):
        raise RuntimeError("roadmap projection must remain under .context/evidence")
    runtime_contract = derivation.get("runtime_evidence_contract")
    runtime_fields = {
        "schema_version", "status", "exact_commit_evidence", "runtime_execution",
        "head_sha", "head_tree_sha", "created_at_epoch", "milestone", "environment",
        "runtime_identity", "outcome",
    }
    if (
        not isinstance(runtime_contract, dict)
        or runtime_contract.get("schema_version") != 1
        or set(runtime_contract.get("required_fields", [])) != runtime_fields
        or runtime_contract.get("accepted_status") != "PASS"
        or runtime_contract.get("accepted_outcome") != "PASS"
        or runtime_contract.get("runtime_identity_required_fields") != ["kind", "id"]
    ):
        raise RuntimeError("roadmap runtime evidence contract is invalid")

    ids = [str(item.get("id") or "") for item in milestones if isinstance(item, dict)]
    if len(ids) != len(milestones) or any(not item for item in ids) or len(ids) != len(set(ids)):
        raise RuntimeError("roadmap milestone ids must be non-empty and unique")
    known = set(ids)
    qualification = load_yaml("config/contracts/qualification-execution-policy.yaml")
    known_gates = set(qualification.get("gates", {}))
    qce_capabilities = {
        str(capability.get("id"))
        for capabilities in value.get("qce_traceability", {}).get("capabilities", {}).values()
        if isinstance(capabilities, list)
        for capability in capabilities
        if isinstance(capability, dict)
    }
    seen: set[str] = set()
    for item in milestones:
        milestone_id = str(item["id"])
        forbidden_status_fields = {"completion_status", "status", "manual_status"} & set(item)
        if forbidden_status_fields:
            raise RuntimeError(
                f"roadmap milestone {milestone_id} contains forbidden static status fields"
            )
        requires = item.get("requires", [])
        if not isinstance(requires, list) or any(dep not in known for dep in requires):
            raise RuntimeError(f"roadmap milestone {milestone_id} has invalid dependencies")
        if any(str(dep) not in seen for dep in requires):
            raise RuntimeError(
                f"roadmap milestone {milestone_id} dependencies must appear earlier in topological order"
            )
        seen.add(milestone_id)
        if "fixed_status" not in item:
            tracker = item.get("tracker")
            heading = item.get("section_heading")
            if type(tracker) is not int or tracker <= 0:
                raise RuntimeError(f"roadmap milestone {item.get('id')} requires a positive tracker issue number")
            if not isinstance(heading, str) or not heading.startswith("### "):
                raise RuntimeError(f"roadmap milestone {item.get('id')} requires a section_heading")
            requirements = item.get("requirements")
            if not isinstance(requirements, dict) or set(requirements) != {
                "implementation_paths", "qualification_gates", "qce_capabilities", "runtime_evidence"
            }:
                raise RuntimeError(f"roadmap milestone {milestone_id} requirements are invalid")
            paths = requirements["implementation_paths"]
            gates = requirements["qualification_gates"]
            capabilities = requirements["qce_capabilities"]
            runtime = requirements["runtime_evidence"]
            if not all(isinstance(group, list) for group in (paths, gates, capabilities, runtime)):
                raise RuntimeError(f"roadmap milestone {milestone_id} requirements must be lists")
            for relative in paths:
                path = Path(str(relative))
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    raise RuntimeError(f"roadmap milestone {milestone_id} has unsafe implementation path")
            if set(gates) - known_gates:
                raise RuntimeError(f"roadmap milestone {milestone_id} references unknown qualification gates")
            if set(capabilities) - qce_capabilities:
                raise RuntimeError(f"roadmap milestone {milestone_id} references unknown QCE capabilities")
            for evidence in runtime:
                if not isinstance(evidence, dict) or set(evidence) != {"path", "environments"}:
                    raise RuntimeError(f"roadmap milestone {milestone_id} runtime evidence is invalid")
                evidence_path = Path(str(evidence["path"]))
                environments = evidence["environments"]
                if (
                    evidence_path.is_absolute()
                    or ".." in evidence_path.parts
                    or evidence_path.parts[:3] != (".context", "evidence", "roadmap")
                    or evidence_path.suffix != ".json"
                    or not isinstance(environments, list)
                    or not environments
                    or not all(isinstance(environment, str) and environment for environment in environments)
                ):
                    raise RuntimeError(f"roadmap milestone {milestone_id} runtime evidence is unsafe")
            if milestone_id in {"M3", "M4", "M5", "M6", "M7", "M8", "M9"} and not runtime:
                raise RuntimeError(f"roadmap milestone {milestone_id} requires runtime evidence")
        elif milestone_id != "M0" or item.get("fixed_status") != "DONE":
            raise RuntimeError("only completed architecture sync may use a fixed roadmap status")
    return value


def github_name_with_owner(gh: str) -> str:
    response = run([gh, "repo", "view", "--json", "nameWithOwner"], check=False)
    if response.returncode:
        detail = (response.stderr or response.stdout or "").strip()
        raise RuntimeError(detail or "unable to resolve GitHub repository")
    try:
        payload = json.loads(response.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid GitHub repository JSON") from exc
    name = str(payload.get("nameWithOwner") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
        raise RuntimeError("invalid GitHub nameWithOwner")
    return name


def tracker_states(gh: str, roadmap_policy: dict[str, Any]) -> dict[int, dict[str, str]]:
    repository = github_name_with_owner(gh)
    states: dict[int, dict[str, str]] = {}
    for milestone in roadmap_policy["milestones"]:
        if "fixed_status" in milestone:
            continue
        tracker = int(milestone["tracker"])
        response = run([gh, "api", f"repos/{repository}/issues/{tracker}"], check=False)
        if response.returncode:
            detail = (response.stderr or response.stdout or "").strip()
            raise RuntimeError(f"unable to read roadmap tracker #{tracker}: {detail or 'GitHub API error'}")
        try:
            issue = json.loads(response.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid GitHub JSON for roadmap tracker #{tracker}") from exc
        if not isinstance(issue, dict) or issue.get("pull_request") is not None:
            raise RuntimeError(f"roadmap tracker #{tracker} must be a GitHub issue, not a pull request")
        if int(issue.get("number") or 0) != tracker:
            raise RuntimeError(f"roadmap tracker #{tracker} returned the wrong issue")
        states[tracker] = {
            "state": str(issue.get("state") or "").lower(),
            "state_reason": str(issue.get("state_reason") or "").lower(),
            "title": str(issue.get("title") or ""),
        }
    return states


def qce_metadata_snapshot(gh: str, roadmap_policy: dict[str, Any]) -> Path:
    """Materialize non-authoritative GitHub relations for offline QCE projection."""
    lock = load_yaml("architecture.lock.yaml")
    sectors = lock.get("developer_platform", {}).get("quality_cloud_engineering", {}).get("sectors", {})
    if not isinstance(sectors, dict) or len(sectors) != 9:
        raise RuntimeError("QCE GitHub snapshot requires exactly nine architecture sectors")
    valid_labels = {"qce:" + str(sector).replace("_", "-") for sector in sectors}
    repository = github_name_with_owner(gh)

    def entities(kind: str, fields: str) -> list[dict[str, Any]]:
        response = run([gh, kind, "list", "--state", "all", "--limit", "1000", "--json", fields], check=False)
        if response.returncode:
            detail = (response.stderr or response.stdout or "").strip()
            raise RuntimeError(f"unable to read GitHub {kind} relations: {detail or 'GitHub CLI error'}")
        try:
            values = json.loads(response.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid GitHub {kind} relation JSON") from exc
        if not isinstance(values, list):
            raise RuntimeError(f"GitHub {kind} relation JSON must be a list")
        normalized = []
        for value in values:
            if not isinstance(value, dict) or type(value.get("number")) is not int:
                raise RuntimeError(f"GitHub {kind} relation entry is invalid")
            labels = sorted(
                str(item.get("name"))
                for item in value.get("labels", [])
                if isinstance(item, dict) and str(item.get("name", "")).startswith("qce:")
            )
            unknown = sorted(set(labels) - valid_labels)
            if unknown:
                raise RuntimeError("unknown QCE label: " + ", ".join(unknown))
            if not labels:
                continue
            entry = {
                "number": int(value["number"]),
                "labels": labels,
                "milestone": (value.get("milestone") or {}).get("title")
                if isinstance(value.get("milestone"), dict)
                else None,
            }
            if kind == "pr":
                entry["head_sha"] = value.get("headRefOid")
            normalized.append(entry)
        return sorted(normalized, key=lambda item: item["number"])

    trace = roadmap_policy.get("qce_traceability", {})
    relative = trace.get("github_metadata_snapshot")
    if not isinstance(relative, str) or not relative.startswith(".context/"):
        raise RuntimeError("QCE GitHub metadata snapshot must remain under .context")
    destination = ROOT / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "issues": entities("issue", "number,labels,milestone"),
        "pull_requests": entities("pr", "number,labels,milestone,headRefOid"),
        "blockers": [],
    }
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _runtime_evidence_result(
    root: Path,
    declaration: dict[str, Any],
    milestone_id: str,
    head: str,
    tree: str,
    contract: dict[str, Any],
    maximum_age: int,
    now: datetime,
) -> tuple[bool, str]:
    path = root / str(declaration["path"])
    relative = path.relative_to(root).as_posix()
    if not path.is_file():
        return False, f"runtime evidence missing: {relative}"
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, f"runtime evidence malformed: {relative}"
    if not isinstance(evidence, dict) or any(
        field not in evidence for field in contract["required_fields"]
    ):
        return False, f"runtime evidence fields missing: {relative}"
    if (
        evidence.get("schema_version") != contract["schema_version"]
        or evidence.get("status") != contract["accepted_status"]
        or evidence.get("outcome") != contract["accepted_outcome"]
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("runtime_execution") is not True
        or evidence.get("milestone") != milestone_id
    ):
        return False, f"runtime evidence outcome or milestone is invalid: {relative}"
    if evidence.get("head_sha") != head or evidence.get("head_tree_sha") != tree:
        return False, f"runtime evidence has wrong SHA or tree: {relative}"
    if evidence.get("environment") not in declaration["environments"]:
        return False, f"runtime evidence has wrong environment: {relative}"
    identity = evidence.get("runtime_identity")
    if not isinstance(identity, dict) or any(
        not isinstance(identity.get(field), str) or not identity[field]
        for field in contract["runtime_identity_required_fields"]
    ):
        return False, f"runtime evidence identity is invalid: {relative}"
    created = evidence.get("created_at_epoch")
    if (
        isinstance(created, bool)
        or not isinstance(created, (int, float))
        or not math.isfinite(float(created))
    ):
        return False, f"runtime evidence timestamp is invalid: {relative}"
    age = now.timestamp() - float(created)
    if age < 0 or age > maximum_age:
        return False, f"runtime evidence is stale or future-dated: {relative}"
    return True, relative


def _qce_capability_statuses(payload: dict[str, Any] | None) -> dict[str, str]:
    statuses: dict[str, str] = {}
    if not isinstance(payload, dict):
        return statuses
    for sector in payload.get("sectors", []):
        if not isinstance(sector, dict):
            continue
        for capability in sector.get("capabilities", []):
            if isinstance(capability, dict) and isinstance(capability.get("id"), str):
                statuses[capability["id"]] = str(capability.get("status", ""))
    return statuses


def derive_projection(
    roadmap_policy: dict[str, Any],
    states: dict[int, dict[str, str]],
    *,
    root: Path = ROOT,
    qualification_gates: dict[str, str] | None = None,
    qualification_evidence_path: str | None = None,
    qce_payload: dict[str, Any] | None = None,
    head: str | None = None,
    tree: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    derivation = roadmap_policy["status_derivation"]
    terminal = set(derivation["dependency_terminal_statuses"])
    completed_state = str(roadmap_policy["github"]["completed_state"]).lower()
    completed_reason = str(roadmap_policy["github"]["completed_state_reason"]).lower()
    head = head or run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tree = tree or run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip()
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    gate_statuses = qualification_gates or {}
    qce_statuses = _qce_capability_statuses(qce_payload)
    results: list[dict[str, Any]] = []
    status_index: dict[str, str] = {}

    for milestone in roadmap_policy["milestones"]:
        milestone_id = str(milestone["id"])
        if "fixed_status" in milestone:
            status = str(milestone["fixed_status"])
            results.append(
                {
                    "milestone": milestone_id,
                    "status": status,
                    "requirements": ["architecture-lock-and-sync-complete"],
                    "evidence": ["architecture.lock.yaml"],
                    "missing_evidence": [],
                    "blockers": [],
                }
            )
            status_index[milestone_id] = status
            continue

        tracker = int(milestone["tracker"])
        state = states.get(tracker)
        if not isinstance(state, dict):
            raise RuntimeError(f"roadmap tracker state missing for #{tracker}")
        requirements = milestone["requirements"]
        evidence: list[str] = []
        missing: list[str] = []
        blockers: list[str] = []
        requirement_names: list[str] = [f"tracker:#{tracker}"]

        dependencies = [str(dep) for dep in milestone.get("requires", [])]
        requirement_names.extend(f"dependency:{dependency}" for dependency in dependencies)
        unmet_dependencies = [
            dependency for dependency in dependencies if status_index.get(dependency) not in terminal
        ]
        blockers.extend(f"dependency not PROVEN: {dependency}" for dependency in unmet_dependencies)

        tracker_complete = (
            state.get("state") == completed_state
            and state.get("state_reason") == completed_reason
        )
        if tracker_complete:
            evidence.append(f"github-issue:#{tracker}:completed")
        else:
            missing.append(f"github-issue:#{tracker}:completed")
            if state.get("state") == completed_state:
                blockers.append(
                    f"tracker #{tracker} closed as {state.get('state_reason') or 'unknown'}"
                )

        paths = [str(path) for path in requirements["implementation_paths"]]
        requirement_names.extend(f"implementation:{path}" for path in paths)
        present_paths = [path for path in paths if (root / path).exists()]
        evidence.extend(present_paths)
        missing.extend(f"implementation:{path}" for path in paths if path not in present_paths)

        gates = [str(gate) for gate in requirements["qualification_gates"]]
        requirement_names.extend(f"qualification:{gate}" for gate in gates)
        for gate in gates:
            if gate_statuses.get(gate) == "PASS":
                evidence.append(f"qualification:{gate}:{qualification_evidence_path or 'exact-SHA'}")
            else:
                missing.append(f"qualification:{gate}")

        capabilities = [str(capability) for capability in requirements["qce_capabilities"]]
        requirement_names.extend(f"qce:{capability}" for capability in capabilities)
        for capability in capabilities:
            capability_status = qce_statuses.get(capability)
            if capability_status == "PROVEN":
                evidence.append(f"qce:{capability}:PROVEN")
            else:
                missing.append(f"qce:{capability}:{capability_status or 'MISSING'}")
                if capability_status == "BLOCKED":
                    blockers.append(f"QCE capability blocked: {capability}")

        runtime_declarations = requirements["runtime_evidence"]
        requirement_names.extend(f"runtime:{item['path']}" for item in runtime_declarations)
        runtime_valid = True
        for declaration in runtime_declarations:
            valid, detail = _runtime_evidence_result(
                root,
                declaration,
                milestone_id,
                head,
                tree,
                derivation["runtime_evidence_contract"],
                int(derivation["evidence_max_age_seconds"]),
                now,
            )
            runtime_valid = runtime_valid and valid
            (evidence if valid else missing).append(detail)

        implementation_complete = tracker_complete and len(present_paths) == len(paths)
        proof_complete = (
            implementation_complete
            and all(gate_statuses.get(gate) == "PASS" for gate in gates)
            and all(qce_statuses.get(capability) == "PROVEN" for capability in capabilities)
            and runtime_valid
        )
        if blockers:
            status = "BLOCKED"
        elif proof_complete:
            status = "PROVEN"
        elif implementation_complete:
            status = "IMPLEMENTED"
        elif tracker_complete or present_paths or evidence:
            status = "PARTIAL"
        else:
            status = "CONTRACTED"
        status_index[milestone_id] = status
        results.append(
            {
                "milestone": milestone_id,
                "status": status,
                "requirements": requirement_names,
                "evidence": sorted(set(evidence)),
                "missing_evidence": sorted(set(missing)),
                "blockers": sorted(set(blockers)),
            }
        )
    return {
        "schema_version": 1,
        "head_sha": head,
        "head_tree_sha": tree,
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "milestones": results,
    }


def compute_statuses(
    roadmap_policy: dict[str, Any],
    states: dict[int, dict[str, str]],
    **kwargs: Any,
) -> dict[str, str]:
    projection = derive_projection(roadmap_policy, states, **kwargs)
    return {item["milestone"]: item["status"] for item in projection["milestones"]}


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_table(roadmap_policy: dict[str, Any], statuses: dict[str, str]) -> str:
    rows = [
        "| Milestone | Tracker | Primary owner | Objective | Entry gate | Exit gate | Current status |",
        "|---|---:|---|---|---|---|---|",
    ]
    for milestone in roadmap_policy["milestones"]:
        milestone_id = str(milestone["id"])
        tracker = "—" if "fixed_status" in milestone else f"#{int(milestone['tracker'])}"
        rows.append(
            "| "
            + " | ".join(
                [
                    cell(f"{milestone_id} {milestone['name']}"),
                    tracker,
                    cell(milestone["owner"]),
                    cell(milestone["objective"]),
                    cell(milestone["entry_gate"]),
                    cell(milestone["exit_gate"]),
                    cell(statuses[milestone_id]),
                ]
            )
            + " |"
        )
    return "\n".join(rows)


def replace_tracker_line(document: str, heading: str, tracker: int) -> str:
    start = document.find(heading)
    if start < 0:
        raise RuntimeError(f"roadmap document missing milestone section {heading!r}")
    next_h3 = document.find("\n### ", start + len(heading))
    next_h2 = document.find("\n## ", start + len(heading))
    ends = [value for value in (next_h3, next_h2) if value >= 0]
    end = min(ends) if ends else len(document)
    section = document[start:end]
    pattern = r"Canonical tracker: GitHub issue `#\d+`\."
    if not re.search(pattern, section):
        raise RuntimeError(f"roadmap section {heading!r} is missing its canonical tracker projection")
    tick = chr(96)
    replacement = f"Canonical tracker: GitHub issue {tick}#{tracker}{tick}."
    section = re.sub(pattern, replacement, section, count=1)
    return document[:start] + section + document[end:]


def render_document(
    document: str,
    roadmap_policy: dict[str, Any],
    statuses: dict[str, str],
) -> str:
    rendering = roadmap_policy["rendering"]
    section_heading = str(rendering["milestone_section_heading"])
    next_heading = str(rendering["next_section_heading"])
    start = document.find(section_heading)
    if start < 0:
        raise RuntimeError(f"roadmap document missing section {section_heading!r}")
    end = document.find(next_heading, start + len(section_heading))
    if end < 0:
        raise RuntimeError(f"roadmap document missing section {next_heading!r}")

    generated = (
        section_heading
        + "\n\n"
        + str(rendering["begin_marker"])
        + "\n"
        + render_table(roadmap_policy, statuses)
        + "\n"
        + str(rendering["end_marker"])
        + "\n\n"
    )
    rendered = document[:start] + generated + document[end:]
    for milestone in roadmap_policy["milestones"]:
        tracker = milestone.get("tracker")
        heading = milestone.get("section_heading")
        if type(tracker) is int and isinstance(heading, str) and heading:
            rendered = replace_tracker_line(rendered, heading, tracker)
    return rendered


def _current_projection(
    roadmap_policy: dict[str, Any], states: dict[int, dict[str, str]]
) -> dict[str, Any]:
    head = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip()
    qualification_gates: dict[str, str] = {}
    qualification_path: str | None = None
    try:
        import repoctl

        exact = repoctl._valid_exact_evidence(
            str(roadmap_policy["status_derivation"]["qualification_base_ref"]),
            head,
        )
    except (ImportError, RuntimeError, ValueError):
        exact = None
    if exact is not None:
        qualification = json.loads(exact.read_text(encoding="utf-8"))
        qualification_gates = {
            str(item["gate"]): str(item["status"])
            for item in qualification.get("gates", [])
            if isinstance(item, dict) and isinstance(item.get("gate"), str)
        }
        qualification_path = exact.relative_to(ROOT).as_posix()
    try:
        import modern_engineering

        qce_payload = modern_engineering.qce_status(ROOT)
    except (ImportError, RuntimeError, TypeError, ValueError):
        qce_payload = {"sectors": []}
    return derive_projection(
        roadmap_policy,
        states,
        qualification_gates=qualification_gates,
        qualification_evidence_path=qualification_path,
        qce_payload=qce_payload,
        head=head,
        tree=tree,
    )


def _write_projection(roadmap_policy: dict[str, Any], projection: dict[str, Any]) -> Path:
    destination = ROOT / str(roadmap_policy["status_derivation"]["projection_output"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(projection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return destination


def expected_document(gh: str) -> tuple[Path, str, dict[str, Any], dict[str, Any]]:
    roadmap_policy = policy()
    path = ROOT / str(roadmap_policy["document"])
    if not path.is_file():
        raise RuntimeError(f"roadmap document is missing: {path.relative_to(ROOT)}")
    states = tracker_states(gh, roadmap_policy)
    projection = _current_projection(roadmap_policy, states)
    documentation_statuses = {
        str(milestone["id"]): (
            str(milestone["fixed_status"])
            if "fixed_status" in milestone
            else str(roadmap_policy["rendering"]["derived_status_label"])
        )
        for milestone in roadmap_policy["milestones"]
    }
    expected = render_document(
        path.read_text(encoding="utf-8"), roadmap_policy, documentation_statuses
    )
    return path, expected, projection, roadmap_policy


def check(gh: str, *, quiet: bool = False) -> int:
    path, expected, projection, roadmap_policy = expected_document(gh)
    destination = _write_projection(roadmap_policy, projection)
    current = path.read_text(encoding="utf-8")
    if current == expected:
        if not quiet:
            print(f"PASS roadmap-check derived projection {destination.relative_to(ROOT)}")
            for milestone in projection["milestones"]:
                print(f"{milestone['milestone']:4} {milestone['status']}")
        return 0
    if not quiet:
        print("ROADMAP_DRIFT")
        for milestone in projection["milestones"]:
            print(f"{milestone['milestone']:4} {milestone['status']}")
        print("ACTION make roadmap-sync")
    return 1


def sync(gh: str) -> int:
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    ).strip()
    if status:
        raise RuntimeError("roadmap-sync requires a clean worktree")
    snapshot = qce_metadata_snapshot(gh, policy())
    path, expected, projection, roadmap_policy = expected_document(gh)
    destination = _write_projection(roadmap_policy, projection)
    current = path.read_text(encoding="utf-8")
    if current == expected:
        print(
            f"PASS roadmap-sync already synchronized; QCE relations {snapshot.relative_to(ROOT)}; "
            f"derived projection {destination.relative_to(ROOT)}"
        )
        for milestone in projection["milestones"]:
            print(f"{milestone['milestone']:4} {milestone['status']}")
        return 0
    path.write_text(expected, encoding="utf-8")
    print(f"PASS roadmap-sync updated {path.relative_to(ROOT)}")
    print(f"PASS roadmap-sync updated QCE relations {snapshot.relative_to(ROOT)}")
    print(f"PASS roadmap-sync wrote derived projection {destination.relative_to(ROOT)}")
    for milestone in projection["milestones"]:
        print(f"{milestone['milestone']:4} {milestone['status']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "sync"])
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        print("FAIL roadmap synchronization requires GitHub CLI", file=sys.stderr)
        return 2
    try:
        if args.action == "check":
            return check(gh, quiet=args.quiet)
        return sync(gh)
    except (RuntimeError, KeyError, ValueError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
