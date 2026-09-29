"""Step decisions for the repository's QualificationExecutionPolicy.

This module has no host side effects. Entrypoints call it before expensive work and
persist its validated checkpoints under their existing evidence roots.
"""

from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path
import re


SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
STATUSES = {"PASS", "FAIL", "BLOCKED_RUNTIME", "SKIPPED_REUSED_VERIFIED"}
STEP_FIELDS = {
    "schema_version", "policy", "policy_version", "qualification", "step",
    "source_sha", "input_digest", "artifact_digest", "status", "started_at",
    "finished_at", "duration_seconds", "executed", "reused", "cache_hit",
    "reused_from", "runtime_evidence", "preflight",
}
REQUIRED = STEP_FIELDS - {"artifact_digest", "reused_from", "runtime_evidence", "preflight"}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_policy(policy: dict, root: Path) -> dict:
    """Validate the new step contract and its sole checkpoint schema fail closed."""
    _require(policy.get("version") == 1, "qualification policy version must be 1")
    _require(policy.get("kind") == "QualificationExecutionPolicy", "qualification policy kind is invalid")
    _require(policy.get("status") == "enforced", "qualification policy must be enforced")
    step = policy.get("step_qualification")
    _require(isinstance(step, dict), "step_qualification is required")
    expected = {
        "properties_authority": "config/contracts/execution-properties-policy.yaml",
        "evidence_schema": "config/contracts/qualification-step-evidence.schema.json",
        "preflight_before_expensive_work": "required", "fail_fast": True,
        "capacity_check": "required", "environment_check": "required",
        "checkpointed": True, "resumable": False, "bounded": True,
        "reuse_identity": "digest", "source_sha_required": True,
        "input_digest_required": True, "artifact_digest_required_when_applicable": True,
        "mutable_identity": "forbidden", "selective_invalidation": True,
        "unknown_impact": "fail_closed", "unchanged_artifact_rebuild": "forbidden",
        "diagnostic_artifact_retention": "until-final-evidence-or-explicit-cleanup",
        "smoke_before_full": "required",
        "smoke_checks": ["runtime_boot", "os_identity", "network", "ssh", "ansible_connectivity"],
        "staged_network_probes": ["runtime_state", "network_interface", "ip", "tcp_port", "protocol_handshake", "application_probe"],
        "monolithic_network_timeout": "forbidden", "bounded_backoff": "required",
        "content_addressed_transfer": "required",
        "unchanged_content_full_retransfer": "forbidden",
        "transfer_manifest": "required", "transfer_digest_verification": "required",
        "transfer_evidence": "required",
        "final_candidate_only_full": True, "runtime_evidence": "required",
        "declaration_only_evidence": "forbidden",
        "exact_sha_reviews": ["CODE", "SECURITY"],
        "statuses": ["PASS", "FAIL", "BLOCKED_RUNTIME", "SKIPPED_REUSED_VERIFIED"],
        "expensive_metrics": ["duration_seconds", "executed", "reused", "cache_hit"],
    }
    _require(step == expected, "step_qualification has missing, unknown, or non-enforced rules")
    properties = root / step["properties_authority"]
    _require(properties.is_file(), "ExecutionPropertiesPolicy authority is missing")
    schema = json.loads((root / step["evidence_schema"]).read_text(encoding="utf-8"))
    _require(schema.get("type") == "object" and schema.get("additionalProperties") is False,
             "step evidence schema must be a closed object")
    _require(set(schema.get("required", [])) == REQUIRED and set(schema.get("properties", {})) == STEP_FIELDS,
             "step evidence schema fields differ from the enforced checkpoint model")
    _require(set(schema["properties"]["status"].get("enum", [])) == STATUSES,
             "step evidence schema statuses are invalid")
    _require(len(schema.get("allOf", [])) == 3,
             "step evidence schema must constrain reuse and preflight")
    return step


def validate_graph(workflow: dict) -> dict:
    graph = workflow.get("step_graph")
    _require(isinstance(graph, dict) and graph, "qualification step_graph is required")
    _require("preflight" in graph and graph["preflight"].get("depends_on") == [],
             "step_graph must start with preflight")
    levels = {"static", "smoke", "full"}
    for name, spec in graph.items():
        _require(isinstance(name, str) and name and isinstance(spec, dict), "invalid step_graph entry")
        _require(set(spec) in ({"depends_on", "level", "expensive"},
                               {"depends_on", "level", "expensive", "artifact"}),
                 f"{name}: unknown or missing step_graph field")
        deps = spec["depends_on"]
        _require(isinstance(deps, list) and len(deps) == len(set(deps))
                 and all(dep in graph and dep != name for dep in deps), f"{name}: invalid dependencies")
        _require(spec["level"] in levels and type(spec["expensive"]) is bool,
                 f"{name}: invalid level or expense")
        if "artifact" in spec:
            _require(isinstance(spec["artifact"], str) and spec["artifact"],
                     f"{name}: invalid artifact identity")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        _require(name not in visiting, "step_graph contains a cycle")
        if name in visited:
            return
        visiting.add(name)
        for dep in graph[name]["depends_on"]:
            visit(dep)
        visiting.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)
    impacts = workflow.get("impact_inputs")
    path_rules = workflow.get("impact_path_rules")
    _require(isinstance(impacts, dict) and impacts, "impact_inputs are required")
    for change_class, starts in impacts.items():
        _require(isinstance(change_class, str) and change_class and isinstance(starts, list)
                 and all(name in graph for name in starts), "invalid impact_inputs")
    _require(isinstance(path_rules, dict) and set(path_rules) == set(impacts),
             "impact_path_rules must cover the declared change classes")
    for patterns in path_rules.values():
        _require(isinstance(patterns, list) and patterns
                 and all(isinstance(pattern, str) and pattern and not pattern.startswith("/")
                         for pattern in patterns), "invalid impact path rule")
    return graph


def validate_checkpoint(record: dict, *, source_sha: str | None = None,
                        input_digest: str | None = None, runtime_required: bool = False) -> None:
    _require(isinstance(record, dict) and REQUIRED <= set(record) and set(record) <= STEP_FIELDS,
             "checkpoint fields are missing or unknown")
    _require(record["schema_version"] == 1 and record["policy"] == "QualificationExecutionPolicy"
             and record["policy_version"] == 1, "checkpoint policy identity is invalid")
    _require(isinstance(record["qualification"], str) and bool(record["qualification"])
             and isinstance(record["step"], str) and bool(record["step"]), "checkpoint step identity is invalid")
    _require(isinstance(record["source_sha"], str) and SHA.fullmatch(record["source_sha"]) is not None,
             "checkpoint source_sha is invalid")
    _require(isinstance(record["input_digest"], str) and DIGEST.fullmatch(record["input_digest"]) is not None,
             "checkpoint input_digest is invalid")
    if source_sha is not None:
        _require(record["source_sha"] == source_sha, "checkpoint belongs to another source SHA")
    if input_digest is not None:
        _require(record["input_digest"] == input_digest, "checkpoint belongs to other inputs")
    if "artifact_digest" in record:
        _require(isinstance(record["artifact_digest"], str)
                 and DIGEST.fullmatch(record["artifact_digest"]) is not None,
                 "checkpoint artifact_digest is invalid")
    _require(isinstance(record["status"], str) and record["status"] in STATUSES,
             "checkpoint status is invalid")
    for name in ("started_at", "finished_at"):
        _require(isinstance(record[name], str) and record[name].endswith("Z"), f"checkpoint {name} is invalid")
        datetime.fromisoformat(record[name].replace("Z", "+00:00"))
    _require(type(record["duration_seconds"]) in (int, float) and record["duration_seconds"] >= 0,
             "checkpoint duration is invalid")
    _require(all(type(record[name]) is bool for name in ("executed", "reused", "cache_hit")),
             "checkpoint execution metrics are invalid")
    reused = record["status"] == "SKIPPED_REUSED_VERIFIED"
    _require(record["reused"] is reused and (not reused or not record["executed"]),
             "reused checkpoint status and execution disagree")
    if reused:
        provenance = record.get("reused_from")
        _require(isinstance(provenance, dict)
                 and set(provenance) == {"source_sha", "input_digest", "artifact_digest"}
                 and isinstance(provenance["source_sha"], str)
                 and SHA.fullmatch(provenance["source_sha"]) is not None
                 and isinstance(provenance["input_digest"], str)
                 and isinstance(provenance["artifact_digest"], str)
                 and provenance["input_digest"] == record["input_digest"]
                 and provenance["artifact_digest"] == record.get("artifact_digest")
                 and record["cache_hit"] is True, "reused checkpoint has invalid provenance")
    else:
        _require("reused_from" not in record and not record["cache_hit"],
                 "non-reused checkpoint has reuse provenance")
    if record["step"] == "preflight" and record["status"] == "PASS":
        _require(record.get("preflight") == {"capacity": "PASS", "environment": "PASS"},
                 "preflight lacks capacity or environment PASS")
    if runtime_required and record["status"] in {"PASS", "SKIPPED_REUSED_VERIFIED"}:
        proof = record.get("runtime_evidence")
        _require(isinstance(proof, dict) and set(proof) == {"path", "sha256"}
                 and isinstance(proof["path"], str) and bool(proof["path"])
                 and isinstance(proof["sha256"], str) and DIGEST.fullmatch(proof["sha256"]) is not None,
                 "runtime PASS lacks content-bound runtime evidence")
        path = Path(proof["path"])
        _require(path.is_file() and _digest_file(path) == proof["sha256"],
                 "runtime evidence is missing or has changed")


def checkpoint(*, qualification: str, step: str, source_sha: str, input_digest: str,
               status: str, started_at: datetime, artifact_digest: str | None = None,
               runtime_path: Path | None = None, preflight: bool = False,
               reused_from: dict | None = None) -> dict:
    finished = datetime.now(timezone.utc)
    reused = status == "SKIPPED_REUSED_VERIFIED"
    record = {
        "schema_version": 1, "policy": "QualificationExecutionPolicy", "policy_version": 1,
        "qualification": qualification, "step": step, "source_sha": source_sha,
        "input_digest": input_digest, "status": status,
        "started_at": started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round(max(0.0, (finished - started_at).total_seconds()), 3),
        "executed": not reused, "reused": reused, "cache_hit": reused,
    }
    if artifact_digest is not None:
        record["artifact_digest"] = artifact_digest
    if runtime_path is not None:
        record["runtime_evidence"] = {"path": str(runtime_path.resolve()),
                                      "sha256": _digest_file(runtime_path)}
    if preflight:
        record["preflight"] = {"capacity": "PASS", "environment": "PASS"}
    if reused_from is not None:
        record["reused_from"] = reused_from
    validate_checkpoint(record, source_sha=source_sha, input_digest=input_digest,
                        runtime_required=runtime_path is not None)
    return record


def verified_reuse(*, path: Path, source_sha: str, recorded_source_sha: str,
                   expected_digest: str, input_digest: str,
                   recorded_input_digest: str, operation: str) -> str:
    _require(all(isinstance(value, str) and SHA.fullmatch(value) is not None
                 for value in (source_sha, recorded_source_sha)), "source SHA provenance is required")
    _require(all(isinstance(value, str) and DIGEST.fullmatch(value) is not None
                 for value in (expected_digest, input_digest, recorded_input_digest)),
             "digest identity is required")
    if not path.is_file() or input_digest != recorded_input_digest or _digest_file(path) != expected_digest:
        return "REBUILD_REQUIRED"
    _require(operation != "build", "unchanged verified artifact must be reused")
    return "SKIPPED_REUSED_VERIFIED"


def invalidate(graph: dict, impacts: dict, changed_classes: list[str]) -> dict:
    unknown = set(changed_classes) - set(impacts)
    affected = set(graph) if unknown else {name for klass in changed_classes for name in impacts[klass]}
    while True:
        downstream = {name for name, spec in graph.items()
                      if any(dep in affected for dep in spec["depends_on"])}
        if downstream <= affected:
            break
        affected |= downstream
    return {"changed_classes": sorted(set(changed_classes)),
            "reusable_steps": [name for name in graph if name not in affected],
            "invalidated_steps": [name for name in graph if name in affected],
            "unknown_impact": sorted(unknown)}


def classify_impact(paths: list[str], components: list[str], path_rules: dict) -> list[str]:
    """Use the canonical affected result as a guard around workflow path rules."""
    if not paths:
        return []
    classes: set[str] = set()
    for path in paths:
        matches = [name for name, patterns in path_rules.items()
                   if any(fnmatchcase(path, pattern) for pattern in patterns)]
        if not matches:
            return ["unknown"]
        classes.update(matches)
    if "system" in components and classes != {"docs_only"}:
        return ["unknown"]
    if "ansible" in classes and "platform:ansible" not in components:
        return ["unknown"]
    return sorted(classes)


def guard_start(*, qualification: str, step: str, graph: dict, source_sha: str, input_digest: str,
                checkpoints: dict[str, dict], final_candidate: bool = True) -> None:
    _require(step in graph, "unregistered qualification step")
    spec = graph[step]
    if spec["expensive"]:
        preflight = checkpoints.get("preflight")
        _require(isinstance(preflight, dict), "expensive work requires preflight PASS")
        validate_checkpoint(preflight, source_sha=source_sha, input_digest=input_digest)
        _require(preflight["qualification"] == qualification, "preflight belongs to another qualification")
        _require(preflight["status"] == "PASS", "expensive work requires preflight PASS")
    predecessors: set[str] = set()
    pending = list(spec["depends_on"])
    while pending:
        predecessor = pending.pop()
        if predecessor not in predecessors:
            predecessors.add(predecessor)
            pending.extend(graph[predecessor]["depends_on"])
    if spec["level"] == "full":
        _require(final_candidate, "FULL is reserved for the final candidate")
        _require(any(graph[name]["level"] == "smoke" for name in predecessors),
                 "FULL requires compatible SMOKE PASS")
    for name in sorted(predecessors):
        predecessor_spec = graph[name]
        record = checkpoints.get(name)
        _require(isinstance(record, dict), f"{step} requires {name} predecessor checkpoint")
        validate_checkpoint(record, source_sha=source_sha, input_digest=input_digest,
                            runtime_required=predecessor_spec["level"] != "static")
        _require(record["step"] == name and record["qualification"] == qualification,
                 f"predecessor checkpoint identity differs: {name}")
        _require(record["status"] in ({"PASS"} if name == "preflight" or predecessor_spec["level"] == "smoke"
                                      else {"PASS", "SKIPPED_REUSED_VERIFIED"}),
                 f"{step} requires {name} predecessor PASS")
        if "artifact" in predecessor_spec:
            _require("artifact_digest" in record,
                     f"{name} predecessor lacks artifact digest")


def guard_transfer(*, source_digest: str, target_digest: str | None,
                   mode: str, manifest_digest: str, final_digest: str | None = None) -> None:
    _require(all(isinstance(value, str) and DIGEST.fullmatch(value) is not None
                 for value in (source_digest, manifest_digest)),
             "transfer requires content and manifest digests")
    _require(target_digest is None or (isinstance(target_digest, str) and DIGEST.fullmatch(target_digest) is not None),
             "target transfer identity must be a digest")
    _require(mode in {"full", "delta", "skip"}, "unknown transfer mode")
    _require(not (target_digest == source_digest and mode == "full"),
             "unchanged content may not be retransferred in full")
    _require(mode != "skip" or target_digest == source_digest, "skip requires matching target digest")
    if mode != "skip":
        _require(final_digest == source_digest, "transfer final digest verification failed")


def guard_cleanup(*, final_evidence_captured: bool, explicitly_authorized: bool) -> None:
    _require(final_evidence_captured is True or explicitly_authorized is True,
             "diagnostic artifact must be retained until final evidence or explicit cleanup")


def guard_review(*, source_sha: str, code_sha: str, security_sha: str) -> None:
    _require(SHA.fullmatch(source_sha) is not None and code_sha == source_sha
             and security_sha == source_sha, "CODE and SECURITY reviews must match the exact SHA")


def guard_network(*, probes: list[str], elapsed_seconds: float, budget_seconds: float,
                  bounded_backoff: bool) -> None:
    expected = ["runtime_state", "network_interface", "ip", "tcp_port",
                "protocol_handshake", "application_probe"]
    _require(probes == expected and bounded_backoff and 0 <= elapsed_seconds <= budget_seconds
             and budget_seconds > 0, "network readiness requires staged probes and a bounded budget")
