#!/usr/bin/env python3
"""Derived QCE traceability, engineering metrics, SLOs, and experiments."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import qualification_cache

UTC = timezone.utc
QCE_STATUSES = (
    "NOT_STARTED",
    "CONTRACTED",
    "PARTIAL",
    "IMPLEMENTED",
    "PROVEN",
    "BLOCKED",
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def yaml_file(path: Path) -> dict[str, Any]:
    value = qualification_cache.psych_load(path)
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a mapping")
    return value


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise ValueError(
            (result.stderr or result.stdout).strip() or f"git {' '.join(args)} failed"
        )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def load_metrics_policy(root: Path) -> dict[str, Any]:
    lock = yaml_file(root / "architecture.lock.yaml")
    relative = lock.get("machine_contracts", {}).get("engineering_metrics_policy")
    if not isinstance(relative, str) or not relative:
        raise ValueError("engineering metrics policy is not registered")
    policy = yaml_file(root / relative)
    validate_metrics_policy(policy)
    return policy


def validate_metrics_policy(policy: dict[str, Any]) -> None:
    if (
        policy.get("version") != 1
        or policy.get("kind") != "EngineeringMetricsPolicy"
        or policy.get("status") != "exact"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
        or policy.get("scope") != "engineering-system-not-individuals"
    ):
        raise ValueError("invalid engineering metrics policy header")
    required_dora = {
        "change_lead_time",
        "deployment_frequency",
        "failed_deployment_recovery_time",
        "change_fail_rate",
        "deployment_rework_rate",
    }
    dora = policy.get("dora")
    if not isinstance(dora, dict) or set(dora) != required_dora:
        raise ValueError(
            "engineering metrics policy must define exactly the five DORA metrics"
        )
    fields = {
        "meaning",
        "event_sources",
        "start_event",
        "end_event",
        "window_days",
        "unit",
        "aggregation",
        "formula",
        "missing_data",
        "evidence",
    }
    for name, metric in dora.items():
        if not isinstance(metric, dict) or fields - set(metric):
            raise ValueError(
                f"DORA metric {name} lacks an explicit calculation contract"
            )
    required_categories = {
        "reliability",
        "quality",
        "security",
        "devex",
        "finops_value",
        "product_outcomes",
        "ai_effectiveness",
        "experiments",
    }
    if any(category not in policy for category in required_categories):
        raise ValueError(
            "engineering metrics policy is missing a required metric category"
        )
    forbidden = set(policy["devex"].get("forbidden_individual_productivity_kpis", []))
    expected_forbidden = {
        "lines_of_code",
        "commit_count",
        "pull_request_count",
        "tickets_closed",
        "hours_online",
        "number_of_ai_prompts",
    }
    if forbidden != expected_forbidden:
        raise ValueError(
            "individual productivity anti-pattern metrics must remain forbidden"
        )
    if (
        policy["ai_effectiveness"].get("productivity_proxy_number_of_prompts")
        != "forbidden"
    ):
        raise ValueError("AI prompt count must never be a productivity metric")
    experiments = policy["experiments"]
    if set(experiments.get("decisions", [])) != {"KEEP", "ROLLBACK", "IMPROVE"}:
        raise ValueError("engineering experiment decisions must be closed")


def reject_forbidden_metrics(names: list[str], policy: dict[str, Any]) -> None:
    forbidden = set(policy["devex"]["forbidden_individual_productivity_kpis"])
    rejected = sorted(set(names) & forbidden)
    if rejected:
        raise ValueError(
            "forbidden individual productivity metrics: " + ", ".join(rejected)
        )


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def calculate_dora(
    events: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    window_end: datetime | str | None = None,
) -> dict[str, Any]:
    validate_metrics_policy(policy)
    if not isinstance(events, list):
        raise TypeError("engineering events must be a list")
    normalized: list[dict[str, Any]] = []
    ids: set[str] = set()
    for item in events:
        if not isinstance(item, dict):
            raise TypeError("engineering event must be an object")
        event_id = item.get("event_id")
        event_type = item.get("type")
        if (
            not isinstance(event_id, str)
            or not event_id
            or not isinstance(event_type, str)
            or not event_type
        ):
            raise ValueError("engineering event requires event_id and type")
        if event_id in ids:
            raise ValueError(f"duplicate engineering event: {event_id}")
        ids.add(event_id)
        parsed = _parse_time(item.get("timestamp"), f"event {event_id}")
        value = dict(item)
        value["_timestamp"] = parsed
        normalized.append(value)
    window_days = int(policy["calculation"]["default_window_days"])
    if isinstance(window_end, str):
        effective_window_end = _parse_time(window_end, "DORA window_end")
    elif isinstance(window_end, datetime):
        if window_end.tzinfo is None:
            raise ValueError("DORA window_end timestamp must include a timezone")
        effective_window_end = window_end.astimezone(UTC)
    elif window_end is None:
        effective_window_end = (
            max(item["_timestamp"] for item in normalized)
            if normalized
            else datetime.now(UTC)
        )
    else:
        raise TypeError("DORA window_end must be a timestamp")
    effective_window_start = effective_window_end - timedelta(days=window_days)
    normalized = [
        item
        for item in normalized
        if effective_window_start <= item["_timestamp"] <= effective_window_end
    ]
    normalized.sort(key=lambda item: (item["_timestamp"], item["event_id"]))
    committed: dict[str, datetime] = {}
    deployed_changes: dict[str, datetime] = {}
    lead_times: list[float] = []
    failed_at: dict[str, datetime] = {}
    recovery_times: list[float] = []
    completed: set[str] = set()
    failed: set[str] = set()
    successful: set[str] = set()
    reworked: set[str] = set()
    for item in normalized:
        kind = item["type"]
        timestamp = item["_timestamp"]
        change_id = item.get("change_id")
        deployment_id = item.get("deployment_id")
        if kind == "change_committed" and isinstance(change_id, str):
            committed.setdefault(change_id, timestamp)
        elif kind == "deployment_succeeded" and isinstance(deployment_id, str):
            completed.add(deployment_id)
            successful.add(deployment_id)
            if isinstance(change_id, str):
                deployed_changes.setdefault(change_id, timestamp)
        elif kind == "deployment_failed" and isinstance(deployment_id, str):
            completed.add(deployment_id)
            failed.add(deployment_id)
            failed_at.setdefault(deployment_id, timestamp)
        elif (
            kind == "deployment_recovered"
            and isinstance(deployment_id, str)
            and deployment_id in failed_at
        ):
            delta = (timestamp - failed_at[deployment_id]).total_seconds()
            if delta < 0:
                raise ValueError(
                    f"recovery precedes deployment failure: {deployment_id}"
                )
            recovery_times.append(delta)
        elif kind in {"deployment_reworked", "deployment_rolled_back"} and isinstance(
            deployment_id, str
        ):
            reworked.add(deployment_id)

    for change_id in sorted(set(committed) & set(deployed_changes)):
        delta = (deployed_changes[change_id] - committed[change_id]).total_seconds()
        if delta < 0:
            raise ValueError(f"deployment precedes committed change: {change_id}")
        lead_times.append(delta)

    def duration_metric(values: list[float]) -> dict[str, Any]:
        if not values:
            return {
                "status": "MISSING",
                "median_seconds": None,
                "p90_seconds": None,
                "samples": 0,
            }
        return {
            "status": "MEASURED",
            "median_seconds": statistics.median(values),
            "p90_seconds": _percentile(values, 0.9),
            "samples": len(values),
        }

    if not completed:
        change_fail_rate = None
        rework_rate = None
    else:
        change_fail_rate = len(failed) / len(completed) * 100
        rework_rate = len(reworked & completed) / len(completed) * 100
    return {
        "event_count": len(normalized),
        "window_days": window_days,
        "window_start": _iso(effective_window_start),
        "window_end": _iso(effective_window_end),
        "change_lead_time": duration_metric(lead_times),
        "deployment_frequency": {
            "status": "MEASURED" if successful else "MISSING",
            "deployments_per_day": len(successful) / window_days
            if successful
            else None,
            "successful_deployments": len(successful),
        },
        "failed_deployment_recovery_time": duration_metric(recovery_times),
        "change_fail_rate": {
            "status": "MEASURED" if change_fail_rate is not None else "MISSING",
            "percent": change_fail_rate,
            "failed": len(failed),
            "completed": len(completed),
        },
        "deployment_rework_rate": {
            "status": "MEASURED" if rework_rate is not None else "MISSING",
            "percent": rework_rate,
            "reworked": len(reworked & completed),
            "completed": len(completed),
        },
    }


def calculate_slo(
    good_events: int | None,
    total_events: int | None,
    objective_percent: float,
    *,
    window_measurements: dict[str, dict[str, dict[str, int]]] | None = None,
    slo_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if good_events is None or total_events is None:
        return {"status": "MISSING", "release_decision": "NOT_PROVEN"}
    if (
        type(good_events) is not int
        or type(total_events) is not int
        or total_events < 0
        or good_events < 0
    ):
        raise ValueError("SLO event counts must be non-negative integers")
    if good_events > total_events:
        raise ValueError("SLO good events cannot exceed total events")
    if not 0 < objective_percent < 100:
        raise ValueError("SLO objective must be between zero and one hundred")
    if total_events == 0:
        return {"status": "MISSING", "release_decision": "NOT_PROVEN"}
    objective_ratio = objective_percent / 100
    bad = total_events - good_events
    allowed_bad = total_events * (1 - objective_ratio)
    remaining = allowed_bad - bad
    burn_rate = (bad / total_events) / (1 - objective_ratio)
    evaluated_windows: dict[str, dict[str, float]] = {}
    high_burn_windows: list[str] = []
    if window_measurements is not None:
        if not isinstance(slo_policy, dict):
            raise ValueError("multi-window burn evaluation requires the service SLO policy")
        contracted_windows = slo_policy.get("burn_rate_windows", {})
        if set(window_measurements) - set(contracted_windows):
            raise ValueError("unknown SLO burn-rate window")

        def sample_burn(sample: object, label: str) -> float:
            if not isinstance(sample, dict):
                raise TypeError(f"{label} burn sample must be an object")
            sample_good = sample.get("good_events")
            sample_total = sample.get("total_events")
            if (
                type(sample_good) is not int
                or type(sample_total) is not int
                or sample_total <= 0
                or sample_good < 0
                or sample_good > sample_total
            ):
                raise ValueError(f"{label} burn sample is invalid")
            return ((sample_total - sample_good) / sample_total) / (
                1 - objective_ratio
            )

        for name, samples in window_measurements.items():
            if not isinstance(samples, dict) or set(samples) != {"short", "long"}:
                raise ValueError(f"{name} burn window requires short and long samples")
            short_burn = sample_burn(samples["short"], f"{name} short")
            long_burn = sample_burn(samples["long"], f"{name} long")
            threshold = float(contracted_windows[name]["threshold"])
            evaluated_windows[name] = {
                "short_burn_rate": short_burn,
                "long_burn_rate": long_burn,
                "threshold": threshold,
            }
            if short_burn >= threshold and long_burn >= threshold:
                high_burn_windows.append(name)
    if remaining <= 0:
        budget_state = "EXHAUSTED"
        decision = "RELIABILITY_WORK_AND_RELEASE_RESTRICTION"
    elif high_burn_windows:
        budget_state = "HIGH_BURN"
        decision = "ELEVATED_RISK"
    else:
        budget_state = "HEALTHY"
        decision = "NORMAL"
    return {
        "status": "MEASURED",
        "attainment_percent": good_events / total_events * 100,
        "allowed_bad_events": allowed_bad,
        "observed_bad_events": bad,
        "error_budget_remaining": remaining,
        "burn_rate": burn_rate,
        "burn_rate_windows": evaluated_windows,
        "high_burn_windows": sorted(high_burn_windows),
        "budget_state": budget_state,
        "release_decision": decision,
    }


def validate_service_slo_policy(
    policy: dict[str, Any], canonical_services: list[str]
) -> None:
    if (
        policy.get("version") != 2
        or policy.get("status") != "provisional"
        or policy.get("architecture_authority") != "architecture.lock.yaml"
        or policy.get("source") != "policy-targets-not-measured-performance"
    ):
        raise ValueError("invalid service SLO policy header")
    model = policy.get("model", {})
    if model.get("sequence") != [
        "SLI",
        "SLO",
        "error-budget",
        "burn-rate",
        "release-reliability-decision",
    ]:
        raise ValueError("service SLO policy chain is invalid")
    if (
        model.get("missing_telemetry_behavior")
        != "NOT_PROVEN-and-release-risk-restriction-when-decision-required"
    ):
        raise ValueError(
            "missing SLO telemetry must fail closed without fabricated proof"
        )
    if set(policy.get("services", {})) != set(canonical_services):
        raise ValueError("service SLO coverage must equal canonical services")
    release = policy.get("release_governance", {})
    if release.get("milestone_activation") != {
        "M1": "contract",
        "M4": "implementation",
        "M5": "proof",
    }:
        raise ValueError("SLO release governance milestones are invalid")
    if (
        release.get("pre-runtime_contract_only_must_not_claim_blocking_proof")
        is not True
    ):
        raise ValueError("pre-runtime SLO contracts must not claim proof")
    if policy.get("rules", {}).get("missing-telemetry-never-means-healthy") is not True:
        raise ValueError("missing telemetry must never mean healthy")


def outcome_delta(
    baseline: float, result: float, expected_direction: str
) -> dict[str, Any]:
    if expected_direction not in {"increase", "decrease"}:
        raise ValueError("expected direction must be increase or decrease")
    delta = result - baseline
    improved = delta > 0 if expected_direction == "increase" else delta < 0
    relative = None if baseline == 0 else delta / abs(baseline) * 100
    return {"absolute_delta": delta, "relative_percent": relative, "improved": improved}


def validate_experiment(experiment: dict[str, Any], policy: dict[str, Any]) -> None:
    required = set(policy["experiments"]["required_fields"])
    missing = sorted(field for field in required if field not in experiment)
    if missing:
        raise ValueError("experiment missing required fields: " + ", ".join(missing))
    experiment_id = experiment.get("experiment_id")
    if not isinstance(experiment_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{2,63}", experiment_id
    ):
        raise ValueError("experiment_id is invalid")
    if not SHA_PATTERN.fullmatch(str(experiment.get("change_sha", ""))):
        raise ValueError("experiment change_sha must be exact")
    if (
        experiment.get("expected_direction")
        not in policy["experiments"]["expected_directions"]
    ):
        raise ValueError("experiment expected_direction is invalid")
    decision = experiment.get("decision")
    if decision not in (None, "PENDING", *policy["experiments"]["decisions"]):
        raise ValueError("experiment decision is invalid")
    for field in ("owner", "hypothesis", "metric", "measurement_window"):
        if not isinstance(experiment.get(field), str) or not experiment[field].strip():
            raise ValueError(f"experiment {field} is required")
    for field in ("baseline_evidence", "evidence"):
        if not isinstance(experiment.get(field), list) or not experiment[field]:
            raise ValueError(f"experiment {field} must contain evidence references")


def evaluate_experiment(
    experiment: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    validate_experiment(experiment, policy)
    result = experiment.get("result")
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("baseline"), (int, float))
        or not isinstance(result.get("measured"), (int, float))
        or isinstance(result.get("baseline"), bool)
        or isinstance(result.get("measured"), bool)
        or not math.isfinite(float(result["baseline"]))
        or not math.isfinite(float(result["measured"]))
    ):
        raise TypeError(
            "experiment result must define numeric baseline and measured values"
        )
    comparison = outcome_delta(
        float(result["baseline"]),
        float(result["measured"]),
        experiment["expected_direction"],
    )
    declared = experiment.get("decision")
    if declared in (None, "PENDING"):
        decision = "KEEP" if comparison["improved"] else "ROLLBACK"
    else:
        decision = declared
    if decision == "KEEP" and not comparison["improved"]:
        decision = "IMPROVE"
    return {**experiment, "comparison": comparison, "decision": decision}


def _qce_contracts(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    lock = yaml_file(root / "architecture.lock.yaml")
    registry = lock.get("machine_contracts", {})
    roadmap = yaml_file(root / str(registry["roadmap_policy"]))
    qualification = yaml_file(root / str(registry["qualification_execution_policy"]))
    return lock, roadmap, qualification


def validate_qce_traceability(
    lock: dict[str, Any],
    roadmap: dict[str, Any],
    qualification: dict[str, Any],
    root: Path,
) -> None:
    qce = lock.get("developer_platform", {}).get("quality_cloud_engineering", {})
    sectors = qce.get("sectors")
    if (
        qce.get("sector_count") != 9
        or not isinstance(sectors, dict)
        or len(sectors) != 9
    ):
        raise ValueError("QCE architecture must contain exactly nine sectors")
    for name, sector in sectors.items():
        if not isinstance(sector, dict) or any(
            not isinstance(sector.get(field), str) or not sector[field]
            for field in ("owner", "input", "output", "evidence")
        ):
            raise ValueError(f"QCE sector {name} lacks owner/input/output/evidence")
    trace = roadmap.get("qce_traceability")
    if not isinstance(trace, dict) or trace.get("sectors_must_be_derived") is not True:
        raise ValueError(
            "roadmap QCE traceability must derive sectors from architecture"
        )
    if set(trace.get("statuses", {})) != set(QCE_STATUSES):
        raise ValueError("QCE status state machine is invalid")
    if trace.get("manual_proven") != "forbidden":
        raise ValueError("manual QCE PROVEN must remain forbidden")
    runtime_evidence = trace.get("runtime_evidence_contract")
    required_runtime_fields = {
        "schema_version",
        "status",
        "exact_commit_evidence",
        "runtime_execution",
        "head_sha",
        "head_tree_sha",
        "created_at_epoch",
        "capabilities",
        "environment",
        "runtime_identity",
        "outcome",
    }
    if (
        not isinstance(runtime_evidence, dict)
        or runtime_evidence.get("schema_version") != 1
        or set(runtime_evidence.get("required_fields", [])) != required_runtime_fields
        or runtime_evidence.get("accepted_status") != "PASS"
        or runtime_evidence.get("exact_commit_evidence_required") is not True
        or runtime_evidence.get("runtime_execution_required") is not True
        or runtime_evidence.get("claimed_capability_membership_required") is not True
        or runtime_evidence.get("accepted_outcome") != "PASS"
        or not isinstance(runtime_evidence.get("allowed_environments"), list)
        or not runtime_evidence.get("allowed_environments")
        or runtime_evidence.get("runtime_identity_required_fields") != ["kind", "id"]
    ):
        raise ValueError("QCE runtime evidence contract is invalid")
    capabilities = trace.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != set(sectors):
        raise ValueError("QCE capabilities must map every and only canonical sector")
    milestones = {
        str(item.get("id")): item
        for item in roadmap.get("milestones", [])
        if isinstance(item, dict)
    }
    gates = qualification.get("gates", {})
    identifiers: set[str] = set()
    for sector_name, entries in capabilities.items():
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"QCE sector {sector_name} has no contracted capability")
        for entry in entries:
            if not isinstance(entry, dict):
                raise TypeError(f"QCE sector {sector_name} capability is malformed")
            identifier = entry.get("id")
            if (
                not isinstance(identifier, str)
                or not identifier
                or identifier in identifiers
            ):
                raise ValueError(
                    "QCE capability identifiers must be non-empty and unique"
                )
            identifiers.add(identifier)
            if str(entry.get("milestone")) not in milestones:
                raise ValueError(
                    f"QCE capability {identifier} references an unknown milestone"
                )
            declared_gates = entry.get("gates")
            paths = entry.get("implementation_paths")
            if not isinstance(declared_gates, list) or not isinstance(paths, list):
                raise TypeError(
                    f"QCE capability {identifier} must declare gates and implementation paths"
                )
            for gate in declared_gates:
                if gate not in gates:
                    raise ValueError(
                        f"QCE capability {identifier} references unknown gate {gate}"
                    )
            for relative in paths:
                path = Path(str(relative))
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError(
                        f"QCE capability {identifier} has unsafe implementation path"
                    )
            proof = entry.get("proof")
            if not isinstance(proof, dict) or proof.get("kind") not in {
                "qualification-gates",
                "runtime-execution",
            }:
                raise ValueError(
                    f"QCE capability {identifier} has an invalid proof contract"
                )
            if proof["kind"] == "qualification-gates":
                if set(proof) != {"kind"} or not declared_gates:
                    raise ValueError(
                        f"QCE capability {identifier} qualification proof requires gates only"
                    )
            else:
                if set(proof) != {"kind", "evidence_path"}:
                    raise ValueError(
                        f"QCE capability {identifier} runtime proof is malformed"
                    )
                evidence_path = Path(str(proof.get("evidence_path", "")))
                if (
                    evidence_path.is_absolute()
                    or ".." in evidence_path.parts
                    or evidence_path.suffix != ".json"
                    or evidence_path.parts[:2] != (".context", "evidence")
                ):
                    raise ValueError(
                        f"QCE capability {identifier} has an unsafe runtime evidence path"
                    )
            guard = entry.get("activation_guard")
            if guard is not None:
                if not isinstance(guard, dict) or set(guard) != {
                    "contract",
                    "field",
                    "allowed_values",
                }:
                    raise ValueError(
                        f"QCE capability {identifier} activation guard is malformed"
                    )
                contract_path = Path(str(guard.get("contract", "")))
                field = guard.get("field")
                allowed = guard.get("allowed_values")
                if (
                    contract_path.is_absolute()
                    or ".." in contract_path.parts
                    or not (root / contract_path).is_file()
                    or not isinstance(field, list)
                    or not field
                    or not all(isinstance(part, str) and part for part in field)
                    or not isinstance(allowed, list)
                    or not allowed
                ):
                    raise ValueError(
                        f"QCE capability {identifier} activation guard is invalid"
                    )


def _github_metadata(path: Path, sectors: list[str]) -> dict[str, Any]:
    if not path.is_file():
        return {"issues": [], "pull_requests": [], "blockers": []}
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("QCE GitHub metadata snapshot is malformed") from exc
    if not isinstance(metadata, dict):
        raise TypeError("QCE GitHub metadata snapshot must be an object")
    if "status" in metadata or any(
        isinstance(item, dict) and "status" in item
        for group in (metadata.get("issues", []), metadata.get("pull_requests", []))
        for item in (group if isinstance(group, list) else [])
    ):
        raise ValueError("QCE status cannot be manually declared")
    valid_labels = {"qce:" + sector.replace("_", "-") for sector in sectors}
    for group_name in ("issues", "pull_requests"):
        group = metadata.get(group_name, [])
        if not isinstance(group, list):
            raise TypeError(f"QCE metadata {group_name} must be a list")
        for item in group:
            if not isinstance(item, dict):
                raise TypeError(f"QCE metadata {group_name} entry is malformed")
            for label in item.get("labels", []):
                if (
                    isinstance(label, str)
                    and label.startswith("qce:")
                    and label not in valid_labels
                ):
                    raise ValueError(f"unknown QCE label: {label}")
            if (
                group_name == "pull_requests"
                and item.get("head_sha") is not None
                and not SHA_PATTERN.fullmatch(str(item.get("head_sha")))
            ):
                raise ValueError("QCE pull request relation has an invalid head SHA")
    blockers = metadata.get("blockers", [])
    if not isinstance(blockers, list):
        raise TypeError("QCE metadata blockers must be a list")
    return metadata


def _qualification_evidence(
    path: Path,
    head: str,
    tree: str,
    maximum_age: int,
    now: datetime,
    *,
    canonical_validator: Callable[[Path], bool] | None = None,
) -> tuple[dict[str, str], str | None]:
    if not path.is_file():
        return {}, "qualification evidence missing"
    if canonical_validator is None or not canonical_validator(path):
        return {}, "qualification evidence failed canonical exact-SHA validation"
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}, "qualification evidence malformed"
    records = evidence.get("gates")
    if not isinstance(records, list):
        return {}, "qualification gate evidence missing"
    return {
        str(item.get("gate")): str(item.get("status"))
        for item in records
        if isinstance(item, dict) and item.get("gate")
    }, None


def _runtime_capability_evidence(
    path: Path,
    capability_id: str,
    head: str,
    tree: str,
    maximum_age: int,
    now: datetime,
    contract: dict[str, Any],
) -> tuple[bool, str | None]:
    relative = f".context/evidence/{path.name}"
    if not path.is_file():
        return False, f"runtime evidence missing: {relative}"
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, f"runtime evidence malformed: {relative}"
    if not isinstance(evidence, dict) or any(
        field not in evidence for field in contract["required_fields"]
    ):
        return False, f"runtime evidence fields missing: {relative}"
    if (
        evidence.get("schema_version") != contract["schema_version"]
        or evidence.get("status") != contract["accepted_status"]
        or evidence.get("exact_commit_evidence") is not True
        or evidence.get("runtime_execution") is not True
        or evidence.get("outcome") != contract["accepted_outcome"]
    ):
        return False, f"runtime evidence is not an exact execution PASS: {relative}"
    if evidence.get("head_sha") != head or evidence.get("head_tree_sha") != tree:
        return False, f"runtime evidence has wrong SHA or tree: {relative}"
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
    capabilities = evidence.get("capabilities")
    if not isinstance(capabilities, list) or capability_id not in capabilities:
        return False, f"runtime evidence does not claim {capability_id}: {relative}"
    if evidence.get("environment") not in contract["allowed_environments"]:
        return False, f"runtime evidence has invalid environment: {relative}"
    runtime_identity = evidence.get("runtime_identity")
    if not isinstance(runtime_identity, dict) or any(
        not isinstance(runtime_identity.get(field), str)
        or not runtime_identity.get(field)
        for field in contract["runtime_identity_required_fields"]
    ):
        return False, f"runtime evidence identity is invalid: {relative}"
    return True, None


def _canonical_qualification_validator(root: Path, head: str) -> Callable[[Path], bool]:
    """Delegate QCE proof acceptance to repoctl's canonical exact-evidence validator."""
    try:
        import repoctl

        if Path(repoctl.ROOT).resolve() != root.resolve():
            canonical = None
        else:
            canonical = repoctl._valid_exact_evidence("origin/main", head)
    except (ImportError, RuntimeError, ValueError):
        canonical = None
    canonical_resolved = canonical.resolve() if canonical is not None else None
    return lambda candidate: (
        canonical_resolved is not None and candidate.resolve() == canonical_resolved
    )


def _activation_guard_blocker(
    root: Path, capability_id: str, guard: dict[str, Any] | None
) -> str | None:
    if guard is None:
        return None
    contract_path = Path(str(guard["contract"]))
    payload: Any = yaml_file(root / contract_path)
    for part in guard["field"]:
        if not isinstance(payload, dict) or part not in payload:
            return (
                f"{capability_id} activation guard field missing: "
                f"{contract_path.as_posix()}#{'.'.join(guard['field'])}"
            )
        payload = payload[part]
    if payload not in guard["allowed_values"]:
        return (
            f"{capability_id} activation blocked by "
            f"{contract_path.as_posix()}#{'.'.join(guard['field'])}={payload}"
        )
    return None


def qce_status(
    root: Path, *, sector: str = "", now: datetime | None = None
) -> dict[str, Any]:
    lock, roadmap, qualification = _qce_contracts(root)
    validate_qce_traceability(lock, roadmap, qualification, root)
    sectors = list(lock["developer_platform"]["quality_cloud_engineering"]["sectors"])
    if sector and sector not in sectors:
        raise ValueError(f"unknown QCE sector: {sector}")
    trace = roadmap["qce_traceability"]
    metadata_path = root / str(trace["github_metadata_snapshot"])
    metadata = _github_metadata(metadata_path, sectors)
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    generated_at = now or datetime.fromisoformat(
        _git(root, "show", "-s", "--format=%cI", "HEAD")
    )
    generated_at = generated_at.astimezone(UTC)
    freshness_time = now or datetime.now(UTC)
    evidence_path = root / ".context" / "evidence" / f"{head}.json"
    gate_evidence, evidence_problem = _qualification_evidence(
        evidence_path,
        head,
        tree,
        int(trace["evidence_max_age_seconds"]),
        freshness_time,
        canonical_validator=_canonical_qualification_validator(root, head),
    )
    # QCE consumes the canonical resolver API.  Tool/configuration presence is
    # never interpreted here as proof of an execution capability.
    import capability_resolver

    try:
        effective_capabilities = capability_resolver.resolve(
            root,
            source_sha=head,
            evidence_path=root / ".context" / "evidence" / "capabilities",
        )
        qce_verification = effective_capabilities["tools"]["qce"]["capabilities"]["verification"]
    except capability_resolver.ResolutionError:
        effective_capabilities = {
            "source_sha": head,
            "toolchain_digest": "unverified",
        }
        qce_verification = {"status": "unsupported"}
    resolver_proven = qce_verification["status"] == "proven"
    milestones = {str(item["id"]): item for item in roadmap["milestones"]}
    result_sectors: list[dict[str, Any]] = []
    selected = [sector] if sector else sectors
    for sector_name in selected:
        label = "qce:" + sector_name.replace("_", "-")
        related_prs = sorted(
            int(item["number"])
            for item in metadata.get("pull_requests", [])
            if isinstance(item.get("number"), int) and label in item.get("labels", [])
        )
        related_metadata_issues = {
            int(item["number"])
            for item in metadata.get("issues", [])
            if isinstance(item.get("number"), int) and label in item.get("labels", [])
        }
        capability_results = []
        missing_evidence: list[str] = []
        sector_blockers = [
            str(item.get("reason"))
            for item in metadata.get("blockers", [])
            if isinstance(item, dict)
            and item.get("sector") == sector_name
            and item.get("reason")
        ]
        for capability in trace["capabilities"][sector_name]:
            required_paths = [str(item) for item in capability["implementation_paths"]]
            required_gates = [str(item) for item in capability["gates"]]
            paths_present = all((root / path).is_file() for path in required_paths)
            gates_present = all(
                gate in qualification["gates"] for gate in required_gates
            )
            implemented = (
                bool(required_paths or required_gates)
                and paths_present
                and gates_present
            )
            proof = capability["proof"]
            runtime_evidence_path: Path | None = None
            runtime_problem: str | None = None
            if proof["kind"] == "qualification-gates":
                proven = implemented and all(
                    gate_evidence.get(gate) == "PASS" for gate in required_gates
                )
                proof_evidence_path = evidence_path
            else:
                runtime_evidence_path = root / str(proof["evidence_path"])
                runtime_proven, runtime_problem = _runtime_capability_evidence(
                    runtime_evidence_path,
                    str(capability["id"]),
                    head,
                    tree,
                    int(trace["evidence_max_age_seconds"]),
                    freshness_time,
                    trace["runtime_evidence_contract"],
                )
                implemented = implemented or runtime_proven
                proven = runtime_proven
                proof_evidence_path = runtime_evidence_path
            blocker = _activation_guard_blocker(
                root, str(capability["id"]), capability.get("activation_guard")
            )
            if blocker:
                capability_status = "BLOCKED"
                sector_blockers.append(blocker)
            elif proven and resolver_proven:
                capability_status = "PROVEN"
            elif implemented:
                capability_status = "IMPLEMENTED"
            elif any((root / path).is_file() for path in required_paths) or any(
                gate in qualification["gates"] for gate in required_gates
            ):
                capability_status = "PARTIAL"
            else:
                capability_status = "CONTRACTED"
            if proven and not resolver_proven:
                missing_evidence.append("effective-capabilities:qce.verification:not-proven")
            if proof["kind"] == "qualification-gates" and not proven:
                missing_evidence.extend(
                    gate for gate in required_gates if gate_evidence.get(gate) != "PASS"
                )
            elif proof["kind"] == "runtime-execution" and not proven:
                missing_evidence.append(runtime_problem or str(proof["evidence_path"]))
            milestone = milestones[str(capability["milestone"])]
            issue = milestone.get("tracker")
            if isinstance(issue, int):
                related_metadata_issues.add(issue)
            capability_results.append(
                {
                    "id": capability["id"],
                    "milestone": capability["milestone"],
                    "issues": [issue] if isinstance(issue, int) else [],
                    "pull_requests": related_prs,
                    "gates": required_gates,
                    "implementation_paths": required_paths,
                    "evidence": [str(proof_evidence_path.relative_to(root))]
                    if proven
                    else [],
                    "blockers": [blocker] if blocker else [],
                    "status": capability_status,
                }
            )
        states = [item["status"] for item in capability_results]
        if sector_blockers:
            status = "BLOCKED"
        elif states and all(item == "PROVEN" for item in states):
            status = "PROVEN"
        elif states and all(item in {"IMPLEMENTED", "PROVEN"} for item in states):
            status = "IMPLEMENTED"
        elif any(item in {"PARTIAL", "IMPLEMENTED", "PROVEN"} for item in states):
            status = "PARTIAL"
        elif states:
            status = "CONTRACTED"
        else:
            status = "NOT_STARTED"
        result_sectors.append(
            {
                "sector": sector_name,
                "owner": lock["developer_platform"]["quality_cloud_engineering"][
                    "sectors"
                ][sector_name]["owner"],
                "capabilities": capability_results,
                "issues": sorted(related_metadata_issues),
                "pull_requests": related_prs,
                "gates": sorted(
                    {gate for item in capability_results for gate in item["gates"]}
                ),
                "evidence": sorted(
                    {
                        evidence
                        for item in capability_results
                        for evidence in item["evidence"]
                    }
                ),
                "missing_evidence": sorted(set(missing_evidence)),
                "blockers": sector_blockers,
                "status": status,
            }
        )
    return {
        "schema_version": 1,
        "architecture": {
            "authority": "architecture.lock.yaml",
            "sha256": _sha256(root / "architecture.lock.yaml"),
            "head_sha": head,
            "head_tree_sha": tree,
        },
        "generated_at": _iso(generated_at),
        "evidence_state": evidence_problem or "fresh-exact-sha",
        "effective_capabilities": {
            "source_sha": effective_capabilities["source_sha"],
            "toolchain_digest": effective_capabilities["toolchain_digest"],
            "qce_verification": qce_verification["status"],
        },
        "sectors": result_sectors,
    }


def write_qce_status(root: Path, payload: dict[str, Any]) -> Path:
    _lock, roadmap, _qualification = _qce_contracts(root)
    path = root / str(roadmap["qce_traceability"]["evidence_output"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path
