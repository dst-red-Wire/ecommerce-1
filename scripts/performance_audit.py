#!/usr/bin/env python3
"""Evidence-driven execution performance audit for ecommerce-1.

This analyzer is intentionally read-only with respect to repository state. It consumes
existing deterministic CI evidence and repository configuration to identify execution
avoidance, critical-path headroom, cache coverage, and the gates with the largest
Amdahl-limited optimization potential.

It never authorizes PASS reuse. Exact verdict reuse remains governed by
config/contracts/ci-evidence.yaml and repoctl's direct-parent evidence rules.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

GLOBAL_GATES = (
    "governance",
    "runtime-efficiency",
    "contracts",
    "automation",
    "security",
)
REUSE_FIELDS = (
    "reused_from_sha",
    "promoted_from_worktree",
    "reused_from_worktree_tree_sha",
)


def _seconds(value: Any) -> float:
    try:
        return max(0.0, float(value or 0.0))
    except (TypeError, ValueError):
        return 0.0


def _round(value: float) -> float:
    return round(float(value), 3)


def _is_reused(record: dict[str, Any]) -> bool:
    return any(bool(record.get(field)) for field in REUSE_FIELDS)


def _source_seconds(record: dict[str, Any]) -> float:
    if _is_reused(record):
        return _seconds(record.get("source_duration_seconds", record.get("duration_seconds", 0.0)))
    return _seconds(record.get("duration_seconds", 0.0))


def _validate_evidence(evidence: dict[str, Any], *, label: str = "evidence") -> list[dict[str, Any]]:
    if not isinstance(evidence, dict):
        raise ValueError(f"{label} must be a JSON object")
    records = evidence.get("gates")
    if not isinstance(records, list):
        raise ValueError(f"{label} must contain a gates array")
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not str(record.get("gate", "")).strip():
            raise ValueError(f"{label} gate record {index} is invalid")
        if record.get("status") not in {"PASS", "FAIL", "SKIP"}:
            raise ValueError(f"{label} gate {record.get('gate')} has invalid status")
    return records


def gate_inventory(records: list[dict[str, Any]]) -> dict[str, Any]:
    executed: list[dict[str, Any]] = []
    reused: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for record in records:
        if record.get("status") == "SKIP":
            skipped.append(record)
        elif record.get("status") == "FAIL":
            failed.append(record)
            if not _is_reused(record):
                executed.append(record)
        elif _is_reused(record):
            reused.append(record)
        else:
            executed.append(record)

    executed_seconds = sum(_seconds(record.get("duration_seconds")) for record in executed)
    reused_seconds = sum(_source_seconds(record) for record in reused)
    equivalent_full_seconds = executed_seconds + reused_seconds
    denominator = len(executed) + len(reused)
    cache_hit_ratio = (len(reused) / denominator) if denominator else 0.0

    return {
        "executed_records": executed,
        "reused_records": reused,
        "skipped_records": skipped,
        "failed_records": failed,
        "executed_gates": len(executed),
        "reused_gates": len(reused),
        "skipped_gates": len(skipped),
        "failed_gates": len(failed),
        "executed_seconds": _round(executed_seconds),
        "estimated_saved_seconds": _round(reused_seconds),
        "equivalent_full_seconds": _round(equivalent_full_seconds),
        "evidence_reuse_hit_ratio": round(cache_hit_ratio, 4),
        "evidence_reuse_hit_percent": round(cache_hit_ratio * 100.0, 1),
    }


def tekton_critical_path(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Model the canonical affected Pipeline after classification.

    The current Pipeline runs one sequential global-gates Task in parallel with a
    matrix of independent component TaskRuns, then joins in the finalizer. Classify,
    pod scheduling and finalizer overhead are not represented in per-gate evidence,
    so this is an execution-gate estimate rather than observed wall clock.
    """
    active = [record for record in records if record.get("status") != "SKIP" and not _is_reused(record)]
    globals_ = [record for record in active if record.get("gate") in GLOBAL_GATES]
    components = [record for record in active if record.get("gate") not in GLOBAL_GATES]

    global_seconds = sum(_seconds(record.get("duration_seconds")) for record in globals_)
    component_durations = [(str(record.get("gate")), _seconds(record.get("duration_seconds"))) for record in components]
    longest_component = max(component_durations, key=lambda row: (row[1], row[0]), default=("", 0.0))
    component_parallel_seconds = longest_component[1]
    serial_seconds = global_seconds + sum(seconds for _, seconds in component_durations)
    critical_seconds = max(global_seconds, component_parallel_seconds)

    if global_seconds >= component_parallel_seconds and globals_:
        branch = "global-gates"
        gates = [str(record.get("gate")) for record in globals_]
    elif longest_component[0]:
        branch = "component-matrix"
        gates = [longest_component[0]]
    else:
        branch = "none"
        gates = []

    parallel_headroom = max(0.0, serial_seconds - critical_seconds)
    speedup = (serial_seconds / critical_seconds) if critical_seconds else 1.0
    utilization = (critical_seconds / serial_seconds) if serial_seconds else 0.0

    return {
        "model": "tekton-affected-v1",
        "assumption": "global gates are serial inside one Task; component gates fan out as a Matrix; both branches start after classify",
        "aggregate_executed_gate_seconds": _round(serial_seconds),
        "global_branch_seconds": _round(global_seconds),
        "component_matrix_branch_seconds": _round(component_parallel_seconds),
        "critical_path_estimate_seconds": _round(critical_seconds),
        "critical_branch": branch,
        "critical_gates": gates,
        "parallelization_headroom_seconds": _round(parallel_headroom),
        "theoretical_gate_only_parallel_speedup": round(speedup, 3),
        "critical_path_fraction_of_serial": round(utilization, 4),
        "excluded_overhead": ["classification", "pod-scheduling", "workspace-io", "finalization", "network"],
    }


def amdahl_priorities(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = [record for record in records if record.get("status") != "SKIP"]
    durations = [(record, _source_seconds(record)) for record in candidates]
    total = sum(seconds for _, seconds in durations)
    priorities: list[dict[str, Any]] = []
    for record, seconds in durations:
        if seconds <= 0.0 or total <= 0.0:
            continue
        fraction = seconds / total
        remainder = total - seconds
        max_speedup = (total / remainder) if remainder > 0.0 else None
        priorities.append(
            {
                "gate": str(record.get("gate")),
                "current_source": "reused" if _is_reused(record) else "executed",
                "full_equivalent_seconds": _round(seconds),
                "full_equivalent_fraction": round(fraction, 4),
                "maximum_time_share_recoverable_percent": round(fraction * 100.0, 1),
                "maximum_speedup_if_gate_cost_were_zero": round(max_speedup, 3) if max_speedup is not None else None,
            }
        )
    priorities.sort(key=lambda row: (-row["full_equivalent_seconds"], row["gate"]))
    return priorities


def _file_contains(path: Path, needles: tuple[str, ...]) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return all(needle in text for needle in needles)


def cache_layers(root: Path) -> list[dict[str, Any]]:
    go_modules = list((root / "services").glob("*/go.mod")) if (root / "services").is_dir() else []
    component_task = root / "platform" / "tekton" / "tasks" / "component-gates.yaml"
    go_pipeline_cache = (
        _file_contains(
            component_task,
            ("name: GOCACHE", ".context/cache/go-build", "name: GOMODCACHE", ".context/cache/go-mod"),
        )
        if component_task.is_file()
        else False
    )

    buildkit_markers = ("cache-from", "cache-to", "buildx build", "buildctl")
    buildkit_registry_cache = False
    candidates: list[Path] = []
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files", "--", "platform", "services", "frontend"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).splitlines()
        candidates = [root / relative for relative in tracked if relative]
    except (OSError, subprocess.CalledProcessError):
        ignored_parts = {".terraform", "vendor", ".git", ".context"}
        for base in (root / "platform", root / "services", root / "frontend"):
            if base.exists():
                candidates.extend(
                    path
                    for path in base.rglob("*")
                    if path.is_file() and not any(part in ignored_parts for part in path.parts)
                )

    for path in candidates:
        try:
            if path.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        if path.suffix.lower() not in {".yaml", ".yml", ".json", ".toml", ".hcl", ""}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(marker in text for marker in buildkit_markers):
            buildkit_registry_cache = True
            break

    return [
        {
            "layer": "L1-evidence",
            "mechanism": "exact direct-parent PASS evidence reuse",
            "enabled": True,
            "scope": "gate execution avoidance",
            "cross_machine_capable": True,
            "authorization": "authenticated OCI evidence when configured",
        },
        {
            "layer": "L3-go",
            "mechanism": "native Go build/test cache",
            "enabled": bool(go_modules),
            "scope": "implemented Go services",
            "pipeline_workspace_shared": go_pipeline_cache,
            "cross_machine_capable": False,
            "authorization": "performance-only; cannot authorize PASS",
        },
        {
            "layer": "L4-buildkit",
            "mechanism": "BuildKit/registry layer cache",
            "enabled": buildkit_registry_cache,
            "scope": "OCI image builds when present",
            "cross_machine_capable": buildkit_registry_cache,
            "authorization": "artifact acceleration only; immutable output digest still required",
        },
    ]


def compare_baseline(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    current_inventory = gate_inventory(_validate_evidence(current, label="current evidence"))
    baseline_inventory = gate_inventory(_validate_evidence(baseline, label="baseline evidence"))
    current_seconds = float(current_inventory["executed_seconds"])
    baseline_seconds = float(baseline_inventory["executed_seconds"])
    saved = baseline_seconds - current_seconds
    baseline_wall = baseline.get("metrics", {}).get("deliver_wall_seconds")
    current_wall = current.get("metrics", {}).get("deliver_wall_seconds")

    result: dict[str, Any] = {
        "baseline_head_sha": baseline.get("head_sha"),
        "current_head_sha": current.get("head_sha"),
        "baseline_executed_seconds": _round(baseline_seconds),
        "current_executed_seconds": _round(current_seconds),
        "measured_gate_time_saved_seconds": _round(saved),
        "measured_gate_savings_percent": round((saved / baseline_seconds) * 100.0, 1) if baseline_seconds else 0.0,
    }
    if baseline_wall is not None and current_wall is not None:
        bwall = _seconds(baseline_wall)
        cwall = _seconds(current_wall)
        wall_saved = bwall - cwall
        result.update(
            {
                "baseline_deliver_wall_seconds": _round(bwall),
                "current_deliver_wall_seconds": _round(cwall),
                "measured_deliver_time_saved_seconds": _round(wall_saved),
                "measured_deliver_savings_percent": round((wall_saved / bwall) * 100.0, 1) if bwall else 0.0,
            }
        )
    return result


def recommendations(
    inventory: dict[str, Any], critical: dict[str, Any], priorities: list[dict[str, Any]], caches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    hit = float(inventory["evidence_reuse_hit_ratio"])
    if inventory["executed_gates"] and hit < 0.5:
        items.append(
            {
                "priority": "high",
                "action": "increase-safe-execution-avoidance",
                "reason": f"evidence reuse hit ratio is {inventory['evidence_reuse_hit_percent']}%",
                "constraint": "reuse verdicts only from exact direct-parent authenticated PASS evidence",
            }
        )
    if float(critical["parallelization_headroom_seconds"]) > 0.0:
        items.append(
            {
                "priority": "high",
                "action": "preserve-tekton-dag-fanout",
                "reason": f"gate-only parallelization headroom is {critical['parallelization_headroom_seconds']}s",
                "constraint": "do not parallelize mutating gates inside one local worktree",
            }
        )
    executed_priorities = [row for row in priorities if row["current_source"] == "executed"]
    if executed_priorities:
        top = executed_priorities[0]
        items.append(
            {
                "priority": "high",
                "action": f"optimize-gate:{top['gate']}",
                "reason": f"largest executed full-equivalent gate cost is {top['full_equivalent_seconds']}s",
                "amdahl_max_recoverable_percent": top["maximum_time_share_recoverable_percent"],
            }
        )
    missing_cache = [layer["layer"] for layer in caches if not layer["enabled"]]
    if missing_cache:
        items.append(
            {
                "priority": "medium",
                "action": "close-relevant-cache-gaps",
                "reason": "disabled/not-observed cache layers: " + ", ".join(missing_cache),
                "constraint": "adopt only where the corresponding workload exists and cache integrity remains deterministic",
            }
        )
    return items


def audit(evidence: dict[str, Any], *, root: Path, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    records = _validate_evidence(evidence)
    inventory = gate_inventory(records)
    critical = tekton_critical_path(records)
    priorities = amdahl_priorities(records)
    caches = cache_layers(root)
    report: dict[str, Any] = {
        "schema_version": 1,
        "head_sha": evidence.get("head_sha"),
        "base_sha": evidence.get("base_sha"),
        "evidence_status": evidence.get("status"),
        "verification_mode": evidence.get("verification", {}).get("mode"),
        "inventory": {key: value for key, value in inventory.items() if not key.endswith("_records")},
        "critical_path": critical,
        "amdahl_priorities": priorities,
        "cache_layers": caches,
        "recommendations": recommendations(inventory, critical, priorities, caches),
        "safety": {
            "content_cache_authorizes_pass_reuse": False,
            "verdict_reuse_policy": "exact-direct-parent-only",
            "unknown_impact_behavior": "fail-closed/full-execution",
            "tekton_remains_ci_authority": True,
        },
    }
    if baseline is not None:
        report["comparison"] = compare_baseline(evidence, baseline)
    return report


def _repo_root() -> Path:
    try:
        value = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("perf-audit must run inside the ecommerce-1 Git checkout") from exc
    return Path(value)


def _default_evidence(root: Path) -> Path:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    exact = root / ".context" / "evidence" / f"{head}.json"
    if exact.is_file():
        return exact
    worktree = root / ".context" / "evidence" / "worktree.json"
    if worktree.is_file():
        return worktree
    raise RuntimeError(
        f"no evidence found for HEAD {head}; run make verify-change first or provide EVIDENCE/--evidence"
    )


def _load(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"unable to read {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return value


def _print_summary(report: dict[str, Any], destination: Path) -> None:
    inventory = report["inventory"]
    critical = report["critical_path"]
    print("EXECUTION PERFORMANCE")
    print(f"head                 {report.get('head_sha')}")
    print(
        f"executed/reused/skip {inventory['executed_gates']}/{inventory['reused_gates']}/{inventory['skipped_gates']}"
    )
    print(f"executed gate time   {inventory['executed_seconds']:.3f}s")
    print(f"reused time saved    {inventory['estimated_saved_seconds']:.3f}s")
    print(f"evidence hit ratio   {inventory['evidence_reuse_hit_percent']:.1f}%")
    print(f"critical path est.   {critical['critical_path_estimate_seconds']:.3f}s ({critical['critical_branch']})")
    print(f"parallel headroom    {critical['parallelization_headroom_seconds']:.3f}s")
    priorities = report.get("amdahl_priorities", [])
    if priorities:
        top = priorities[0]
        print(
            f"top Amdahl target    {top['gate']} ({top['full_equivalent_seconds']:.3f}s, max {top['maximum_time_share_recoverable_percent']:.1f}% share)"
        )
    comparison = report.get("comparison")
    if comparison:
        print(
            f"vs baseline saved    {comparison['measured_gate_time_saved_seconds']:.3f}s ({comparison['measured_gate_savings_percent']:.1f}%)"
        )
    print(f"PERFORMANCE_EVIDENCE {destination}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit ecommerce-1 execution performance from deterministic evidence")
    parser.add_argument("--evidence", default=os.environ.get("EVIDENCE", ""))
    parser.add_argument("--baseline", default=os.environ.get("BASELINE_EVIDENCE", ""))
    parser.add_argument("--output", default=os.environ.get("PERF_OUTPUT", ""))
    parser.add_argument("--json", action="store_true", help="print the full JSON report to stdout")
    args = parser.parse_args(argv)

    try:
        root = _repo_root()
        evidence_path = Path(args.evidence).expanduser() if args.evidence else _default_evidence(root)
        if not evidence_path.is_absolute():
            evidence_path = root / evidence_path
        evidence = _load(evidence_path, label="evidence")
        baseline = None
        if args.baseline:
            baseline_path = Path(args.baseline).expanduser()
            if not baseline_path.is_absolute():
                baseline_path = root / baseline_path
            baseline = _load(baseline_path, label="baseline evidence")
        report = audit(evidence, root=root, baseline=baseline)
        identity = str(report.get("head_sha") or "worktree")
        destination = (
            Path(args.output).expanduser() if args.output else root / ".context" / "performance" / f"{identity}.json"
        )
        if not destination.is_absolute():
            destination = root / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        _print_summary(report, destination.relative_to(root) if destination.is_relative_to(root) else destination)
        return 1 if report["inventory"]["failed_gates"] else 0
    except (RuntimeError, ValueError) as exc:
        print(f"FAIL perf-audit: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
