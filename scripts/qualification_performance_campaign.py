#!/usr/bin/env python3
"""Run the complete qualification performance campaign and write blocking evidence."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import qualification_cache
import repoctl


def _run_sample(label: str, command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> dict:
    logs = ROOT / ".context" / "performance" / "campaign-logs"
    logs.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in label)
    log_path = logs / f"{safe}.log"
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    wall = round(time.monotonic() - started, 3)
    if completed.returncode:
        tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:])
        raise RuntimeError(f"{label} failed ({completed.returncode}) after {wall:.3f}s\n{tail}")
    return {"label": label, "wall_seconds": wall, "log": str(log_path.relative_to(ROOT))}


def _median(samples: list[dict]) -> float:
    return round(statistics.median(float(sample["wall_seconds"]) for sample in samples), 3)


def _clear_qualification_content_cache() -> None:
    qualification_cache.clear_memory_cache()
    root = qualification_cache.cache_root()
    if root.exists():
        shutil.rmtree(root)


def _controller(*args: str) -> list[str]:
    return [sys.executable, str(ROOT / "scripts" / "repoctl.py"), *args]


def _measure(
    label: str,
    command: list[str],
    repetitions: int,
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    clear_before_each: bool = False,
    warmup: bool = False,
) -> dict:
    if warmup:
        _run_sample(f"{label}-warmup", command, cwd=cwd, env=env)
    samples = []
    for index in range(repetitions):
        if clear_before_each:
            _clear_qualification_content_cache()
        samples.append(_run_sample(f"{label}-{index + 1}", command, cwd=cwd, env=env))
    return {"samples": samples, "median_wall_seconds": _median(samples)}


def _synthetic_worktree(kind: str):
    class Worktree:
        def __enter__(self):
            self.temp = tempfile.TemporaryDirectory(prefix=f"ecommerce-perf-{kind}-")
            self.root = Path(self.temp.name) / "repository"
            subprocess.run(
                ["git", "worktree", "add", "--quiet", "--detach", str(self.root), "HEAD"],
                cwd=ROOT,
                check=True,
            )
            if kind == "product":
                candidates = sorted((self.root / "services" / "product").rglob("*.go"))
                if not candidates:
                    raise RuntimeError("Product synthetic impact requires at least one Go source")
                target = next((path for path in candidates if not path.name.endswith("_templ.go")), candidates[0])
                with target.open("a", encoding="utf-8") as handle:
                    handle.write("// qualification-performance-campaign product impact\n")
            elif kind == "governance":
                target = self.root / "config" / "contracts" / "review-policy.yaml"
                with target.open("a", encoding="utf-8") as handle:
                    handle.write("\n# qualification-performance-campaign governance impact\n")
            else:
                raise RuntimeError(f"unsupported synthetic worktree kind: {kind}")
            return self.root

        def __exit__(self, exc_type, exc, tb):
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(self.root)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.temp.cleanup()

    return Worktree()


def _budget_result(actual: float, maximum: float) -> dict:
    return {
        "actual_seconds": round(actual, 3),
        "maximum_seconds": round(maximum, 3),
        "status": "PASS" if actual <= maximum else "FAIL",
    }


def campaign(base: str, repetitions: int) -> tuple[dict, bool]:
    policy = repoctl.qualification_execution_policy()
    perf = policy["performance"]
    configured_repetitions = int(perf["campaign"]["repetitions"])
    if repetitions != configured_repetitions:
        raise RuntimeError(
            f"performance campaign repetitions must match central contract: {configured_repetitions}"
        )
    budgets = perf["budgets_seconds"]
    baselines = perf["baselines_seconds"]

    clean = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    ).strip()
    if clean:
        raise RuntimeError("performance campaign requires a clean worktree")

    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    full_env = os.environ.copy()
    full_env["ECOMMERCE_FORCE_FULL_QUALIFICATION"] = "1"

    verify = _controller("verify-change", "--base", base, "--head", head)
    cold = _measure(
        "cold-verify-change",
        verify,
        repetitions,
        env=full_env,
        clear_before_each=True,
    )
    _clear_qualification_content_cache()
    warm = _measure(
        "warm-verify-change",
        verify,
        repetitions,
        env=full_env,
        warmup=True,
    )

    gate_warm: dict[str, dict] = {}
    for name, command in (
        ("system", _controller("system")),
        ("governance", _controller("governance")),
        ("ansible", _controller("ansible")),
        ("service-product", _controller("service", "product")),
    ):
        gate_warm[name] = _measure(
            f"warm-{name}",
            command,
            repetitions,
            env=full_env,
            warmup=True,
        )

    with _synthetic_worktree("product") as worktree:
        product_env = dict(full_env)
        product = _measure(
            "affected-product",
            [sys.executable, "scripts/repoctl.py", "verify-change", "--base", "HEAD", "--head", "WORKTREE"],
            repetitions,
            cwd=worktree,
            env=product_env,
            warmup=True,
        )

    with _synthetic_worktree("governance") as worktree:
        governance_env = dict(full_env)
        governance = _measure(
            "affected-governance",
            [sys.executable, "scripts/repoctl.py", "verify-change", "--base", "HEAD", "--head", "WORKTREE"],
            repetitions,
            cwd=worktree,
            env=governance_env,
            warmup=True,
        )

    final_product = _run_sample("final-product-exact", _controller("service", "product"), env=full_env)
    final_verify = _run_sample("final-verify-exact", verify, env=full_env)

    checks = {
        "cold_verify_change_wall": _budget_result(
            cold["median_wall_seconds"], float(budgets["cold_verify_change_wall_max"])
        ),
        "warm_verify_change_wall": _budget_result(
            warm["median_wall_seconds"], float(budgets["warm_verify_change_wall_max"])
        ),
        "affected_product_wall": _budget_result(
            product["median_wall_seconds"], float(budgets["affected_product_wall_max"])
        ),
        "affected_governance_wall": _budget_result(
            governance["median_wall_seconds"], float(budgets["affected_governance_wall_max"])
        ),
        "service_product_warm_wall": _budget_result(
            gate_warm["service-product"]["median_wall_seconds"],
            float(budgets["service_product_warm_wall_max"]),
        ),
        "system_warm_wall": _budget_result(
            gate_warm["system"]["median_wall_seconds"], float(budgets["system_warm_wall_max"])
        ),
        "governance_warm_wall": _budget_result(
            gate_warm["governance"]["median_wall_seconds"], float(budgets["governance_warm_wall_max"])
        ),
        "ansible_warm_wall": _budget_result(
            gate_warm["ansible"]["median_wall_seconds"], float(budgets["ansible_warm_wall_max"])
        ),
    }

    report = {
        "schema_version": 1,
        "head_sha": head,
        "base": base,
        "repetitions": repetitions,
        "baselines_seconds": baselines,
        "cold_verify_change": cold,
        "warm_verify_change": warm,
        "affected_product": product,
        "affected_governance": governance,
        "warm_gates": gate_warm,
        "final_product_exact": final_product,
        "final_verify_exact": final_verify,
        "budgets": checks,
        "status": "PASS" if all(item["status"] == "PASS" for item in checks.values()) else "FAIL",
        "safety": {
            "qualification_content_cache_only_cleared_for_cold_runs": True,
            "native_dependency_caches_preserved": True,
            "synthetic_impacts_run_in_detached_temporary_worktrees": True,
            "product_runtime_tests_remain_fresh": True,
        },
    }
    return report, report["status"] == "PASS"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the complete qualification performance campaign")
    parser.add_argument("--base", default=os.environ.get("BASE", "origin/main"))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output", default=os.environ.get("PERF_CAMPAIGN_OUTPUT", ""))
    args = parser.parse_args(argv)

    try:
        report, passed = campaign(args.base, args.repetitions)
        destination = (
            Path(args.output).expanduser()
            if args.output
            else ROOT / ".context" / "performance" / f"campaign-{report['head_sha']}.json"
        )
        if not destination.is_absolute():
            destination = ROOT / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], "output": str(destination)}, sort_keys=True))
        return 0 if passed else 1
    except (RuntimeError, OSError, subprocess.CalledProcessError, KeyError, ValueError) as exc:
        print(f"FAIL qualification performance campaign: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
