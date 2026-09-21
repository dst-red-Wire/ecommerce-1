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
import performance_audit
import repoctl


def _supports_color() -> bool:
    return (
        "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "") != "dumb"
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )


def _paint(text: str, code: str) -> str:
    if not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def _status(kind: str, label: str, wall: float | None = None, log_path: Path | None = None) -> None:
    styles = {
        "RUN": ("●", "36"),
        "PASS": ("✓", "32"),
        "FAIL": ("✗", "31"),
    }
    symbol, color = styles[kind]
    suffix = f"  {wall:.3f}s" if wall is not None else ""
    detail = f"  log={log_path.relative_to(ROOT)}" if kind == "FAIL" and log_path is not None else ""
    print(_paint(f"{symbol} {kind:<4} {label}{suffix}{detail}", color), flush=True)


def _run_sample(label: str, command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> dict:
    logs = ROOT / ".context" / "performance" / "campaign-logs"
    logs.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in label)
    log_path = logs / f"{safe}.log"

    _status("RUN", label)
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
        _status("FAIL", label, wall, log_path)
        raise RuntimeError(
            f"{label} failed ({completed.returncode}) after {wall:.3f}s; "
            f"log={log_path.relative_to(ROOT)}"
        )

    _status("PASS", label, wall)
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
                target = self.root / "services" / "product" / "internal" / "domain" / "product.go"
                if not target.is_file():
                    raise RuntimeError(
                        "Product synthetic impact source is missing: "
                        "services/product/internal/domain/product.go"
                    )
                relative = target.relative_to(self.root).as_posix()
                if any(token in relative for token in ("/generated/", "/sqlcgen/")) or target.name.endswith("_templ.go"):
                    raise RuntimeError(f"Product synthetic impact selected generated source: {relative}")
                with target.open("a", encoding="utf-8") as handle:
                    handle.write(
                        '\nconst qualificationPerformanceCampaignMarker = "synthetic-product-impact"\n'
                    )
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


def _baseline_comparison(baseline: float, actual: float) -> dict:
    saved = baseline - actual
    return {
        "baseline_seconds": round(baseline, 3),
        "actual_seconds": round(actual, 3),
        "saved_seconds": round(saved, 3),
        "savings_percent": round((saved / baseline) * 100.0, 1) if baseline else 0.0,
        "speedup": round((baseline / actual), 3) if actual > 0.0 else None,
    }


def _budget_result(actual: float, maximum: float) -> dict:
    return {
        "actual_seconds": round(actual, 3),
        "maximum_seconds": round(maximum, 3),
        "status": "PASS" if actual <= maximum else "FAIL",
    }


def _assert_frozen_checkout(expected_head: str | None = None) -> str:
    clean = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    ).strip()
    if clean:
        raise RuntimeError("performance campaign worktree changed during execution")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if expected_head is not None and head != expected_head:
        raise RuntimeError("performance campaign HEAD changed during execution")
    return head


def campaign(base: str, repetitions: int) -> tuple[dict, bool]:
    policy = repoctl.qualification_execution_policy()
    perf = policy["performance"]
    configured_repetitions = int(policy["workflows"]["performance_campaign"]["repetitions"])
    if repetitions != configured_repetitions:
        raise RuntimeError(
            f"performance campaign repetitions must match central contract: {configured_repetitions}"
        )
    budgets = perf["budgets_seconds"]
    baselines = perf["baselines_seconds"]

    head = _assert_frozen_checkout()
    head_tree = subprocess.check_output(["git", "rev-parse", f"{head}^{{tree}}"], cwd=ROOT, text=True).strip()
    identity = repoctl.qualification_identity()
    base_env = os.environ.copy()
    base_env.pop("ECOMMERCE_FORCE_FULL_QUALIFICATION", None)
    full_env = dict(base_env)
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
            env=base_env,
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

    final_product = _run_sample("final-product-exact", _controller("service", "product"), env=base_env)
    final_verify = _run_sample("final-verify-exact", verify, env=full_env)

    _assert_frozen_checkout(head)

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
        "head_tree_sha": head_tree,
        "qualification_identity": identity,
        "created_at_epoch": time.time(),
        "base": base,
        "repetitions": repetitions,
        "baselines_seconds": baselines,
        "cold_verify_change": cold,
        "warm_verify_change": warm,
        "affected_product": product,
        "affected_governance": governance,
        "warm_gates": gate_warm,
        "baseline_comparison": {
            "system": _baseline_comparison(
                float(baselines["system"]), gate_warm["system"]["median_wall_seconds"]
            ),
            "governance": _baseline_comparison(
                float(baselines["governance"]), gate_warm["governance"]["median_wall_seconds"]
            ),
            "platform:ansible": _baseline_comparison(
                float(baselines["platform:ansible"]), gate_warm["ansible"]["median_wall_seconds"]
            ),
            "service:product": _baseline_comparison(
                float(baselines["service:product"]), gate_warm["service-product"]["median_wall_seconds"]
            ),
        },
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


def _resolve_pr_url() -> str:
    gh = shutil.which("gh") or shutil.which("gh.exe")
    if not gh:
        return "unresolved-offline"
    completed = subprocess.run(
        [gh, "pr", "view", "--json", "url", "--jq", ".url"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    value = (completed.stdout or "").strip()
    return value if completed.returncode == 0 and value else "unresolved-offline"


def _markdown_report(
    report: dict,
    audit_report: dict,
    files_changed: list[str],
    branch: str,
    pr_url: str,
) -> str:
    before = report["baselines_seconds"]
    cold = report["cold_verify_change"]["median_wall_seconds"]
    warm = report["warm_verify_change"]["median_wall_seconds"]
    affected_product = report["affected_product"]["median_wall_seconds"]
    affected_governance = report["affected_governance"]["median_wall_seconds"]
    inventory = audit_report["inventory"]
    critical = audit_report["critical_path"]
    baseline_total = round(sum(float(value) for value in before.values()), 3)

    lines = [
        "BRANCH",
        branch,
        "",
        "HEAD",
        str(report["head_sha"]),
        "",
        "FILES CHANGED",
        *[f"- {path}" for path in files_changed],
        "",
        "CENTRAL AUTHORITY",
        "architecture.lock.yaml -> config/contracts/qualification-execution-policy.yaml",
        "",
        "ARCHITECTURE",
        "canonical planner -> RUN/FRESH/REUSE/SKIP -> bounded local DAG / Tekton matrices -> exact-SHA evidence",
        "",
        "BEFORE",
        f"system             {float(before['system']):.3f}s",
        f"governance          {float(before['governance']):.3f}s",
        f"platform:ansible    {float(before['platform:ansible']):.3f}s",
        f"service:product     {float(before['service:product']):.3f}s",
        "",
        "AFTER COLD",
        f"median verify-change {cold:.3f}s",
        "",
        "AFTER WARM",
        f"median verify-change {warm:.3f}s",
        f"system {report['warm_gates']['system']['median_wall_seconds']:.3f}s",
        f"governance {report['warm_gates']['governance']['median_wall_seconds']:.3f}s",
        f"ansible {report['warm_gates']['ansible']['median_wall_seconds']:.3f}s",
        f"service:product {report['warm_gates']['service-product']['median_wall_seconds']:.3f}s",
        "",
        "AFFECTED PRODUCT",
        f"median {affected_product:.3f}s",
        "",
        "AFFECTED GOVERNANCE",
        f"median {affected_governance:.3f}s",
        "",
        "CACHE HIT RATIO",
        f"exact-parent evidence reuse {inventory.get('evidence_reuse_hit_percent', 0.0):.1f}%",
        f"content-cache hits {inventory.get('content_cache_hits', 0)}",
        f"content-cache misses {inventory.get('content_cache_misses', 0)}",
        "",
        "CRITICAL PATH BEFORE",
        f"{baseline_total:.3f}s baseline serial slice",
        "",
        "CRITICAL PATH AFTER",
        f"{critical.get('critical_path_estimate_seconds', 0.0):.3f}s ({critical.get('critical_branch', 'none')})",
        "",
        "QUALIFICATION",
        f"final verify-change {report['final_verify_exact']['wall_seconds']:.3f}s",
        f"final Product/Testcontainers gate {report['final_product_exact']['wall_seconds']:.3f}s",
        "",
        "REGRESSION TESTS",
        *[
            f"- {name}: {value['status']} actual={value['actual_seconds']:.3f}s max={value['maximum_seconds']:.3f}s"
            for name, value in sorted(report["budgets"].items())
        ],
        "",
        "SECURITY / DYNAMIC CHECKS",
        "fresh: security, Docker/Testcontainers, network, Kubernetes, secrets/authentication, provisioning state",
        "",
        "EXACT-SHA EVIDENCE",
        f".context/evidence/{report['head_sha']}.json",
        "",
        "PR",
        pr_url,
        "",
        "VERDICT",
        "READY FOR REVIEW" if report["status"] == "PASS" else "BLOCKED: performance/qualification budget failure",
        "",
    ]
    return "\n".join(lines)


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

        evidence_path = ROOT / ".context" / "evidence" / f"{report['head_sha']}.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        audit_report = performance_audit.audit(evidence, root=ROOT)
        branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip() or "DETACHED"
        files_changed = subprocess.check_output(
            ["git", "diff", "--name-only", args.base, report["head_sha"], "--"],
            cwd=ROOT,
            text=True,
        ).splitlines()
        markdown = destination.with_suffix(".md")
        markdown.write_text(
            _markdown_report(
                report,
                audit_report,
                sorted(set(files_changed)),
                branch,
                _resolve_pr_url(),
            ),
            encoding="utf-8",
        )
        print(
            json.dumps(
                {"status": report["status"], "output": str(destination), "report": str(markdown)},
                sort_keys=True,
            )
        )
        return 0 if passed else 1
    except (RuntimeError, OSError, subprocess.CalledProcessError, KeyError, ValueError) as exc:
        print(f"FAIL qualification performance campaign: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
