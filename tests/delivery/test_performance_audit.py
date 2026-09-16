from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("performance_audit", ROOT / "scripts/performance_audit.py")
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PerformanceAuditTests(unittest.TestCase):
    def campaign(self):
        runs = []
        for scenario in AUDIT.CAMPAIGN_SCENARIOS:
            runs.append(
                {
                    "scenario": scenario,
                    "cache_state": "cold-isolated",
                    "cache_root": f"/tmp/{scenario}",
                    "result": "PASS",
                    "wall_seconds": 10.0,
                    "task_duration_sum_seconds": 14.0,
                    "estimated_saved_seconds": 0.0,
                    "phases": {"tests": 5.0, "tool-preparation": 2.0},
                }
            )
            runs.append(
                {
                    "scenario": scenario,
                    "cache_state": "warm",
                    "result": "PASS",
                    "wall_seconds": 6.0,
                    "task_duration_sum_seconds": 8.0,
                    "estimated_saved_seconds": 2.0,
                    "phases": {"tests": 3.0, "tool-preparation": 0.5},
                }
            )
        return {
            "head_sha": "2" * 40,
            "environment": {"cpus": 4, "memory_bytes": 1024},
            "commands": ["make verify-change"],
            "limitations": ["local observation"],
            "runs": runs,
        }

    def test_invalid_scenario_diagnostic_does_not_echo_untrusted_content(self):
        campaign = self.campaign()
        sensitive = "credential-shaped-private-diagnostic"
        campaign["runs"][0]["scenario"] = sensitive
        with self.assertRaises(ValueError) as failure:
            AUDIT.campaign_summary(campaign)
        self.assertEqual("campaign run 0 has unknown scenario", str(failure.exception))
        self.assertNotIn(sensitive, str(failure.exception))

    def evidence(self):
        return {
            "schema_version": 4,
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "status": "PASS",
            "verification": {"mode": "incremental"},
            "gates": [
                {"gate": "governance", "status": "PASS", "duration_seconds": 2.0},
                {"gate": "contracts", "status": "PASS", "duration_seconds": 3.0},
                {"gate": "frontend:storefront", "status": "PASS", "duration_seconds": 4.0},
                {"gate": "service:product", "status": "PASS", "duration_seconds": 1.0},
                {
                    "gate": "platform:terraform",
                    "status": "PASS",
                    "duration_seconds": 0.0,
                    "source_duration_seconds": 6.0,
                    "reused_from_sha": "9" * 40,
                },
                {"gate": "system", "status": "SKIP", "duration_seconds": 0.0},
            ],
        }

    def make_root(self, temp: str) -> Path:
        root = Path(temp)
        (root / "scripts").mkdir(parents=True)
        (root / "services" / "product").mkdir(parents=True)
        (root / "frontend").mkdir(parents=True)
        (root / "scripts" / "repoctl.py").write_text(
            'run(["corepack", "pnpm", "install", "--frozen-lockfile", "--prefer-offline"])\n',
            encoding="utf-8",
        )
        (root / "services" / "product" / "go.mod").write_text("module example/product\n", encoding="utf-8")
        (root / "frontend" / "package.json").write_text(
            json.dumps({"scripts": {"build": "turbo run build"}}), encoding="utf-8"
        )
        (root / "frontend" / "turbo.json").write_text('{"tasks":{"build":{"outputs":["dist/**"]}}}\n', encoding="utf-8")
        task = root / "platform" / "tekton" / "tasks" / "component-gates.yaml"
        task.parent.mkdir(parents=True)
        task.write_text(
            "name: GOCACHE\nvalue: .context/cache/go-build\nname: GOMODCACHE\nvalue: .context/cache/go-mod\n",
            encoding="utf-8",
        )
        return root

    def test_inventory_counts_execution_reuse_skip_and_saved_time(self):
        inventory = AUDIT.gate_inventory(self.evidence()["gates"])
        self.assertEqual(4, inventory["executed_gates"])
        self.assertEqual(1, inventory["reused_gates"])
        self.assertEqual(1, inventory["skipped_gates"])
        self.assertEqual(10.0, inventory["executed_seconds"])
        self.assertEqual(6.0, inventory["estimated_saved_seconds"])
        self.assertEqual(16.0, inventory["equivalent_full_seconds"])
        self.assertEqual(20.0, inventory["evidence_reuse_hit_percent"])

    def test_tekton_critical_path_models_global_serial_vs_component_matrix(self):
        critical = AUDIT.tekton_critical_path(self.evidence()["gates"])
        self.assertEqual(5.0, critical["global_branch_seconds"])
        self.assertEqual(4.0, critical["component_matrix_branch_seconds"])
        self.assertEqual(5.0, critical["critical_path_estimate_seconds"])
        self.assertEqual("global-gates", critical["critical_branch"])
        self.assertEqual(["governance", "contracts"], critical["critical_gates"])
        self.assertEqual(5.0, critical["parallelization_headroom_seconds"])
        self.assertEqual(2.0, critical["theoretical_gate_only_parallel_speedup"])

    def test_component_becomes_critical_when_it_is_longer_than_global_branch(self):
        evidence = self.evidence()
        next(record for record in evidence["gates"] if record["gate"] == "frontend:storefront")["duration_seconds"] = (
            12.0
        )
        critical = AUDIT.tekton_critical_path(evidence["gates"])
        self.assertEqual(12.0, critical["critical_path_estimate_seconds"])
        self.assertEqual("component-matrix", critical["critical_branch"])
        self.assertEqual(["frontend:storefront"], critical["critical_gates"])

    def test_amdahl_priorities_use_full_equivalent_cost_and_identify_largest_share(self):
        priorities = AUDIT.amdahl_priorities(self.evidence()["gates"])
        self.assertEqual("platform:terraform", priorities[0]["gate"])
        self.assertEqual("reused", priorities[0]["current_source"])
        self.assertEqual(6.0, priorities[0]["full_equivalent_seconds"])
        self.assertEqual(37.5, priorities[0]["maximum_time_share_recoverable_percent"])

    def test_cache_layers_distinguish_performance_cache_from_verdict_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_root(temp)
            layers = {row["layer"]: row for row in AUDIT.cache_layers(root)}
        self.assertTrue(layers["L1-evidence"]["enabled"])
        self.assertTrue(layers["L2-pnpm-store"]["enabled"])
        self.assertTrue(layers["L3-turborepo"]["enabled"])
        self.assertTrue(layers["L3-go"]["enabled"])
        self.assertTrue(layers["L3-go"]["pipeline_workspace_shared"])
        self.assertFalse(layers["L4-buildkit"]["enabled"])
        self.assertIn("cannot authorize PASS", layers["L3-turborepo"]["authorization"])

    def test_audit_is_fail_closed_about_content_cache_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            report = AUDIT.audit(self.evidence(), root=self.make_root(temp))
        self.assertFalse(report["safety"]["content_cache_authorizes_pass_reuse"])
        self.assertEqual("exact-direct-parent-only", report["safety"]["verdict_reuse_policy"])
        self.assertEqual("global-gates", report["critical_path"]["critical_branch"])
        self.assertTrue(report["recommendations"])

    def test_baseline_comparison_reports_measured_gate_savings(self):
        current = self.evidence()
        baseline = self.evidence()
        for record in baseline["gates"]:
            if record.get("reused_from_sha"):
                record.pop("reused_from_sha")
                record["duration_seconds"] = record.pop("source_duration_seconds")
        comparison = AUDIT.compare_baseline(current, baseline)
        self.assertEqual(16.0, comparison["baseline_executed_seconds"])
        self.assertEqual(10.0, comparison["current_executed_seconds"])
        self.assertEqual(6.0, comparison["measured_gate_time_saved_seconds"])
        self.assertEqual(37.5, comparison["measured_gate_savings_percent"])

    def test_invalid_gate_status_fails_closed(self):
        evidence = self.evidence()
        evidence["gates"][0]["status"] = "UNKNOWN"
        with self.assertRaisesRegex(ValueError, "invalid status"):
            AUDIT.audit(evidence, root=Path("."))

    def test_campaign_separates_wall_task_sum_execution_savings_and_cache_state(self):
        summary = AUDIT.campaign_summary(self.campaign())
        self.assertEqual(6, summary["scenario_count"])
        self.assertEqual(12, summary["run_count"])
        warm = next(
            row for row in summary["groups"] if row["scenario"] == "documentation" and row["cache_state"] == "warm"
        )
        self.assertEqual(6.0, warm["wall_seconds_median"])
        self.assertEqual(8.0, warm["task_duration_sum_seconds_median"])
        self.assertEqual(2.0, warm["estimated_saved_seconds_median"])
        self.assertEqual(1, warm["executed_runs"])
        self.assertFalse(summary["safety"]["authorizes_pass"])

    def test_campaign_rejects_wrong_sha_nonfinite_and_missing_observations(self):
        campaign = self.campaign()
        campaign["head_sha"] = "3" * 40
        with self.assertRaises(ValueError):
            AUDIT.audit(self.evidence(), root=ROOT, campaign=campaign)
        for value in (True, float("nan"), float("inf"), -1, 10**400):
            for field in ("wall_seconds", "task_duration_sum_seconds", "estimated_saved_seconds"):
                campaign = self.campaign()
                campaign["runs"][0][field] = value
                with self.assertRaises(ValueError):
                    AUDIT.campaign_summary(campaign)
            campaign = self.campaign()
            campaign["runs"][0]["phases"]["tests"] = value
            with self.assertRaises(ValueError):
                AUDIT.campaign_summary(campaign)
        campaign = self.campaign()
        campaign["runs"][0]["phases"] = {}
        with self.assertRaises(ValueError):
            AUDIT.campaign_summary(campaign)
        campaign = self.campaign()
        campaign["runs"] = [run for run in campaign["runs"] if run["cache_state"] == "warm"]
        with self.assertRaises(ValueError):
            AUDIT.campaign_summary(campaign)

    def test_campaign_redacts_metadata_and_reports_all_ranges(self):
        campaign = self.campaign()
        campaign["environment"]["TOKEN"] = "sensitive-fixture"
        campaign["limitations"] += ["blocked because TOKEN=sensitive-fixture"]
        campaign["commands"] += ["curl --token sensitive-fixture", "TOKEN=sensitive-fixture make ci"]
        sample = dict(
            campaign["runs"][0],
            wall_seconds=12,
            task_duration_sum_seconds=20,
            estimated_saved_seconds=4,
            phases={"tests": 9},
        )
        campaign["runs"].append(sample)
        summary = AUDIT.campaign_summary(campaign)
        self.assertNotIn("sensitive-fixture", json.dumps(summary))
        group = next(
            group
            for group in summary["groups"]
            if group["scenario"] == sample["scenario"] and group["cache_state"] == "cold-isolated"
        )
        self.assertEqual(6, group["task_duration_sum_seconds_range"])
        self.assertEqual(4, group["estimated_saved_seconds_range"])
        self.assertEqual(4, group["phase_seconds_range"]["tests"])
        self.assertIsNone(group["phase_seconds_median"]["compilation"])
        self.assertEqual(1, group["phase_sample_counts"]["tool-preparation"])

    def test_campaign_limits_are_bounded_typed_metadata(self):
        for value in ({"TOKEN": "sensitive-fixture"}, ["x" * 257], ["local observation"] * 33, [123]):
            campaign = self.campaign()
            campaign["limitations"] = value
            with self.assertRaises(ValueError):
                AUDIT.campaign_summary(campaign)

    def test_campaign_requires_all_bounded_scenarios(self):
        campaign = self.campaign()
        campaign["runs"] = [run for run in campaign["runs"] if run["scenario"] != "ansible"]
        with self.assertRaisesRegex(ValueError, "missing required scenarios: ansible"):
            AUDIT.campaign_summary(campaign)

    def test_cold_campaign_requires_isolated_cache_root(self):
        campaign = self.campaign()
        campaign["runs"][0].pop("cache_root")
        with self.assertRaisesRegex(ValueError, "isolated cache_root"):
            AUDIT.campaign_summary(campaign)


if __name__ == "__main__":
    unittest.main()
