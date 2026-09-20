from __future__ import annotations

import importlib.util
import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_performance_campaign",
    ROOT / "scripts" / "qualification_performance_campaign.py",
)
assert SPEC and SPEC.loader
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


class QualificationPerformanceCampaignTests(unittest.TestCase):
    def test_median_and_budget_result_are_deterministic(self):
        samples = [
            {"wall_seconds": 4.0},
            {"wall_seconds": 2.0},
            {"wall_seconds": 3.0},
        ]
        self.assertEqual(3.0, CAMPAIGN._median(samples))
        self.assertEqual(
            {"actual_seconds": 3.0, "maximum_seconds": 3.0, "status": "PASS"},
            CAMPAIGN._budget_result(3.0, 3.0),
        )
        self.assertEqual("FAIL", CAMPAIGN._budget_result(3.001, 3.0)["status"])

    def test_run_sample_streams_live_and_keeps_identical_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            terminal = io.StringIO()
            with (
                mock.patch.object(CAMPAIGN, "ROOT", root),
                redirect_stdout(terminal),
            ):
                result = CAMPAIGN._run_sample(
                    "live-tee",
                    [CAMPAIGN.sys.executable, "-c", "print('VISIBLE-LINE')"],
                    cwd=root,
                    env=CAMPAIGN.os.environ.copy(),
                )

            output = terminal.getvalue()
            log_path = root / result["log"]
            self.assertIn("=== START live-tee ===", output)
            self.assertIn("VISIBLE-LINE", output)
            self.assertIn("=== PASS live-tee", output)
            self.assertEqual("VISIBLE-LINE\n", log_path.read_text(encoding="utf-8"))

    def test_baseline_comparison_reports_savings_and_speedup(self):
        comparison = CAMPAIGN._baseline_comparison(100.0, 25.0)
        self.assertEqual(75.0, comparison["saved_seconds"])
        self.assertEqual(75.0, comparison["savings_percent"])
        self.assertEqual(4.0, comparison["speedup"])

    def test_campaign_is_python_only_and_preserves_native_dependency_caches(self):
        source = (ROOT / "scripts" / "qualification_performance_campaign.py").read_text(encoding="utf-8")
        self.assertNotIn(".sh", source)
        self.assertIn("qualification_cache.cache_root()", source)
        self.assertNotIn("GOMODCACHE", source)
        self.assertNotIn("go clean", source)
        self.assertIn('["git", "worktree", "add"', source)
        self.assertIn("ECOMMERCE_FORCE_FULL_QUALIFICATION", source)

    def test_final_markdown_report_contains_required_29th_point_sections(self):
        source = (ROOT / "scripts" / "qualification_performance_campaign.py").read_text(encoding="utf-8")
        for heading in (
            "BRANCH",
            "HEAD",
            "FILES CHANGED",
            "CENTRAL AUTHORITY",
            "ARCHITECTURE",
            "BEFORE",
            "AFTER COLD",
            "AFTER WARM",
            "AFFECTED PRODUCT",
            "CACHE HIT RATIO",
            "CRITICAL PATH BEFORE",
            "CRITICAL PATH AFTER",
            "QUALIFICATION",
            "REGRESSION TESTS",
            "SECURITY / DYNAMIC CHECKS",
            "EXACT-SHA EVIDENCE",
            "PR",
            "VERDICT",
        ):
            self.assertIn(f'"{heading}"', source)

    def test_make_exposes_complete_campaign_and_final_proof(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("perf-campaign:", makefile)
        self.assertIn("qualification-proof:", makefile)
        self.assertIn("qualification_performance_campaign.py", makefile)
        self.assertIn("performance_audit.py", makefile)

    def test_finish_pr_blocks_without_exact_campaign_proof(self):
        repoctl = (ROOT / "scripts" / "repoctl.py").read_text(encoding="utf-8")
        self.assertIn("_valid_performance_campaign(head)", repoctl)
        self.assertIn("run make qualification-proof on the exact clean head", repoctl)

    def test_ci_evidence_requires_campaign_before_merge(self):
        contract = (ROOT / "config" / "contracts" / "ci-evidence.yaml").read_text(encoding="utf-8")
        self.assertIn("performance_campaign:", contract)
        self.assertIn("required_before_merge: true", contract)
        self.assertIn("budget_failure_blocks_readiness: true", contract)
        self.assertIn("conditional_content_cache_fields:", contract)


if __name__ == "__main__":
    unittest.main()
