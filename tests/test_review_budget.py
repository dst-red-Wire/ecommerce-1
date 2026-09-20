import json
import pathlib
import tempfile
import unittest
from unittest import mock

import scripts.review_budget as review_budget


class ReviewBudgetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.patcher = mock.patch.object(review_budget, "ROOT", self.root)
        self.patcher.start()
        (self.root / "config/contracts").mkdir(parents=True)
        (self.root / "config/contracts/review-budget.json").write_text(
            json.dumps(
                {
                    "state_directory": ".context/review-budget",
                    "max_failure_summary_lines": 4,
                    "max_failure_summary_bytes": 100,
                }
            ),
            encoding="utf-8",
        )
        self.contract_patcher = mock.patch.object(
            review_budget, "CONTRACT_PATH", self.root / "config/contracts/review-budget.json"
        )
        self.contract_patcher.start()

    def tearDown(self):
        self.contract_patcher.stop()
        self.patcher.stop()
        self.tmp.cleanup()

    def snap(self, **overrides):
        value = {
            "base_sha": "base",
            "head_sha": "head1",
            "last_reviewed_sha": "",
            "unresolved_finding_ids": [],
            "checks": {"ci": "PASS"},
            "reviews": {"code": "RUNNING", "security": "RUNNING"},
        }
        value.update(overrides)
        return value

    def test_initial_snapshot_invokes_normal_review(self):
        out = review_budget.decision(10, self.snap(), "combined", False)
        self.assertTrue(out["should_invoke_ai"])
        self.assertEqual("initial_review", out["reason"])
        self.assertEqual("NORMAL", out["depth"])

    def test_unchanged_snapshot_suppresses_ai(self):
        review_budget.decision(10, self.snap(), "combined", False)
        out = review_budget.decision(10, self.snap(), "combined", False)
        self.assertFalse(out["should_invoke_ai"])
        self.assertEqual("unchanged_status", out["reason"])

    def test_head_change_requests_delta_review(self):
        review_budget.decision(10, self.snap(), "combined", False)
        out = review_budget.decision(
            10,
            self.snap(head_sha="head2", last_reviewed_sha="head1"),
            "combined",
            False,
        )
        self.assertTrue(out["should_invoke_ai"])
        self.assertEqual("head_changed", out["reason"])
        self.assertEqual("head1", out["diff_base_sha"])
        self.assertIn("BASE=head1", out["affected_command"])

    def test_new_finding_triggers_review(self):
        review_budget.decision(10, self.snap(), "combined", False)
        out = review_budget.decision(
            10,
            self.snap(unresolved_finding_ids=["R1"]),
            "combined",
            False,
        )
        self.assertTrue(out["should_invoke_ai"])
        self.assertEqual("new_finding", out["reason"])

    def test_review_completion_triggers_review(self):
        review_budget.decision(10, self.snap(), "combined", False)
        out = review_budget.decision(
            10,
            self.snap(reviews={"code": "COMPLETED", "security": "RUNNING"}),
            "combined",
            False,
        )
        self.assertTrue(out["should_invoke_ai"])
        self.assertEqual("review_completed", out["reason"])

    def test_exact_sha_cache_suppresses_equivalent_review(self):
        review_budget.mark_cache(10, "head1", "combined", "test")
        out = review_budget.decision(10, self.snap(), "combined", True)
        self.assertFalse(out["should_invoke_ai"])
        self.assertEqual("exact_sha_cache_hit", out["reason"])

    def test_final_candidate_uses_deep_once_when_not_cached(self):
        out = review_budget.decision(10, self.snap(), "security", True)
        self.assertTrue(out["should_invoke_ai"])
        self.assertEqual("final_candidate", out["reason"])
        self.assertEqual("DEEP", out["depth"])

    def test_log_summary_is_bounded(self):
        log = self.root / "failure.log"
        log.write_text("\n".join(f"line-{i}" for i in range(10)), encoding="utf-8")
        out = review_budget.summarize_log(log)
        self.assertNotIn("line-0", out)
        self.assertIn("line-9", out)
        self.assertLessEqual(len(out.encode("utf-8")), 101)


if __name__ == "__main__":
    unittest.main()
