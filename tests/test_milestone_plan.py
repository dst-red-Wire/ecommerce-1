from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import milestone_plan as PLAN


class MilestonePlanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.roadmap = PLAN.load_roadmap(ROOT)
        self.package = {
            "id": "m25-rke2-runtime",
            "milestone": "M2.5",
            "tracker_issue": 32,
            "work_item_issue": None,
            "objective": "Verify M2.5 runtime evidence",
            "scope": {
                "allowed_paths": ["scripts/m25_runtime_evidence.py"],
                "forbidden_paths": [],
            },
            "dependencies": [],
            "acceptance": {
                "contracts": ["config/contracts/roadmap-policy.yaml"],
                "qualification_gates": ["governance"],
                "runtime_evidence": [".context/evidence/roadmap/M2-5-persistent-mgmt-bootstrap.json"],
                "tests": ["tests/test_m25_runtime_evidence.py"],
                "qce_capabilities": [],
            },
            "execution": {
                "preflight_required": True,
                "runtime_required": True,
                "recovery_required": False,
            },
            "review": {"code": "required", "security": "required"},
            "completion": {"post_merge_verification": True},
            "exit_criteria": ["Exact lab proof is not deployment proof"],
        }
        self.package_path = (
            self.root / "config/work-packages/M2.5/m25-rke2-runtime.yaml"
        )
        self.tracker = {
            "number": 32, "category": "milestone-tracker",
            "state": "open", "url": "https://github.test/issues/32",
        }

    def declare(self):
        self.package_path.parent.mkdir(parents=True, exist_ok=True)
        self.package_path.write_text(
            yaml.safe_dump(self.package), encoding="utf-8"
        )

    def plan(self, issues):
        with (
            mock.patch.object(PLAN, "load_roadmap", return_value=self.roadmap),
            mock.patch.object(PLAN, "tracker_readback", return_value=self.tracker),
            mock.patch.object(PLAN, "all_github_issues", return_value=issues),
            mock.patch.object(PLAN.work_package, "validate_work_package", return_value=[]),
        ):
            return PLAN.plan_milestone(
                self.root, "M2.5", gh="gh", repository="owner/repo"
            )

    def github_issue(self, body, *, number=170, state="open"):
        return {
            "number": number, "state": state, "body": body,
            "title": "M2.5 runtime", "html_url": f"https://github.test/issues/{number}",
        }

    def test_canonical_roadmap_preserves_m25_tracker(self):
        self.assertEqual(32, PLAN.issue_lifecycle.tracker_for_milestone(
            self.roadmap, "M2.5"
        ))

    def test_no_declaration_blocks_without_creating_historical_packages(self):
        result = self.plan([])
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual("NO_DECLARED_PACKAGES", result["reason"])
        self.assertEqual([], result["proposals"])
        self.assertFalse((self.root / "config/work-packages").exists())

    def test_read_only_plan_proposes_only_missing_package_key(self):
        self.declare()
        result = self.plan([])
        self.assertEqual("PASS", result["status"])
        self.assertEqual(1, len(result["proposals"]))
        proposal = result["proposals"][0]
        self.assertEqual(
            "M2.5:m25-rke2-runtime", proposal["idempotency_key"]
        )
        self.assertEqual("DRAFT_RELATION_PENDING", proposal["relation_state"])
        self.assertIn(PLAN.MARKER, proposal["body"])
        self.assertIn("config/work-packages/M2.5/m25-rke2-runtime.yaml", proposal["body"])
        self.assertIsNone(yaml.safe_load(
            self.package_path.read_text(encoding="utf-8")
        )["work_item_issue"])

    def test_closed_issue_is_reused_and_not_recreated(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        result = self.plan([self.github_issue(body, state="closed")])
        self.assertEqual("PASS", result["status"])
        self.assertEqual([], result["proposals"])
        self.assertEqual(170, result["reused"][0]["issue"])
        self.assertEqual("closed", result["reused"][0]["state"])

    def test_duplicate_structured_issues_fail_closed(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        result = self.plan([
            self.github_issue(body),
            self.github_issue(body, number=171, state="closed"),
        ])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("duplicate work-item", " ".join(result["errors"]))
        self.assertEqual([], result["proposals"])

    def test_malformed_or_ambiguous_historical_issue_blocks_creation(self):
        self.declare()
        malformed = self.github_issue("<!-- ecommerce-work-item:v1 broken -->")
        result = self.plan([malformed])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("contains invalid JSON", result["errors"][0])
        ambiguous = self.github_issue(
            "Historical m25-rke2-runtime work, no structured relation"
        )
        result = self.plan([ambiguous])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("ambiguous historical issue", result["errors"][0])

    def test_bound_package_without_exact_existing_issue_blocks(self):
        self.package["work_item_issue"] = 170
        self.declare()
        result = self.plan([])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("has no matching GitHub issue", result["errors"][0])

    def test_wrong_existing_issue_number_or_path_blocks(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        self.package["work_item_issue"] = 171
        self.declare()
        result = self.plan([self.github_issue(body)])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("binds another issue number", result["errors"][0])
        self.package["work_item_issue"] = None
        self.declare()
        wrong_path = body.replace(
            "config/work-packages/M2.5/m25-rke2-runtime.yaml",
            "config/work-packages/M2.5/other.yaml",
        )
        result = self.plan([self.github_issue(wrong_path)])
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("invalid package path", result["errors"][0])

    def test_invalid_package_declaration_blocks_before_proposal(self):
        self.declare()
        with (
            mock.patch.object(PLAN, "load_roadmap", return_value=self.roadmap),
            mock.patch.object(PLAN, "tracker_readback", return_value=self.tracker),
            mock.patch.object(PLAN.work_package, "validate_work_package",
                              return_value=["scope allowed_paths missing"]),
        ):
            result = PLAN.plan_milestone(
                self.root, "M2.5", gh="gh", repository="owner/repo"
            )
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], result["proposals"])
        self.assertIn("scope allowed_paths missing", result["errors"][0])

    def test_create_rechecks_and_skips_issue_added_by_another_writer(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        issue = self.github_issue(body)
        snapshots = [[], [issue], [issue]]
        with (
            mock.patch.object(PLAN, "load_roadmap", return_value=self.roadmap),
            mock.patch.object(PLAN, "tracker_readback", return_value=self.tracker),
            mock.patch.object(PLAN, "all_github_issues", side_effect=snapshots),
            mock.patch.object(PLAN.work_package, "validate_work_package", return_value=[]),
            mock.patch.object(PLAN, "_gh_json") as api,
        ):
            result = PLAN.create_missing(
                self.root, "M2.5", gh="gh", repository="owner/repo"
            )
        self.assertEqual("PASS", result["status"])
        self.assertEqual([], result["created"])
        self.assertEqual(170, result["reused"][0]["issue"])
        api.assert_not_called()

    def test_create_posts_once_then_reads_back_exact_relation(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        issue = self.github_issue(body)
        snapshots = [[], [], [issue]]

        def api(_gh, args, *, method="GET"):
            if method == "POST":
                self.assertEqual("repos/owner/repo/issues", args[0])
                return {"number": 170}
            self.assertEqual("repos/owner/repo/issues/170", args[0])
            return issue

        with (
            mock.patch.object(PLAN, "load_roadmap", return_value=self.roadmap),
            mock.patch.object(PLAN, "tracker_readback", return_value=self.tracker),
            mock.patch.object(PLAN, "all_github_issues", side_effect=snapshots),
            mock.patch.object(PLAN.work_package, "validate_work_package", return_value=[]),
            mock.patch.object(PLAN, "_gh_json", side_effect=api) as api_mock,
        ):
            result = PLAN.create_missing(
                self.root, "M2.5", gh="gh", repository="owner/repo"
            )
        self.assertEqual("PASS", result["status"])
        self.assertEqual(170, result["created"][0]["number"])
        self.assertEqual([], result["proposals"])
        self.assertEqual(2, api_mock.call_count)
        self.assertIsNone(yaml.safe_load(
            self.package_path.read_text(encoding="utf-8")
        )["work_item_issue"])

    def test_create_blocks_when_list_index_lags_exact_get(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        issue = self.github_issue(body)
        snapshots = [[], [], []]

        def api(_gh, args, *, method="GET"):
            if method == "POST":
                return {"number": 170}
            self.assertEqual("repos/owner/repo/issues/170", args[0])
            return issue

        with (
            mock.patch.object(PLAN, "load_roadmap", return_value=self.roadmap),
            mock.patch.object(PLAN, "tracker_readback", return_value=self.tracker),
            mock.patch.object(PLAN, "all_github_issues", side_effect=snapshots),
            mock.patch.object(PLAN.work_package, "validate_work_package", return_value=[]),
            mock.patch.object(PLAN, "_gh_json", side_effect=api) as api_mock,
        ):
            result = PLAN.create_missing(
                self.root, "M2.5", gh="gh", repository="owner/repo"
            )
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual("PENDING_INDEXING", result["reason"])
        self.assertEqual(["M2.5:m25-rke2-runtime"], result["pending_indexing"])
        self.assertEqual([], result["proposals"])
        self.assertEqual(170, result["created"][0]["number"])
        self.assertEqual(2, api_mock.call_count)

    def test_marker_uses_structured_relation_not_labels(self):
        self.declare()
        body = self.plan([])["proposals"][0]["body"]
        issue = self.github_issue(body)
        issue["labels"] = [{"name": "proven"}]
        relation = PLAN._structured_issue(issue)
        self.assertEqual("m25-rke2-runtime", relation["work_package_id"])
        self.assertEqual(32, relation["tracker_issue"])


    def test_pagination_reads_every_page_and_excludes_pull_requests(self):
        first = [self.github_issue("", number=number) for number in range(1, 101)]
        first[49]["pull_request"] = {"url": "https://github.test/pulls/50"}
        second = [self.github_issue("", number=101, state="closed")]
        with mock.patch.object(PLAN, "_gh_json", side_effect=[first, second]) as api:
            issues = PLAN.all_github_issues("gh", "owner/repo")
        self.assertEqual(100, len(issues))
        self.assertEqual(101, issues[-1]["number"])
        self.assertEqual("closed", issues[-1]["state"])
        self.assertEqual(2, api.call_count)
        self.assertIn("page=1", api.call_args_list[0].args[1][0])
        self.assertIn("page=2", api.call_args_list[1].args[1][0])

    def test_pagination_rejects_repeated_pages_and_unknown_completion(self):
        full = [self.github_issue("", number=number) for number in range(1, 101)]
        with mock.patch.object(PLAN, "_gh_json", side_effect=[full, full]):
            with self.assertRaisesRegex(PLAN.MilestonePlanError, "repeated issue"):
                PLAN.all_github_issues("gh", "owner/repo")
        second = [self.github_issue("", number=number) for number in range(101, 201)]
        with (
            mock.patch.object(PLAN, "MAX_ISSUE_PAGES", 2),
            mock.patch.object(PLAN, "_gh_json", side_effect=[full, second]),
        ):
            with self.assertRaisesRegex(PLAN.MilestonePlanError, "completeness is unknown"):
                PLAN.all_github_issues("gh", "owner/repo")

    def test_pagination_rejects_malformed_page(self):
        with mock.patch.object(PLAN, "_gh_json", return_value={"number": 1}):
            with self.assertRaisesRegex(PLAN.MilestonePlanError, "page 1 is malformed"):
                PLAN.all_github_issues("gh", "owner/repo")


if __name__ == "__main__":
    unittest.main()
