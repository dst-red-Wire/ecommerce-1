from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("roadmap_sync_test", ROOT / "scripts" / "roadmap_sync.py")
assert SPEC and SPEC.loader
ROADMAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROADMAP)

REPOCTL_SPEC = importlib.util.spec_from_file_location("repoctl_roadmap_test", ROOT / "scripts" / "repoctl.py")
assert REPOCTL_SPEC and REPOCTL_SPEC.loader
REPOCTL = importlib.util.module_from_spec(REPOCTL_SPEC)
REPOCTL_SPEC.loader.exec_module(REPOCTL)


class RoadmapSyncTests(unittest.TestCase):
    def test_central_policy_uses_issue_32_for_m2_5(self):
        policy = ROADMAP.policy()
        milestones = {item["id"]: item for item in policy["milestones"]}
        self.assertEqual(32, milestones["M2.5"]["tracker"])
        self.assertEqual(["M1"], milestones["M2"]["requires"])
        self.assertEqual(["M1"], milestones["M2.5"]["requires"])
        self.assertEqual(["M2.5"], milestones["M3"]["requires"])
        self.assertEqual(["M2", "M4"], milestones["M5"]["requires"])

    def test_statuses_unblock_m2_and_m2_5_after_m1_proven(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}
        states[13]["state"] = "closed"
        states[13]["state_reason"] = "completed"

        statuses = ROADMAP.compute_statuses(policy, states)

        self.assertEqual("DONE", statuses["M0"])
        self.assertEqual("PROVEN", statuses["M1"])
        self.assertEqual("READY FOR CODEX", statuses["M2"])
        self.assertEqual("READY FOR CODEX", statuses["M2.5"])
        self.assertEqual("BLOCKED by M2.5", statuses["M3"])
        self.assertEqual("BLOCKED by M3", statuses["M4"])
        self.assertEqual("BLOCKED by M2/M4", statuses["M5"])

    def test_completed_tracker_does_not_bypass_unmet_dependencies(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}

        states[13] = {"state": "closed", "state_reason": "completed", "title": "M1"}
        states[16] = {"state": "closed", "state_reason": "completed", "title": "M3"}

        statuses = ROADMAP.compute_statuses(policy, states)

        self.assertEqual("PROVEN", statuses["M1"])
        self.assertEqual("READY FOR CODEX", statuses["M2.5"])
        self.assertEqual(
            "BLOCKED by M2.5 (tracker #16 completed before prerequisites)",
            statuses["M3"],
        )
        self.assertEqual("BLOCKED by M3", statuses["M4"])

    def test_policy_rejects_non_topological_dependency_order(self):
        policy = ROADMAP.policy()
        broken = json.loads(json.dumps(policy))
        by_id = {item["id"]: item for item in broken["milestones"]}
        by_id["M2"]["requires"] = ["M4"]

        with (
            mock.patch.object(ROADMAP, "load_yaml", side_effect=[{"machine_contracts": {"roadmap_policy": "config/contracts/roadmap-policy.yaml"}}, broken]),
        ):
            with self.assertRaisesRegex(RuntimeError, "topological order"):
                ROADMAP.policy()

    def test_closed_not_planned_tracker_does_not_become_proven(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}
        states[13] = {"state": "closed", "state_reason": "not_planned", "title": "M1"}
        statuses = ROADMAP.compute_statuses(policy, states)
        self.assertIn("closed as not_planned", statuses["M1"])
        self.assertEqual("BLOCKED by M1", statuses["M2"])
        self.assertEqual("BLOCKED by M1", statuses["M2.5"])

    def test_render_replaces_generated_table_and_stale_tracker(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}
        states[13] = {"state": "closed", "state_reason": "completed", "title": "M1"}
        statuses = ROADMAP.compute_statuses(policy, states)

        original = (ROOT / "docs/project/MASTER_EXECUTION_PLAN.md").read_text(encoding="utf-8")
        original = original.replace(
            "Canonical tracker: GitHub issue `#32`.",
            "Canonical tracker: GitHub issue `#15`.",
            1,
        )
        rendered = ROADMAP.render_document(original, policy, statuses)
        tick = chr(96)

        self.assertIn("<!-- BEGIN GENERATED ROADMAP MILESTONES -->", rendered)
        self.assertIn("| M1 Monorepo Bootstrap | #13 |", rendered)
        self.assertIn("| M2.5 Persistent MGMT Bootstrap | #32 |", rendered)
        self.assertIn(f"Canonical tracker: GitHub issue {tick}#32{tick}.", rendered)
        self.assertNotIn(f"Canonical tracker: GitHub issue {tick}#15{tick}.", rendered)

    def test_projection_missing_tracker_line_fails_closed(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}
        states[13] = {"state": "closed", "state_reason": "completed", "title": "M1"}
        statuses = ROADMAP.compute_statuses(policy, states)

        original = (ROOT / "docs/project/MASTER_EXECUTION_PLAN.md").read_text(encoding="utf-8")
        original = original.replace("Canonical tracker: GitHub issue `#32`.", "tracker removed", 1)

        with self.assertRaisesRegex(RuntimeError, "missing its canonical tracker projection"):
            ROADMAP.render_document(original, policy, statuses)

    def test_projection_missing_milestone_heading_fails_closed(self):
        policy = ROADMAP.policy()
        states = {}
        for item in policy["milestones"]:
            tracker = item.get("tracker")
            if type(tracker) is int:
                states[tracker] = {"state": "open", "state_reason": "", "title": str(item["name"])}
        states[13] = {"state": "closed", "state_reason": "completed", "title": "M1"}
        statuses = ROADMAP.compute_statuses(policy, states)

        original = (ROOT / "docs/project/MASTER_EXECUTION_PLAN.md").read_text(encoding="utf-8")
        original = original.replace("### M2.5 — Persistent MGMT Bootstrap", "### renamed M2.5", 1)

        with self.assertRaisesRegex(RuntimeError, "missing milestone section"):
            ROADMAP.render_document(original, policy, statuses)

    def test_finish_pr_source_fails_closed_on_unknown_remote_branch_state(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def precommit(")]
        self.assertIn("remote_branch.returncode not in {0, 2}", finish)
        self.assertIn("cannot prove remote branch state", finish)

    def test_finish_pr_uses_exact_sha_branch_deletion_helpers(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def precommit(")]
        self.assertIn('_delete_branch_ref("remote", branch, head)', finish)
        self.assertIn('_delete_branch_ref("local", branch, head)', finish)
        self.assertNotIn('["git", "push", "origin", "--delete", branch]', finish)

    def test_tracker_reader_rejects_pull_request_tracker(self):
        policy = {"milestones": [{"id": "M2.5", "name": "MGMT", "tracker": 32}]}
        repo = subprocess.CompletedProcess([], 0, json.dumps({"nameWithOwner": "dst-red-Wire/ecommerce-1"}), "")
        pull = subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {
                    "number": 32,
                    "state": "closed",
                    "state_reason": "completed",
                    "pull_request": {"url": "https://api.github.com/pulls/32"},
                }
            ),
            "",
        )

        def fake_run(command, *, check=True):
            if command[1:4] == ["repo", "view", "--json"]:
                return repo
            if command[1] == "api":
                return pull
            raise AssertionError(command)

        with mock.patch.object(ROADMAP, "run", side_effect=fake_run):
            with self.assertRaisesRegex(RuntimeError, "must be a GitHub issue"):
                ROADMAP.tracker_states("gh", policy)

    def test_qce_snapshot_derives_valid_labels_and_pr_sha(self):
        lock = {
            "developer_platform": {
                "quality_cloud_engineering": {
                    "sectors": {name: {} for name in (
                        "continuous_testing", "test_first", "test_strategy", "automation",
                        "monitoring_observability", "release_governance_automation", "golden_path",
                        "developer_hub", "measuring_engineering",
                    )}
                }
            }
        }
        policy = {"qce_traceability": {"github_metadata_snapshot": ".context/qce/github-metadata.json"}}
        issue = subprocess.CompletedProcess(
            [], 0, json.dumps([{"number": 13, "labels": [{"name": "qce:automation"}], "milestone": None}]), ""
        )
        pull = subprocess.CompletedProcess(
            [], 0, json.dumps([{
                "number": 126,
                "labels": [{"name": "qce:continuous-testing"}],
                "milestone": {"title": "M1"},
                "headRefOid": "a" * 40,
            }]), ""
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(ROADMAP, "ROOT", Path(directory)),
            mock.patch.object(ROADMAP, "load_yaml", return_value=lock),
            mock.patch.object(ROADMAP, "github_name_with_owner", return_value="dst-red-Wire/ecommerce-1"),
            mock.patch.object(ROADMAP, "run", side_effect=[issue, pull]),
        ):
            destination = ROADMAP.qce_metadata_snapshot("gh", policy)
            payload = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual([13], [item["number"] for item in payload["issues"]])
        self.assertEqual("a" * 40, payload["pull_requests"][0]["head_sha"])


    def test_post_merge_does_not_treat_check_error_as_drift(self):
        with (
            mock.patch.object(REPOCTL, "roadmap_check", return_value=2),
            mock.patch.object(REPOCTL, "git") as git,
        ):
            self.assertNotEqual(0, REPOCTL._roadmap_followup_after_merge())
        git.assert_not_called()

    def test_finish_pr_source_runs_post_merge_roadmap_reconciliation(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        finish = source[source.index("def finish_pr(") : source.index("def precommit(")]
        self.assertIn("_roadmap_followup_after_merge()", finish)
        self.assertIn("automatic roadmap synchronization failed", finish)

        followup = source[source.index("def _roadmap_followup_after_merge(") : source.index("def git_sync(")]
        self.assertIn("roadmap_check(quiet=True)", followup)
        self.assertIn("roadmap_sync()", followup)
        self.assertIn("deliver(default_branch, title, title)", followup)
        self.assertNotIn("git push origin main", followup)


if __name__ == "__main__":
    unittest.main()
