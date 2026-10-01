from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
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

    def test_closed_tracker_is_implemented_not_proven_without_evidence(self):
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
        self.assertEqual("IMPLEMENTED", statuses["M1"])
        self.assertEqual("BLOCKED", statuses["M2"])
        self.assertEqual("BLOCKED", statuses["M2.5"])
        self.assertEqual("BLOCKED", statuses["M3"])
        self.assertEqual("BLOCKED", statuses["M4"])
        self.assertEqual("BLOCKED", statuses["M5"])

    def test_closed_tracker_alone_is_not_technical_progress(self):
        policy = self._runtime_policy()
        with tempfile.TemporaryDirectory() as directory:
            projection = ROADMAP.derive_projection(
                policy,
                {99: {"state": "closed", "state_reason": "completed", "title": "M4"}},
                root=Path(directory),
                head="a" * 40,
                tree="b" * 40,
            )
        self.assertEqual("CONTRACTED", projection["milestones"][0]["status"])
        self.assertIn("implementation:impl", projection["milestones"][0]["missing_evidence"])

    def test_missing_contract_is_not_started(self):
        policy = self._runtime_policy()
        del policy["milestones"][0]["requirements"]
        projection = ROADMAP.derive_projection(
            policy,
            {99: {"state": "closed", "state_reason": "completed", "title": "M4"}},
            head="a" * 40,
            tree="b" * 40,
        )
        self.assertEqual("NOT_STARTED", projection["milestones"][0]["status"])
        self.assertEqual(["contract"], projection["milestones"][0]["missing_evidence"])

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

        self.assertEqual("IMPLEMENTED", statuses["M1"])
        self.assertEqual("BLOCKED", statuses["M2.5"])
        self.assertEqual("BLOCKED", statuses["M3"])
        self.assertEqual("BLOCKED", statuses["M4"])

    def test_policy_rejects_non_topological_dependency_order(self):
        policy = ROADMAP.policy()
        broken = json.loads(json.dumps(policy))
        by_id = {item["id"]: item for item in broken["milestones"]}
        by_id["M2"]["requires"] = ["M4"]

        with (
            mock.patch.object(
                ROADMAP,
                "load_yaml",
                side_effect=[
                    {"machine_contracts": {"roadmap_policy": "config/contracts/roadmap-policy.yaml"}},
                    broken,
                    ROADMAP.load_yaml("config/contracts/qualification-execution-policy.yaml"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "topological order"):
                ROADMAP.policy()

    def test_policy_rejects_unknown_resolved_capability_reference(self):
        broken = json.loads(json.dumps(ROADMAP.policy()))
        milestone = next(item for item in broken["milestones"] if item["id"] == "M4")
        milestone["requirements"]["resolved_capabilities"][0]["tool"] = "typo-tool"
        with mock.patch.object(
            ROADMAP,
            "load_yaml",
            side_effect=[
                {"machine_contracts": {"roadmap_policy": "config/contracts/roadmap-policy.yaml"}},
                broken,
                ROADMAP.load_yaml("config/contracts/qualification-execution-policy.yaml"),
            ],
        ):
            with self.assertRaisesRegex(RuntimeError, "unknown resolved capability"):
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
        self.assertEqual("BLOCKED", statuses["M1"])
        self.assertEqual("BLOCKED", statuses["M2"])
        self.assertEqual("BLOCKED", statuses["M2.5"])

    def test_static_proven_and_manual_overrides_are_rejected(self):
        for milestone_id in ("M8", "M9"):
            broken = json.loads(json.dumps(ROADMAP.policy()))
            milestone = next(item for item in broken["milestones"] if item["id"] == milestone_id)
            milestone["completion_status"] = "PROVEN"
            with (
                self.subTest(milestone=milestone_id),
                mock.patch.object(
                    ROADMAP,
                    "load_yaml",
                    side_effect=[
                        {"machine_contracts": {"roadmap_policy": "config/contracts/roadmap-policy.yaml"}},
                        broken,
                        ROADMAP.load_yaml("config/contracts/qualification-execution-policy.yaml"),
                    ],
                ),
                self.assertRaisesRegex(RuntimeError, "forbidden static status"),
            ):
                ROADMAP.policy()

    def _runtime_policy(self, milestone_id="M4", requires=None):
        return {
            "github": {"completed_state": "closed", "completed_state_reason": "completed"},
            "status_derivation": {
                "dependency_terminal_statuses": ["DONE", "PROVEN"],
                "evidence_max_age_seconds": 86400,
                "runtime_evidence_contract": {
                    "schema_version": 1,
                    "required_fields": [
                        "schema_version", "status", "exact_commit_evidence", "runtime_execution",
                        "head_sha", "head_tree_sha", "created_at_epoch", "milestone",
                        "environment", "runtime_identity", "outcome",
                    ],
                    "accepted_status": "PASS",
                    "accepted_outcome": "PASS",
                    "runtime_identity_required_fields": ["kind", "id"],
                },
            },
            "milestones": [
                {
                    "id": milestone_id,
                    "tracker": 99,
                    "requires": requires or [],
                    "requirements": {
                        "implementation_paths": ["impl"],
                        "qualification_gates": ["governance"],
                        "qce_capabilities": [],
                        "runtime_evidence": [
                            {"path": f".context/evidence/roadmap/{milestone_id}.json", "environments": ["preprod"]}
                        ],
                    },
                }
            ],
        }

    def test_runtime_milestone_requires_fresh_exact_environment_bound_evidence(self):
        head, tree = "a" * 40, "b" * 40
        now = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        for mutation, expected in (
            ({}, "PROVEN"),
            ({"created_at_epoch": (now - timedelta(days=2)).timestamp()}, "QUALIFIED"),
            ({"created_at_epoch": float("nan")}, "QUALIFIED"),
            ({"head_sha": "c" * 40}, "QUALIFIED"),
            ({"environment": "prod-a"}, "QUALIFIED"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "impl").mkdir()
                evidence_path = root / ".context/evidence/roadmap/M4.json"
                evidence_path.parent.mkdir(parents=True)
                evidence = {
                    "schema_version": 1,
                    "status": "PASS",
                    "exact_commit_evidence": True,
                    "runtime_execution": True,
                    "head_sha": head,
                    "head_tree_sha": tree,
                    "created_at_epoch": now.timestamp(),
                    "milestone": "M4",
                    "environment": "preprod",
                    "runtime_identity": {"kind": "rke2-cluster", "id": "preprod-01"},
                    "outcome": "PASS",
                    **mutation,
                }
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
                projection = ROADMAP.derive_projection(
                    self._runtime_policy(),
                    {99: {"state": "closed", "state_reason": "completed", "title": "M4"}},
                    root=root,
                    qualification_gates={"governance": "PASS"},
                    head=head,
                    tree=tree,
                    now=now,
                )
                self.assertEqual(expected, projection["milestones"][0]["status"])

    def test_contracts_or_manifests_without_runtime_never_prove_m25_m4_m5_or_m9(self):
        for milestone_id in ("M2.5", "M4", "M5", "M9"):
            with self.subTest(milestone=milestone_id), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "impl").mkdir()
                projection = ROADMAP.derive_projection(
                    self._runtime_policy(milestone_id),
                    {99: {"state": "closed", "state_reason": "completed", "title": milestone_id}},
                    root=root,
                    qualification_gates={"governance": "PASS"},
                    head="a" * 40,
                    tree="b" * 40,
                )
                self.assertEqual("QUALIFIED", projection["milestones"][0]["status"])
                self.assertNotEqual("PROVEN", projection["milestones"][0]["status"])

    def test_m2_5_lab_proof_and_closed_tracker_do_not_prove_deployment(self):
        policy = self._runtime_policy("M2.5")
        declaration = policy["milestones"][0]["requirements"]["runtime_evidence"][0]
        declaration["environments"] = ["management"]
        declaration["proof_type"] = "persistent-deployment"
        head, tree = "a" * 40, "b" * 40
        now = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "impl").mkdir()
            evidence_path = root / declaration["path"]
            evidence_path.parent.mkdir(parents=True)
            payload = {
                "schema_version": 1,
                "status": "PASS",
                "exact_commit_evidence": True,
                "runtime_execution": True,
                "head_sha": head,
                "head_tree_sha": tree,
                "created_at_epoch": now.timestamp(),
                "milestone": "M2.5",
                "environment": "lab",
                "runtime_identity": {"kind": "rke2-cluster", "id": "lab-01"},
                "outcome": "PASS",
                "deployment_state": "NOT_DEPLOYED",
                "deployment_persistence": "ephemeral",
                "deployment_verified": False,
            }

            def status(tracker_state: str) -> str:
                evidence_path.write_text(json.dumps(payload), encoding="utf-8")
                projection = ROADMAP.derive_projection(
                    policy,
                    {99: {"state": tracker_state, "state_reason": "completed", "title": "M2.5"}},
                    root=root,
                    qualification_gates={"governance": "PASS"},
                    head=head,
                    tree=tree,
                    now=now,
                )
                return projection["milestones"][0]["status"]

            self.assertEqual("QUALIFIED", status("closed"))
            payload["environment"] = "management"
            payload["deployment_verified"] = True
            self.assertEqual("QUALIFIED", status("closed"))
            payload["deployment_state"] = "DEPLOYED"
            self.assertEqual("QUALIFIED", status("closed"))
            payload["deployment_persistence"] = "persistent"
            self.assertEqual("QUALIFIED", status("open"))
            self.assertEqual("QUALIFIED", status("closed"))
            valid, detail = ROADMAP._runtime_evidence_result(
                root, declaration, "M2.5", head, tree,
                policy["status_derivation"]["runtime_evidence_contract"], 86400, now,
            )
            self.assertFalse(valid)
            self.assertIn("no registered producer and state verifier", detail)

    def test_runtime_and_post_merge_proofs_advance_separate_statuses(self):
        policy = self._runtime_policy()
        merge_sha = "c" * 40
        reference = f".context/evidence/post-merge/{merge_sha}.json"
        policy["milestones"][0]["requirements"]["post_merge_evidence"] = [reference]
        head, tree = "a" * 40, "b" * 40
        now = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "impl").mkdir()
            runtime_path = root / ".context/evidence/roadmap/M4.json"
            runtime_path.parent.mkdir(parents=True)
            runtime_path.write_text(json.dumps({
                "schema_version": 1, "status": "PASS",
                "exact_commit_evidence": True, "runtime_execution": True,
                "head_sha": head, "head_tree_sha": tree,
                "created_at_epoch": now.timestamp(), "milestone": "M4",
                "environment": "preprod",
                "runtime_identity": {"kind": "rke2-cluster", "id": "preprod-01"},
                "outcome": "PASS",
            }), encoding="utf-8")

            def status(tracker_state: str) -> str:
                projection = ROADMAP.derive_projection(
                    policy,
                    {99: {"state": tracker_state, "state_reason": "completed", "title": "M4"}},
                    root=root,
                    qualification_gates={"governance": "PASS"},
                    head=head,
                    tree=tree,
                    now=now,
                )
                return projection["milestones"][0]["status"]

            self.assertEqual("RUNTIME_PROVEN", status("closed"))
            post_merge_path = root / reference
            post_merge_path.parent.mkdir(parents=True)
            proof = {
                "status": "PASS", "base_sha": "d" * 40, "head_sha": head,
                "merge_sha": merge_sha, "merge_tree_sha": tree,
                "signature_verified": True, "main_contains_change": True,
                "qualified_tree_matches": True, "clean_worktree": True,
                "roadmap_sync": "PASS",
            }
            post_merge_path.write_text(json.dumps(proof), encoding="utf-8")
            self.assertEqual("RUNTIME_PROVEN", status("open"))
            self.assertEqual("RUNTIME_PROVEN", status("closed"))
            proof["signature_verified"] = False
            post_merge_path.write_text(json.dumps(proof), encoding="utf-8")
            self.assertEqual("RUNTIME_PROVEN", status("closed"))

    def test_policy_requires_persistent_mgmt_proof(self):
        policy = ROADMAP.policy()
        milestone = next(item for item in policy["milestones"] if item["id"] == "M2.5")
        self.assertEqual(32, milestone["tracker"])
        self.assertEqual(
            ["lab-readiness", "persistent-deployment"],
            [
                declaration["proof_type"]
                for declaration in milestone["requirements"]["runtime_evidence"]
            ],
        )
        broken = json.loads(json.dumps(policy))
        requirement = next(
            item for item in broken["milestones"] if item["id"] == "M2.5"
        )["requirements"]
        requirement["runtime_evidence"] = requirement["runtime_evidence"][:1]
        with (
            mock.patch.object(
                ROADMAP,
                "load_yaml",
                side_effect=[
                    {"machine_contracts": {"roadmap_policy": "config/contracts/roadmap-policy.yaml"}},
                    broken,
                    ROADMAP.load_yaml("config/contracts/qualification-execution-policy.yaml"),
                ],
            ),
            self.assertRaisesRegex(RuntimeError, "M2.5 requires canonical lab and persistent"),
        ):
            ROADMAP.policy()

    def test_document_only_checks_rendering_without_projecting_proofs(self):
        with (
            mock.patch.object(ROADMAP, "tracker_states") as tracker,
            mock.patch.object(ROADMAP, "_current_projection") as projection,
            mock.patch.object(ROADMAP, "_write_projection") as writer,
        ):
            self.assertEqual(0, ROADMAP.check_document(quiet=True))
        tracker.assert_not_called()
        projection.assert_not_called()
        writer.assert_not_called()

    def test_document_only_rejects_actual_rendering_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ROOT / "docs/project/MASTER_EXECUTION_PLAN.md"
            path = root / "docs/project/MASTER_EXECUTION_PLAN.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                source.read_text(encoding="utf-8").replace(
                    "Canonical tracker: GitHub issue `#32`.",
                    "Canonical tracker: GitHub issue `#15`.", 1,
                ), encoding="utf-8",
            )
            policy = ROADMAP.policy()
            with (
                mock.patch.object(ROADMAP, "ROOT", root),
                mock.patch.object(ROADMAP, "policy", return_value=policy),
            ):
                self.assertEqual(1, ROADMAP.check_document(quiet=True))

    def test_blocked_qce_capability_blocks_mapped_milestone(self):
        policy = self._runtime_policy()
        policy["milestones"][0]["requirements"]["qce_capabilities"] = ["automation"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "impl").mkdir()
            projection = ROADMAP.derive_projection(
                policy,
                {99: {"state": "closed", "state_reason": "completed", "title": "M4"}},
                root=root,
                qualification_gates={"governance": "PASS"},
                qce_payload={
                    "sectors": [
                        {"capabilities": [{"id": "automation", "status": "BLOCKED"}]}
                    ]
                },
                head="a" * 40,
                tree="b" * 40,
            )
        milestone = projection["milestones"][0]
        self.assertEqual("BLOCKED", milestone["status"])
        self.assertIn("QCE capability blocked: automation", milestone["blockers"])

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
        self.assertIn("if cleanup_rc or roadmap_rc:", finish)
        self.assertIn("post-merge cleanup or roadmap verification is incomplete", finish)

        followup = source[source.index("def _roadmap_followup_after_merge(") : source.index("def git_sync(")]
        self.assertIn("roadmap_check(quiet=True)", followup)
        self.assertIn("roadmap_sync()", followup)
        self.assertIn("deliver(default_branch, title, title)", followup)
        self.assertNotIn("git push origin main", followup)


    def test_document_only_cannot_be_used_to_sync(self):
        with (
            mock.patch.object(ROADMAP.sys, "argv", ["roadmap_sync", "sync", "--document-only"]),
            mock.patch.object(ROADMAP, "sync") as sync,
            self.assertRaises(SystemExit) as failure,
        ):
            ROADMAP.main()
        self.assertEqual(2, failure.exception.code)
        sync.assert_not_called()

    def test_document_only_cli_does_not_request_github_or_project_proofs(self):
        with (
            mock.patch.object(ROADMAP.sys, "argv", ["roadmap_sync", "check", "--quiet", "--document-only"]),
            mock.patch.object(ROADMAP.shutil, "which", side_effect=AssertionError("GitHub lookup is forbidden")),
            mock.patch.object(ROADMAP, "tracker_states", side_effect=AssertionError("proof recursion")),
            mock.patch.object(ROADMAP, "_current_projection", side_effect=AssertionError("proof recursion")),
            mock.patch.object(ROADMAP, "_write_projection") as writer,
        ):
            self.assertEqual(0, ROADMAP.main())
        writer.assert_not_called()

    def test_registered_m25_lab_proof_remains_not_deployed(self):
        from tests import test_m25_runtime_evidence

        fixture = test_m25_runtime_evidence.M25RuntimeEvidenceTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        contract = ROADMAP.policy()["status_derivation"]["runtime_evidence_contract"]
        declaration = {
            "path": ROADMAP.m25_runtime_evidence.OUTPUT.as_posix(),
            "environments": ["lab"],
            "proof_type": "lab-readiness",
        }

        def result():
            fixture.write()
            return ROADMAP._runtime_evidence_result(
                fixture.root, declaration, "M2.5", test_m25_runtime_evidence.HEAD,
                test_m25_runtime_evidence.TREE, contract, 86400,
                datetime.now(timezone.utc),
            )

        valid, detail = result()
        self.assertTrue(valid, detail)
        self.assertEqual("NOT_DEPLOYED", fixture.evidence["deployment_state"])
        fixture.evidence["deployment_state"] = "DEPLOYED"
        self.assertFalse(result()[0])
        fixture.evidence["deployment_state"] = "NOT_DEPLOYED"
        source = fixture.root / ROADMAP.m25_runtime_evidence._paths(test_m25_runtime_evidence.VM)["rke2_result"]
        source.unlink()
        self.assertFalse(result()[0])

class RoadmapFollowupTests(unittest.TestCase):
    """Use real local Git refs, package selection and preflight without GitHub writes."""

    document = "docs/project/MASTER_EXECUTION_PLAN.md"
    package_path = "config/work-packages/M7/m7-verified-delivery-chain.yaml"

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name) / "repo"
        self.root.mkdir()
        self.remote = Path(self.workspace.name) / "remote.git"
        subprocess.run(
            ["git", "init", "--bare", "-q", str(self.remote)],
            check=True, capture_output=True,
        )
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Roadmap tests")
        self.git("config", "user.email", "roadmap@example.test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", "/dev/null")
        self.git("remote", "add", "origin", str(self.remote))
        shutil.copytree(ROOT / "config/contracts", self.root / "config/contracts")
        # The canonical preflight binds the producer and runtime Git blobs,
        # including for a publication diagnosis that grants no merge authority.
        for relative in (
            "architecture.lock.yaml", self.package_path,
            "scripts/delivery_preflight.py", "scripts/runtime_orchestration.py",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        path = self.root / self.document
        path.parent.mkdir(parents=True)
        path.write_text("stale\n", encoding="utf-8")
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture main")
        self.git("push", "-q", "-u", "origin", "main")
        self.main = self.git("rev-parse", "HEAD")
        self.prs = []
        self.deliveries = 0
        self.original_output = REPOCTL.output
        self.patches = [
            mock.patch.object(REPOCTL, "ROOT", self.root),
            mock.patch.object(REPOCTL, "roadmap_check", side_effect=self.check),
            mock.patch.object(REPOCTL, "roadmap_sync", side_effect=self.sync),
            mock.patch.object(REPOCTL, "output", side_effect=self.output),
            mock.patch.object(REPOCTL, "deliver", side_effect=self.deliver),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def git(self, *arguments):
        result = subprocess.run(
            ["git", *arguments], cwd=self.root, text=True,
            capture_output=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def check(self, *, quiet=False):
        return int((self.root / self.document).read_text(encoding="utf-8") != "synced\n")

    def sync(self):
        (self.root / self.document).write_text("synced\n", encoding="utf-8")
        return 0

    def output(self, command, **kwargs):
        if command[1:3] == ["pr", "list"]:
            if command[command.index("--state") + 1] == "open":
                return json.dumps([pr for pr in self.prs if pr["state"] == "OPEN"])
            return json.dumps(self.prs)
        return self.original_output(command, **kwargs)

    def deliver(self, base, title, message):
        self.deliveries += 1
        if self.git("status", "--porcelain", "--untracked-files=all"):
            self.git("add", self.document)
            self.git("commit", "-qm", message)
        head = self.git("rev-parse", "HEAD")
        # This is the actual publication preflight, including the canonical
        # selector and the base-owned toolchain capability probe.
        result = REPOCTL._delivery_publish_preflight("origin/main", head)
        self.assertEqual(0, result)
        branch = self.git("branch", "--show-current")
        self.git("push", "-q", "-u", "origin", branch)
        self.prs = [{
            "number": 200, "state": "OPEN", "headRefOid": head,
            "baseRefName": "main", "headRefName": branch,
        }]
        return 0

    def commit_main_change(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture policy change")
        self.git("push", "-q", "origin", "main")
        self.main = self.git("rev-parse", "HEAD")

    def test_scoped_followup_passes_real_preflight_and_reruns_without_new_commit(self):
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual("main", self.git("branch", "--show-current"))
        self.assertEqual(self.main, self.git("rev-parse", "HEAD"))
        branch = f"automation/roadmap-sync/{self.main[:12]}"
        followup = self.git("rev-parse", branch)
        self.assertEqual("1", self.git("rev-list", "--count", f"main..{branch}"))
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(1, self.deliveries)
        self.assertEqual(followup, self.git("rev-parse", branch))
        self.assertEqual("main", self.git("branch", "--show-current"))
        self.assertEqual("", self.git("status", "--porcelain"))

    def test_missing_scope_blocks_before_branch_or_commit(self):
        import yaml

        path = self.root / self.package_path
        package = yaml.safe_load(path.read_text(encoding="utf-8"))
        package["scope"]["allowed_paths"].remove(self.document)
        path.write_text(yaml.safe_dump(package), encoding="utf-8")
        self.commit_main_change()
        self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(0, self.deliveries)
        self.assertEqual("", self.git("for-each-ref", "refs/heads/automation/"))
        self.assertEqual(self.main, self.git("rev-parse", "HEAD"))

    def test_ambiguous_scope_blocks_before_branch_or_commit(self):
        import yaml

        package = yaml.safe_load((self.root / self.package_path).read_text(encoding="utf-8"))
        package["id"] = "m7-duplicate-roadmap"
        package["work_item_issue"] = 171
        path = self.root / "config/work-packages/M7/m7-duplicate-roadmap.yaml"
        path.write_text(yaml.safe_dump(package), encoding="utf-8")
        self.commit_main_change()
        self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(0, self.deliveries)
        self.assertEqual("", self.git("for-each-ref", "refs/heads/automation/"))

    def test_failed_publication_restores_main_and_reuses_retained_commit(self):
        def fail_after_commit(base, title, message):
            self.git("add", self.document)
            self.git("commit", "-qm", message)
            return 1

        with mock.patch.object(REPOCTL, "deliver", side_effect=fail_after_commit):
            self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        branch = f"automation/roadmap-sync/{self.main[:12]}"
        retained = self.git("rev-parse", branch)
        self.assertEqual("main", self.git("branch", "--show-current"))
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(retained, self.git("rev-parse", branch))
        self.assertEqual("1", self.git("rev-list", "--count", f"main..{branch}"))

    def test_failed_publication_before_commit_restores_only_generated_bytes(self):
        with mock.patch.object(REPOCTL, "deliver", return_value=1):
            self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual("main", self.git("branch", "--show-current"))
        self.assertEqual("", self.git("status", "--porcelain"))
        self.assertEqual(self.main, self.git("rev-parse", "HEAD"))
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(1, self.deliveries)

    def test_out_of_scope_generation_is_preserved_without_commit_or_publication(self):
        def bad_sync():
            self.sync()
            (self.root / "architecture.lock.yaml").write_text("unexpected\n", encoding="utf-8")
            return 0

        with mock.patch.object(REPOCTL, "roadmap_sync", side_effect=bad_sync):
            self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(0, self.deliveries)
        self.assertEqual(self.main, self.git("rev-parse", "HEAD"))
        self.assertIn("architecture.lock.yaml", self.git("status", "--porcelain"))

    def test_advancing_main_does_not_duplicate_an_open_followup(self):
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        (self.root / "other.txt").write_text("unrelated main change\n", encoding="utf-8")
        self.commit_main_change()
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(1, self.deliveries)
        branches = self.git("for-each-ref", "--format=%(refname)", "refs/heads/automation/")
        self.assertEqual(1, len(branches.splitlines()))
        self.assertEqual("main", self.git("branch", "--show-current"))
        self.assertEqual(self.main, self.git("rev-parse", "HEAD"))

    def test_closed_followup_is_not_recreated_in_a_loop(self):
        self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
        self.prs[0]["state"] = "CLOSED"
        self.assertEqual(2, REPOCTL._roadmap_followup_after_merge())
        self.assertEqual(1, self.deliveries)
        self.assertEqual("main", self.git("branch", "--show-current"))


class RoadmapSignedPostMergeTests(unittest.TestCase):
    """Exercise the real Git/GPG/bundle verifier; only GitHub transport is faked."""

    @classmethod
    def setUpClass(cls):
        from tests import test_post_merge_verify

        cls.fixture_type = test_post_merge_verify.PostMergeVerifyTests
        cls.verifier = test_post_merge_verify.post_merge_verify
        cls.fixture_type.setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.fixture_type.tearDownClass()

    def setUp(self):
        self.fixture = self.fixture_type(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.reference = (
            f".context/evidence/post-merge/{self.fixture.merge}.json"
        )
        self.proof = self.verifier.write_post_merge_proof(
            self.fixture.root, pr_number=171, snapshot=self.fixture.snapshot,
            qualification=self.fixture.qualification,
        )

    def project(self, *, snapshot=None):
        policy = RoadmapSyncTests()._runtime_policy()
        requirements = policy["milestones"][0]["requirements"]
        requirements["implementation_paths"] = ["base.txt"]
        requirements["runtime_evidence"] = []
        requirements["post_merge_evidence"] = [self.reference]
        with mock.patch.object(
            ROADMAP, "_fresh_post_merge_snapshot",
            return_value=self.fixture.snapshot if snapshot is None else snapshot,
        ) as read:
            projection = ROADMAP.derive_projection(
                policy,
                {99: {"state": "closed", "state_reason": "completed"}},
                root=self.fixture.root,
                qualification_gates={"governance": "PASS"},
                effective_capabilities={"tools": {}},
                head=self.fixture.git("rev-parse", "HEAD"),
                tree=self.fixture.git("rev-parse", "HEAD^{tree}"),
            )
        read.assert_called_once_with(171)
        return projection["milestones"][0]

    def test_real_signed_proof_with_fresh_github_allows_proven(self):
        result = self.project()
        self.assertEqual("PROVEN", result["status"], result["missing_evidence"])
        self.assertIn(self.reference, result["evidence"])
        # Every projection requests a new snapshot, never a saved GitHub flag.
        self.assertEqual("PROVEN", self.project()["status"])

    def test_unsigned_complete_proof_cannot_advance_projection(self):
        self.proof.with_suffix(".json.sig").unlink()
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("signature is missing", " ".join(result["missing_evidence"]))

    def test_invalid_signature_cannot_advance_projection(self):
        self.proof.with_suffix(".json.sig").write_bytes(b"not a signature")
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("signature did not verify", " ".join(result["missing_evidence"]))

    def test_other_valid_signer_cannot_advance_projection(self):
        signed = subprocess.run(
            [
                "gpg", "--batch", "--yes", "--local-user",
                self.fixture.untrusted_fingerprint,
                "--output", str(self.proof.with_suffix(".json.sig")),
                "--detach-sign", str(self.proof),
            ],
            text=True, capture_output=True, check=False, timeout=30,
        )
        self.assertEqual(0, signed.returncode, signed.stderr)
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("historical signing authority", " ".join(result["missing_evidence"]))

    def test_tampered_signed_proof_cannot_advance_projection(self):
        value = json.loads(self.proof.read_text(encoding="utf-8"))
        value["merge_signature"]["fingerprint"] = "f" * 40
        self.proof.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("signature did not verify", " ".join(result["missing_evidence"]))

    def test_wrong_fresh_pr_or_head_cannot_advance_projection(self):
        for mutation in ({"number": 172}, {"head_sha": "f" * 40}):
            with self.subTest(mutation=mutation):
                result = self.project(snapshot={**self.fixture.snapshot, **mutation})
                self.assertEqual("QUALIFIED", result["status"])
                self.assertTrue(result["missing_evidence"])

    def test_main_without_merged_change_cannot_advance_projection(self):
        self.fixture.git("switch", "--detach", self.fixture.base)
        self.fixture.git("update-ref", "refs/remotes/origin/main", self.fixture.base)
        self.fixture.git(
            "update-ref", "refs/heads/main", self.fixture.base,
            repo=self.fixture.remote,
        )
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("does not contain", " ".join(result["missing_evidence"]))

    def test_tampered_qualification_bundle_cannot_advance_projection(self):
        evidence = self.fixture.root / ".context/evidence" / f"{self.fixture.head}.json"
        evidence.write_bytes(evidence.read_bytes() + b"\n")
        result = self.project()
        self.assertEqual("QUALIFIED", result["status"])
        self.assertIn("differ from trusted witness", " ".join(result["missing_evidence"]))

    def test_unavailable_github_cannot_use_saved_pass(self):
        with mock.patch.object(
            ROADMAP, "_fresh_post_merge_snapshot",
            side_effect=RuntimeError("GitHub unavailable"),
        ):
            valid, detail = ROADMAP._post_merge_evidence_result(
                self.fixture.root, self.reference
            )
        self.assertFalse(valid)
        self.assertIn("GitHub unavailable", detail)

    def prepare_publication_reentry(self):
        root = self.fixture.root
        for relative in (
            ".gitattributes", "scripts/repository_delivery.py",
            "scripts/delivery_preflight.py", "scripts/runtime_orchestration.py",
        ):
            shutil.copyfile(ROOT / relative, root / relative)
        # The signed fixture's producer exercises the actual capability probe
        # and records only harmless facts. It never contacts a real GitHub API.
        (root / "scripts/repoctl.py").write_text(
            "import hashlib, json, os, subprocess\n"
            "from pathlib import Path\n"
            "import delivery_preflight\n"
            "def _roadmap_followup_after_merge():\n"
            "    root = Path.cwd()\n"
            "    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()\n"
            "    branch = 'automation/roadmap-sync/reentry-test'\n"
            "    subprocess.run(['git', 'switch', '-c', branch], check=True, capture_output=True)\n"
            "    try:\n"
            "        digest = 'sha256:' + hashlib.sha256((root / 'config/contracts/toolchain-lock.json').read_bytes()).hexdigest()\n"
            "        proof = delivery_preflight.run_preflight(root, expected_head_sha=head, expected_base_sha=head, expected_branch=branch, required_capabilities=['toolchain-pinned'], capability_parameters={'toolchain-pinned': {'sha256': digest}})\n"
            "        proof['inherited_merge_context'] = any(k.startswith('REPOCTL_TRUSTED_') for k in os.environ)\n"
            "        (root / '.context/reentry.json').write_text(json.dumps(proof))\n"
            "        return 3 if proof['status'] == 'PASS' else 2\n"
            "    finally:\n"
            "        subprocess.run(['git', 'switch', 'main'], check=True, capture_output=True)\n",
            encoding="utf-8",
        )
        self.fixture.git("add", ".")
        # The qualification runner sets commit.gpgsign=false for synthetic
        # repositories; this fixture specifically requires a signed new main.
        self.fixture.git("commit", "-S", "-qm", "new signed main producer")
        current = self.fixture.git("rev-parse", "HEAD")
        self.fixture.git("verify-commit", current)
        self.fixture.git("push", "-q", "origin", "main")
        return current

    def test_new_main_publication_drops_stale_merge_context_only_in_child(self):
        current = self.prepare_publication_reentry()
        inherited = {
            "REPOCTL_TRUSTED_BASE_SHA": self.fixture.base,
            "REPOCTL_TRUSTED_HEAD_SHA": self.fixture.head,
            "REPOCTL_TRUSTED_POLICY_ROOT": str(self.fixture.root),
            "REPOCTL_TRUSTED_TARGET_ROOT": str(self.fixture.root),
            "REPOCTL_TRUSTED_CONTROLLER": str(self.fixture.root / "scripts/repoctl.py"),
        }
        with (
            mock.patch.object(REPOCTL, "ROOT", self.fixture.root),
            mock.patch.dict(os.environ, inherited),
        ):
            self.assertEqual(3, REPOCTL._roadmap_followup_after_merge())
            for name, value in inherited.items():
                self.assertEqual(value, os.environ[name])
        proof = json.loads((self.fixture.root / ".context/reentry.json").read_text())
        self.assertEqual("PASS", proof["status"])
        self.assertEqual(current, proof["source_sha"])
        self.assertEqual(current, proof["base_sha"])
        self.assertFalse(proof["inherited_merge_context"])
        self.assertEqual("main", self.fixture.git("branch", "--show-current"))
        self.assertEqual("", self.fixture.git("status", "--porcelain"))

    def test_reentry_rejects_hidden_checkout_substitution_before_execution(self):
        current = self.prepare_publication_reentry()
        controller = self.fixture.root / "scripts/repoctl.py"
        controller.write_text(
            "from pathlib import Path\n"
            "Path('.context/unsafe-producer').touch()\n", encoding="utf-8",
        )
        self.fixture.git("update-index", "--assume-unchanged", "scripts/repoctl.py")
        self.assertEqual("", self.fixture.git("status", "--porcelain"))
        with mock.patch.object(REPOCTL, "ROOT", self.fixture.root):
            self.assertEqual(2, REPOCTL._roadmap_publication_reentry(current, "main"))
        self.assertFalse((self.fixture.root / ".context/unsafe-producer").exists())
        self.assertFalse((self.fixture.root / ".context/reentry.json").exists())

    def test_unsafe_reference_cannot_select_another_proof(self):
        with mock.patch.object(ROADMAP, "_fresh_post_merge_snapshot") as snapshot:
            for reference in (
                "/tmp/proof.json",
                ".context/evidence/post-merge/../elsewhere.json",
                ".context/evidence/post-merge/not-a-sha.json",
            ):
                with self.subTest(reference=reference):
                    valid, detail = ROADMAP._post_merge_evidence_result(
                        self.fixture.root, reference
                    )
                    self.assertFalse(valid)
                    self.assertIn("reference is unsafe", detail)
        snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
