from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "issue_lifecycle_test", ROOT / "scripts" / "issue_lifecycle.py"
)
assert SPEC and SPEC.loader
ISSUES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ISSUES)


class IssueLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.roadmap = yaml.safe_load(
            (ROOT / "config/contracts/roadmap-policy.yaml").read_text(encoding="utf-8")
        )
        self.tracker = {
            "number": 32, "category": "milestone-tracker",
            "milestone": "M2.5", "state": "open",
        }
        self.work_item = {
            "number": 170, "category": "work-item", "milestone": "M2.5",
            "tracker_issue": 32, "work_package_id": "m25-rke2-runtime",
            "state": "open",
        }
        self.package = {
            "id": "m25-rke2-runtime", "milestone": "M2.5",
            "tracker_issue": 32, "work_item_issue": 170,
            "execution": {"runtime_required": False, "recovery_required": False},
        }
        self.pr = {
            "number": 171, "work_item_issue": 170, "state": "OPEN",
            "base_sha": "a" * 40, "head_sha": "b" * 40,
        }
        self.package_validation = {
            "status": "VALID", "id": "m25-rke2-runtime",
        }

    def project(self, **overrides):
        values = {
            "roadmap": self.roadmap,
            "tracker_issue": self.tracker,
            "work_item_issue": self.work_item,
            "work_package": self.package,
            "pr": self.pr,
            "work_package_validation": self.package_validation,
        }
        values.update(overrides)
        return ISSUES.project_work_item(**values)

    def pass_proofs(self):
        head = self.pr["head_sha"]
        merge = "c" * 40
        self.pr.update(state="MERGED", merge_sha=merge)
        proof = {"status": "PASS", "head_sha": head}
        return {
            "qualification": dict(proof),
            "code_review": dict(proof),
            "security_review": dict(proof),
            "acceptance": {
                **proof,
                "authority": ISSUES.ACCEPTANCE_AUTHORITY,
                "head_tree_sha": "d" * 40,
                "historical_verification": "VERIFIED",
                "qualification_evidence_sha256": "sha256:" + "1" * 64,
                "work_package_id": self.package["id"],
                "milestone": self.package["milestone"],
                "work_item_issue": self.package["work_item_issue"],
                "gate_results": {"governance": "PASS"},
                "test_owners": {"tests/test_issue_lifecycle.py": "governance"},
                "contracts": {"config/contracts/roadmap-policy.yaml": "PRESENT"},
                "qce_capabilities": {},
                "errors": [],
            },
            "evidence_bundle": dict(proof),
            "post_merge": {
                **proof, "base_sha": self.pr["base_sha"],
                "merge_sha": merge, "merge_tree_sha": "d" * 40,
                "signature_verified": True, "main_contains_change": True,
                "qualified_tree_matches": True, "clean_worktree": True,
                "roadmap_sync": "PASS",
            },
        }

    def test_registered_policy_and_m25_tracker_are_exact(self):
        self.assertEqual("IssueLifecyclePolicy", ISSUES.load_policy()["kind"])
        self.assertEqual(32, ISSUES.tracker_for_milestone(self.roadmap, "M2.5"))
        self.assertEqual(
            "M2.5:m25-rke2-runtime",
            ISSUES.idempotency_key("M2.5", "m25-rke2-runtime"),
        )

    def test_policy_cannot_make_manual_issue_close_a_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ISSUES.POLICY_PATH
            path.parent.mkdir(parents=True)
            value = ISSUES.load_policy()
            value["completion"]["manual_issue_close_is_proof"] = True
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(ISSUES.IssueLifecycleError, "completion"):
                ISSUES.load_policy(Path(directory))

    def test_structured_hierarchy_rejects_missing_package_and_wrong_pr(self):
        self.assertEqual(
            [], ISSUES.validate_relations(
                self.roadmap, self.tracker, self.work_item, self.package, self.pr
            ),
        )
        self.assertIn(
            "work-item has no work package",
            ISSUES.validate_relations(
                self.roadmap, self.tracker, self.work_item, None, self.pr
            ),
        )
        wrong_pr = {**self.pr, "work_item_issue": 999}
        self.assertIn(
            "PR does not bind the exact primary work item and SHA",
            ISSUES.validate_relations(
                self.roadmap, self.tracker, self.work_item, self.package, wrong_pr
            ),
        )
        self.assertEqual("BLOCKED", self.project(work_package=None)["status"])

    def test_duplicate_tracker_in_roadmap_fails_closed(self):
        duplicate = copy.deepcopy(self.roadmap)
        next(item for item in duplicate["milestones"] if item["id"] == "M3")["tracker"] = 32
        with self.assertRaisesRegex(ISSUES.IssueLifecycleError, "multiple milestones"):
            ISSUES.tracker_for_milestone(duplicate, "M2.5")

    def test_planning_reuses_closed_issue_and_never_duplicates(self):
        existing = [{
            **self.work_item, "state": "closed",
        }]
        plan = ISSUES.plan_missing_work_items(
            self.roadmap, "M2.5",
            ["m25-rke2-runtime", "m25-deploy-mgmt"], existing,
        )
        self.assertEqual("PASS", plan["status"])
        self.assertEqual([170], [item["issue"] for item in plan["reused"]])
        self.assertEqual(["m25-deploy-mgmt"], [
            item["work_package_id"] for item in plan["missing"]
        ])
        duplicate = ISSUES.plan_missing_work_items(
            self.roadmap, "M2.5", ["m25-rke2-runtime"],
            [existing[0], {**existing[0], "number": 172}],
        )
        self.assertEqual("FAIL", duplicate["status"])
        self.assertEqual([], duplicate["missing"])
        self.assertIn("duplicate work-item", " ".join(duplicate["errors"]))

    def test_blocking_finding_never_becomes_follow_up(self):
        finding = {
            "pr": 171, "blocking": True,
            "outside_scope": True, "deferrable": True,
        }
        follow_up = {
            "number": 172, "category": "follow-up", "linked_pr": 171,
            "governance_decision": "decision-42",
        }
        self.assertIn(
            "blocking or unknown finding cannot become follow-up",
            ISSUES.validate_follow_up(finding, follow_up),
        )
        finding["blocking"] = False
        self.assertEqual([], ISSUES.validate_follow_up(finding, follow_up))
        follow_up["governance_decision"] = ""
        self.assertTrue(ISSUES.validate_follow_up(finding, follow_up))

    def test_defect_requires_work_outside_correcting_pr(self):
        finding = {"outside_correcting_pr": False}
        issue = {"number": 173, "category": "defect"}
        self.assertTrue(ISSUES.validate_defect(finding, issue))
        finding["outside_correcting_pr"] = True
        self.assertEqual([], ISSUES.validate_defect(finding, issue))

    def test_closed_tracker_and_manual_work_item_close_prove_nothing(self):
        self.tracker["state"] = "closed"
        self.work_item["state"] = "closed"
        result = self.project()
        self.assertEqual("BLOCKED", result["status"])
        self.assertIn("manual issue closure has no technical proof", result["errors"])
        self.work_item["state"] = "open"
        self.assertEqual("PR_OPEN", self.project()["status"])

    def test_code_pass_does_not_create_security_pass(self):
        head = self.pr["head_sha"]
        result = self.project(
            qualification={"status": "PASS", "head_sha": head},
            code_review={"status": "PASS", "head_sha": head},
        )
        self.assertEqual("QUALIFIED", result["status"])
        self.assertEqual("MISSING", result["proofs"]["security_review"])

    def test_old_head_proofs_are_superseded(self):
        old = {"status": "PASS", "head_sha": "e" * 40}
        result = self.project(
            qualification=old, code_review=old, security_review=old,
        )
        self.assertEqual("PR_OPEN", result["status"])
        self.assertEqual("SUPERSEDED", result["proofs"]["qualification"])
        self.assertEqual("SUPERSEDED", result["proofs"]["code_review"])
        self.assertEqual("SUPERSEDED", result["proofs"]["security_review"])

    def test_work_item_closes_only_after_exact_post_merge_and_acceptance(self):
        proofs = self.pass_proofs()
        self.tracker["state"] = "closed"
        self.assertEqual("VERIFIED", self.project(**proofs)["status"])
        self.work_item["state"] = "closed"
        self.assertEqual("CLOSED", self.project(**proofs)["status"])
        proofs["post_merge"]["signature_verified"] = False
        result = self.project(**proofs)
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual("FAIL", result["proofs"]["post_merge"])
        proofs["post_merge"]["signature_verified"] = True
        proofs["acceptance"]["head_sha"] = "f" * 40
        result = self.project(**proofs)
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual("SUPERSEDED", result["proofs"]["acceptance"])

    def test_runtime_and_recovery_proofs_are_required_when_declared(self):
        self.package["execution"] = {
            "runtime_required": True, "recovery_required": True,
        }
        proofs = self.pass_proofs()
        result = self.project(**proofs)
        self.assertEqual("MERGED", result["status"])
        self.assertEqual("MISSING", result["proofs"]["runtime"])
        proofs["runtime"] = {
            "status": "PASS", "head_sha": self.pr["head_sha"],
        }
        self.assertEqual("MERGED", self.project(**proofs)["status"])
        proofs["recovery"] = {
            "status": "PASS", "head_sha": self.pr["head_sha"],
        }
        self.assertEqual("VERIFIED", self.project(**proofs)["status"])

    def acceptance_inputs(self):
        package = copy.deepcopy(self.package)
        package["acceptance"] = {
            "contracts": ["config/contracts/roadmap-policy.yaml"],
            "qualification_gates": ["governance", "system"],
            "tests": [
                "tests/test_runtime_orchestration.py",
                "tests/test_issue_lifecycle.py",
            ],
            "qce_capabilities": [],
        }
        head = "b" * 40
        tree = "d" * 40
        qualification = {
            "status": "PASS",
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "head_sha": head,
            "head_tree_sha": tree,
            "gates": [
                {"gate": "governance", "status": "PASS"},
                {"gate": "system", "status": "PASS"},
            ],
            "historical_verification": {
                "status": "VERIFIED",
                "merge_sha": "c" * 40,
                "evidence_sha256": "sha256:" + "1" * 64,
                "bundle_digest": "sha256:" + "2" * 64,
            },
        }
        snapshot = {
            "authority": "git-qualified-head-snapshot",
            "head_sha": head,
            "tree_sha": tree,
            "paths": [
                "config/contracts/roadmap-policy.yaml",
                "config/work-packages/M2.5/m25-rke2-runtime.yaml",
                "tests/test_runtime_orchestration.py",
                "tests/test_issue_lifecycle.py",
            ],
            "qualification_policy": yaml.safe_load(
                (ROOT / "config/contracts/qualification-execution-policy.yaml")
                .read_text(encoding="utf-8")
            ),
            "roadmap_policy": yaml.safe_load(
                (ROOT / "config/contracts/roadmap-policy.yaml")
                .read_text(encoding="utf-8")
            ),
        }
        return package, qualification, snapshot

    def test_acceptance_derives_test_owners_and_required_gate_pass(self):
        package, qualification, snapshot = self.acceptance_inputs()
        result = ISSUES.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("b" * 40, result["head_sha"])
        self.assertEqual(
            {
                "tests/test_runtime_orchestration.py": "governance",
                "tests/test_issue_lifecycle.py": "system",
            },
            result["test_owners"],
        )
        self.assertEqual(
            {"governance": "PASS", "system": "PASS"},
            result["gate_results"],
        )
        self.assertEqual(
            "PASS", ISSUES.acceptance_proof_state(result, "b" * 40, package)
        )

    def test_premerge_acceptance_uses_exact_head_without_historical_witness(self):
        package, qualification, snapshot = self.acceptance_inputs()
        qualification.pop("historical_verification")
        premerge = ISSUES.derive_premerge_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("PASS", premerge["status"])
        self.assertEqual(
            ISSUES.PREMERGE_ACCEPTANCE_AUTHORITY, premerge["authority"]
        )
        self.assertEqual("NOT_APPLICABLE", premerge["historical_verification"])
        self.assertEqual(
            "FAIL", ISSUES.derive_work_package_acceptance(
                package, qualification, snapshot
            )["status"],
        )
        proofs = self.pass_proofs()
        proofs["acceptance"] = premerge
        self.assertEqual("MERGED", self.project(**proofs)["status"])
        qualification["gates"][1]["status"] = "SKIP"
        self.assertEqual(
            "FAIL", ISSUES.derive_premerge_acceptance(
                package, qualification, snapshot
            )["status"],
        )

    def test_qce_capability_requires_head_roadmap_paths_and_all_proof_gates(self):
        package, qualification, snapshot = self.acceptance_inputs()
        package["acceptance"]["qce_capabilities"] = ["exact-sha-qualification"]
        qualification["gates"].extend([
            {"gate": "contracts", "status": "PASS"},
            {"gate": "security", "status": "PASS"},
        ])
        snapshot["paths"].extend([
            "config/contracts/ci-evidence.yaml",
            "scripts/repoctl.py",
        ])
        for derive in (
            ISSUES.derive_premerge_acceptance,
            ISSUES.derive_work_package_acceptance,
        ):
            with self.subTest(derive=derive.__name__):
                result = derive(package, qualification, snapshot)
                self.assertEqual("PASS", result["status"])
                self.assertEqual(
                    {"exact-sha-qualification": "PASS"},
                    result["qce_capabilities"],
                )
                qualification["gates"][-1]["status"] = "SKIP"
                result = derive(package, qualification, snapshot)
                self.assertEqual("FAIL", result["status"])
                self.assertIn(
                    "QCE capability gate is not canonical PASS: "
                    "exact-sha-qualification -> security",
                    result["errors"],
                )
                qualification["gates"][-1]["status"] = "PASS"
                snapshot["paths"].remove("scripts/repoctl.py")
                result = derive(package, qualification, snapshot)
                self.assertEqual("FAIL", result["status"])
                self.assertIn(
                    "QCE implementation is absent from qualified Git HEAD: "
                    "exact-sha-qualification -> scripts/repoctl.py",
                    result["errors"],
                )
                snapshot["paths"].append("scripts/repoctl.py")

    def test_qce_runtime_or_unknown_capability_fails_closed(self):
        package, qualification, snapshot = self.acceptance_inputs()
        package["acceptance"]["qce_capabilities"] = ["exact-sha-qualification"]
        qualification["gates"].extend([
            {"gate": "contracts", "status": "PASS"},
            {"gate": "security", "status": "PASS"},
        ])
        snapshot["paths"].extend([
            "config/contracts/ci-evidence.yaml",
            "scripts/repoctl.py",
        ])
        roadmap = copy.deepcopy(snapshot["roadmap_policy"])
        snapshot["roadmap_policy"] = roadmap
        capability = next(
            entry for entries in roadmap["qce_traceability"]["capabilities"].values()
            for entry in entries if entry["id"] == "exact-sha-qualification"
        )
        capability["proof"] = {
            "kind": "runtime-execution",
            "evidence_path": ".context/evidence/qce-runtime.json",
        }
        result = ISSUES.derive_premerge_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn(
            "QCE capability has no verifiable qualification-gates proof: "
            "exact-sha-qualification",
            result["errors"],
        )
        package["acceptance"]["qce_capabilities"] = ["fabricated-capability"]
        result = ISSUES.derive_premerge_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn(
            "required QCE capability is absent from qualified RoadmapPolicy: "
            "fabricated-capability",
            result["errors"],
        )

    def test_acceptance_fails_for_unverified_or_skipped_gate(self):
        package, qualification, snapshot = self.acceptance_inputs()
        qualification["historical_verification"]["status"] = "UNVERIFIED"
        result = ISSUES.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn("historical exact qualification", " ".join(result["errors"]))
        qualification["historical_verification"]["status"] = "VERIFIED"
        qualification["gates"][1]["status"] = "SKIP"
        result = ISSUES.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn("required acceptance gate is not PASS: system", result["errors"])
        self.assertIn(
            "required test owner gate is not PASS: tests/test_issue_lifecycle.py -> system",
            result["errors"],
        )

    def test_acceptance_fails_for_wrong_head_missing_test_or_contract(self):
        package, qualification, snapshot = self.acceptance_inputs()
        snapshot["tree_sha"] = "e" * 40
        result = ISSUES.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn("qualified Git HEAD snapshot does not match qualification", result["errors"])
        snapshot["tree_sha"] = qualification["head_tree_sha"]
        snapshot["paths"].remove("tests/test_runtime_orchestration.py")
        snapshot["paths"].remove("config/contracts/roadmap-policy.yaml")
        result = ISSUES.derive_work_package_acceptance(
            package, qualification, snapshot
        )
        self.assertEqual("FAIL", result["status"])
        self.assertIn(
            "required test is absent from qualified Git HEAD: tests/test_runtime_orchestration.py",
            result["errors"],
        )
        self.assertIn(
            "required contract is absent from qualified Git HEAD: config/contracts/roadmap-policy.yaml",
            result["errors"],
        )

    def test_plain_pass_or_issue_label_cannot_close_work_item(self):
        proofs = self.pass_proofs()
        proofs["acceptance"] = {
            "status": "PASS", "head_sha": self.pr["head_sha"],
            "labels": ["accepted"],
        }
        self.assertEqual("MERGED", self.project(**proofs)["status"])
        self.work_item["state"] = "closed"
        self.assertEqual("BLOCKED", self.project(**proofs)["status"])

    def test_acceptance_reads_qualified_git_head_not_mutable_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                result = subprocess.run(
                    ["git", "-C", str(root), *args],
                    text=True, capture_output=True, check=True,
                )
                return result.stdout.strip()

            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            policy_path = root / "config/contracts/qualification-execution-policy.yaml"
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(yaml.safe_dump({
                "kind": "QualificationExecutionPolicy",
                "status": "enforced",
                "gates": {
                    "governance": {
                        "owned_tests": ["tests/test_runtime_orchestration.py"],
                    },
                    "system": {},
                },
            }), encoding="utf-8")
            roadmap_path = root / "config/contracts/roadmap-policy.yaml"
            roadmap_path.write_text(
                yaml.safe_dump({
                    "kind": "RoadmapPolicy",
                    "status": "enforced",
                    "qce_traceability": {"capabilities": {}},
                }),
                encoding="utf-8",
            )
            package, qualification, _snapshot = self.acceptance_inputs()
            package["acceptance"]["contracts"] = ["config/contracts/extra.yaml"]
            contract = root / "config/contracts/extra.yaml"
            contract.write_text("kind: ExtraContract\n", encoding="utf-8")
            package_path = root / "config/work-packages/M2.5/m25-rke2-runtime.yaml"
            package_path.parent.mkdir(parents=True)
            package_path.write_text(yaml.safe_dump(package), encoding="utf-8")
            for relative in package["acceptance"]["tests"]:
                test_path = root / relative
                test_path.parent.mkdir(parents=True, exist_ok=True)
                test_path.write_text("# test fixture\n", encoding="utf-8")
            git("add", ".")
            git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "qualified")
            head = git("rev-parse", "HEAD")
            snapshot = ISSUES.read_qualified_head_snapshot(root, head)
            qualification["head_sha"] = head
            qualification["head_tree_sha"] = snapshot["tree_sha"]
            result = ISSUES.derive_work_package_acceptance(
                package, qualification, snapshot
            )
            self.assertEqual("PASS", result["status"])
            contract.unlink()
            self.assertEqual(
                "PASS", ISSUES.derive_work_package_acceptance(
                    package, qualification,
                    ISSUES.read_qualified_head_snapshot(root, head),
                )["status"],
            )
            git("add", "-u")
            git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "remove contract")
            changed_head = git("rev-parse", "HEAD")
            changed_snapshot = ISSUES.read_qualified_head_snapshot(root, changed_head)
            qualification["head_sha"] = changed_head
            qualification["head_tree_sha"] = changed_snapshot["tree_sha"]
            result = ISSUES.derive_work_package_acceptance(
                package, qualification, changed_snapshot
            )
            self.assertEqual("FAIL", result["status"])
            self.assertIn(
                "required contract is absent from qualified Git HEAD: "
                "config/contracts/extra.yaml",
                result["errors"],
            )

    def test_wrong_merge_sha_cannot_verify(self):
        proofs = self.pass_proofs()
        proofs["post_merge"]["merge_sha"] = "f" * 40
        result = self.project(**proofs)
        self.assertEqual("MERGED", result["status"])
        self.assertEqual("FAIL", result["proofs"]["post_merge"])


    def github_pr_relation(self):
        path = "config/work-packages/M2.5/m25-rke2-runtime.yaml"
        issue_marker = {
            "category": "work-item",
            "milestone": "M2.5",
            "tracker_issue": 32,
            "work_package_id": "m25-rke2-runtime",
            "work_package_path": path,
        }
        issue = {
            "number": 170, "state": "open",
            "body": "<!-- ecommerce-work-item:v1 "
            + json.dumps(issue_marker, sort_keys=True) + " -->",
        }
        tracker = {"number": 32, "state": "open", "body": "M2.5 tracker"}
        pr = {
            "number": 171, "state": "open", "merged_at": None,
            "body": ISSUES.format_pr_work_item_marker(self.package),
            "head": {"sha": "b" * 40},
            "base": {"sha": "a" * 40},
        }
        return pr, issue, tracker

    def test_pr_marker_is_exact_and_preserves_single_primary_work_item(self):
        pr, issue, tracker = self.github_pr_relation()
        marker = ISSUES.parse_pr_work_item_marker(pr["body"])
        self.assertEqual(170, marker["work_item_issue"])
        self.assertEqual("M2.5", marker["milestone"])
        self.assertEqual(
            [], ISSUES.validate_pr_work_item_readback(
                self.roadmap, pr, issue, self.package, tracker
            ),
        )
        issue["labels"] = [{"name": "verified"}]
        issue["state"] = "closed"
        self.assertEqual(
            [], ISSUES.validate_pr_work_item_readback(
                self.roadmap, pr, issue, self.package, tracker
            ),
        )

    def test_pr_marker_rejects_missing_duplicate_and_unsafe_relations(self):
        pr, issue, tracker = self.github_pr_relation()
        for body in (
            "",
            pr["body"] + "\n" + pr["body"],
            pr["body"].replace("M2.5/m25-rke2-runtime.yaml", "M2.5/../x.yaml"),
            pr["body"].replace('"work_item_issue":170', '"work_item_issue":999'),
        ):
            with self.subTest(body=body):
                pr["body"] = body
                self.assertTrue(ISSUES.validate_pr_work_item_readback(
                    self.roadmap, pr, issue, self.package, tracker
                ))

    def test_pr_readback_checks_canonical_issue_tracker_and_merge_state(self):
        pr, issue, tracker = self.github_pr_relation()
        issue["number"] = 999
        self.assertTrue(ISSUES.validate_pr_work_item_readback(
            self.roadmap, pr, issue, self.package, tracker
        ))
        issue["number"] = 170
        tracker["number"] = 999
        self.assertTrue(ISSUES.validate_pr_work_item_readback(
            self.roadmap, pr, issue, self.package, tracker
        ))
        tracker["number"] = 32
        pr["state"] = "closed"
        errors = ISSUES.validate_pr_work_item_readback(
            self.roadmap, pr, issue, self.package, tracker
        )
        self.assertIn("GitHub PR state is inconsistent or closed without merge", errors)
        pr["merged_at"] = "2026-09-30T12:00:00Z"
        pr["merge_commit_sha"] = "c" * 40
        self.assertEqual([], ISSUES.validate_pr_work_item_readback(
            self.roadmap, pr, issue, self.package, tracker
        ))

    def test_live_pr_readback_rejects_invalid_package_without_network(self):
        from unittest import mock

        with mock.patch.object(ISSUES.subprocess, "run") as api:
            result = ISSUES.read_pr_work_item_relation(
                "gh", "owner/repo", 171, self.roadmap, None
            )
        self.assertEqual("FAIL", result["status"])
        self.assertEqual(None, result["head_sha"])
        api.assert_not_called()

    def test_live_pr_readback_only_gets_exact_pr_and_issue_relations(self):
        from unittest import mock

        pr, issue, tracker = self.github_pr_relation()
        responses = {
            "repos/owner/repo/pulls/171": pr,
            "repos/owner/repo/issues/170": issue,
            "repos/owner/repo/issues/32": tracker,
        }
        calls = []

        def api(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command, 0, json.dumps(responses[command[2]]), ""
            )

        with mock.patch.object(ISSUES.subprocess, "run", side_effect=api):
            result = ISSUES.read_pr_work_item_relation(
                "gh", "owner/repo", 171, self.roadmap, self.package
            )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("b" * 40, result["head_sha"])
        self.assertEqual("a" * 40, result["base_sha"])
        self.assertEqual(3, len(calls))
        self.assertTrue(all(command[:2] == ["gh", "api"] for command in calls))
        self.assertEqual(
            [
                "repos/owner/repo/pulls/171",
                "repos/owner/repo/issues/170",
                "repos/owner/repo/issues/32",
            ],
            [command[2] for command in calls],
        )


if __name__ == "__main__":
    unittest.main()
