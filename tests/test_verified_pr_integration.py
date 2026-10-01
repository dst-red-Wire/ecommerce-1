"""Repoctl PR completion requires independent post-merge proof."""

from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_verified_pr_integration_test", ROOT / "scripts/repoctl.py"
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)

import post_merge_verify

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40


class VerifiedPRIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".git").mkdir()
        for name, value in (("ROOT", self.root), ("CONTEXT", self.root / ".context")):
            patcher = mock.patch.object(REPOCTL, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def snapshot(self):
        return {
            "number": 171,
            "state": "MERGED",
            "merged": True,
            "merged_at": "2026-09-30T10:00:00Z",
            "head_sha": HEAD,
            "head_branch": "feat/verified-pr",
            "base": "main",
            "base_sha": BASE,
            "merge_commit_sha": MERGE,
        }

    def proof(self, **overrides):
        result = {
            "schema_version": 2,
            "kind": "PostMergeVerification",
            "status": "PASS",
            "pr": 171,
            "base_sha": BASE,
            "head_sha": HEAD,
            "head_tree_sha": "d" * 40,
            "qualification_identity": "e" * 64,
            "merge_sha": MERGE,
            "merge_tree_sha": "f" * 40,
            "recomputed_tree_sha": "f" * 40,
            "main_sha": MERGE,
            "merge_signature": {"status": "VERIFIED", "fingerprint": "1" * 40},
            "signature_verified": True,
            "main_contains_change": True,
            "qualified_tree_matches": True,
            "clean_worktree": True,
            "branch_cleanup": {"local": "DELETED", "remote": "DELETED"},
            "roadmap_sync": "PASS",
            "qualification_witness": {
                "evidence_sha256": "sha256:" + "2" * 64,
                "manifest_sha256": "sha256:" + "3" * 64,
            },
            "errors": [],
        }
        result.update(overrides)
        return result

    @staticmethod
    def git(*args):
        if args[:1] == ("status",):
            return ""
        if args[:2] == ("branch", "--show-current"):
            return "main"
        raise AssertionError(f"unexpected Git probe: {args}")

    def post_merge(self, *, proof, roadmap_check=0, issue_status="CLOSED"):
        snapshot = self.snapshot()
        result = REPOCTL._pr_loop_empty_result(171)
        result.update(head_sha=HEAD, head_branch=snapshot["head_branch"], base="main")
        output = io.StringIO()
        with (
            mock.patch.object(REPOCTL, "git", side_effect=self.git),
            mock.patch.object(
                REPOCTL, "run", return_value=subprocess.CompletedProcess(["git"], 0)
            ),
            mock.patch.object(REPOCTL, "branch_cleanup", return_value=0),
            mock.patch.object(REPOCTL, "_roadmap_followup_after_merge", return_value=0),
            mock.patch.object(REPOCTL, "roadmap_check", return_value=roadmap_check),
            mock.patch.object(REPOCTL, "_github_pr_snapshot", return_value=snapshot),
            mock.patch.object(
                REPOCTL,
                "pull_request_authority_evidence",
                return_value=({"code": {}, "security": {}}, {}),
            ),
            mock.patch(
                "issue_completion.complete_work_item",
                return_value={"status": issue_status, "issue": 170, "errors": []},
            ),
            mock.patch.object(
                post_merge_verify,
                "recover_post_merge_proof",
                side_effect=proof if isinstance(proof, Exception) else None,
                return_value=None if isinstance(proof, Exception) else proof,
            ) as recover_proof,
            contextlib.redirect_stdout(output),
        ):
            code = REPOCTL._pr_loop_post_merge(
                "gh", "owner/repo", snapshot, result, dry_run=False, json_output=True
            )
        return code, json.loads(output.getvalue()), recover_proof

    def test_pr_loop_refuses_done_when_signed_proof_is_missing(self):
        code, result, recover_proof = self.post_merge(
            proof=post_merge_verify.PostMergeError("signed proof missing")
        )
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PASS", result["merge_result"])
        self.assertEqual("FAIL", result["post_merge_result"])
        self.assertEqual("VERIFY_POST_MERGE", result["next_action"])
        recover_proof.assert_called_once_with(
            REPOCTL.ROOT,
            pr_number=171,
            snapshot=self.snapshot(),
        )

    def test_pr_loop_refuses_done_when_proof_reader_returns_fail(self):
        code, result, _ = self.post_merge(proof=self.proof(status="FAIL"))
        self.assertEqual(1, code)
        self.assertNotEqual("DONE", result["state"])
        self.assertNotEqual("PASS", result["post_merge_result"])

    def test_pr_loop_refuses_pass_with_unverified_signature_flag(self):
        code, result, _ = self.post_merge(proof=self.proof(signature_verified=False))
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("FAIL", result["post_merge_result"])
        self.assertEqual("VERIFY_POST_MERGE", result["next_action"])

    def test_pr_loop_refuses_done_when_roadmap_is_pending(self):
        code, result, recover_proof = self.post_merge(proof=self.proof(), roadmap_check=1)
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PENDING_ROADMAP_PR", result["roadmap_result"])
        self.assertEqual("PENDING", result["post_merge_result"])
        self.assertEqual("FIX_ROADMAP_SYNC", result["next_action"])
        recover_proof.assert_not_called()

    def test_pr_loop_refuses_done_when_work_item_close_is_unverified(self):
        code, result, _ = self.post_merge(proof=self.proof(), issue_status="BLOCKED")
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("CLOSE_WORK_ITEM", result["next_action"])
        self.assertEqual("PASS", result["post_merge_result"])
        self.assertEqual("BLOCKED", result["work_item_completion"]["status"])

    def test_pr_loop_done_requires_revalidated_signed_pass(self):
        code, result, recover_proof = self.post_merge(proof=self.proof())
        self.assertEqual(0, code)
        self.assertEqual("DONE", result["state"])
        self.assertEqual("PASS", result["post_merge_result"])
        self.assertEqual("NONE", result["next_action"])
        self.assertEqual(
            f".context/evidence/post-merge/{MERGE}.json",
            result["post_merge_evidence"],
        )
        recover_proof.assert_called_once()

    def finish_json(self, *, through_public_command):
        before = {"number": 171, "headRefOid": HEAD}
        after = {
            "state": "MERGED",
            "mergedAt": "2026-09-30T10:00:00Z",
            "headRefOid": HEAD,
            "mergeCommit": {"oid": MERGE},
        }

        def merged_without_post_merge_proof(_base):
            phases = REPOCTL._FINISH_PR_PHASES.get()
            self.assertIsNotNone(phases)
            phases["cleanup_result"] = "PASS"
            phases["roadmap_result"] = "PASS"
            return 0

        original_finish = REPOCTL.finish_pr

        def dispatch(base, *, json_output=False):
            if json_output:
                return original_finish(base, json_output=True)
            return merged_without_post_merge_proof(base)

        output = io.StringIO()
        with (
            mock.patch.object(REPOCTL.shutil, "which", return_value="gh"),
            mock.patch.object(REPOCTL, "git", return_value=HEAD),
            mock.patch.object(
                REPOCTL, "output", side_effect=[json.dumps(before), json.dumps(after)]
            ),
            mock.patch.object(
                REPOCTL,
                "finish_pr",
                side_effect=dispatch
                if through_public_command
                else merged_without_post_merge_proof,
            ),
            contextlib.redirect_stdout(output),
        ):
            code = (
                REPOCTL.finish_pr("main", json_output=True)
                if through_public_command
                else REPOCTL._finish_pr_json("main")
            )
        return code, json.loads(output.getvalue())

    def test_finish_pr_json_refuses_success_from_github_merged_alone(self):
        code, result = self.finish_json(through_public_command=False)
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PASS", result["merge_result"])
        self.assertEqual("PASS", result["cleanup_result"])
        self.assertEqual("PASS", result["roadmap_result"])
        self.assertEqual("NOT_ATTEMPTED", result["post_merge_result"])
        self.assertEqual("VERIFY_POST_MERGE", result["next_action"])

    def test_public_finish_pr_json_refuses_success_without_post_merge_result(self):
        code, result = self.finish_json(through_public_command=True)
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PASS", result["merge_result"])
        self.assertEqual("NOT_ATTEMPTED", result["post_merge_result"])
        self.assertNotEqual("DONE", result["state"])


class RiskEvidenceGateTests(unittest.TestCase):
    def setUp(self):
        import evidence_bundle
        import runtime_authority

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".git").mkdir()
        # Keep real lock acquisition inside the fixture. Qualification itself
        # may already hold the canonical workspace's PR transition lock.
        for name, value in (("ROOT", self.root), ("CONTEXT", self.root / ".context")):
            patcher = mock.patch.object(REPOCTL, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.runtime_path = runtime_authority._LAB_PATH
        path = self.root / self.runtime_path
        path.parent.mkdir(parents=True)
        path.write_text("{}\n", encoding="utf-8")
        self.runtime_digest = evidence_bundle.digest_file(path)
        self.manifest = {
            "runtime_evidence": [
                {"path": self.runtime_path, "sha256": self.runtime_digest}
            ],
        }
        self.manifest_path = self.root / f".context/evidence/{HEAD}/manifest.json"
        self.manifest_path.parent.mkdir(parents=True)
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.digest = evidence_bundle.digest_file(self.manifest_path)
        self.bundle = {
            "status": "PASS",
            "manifest": str(self.manifest_path.relative_to(self.root)),
            "manifest_digest": self.digest,
        }
        self.package = {
            "milestone": "M2.5",
            "execution": {"runtime_required": True, "recovery_required": True},
            "acceptance": {"runtime_evidence": [self.runtime_path]},
        }
        self.work_item = {
            "work_package": "config/work-packages/M2.5/fixture.yaml",
            "work_item_issue": 170,
            "milestone": "M2.5",
        }

    def risk(self, classification):
        return REPOCTL._merge_risk_result(
            classification,
            base_sha=BASE,
            head_sha=HEAD,
            pr_number=171,
            changed_files=["platform/ansible/production.yml"],
            reasons=["runtime"],
            matched_capabilities=["production"],
            analysis_complete=True,
        )

    def gate(self, classification, *, verdict=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(REPOCTL, "ROOT", self.root))
            stack.enter_context(
                mock.patch.object(REPOCTL, "git", return_value="d" * 40)
            )
            stack.enter_context(
                mock.patch.object(
                    REPOCTL,
                    "_delivery_package_input",
                    return_value=(
                        self.package,
                        {"status": "VALID"},
                        self.root / "package.yaml",
                    ),
                )
            )
            stack.enter_context(
                mock.patch(
                    "evidence_bundle.verify_bundle",
                    return_value={
                        "status": "PASS",
                        "manifest_digest": self.digest,
                    },
                )
            )
            if verdict is not None:
                stack.enter_context(
                    mock.patch(
                        "runtime_authority.verify_runtime_proof", return_value=verdict
                    )
                )
            return REPOCTL._delivery_risk_evidence_gate(
                BASE,
                HEAD,
                self.risk(classification),
                self.work_item,
                self.bundle,
            )

    def verdict(self):
        # A mocked future producer verdict tests consumer validation only. The
        # current real producer explicitly refuses capture/restore authority.
        return {
            "status": "PASS",
            "producer": "fixture:validate",
            "environment": "lab",
            "head_sha": HEAD,
            "head_tree_sha": "d" * 40,
            "evidence_path": self.runtime_path,
            "evidence_digest": self.runtime_digest,
            "recovery": {
                "capture": "PASS",
                "restore": "PASS",
                "restore_verification": "PASS",
            },
        }

    def test_risk_rejects_flags_that_attempt_to_remove_runtime_or_recovery(self):
        for classification in ("PRIVILEGED", "PRODUCTION"):
            for missing in ("runtime_required", "recovery_required"):
                with self.subTest(classification=classification, missing=missing):
                    self.package["execution"][missing] = False
                    with self.assertRaisesRegex(
                        RuntimeError, "runtime_required=true and recovery_required=true"
                    ):
                        self.gate(classification)
                    self.package["execution"][missing] = True

    def test_real_producer_cannot_issue_recovery_even_with_all_flags_enabled(self):
        for classification in ("PRIVILEGED", "PRODUCTION"):
            with (
                self.subTest(classification=classification),
                self.assertRaisesRegex(
                    RuntimeError,
                    "capture, restore and restore verification are unavailable",
                ),
            ):
                self.gate(classification)

    def test_production_rejects_host_or_lab_runtime_producer(self):
        for environment in ("lab", "host", None):
            with self.subTest(environment=environment):
                verdict = self.verdict()
                verdict["environment"] = environment
                with self.assertRaisesRegex(RuntimeError, "production producer"):
                    self.gate("PRODUCTION", verdict=verdict)

    def test_missing_recovery_phase_and_wrong_bundled_digest_block_privileged(self):
        for phase in ("capture", "restore", "restore_verification"):
            with self.subTest(phase=phase):
                verdict = self.verdict()
                verdict["recovery"][phase] = "FAIL"
                with self.assertRaisesRegex(RuntimeError, "producer-verified capture"):
                    self.gate("PRIVILEGED", verdict=verdict)
        verdict = self.verdict()
        verdict["evidence_digest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(RuntimeError, "bundled bytes"):
            self.gate("PRIVILEGED", verdict=verdict)

    def test_changed_bundle_and_absent_runtime_reference_are_rejected(self):
        original = self.manifest_path.read_bytes()
        self.manifest_path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(RuntimeError, "bundle changed"):
            self.gate("PRIVILEGED")
        self.manifest_path.write_bytes(original)
        self.package["acceptance"]["runtime_evidence"] = [".context/unbundled.json"]
        with self.assertRaisesRegex(RuntimeError, "absent from exact bundle"):
            self.gate("PRIVILEGED")

    def test_low_and_sensitive_keep_the_contract_driven_bundle_boundary(self):
        for classification in ("LOW_RISK", "SENSITIVE"):
            with (
                self.subTest(classification=classification),
                mock.patch("runtime_authority.verify_runtime_proof") as producer,
            ):
                result = REPOCTL._delivery_risk_evidence_gate(
                    BASE,
                    HEAD,
                    self.risk(classification),
                    {},
                    {},
                )
                self.assertEqual("PASS", result["status"])
                self.assertEqual("CONTRACT_DRIVEN", result["runtime"])
                producer.assert_not_called()

    def test_isolated_pr_loop_preserves_real_lock_exclusion(self):
        stream = io.StringIO()
        with (
            REPOCTL._pr_sync_lock_path().open("w") as held_lock,
            mock.patch.object(REPOCTL, "_pr_loop_impl_locked") as transition,
            contextlib.redirect_stdout(stream),
        ):
            fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code = REPOCTL.pr_loop(171, json_output=True)
        result = json.loads(stream.getvalue())
        self.assertEqual(1, code)
        self.assertEqual("SYNC_BUSY", result["state"])
        self.assertEqual("RETRY_SYNC_PR_BASE", result["next_action"])
        self.assertEqual("NOT_ATTEMPTED", result["merge_result"])
        transition.assert_not_called()

    def test_pr_loop_owner_pass_cannot_bypass_privileged_or_production_evidence(self):
        snapshot = {
            "number": 171,
            "state": "OPEN",
            "draft": False,
            "head_sha": HEAD,
            "head_branch": "feat/verified-pr",
            "base": "main",
            "base_sha": BASE,
            "merge_commit_sha": "",
            "merged": False,
            "head_repository": "owner/repo",
        }
        reviews = {
            kind: {
                "provider": "ChatGPT",
                "kind": kind,
                "status": "PASS",
                "blocking_findings": 0,
                "head_sha": HEAD,
            }
            for kind in ("code", "security")
        }
        self.package["execution"] = {
            "runtime_required": False,
            "recovery_required": False,
        }
        for classification in ("PRIVILEGED", "PRODUCTION"):
            for dry_run in (False, True):
                with self.subTest(classification=classification, dry_run=dry_run):
                    stream = io.StringIO()
                    with (
                        mock.patch.object(REPOCTL.shutil, "which", return_value="gh"),
                        mock.patch.multiple(
                            REPOCTL,
                            repository_delivery_policy=mock.Mock(
                                return_value={
                                    "pr_loop": {"state_persistence": "forbidden"}
                                }
                            ),
                            _github_repository_identity=mock.Mock(
                                return_value=("owner", "owner/repo")
                            ),
                            _github_pr_snapshot=mock.Mock(return_value=snapshot),
                            _pr_loop_checkout_errors=mock.Mock(return_value=[]),
                            _remote_ref_sha=mock.Mock(return_value=BASE),
                            _pr_loop_current_base=mock.Mock(return_value=snapshot),
                            _pr_loop_qualification=mock.Mock(
                                return_value={"status": "PASS", "head_sha": HEAD}
                            ),
                            classify_merge_risk=mock.Mock(
                                return_value=self.risk(classification)
                            ),
                            pull_request_authority_evidence=mock.Mock(
                                return_value=(
                                    reviews,
                                    {"status": "PASS", "head_sha": HEAD},
                                )
                            ),
                            _delivery_pr_work_item_preflight=mock.Mock(
                                return_value={
                                    **self.work_item,
                                    "status": "PASS",
                                    "reason": "",
                                    "preflight": {"status": "PASS"},
                                }
                            ),
                            _delivery_exact_bundle_gate=mock.Mock(
                                return_value=self.bundle
                            ),
                            _delivery_package_input=mock.Mock(
                                return_value=(
                                    self.package,
                                    {"status": "VALID"},
                                    self.root / "package.yaml",
                                )
                            ),
                            _require_trusted_pr_execution=mock.Mock(
                                return_value={
                                    "trusted_root": Path("/trusted/base"),
                                    "target_root": self.root,
                                    "base_sha": BASE,
                                }
                            ),
                            run=mock.Mock(
                                return_value=subprocess.CompletedProcess([], 0, "", "")
                            ),
                        ),
                        mock.patch.object(REPOCTL, "finish_pr") as finish,
                        contextlib.redirect_stdout(stream),
                    ):
                        code = REPOCTL.pr_loop(171, json_output=True, dry_run=dry_run)
                    result = json.loads(stream.getvalue())
                    self.assertEqual(1, code)
                    self.assertEqual("BLOCKED", result["state"])
                    self.assertEqual("NOT_ATTEMPTED", result["merge_result"])
                    self.assertIn("runtime_required=true", " ".join(result["blockers"]))
                    finish.assert_not_called()


class NativeRecoveryRiskPolicyTests(unittest.TestCase):
    def test_windows_native_changes_keep_privileged_capture_restore_gate(self):
        import merge_risk
        import yaml

        document = yaml.safe_load(
            (ROOT / "config/contracts/review-policy.yaml").read_text(encoding="utf-8")
        )
        policy = document["repository_delivery"]["pr_loop"]["risk_classification"]
        path = "scripts/windows/LabNativeBoot.ps1"
        result = merge_risk.evaluate_merge_risk(
            policy, base_sha=BASE, head_sha=HEAD, pr_number=181,
            changed_files=[path], file_changes={path: "record native recovery observations"},
        )
        self.assertEqual("PRIVILEGED", result["classification"], result)
        self.assertEqual("exact-pr-base-sha", result["controller_source"])
        self.assertEqual("exact-pr-base-sha", result["policy_source"])
        self.assertIn("host-mutation", result["matched_capabilities"])
        requirements = {
            "owner_authorization": "explicit-repository-owner",
            "review_depth": "privileged",
            "runtime_evidence": "host-runtime-before-mutation",
            "recovery": "capture-restore-verify",
        }
        self.assertEqual(requirements, result["requirements"])
        self.assertEqual(requirements, REPOCTL._RISK_CLASS_REQUIREMENTS["PRIVILEGED"])
        execution = yaml.safe_load(
            (ROOT / "config/contracts/execution-properties-policy.yaml").read_text(encoding="utf-8")
        )
        recovery = execution["properties"]["recovery"]
        self.assertEqual("required", recovery["capture_before_mutation"])
        self.assertEqual("required", recovery["restore_on_failure"])
        self.assertEqual("required", recovery["restore_verification"])
        self.assertEqual(
            ["recovery.capture", "recovery.restore", "recovery.restore_verification"],
            recovery["proof_fields"],
        )
        self.assertEqual("PASS", recovery["proof_success_status"])


if __name__ == "__main__":
    unittest.main()
