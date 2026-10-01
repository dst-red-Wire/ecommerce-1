"""Delivery primitives keep qualification, merge, and issue closure independent."""

from __future__ import annotations

import contextlib
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
    "repoctl_delivery_witness_bootstrap_test", ROOT / "scripts/repoctl.py"
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)

import evidence_bundle
import post_merge_verify

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40


class BootstrapPostMergeTests(unittest.TestCase):
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
        code, result, recover_proof = self.post_merge(
            proof=self.proof(), roadmap_check=1
        )
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PENDING_ROADMAP_PR", result["roadmap_result"])
        self.assertEqual("PENDING", result["post_merge_result"])
        self.assertEqual("FIX_ROADMAP_SYNC", result["next_action"])
        recover_proof.assert_not_called()

    def test_pr_loop_refuses_done_when_work_item_close_is_unverified(self):
        code, result, _ = self.post_merge(proof=self.proof(), issue_status="BLOCKED")
        self.assertEqual(1, code)
        self.assertEqual("VERIFIED", result["state"])
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

    def test_recovery_command_requires_fresh_merged_snapshot(self):
        snapshot = self.snapshot()
        output = io.StringIO()
        with (
            mock.patch.object(REPOCTL.shutil, "which", return_value="gh"),
            mock.patch.object(
                REPOCTL,
                "_github_repository_identity",
                return_value=("owner", "owner/repo"),
            ),
            mock.patch.object(REPOCTL, "_github_pr_snapshot", return_value=snapshot),
            mock.patch.object(
                post_merge_verify, "recover_post_merge_proof", return_value=self.proof()
            ) as recovery,
            contextlib.redirect_stdout(output),
        ):
            code = REPOCTL.post_merge_verify_command(171)
        self.assertEqual(0, code)
        self.assertEqual("PASS", json.loads(output.getvalue())["status"])
        recovery.assert_called_once_with(self.root, pr_number=171, snapshot=snapshot)

    def test_recovery_command_failure_never_reports_pass(self):
        output = io.StringIO()
        with (
            mock.patch.object(REPOCTL.shutil, "which", return_value="gh"),
            mock.patch.object(
                REPOCTL,
                "_github_repository_identity",
                return_value=("owner", "owner/repo"),
            ),
            mock.patch.object(
                REPOCTL, "_github_pr_snapshot", return_value=self.snapshot()
            ),
            mock.patch.object(
                post_merge_verify,
                "recover_post_merge_proof",
                side_effect=post_merge_verify.PostMergeError("signed witness missing"),
            ),
            contextlib.redirect_stdout(output),
        ):
            code = REPOCTL.post_merge_verify_command(171)
        self.assertNotEqual(0, code)
        self.assertNotEqual("PASS", json.loads(output.getvalue())["status"])

    def test_proof_for_other_pr_head_or_merge_never_completes(self):
        for field, wrong in (
            ("pr", 172),
            ("head_sha", "9" * 40),
            ("merge_sha", "8" * 40),
        ):
            with self.subTest(field=field):
                code, result, _ = self.post_merge(proof=self.proof(**{field: wrong}))
                self.assertNotEqual(0, code)
                self.assertEqual("FAIL", result["post_merge_result"])
                self.assertNotEqual("DONE", result["state"])


class BootstrapFinishWitnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q", "-b", "fix/witness-bootstrap")
        self.git("config", "user.name", "Delivery Test")
        self.git("config", "user.email", "delivery@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        lock = self.root / "config/contracts/toolchain-lock.json"
        lock.parent.mkdir(parents=True)
        lock.write_text("{}\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "base fixture")
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        (self.root / "change.txt").write_text("qualified change\n", encoding="utf-8")
        self.git("add", "change.txt")
        self.git("commit", "-qm", "qualified fixture")
        self.head = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.context = self.root / ".context"
        self.raw = self.context / "evidence" / f"{self.head}.json"
        self.audit = self.context / "performance" / f"{self.head}.json"
        archive = self.context / "evidence/controller-compatibility/v1"
        self.archived_raw = archive / "raw" / self.head / "proof.json"
        self.archived_audit = archive / "audit" / self.head / "audit.json"
        self.final_payload = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_sha": self.base,
            "head_sha": self.head,
            "head_tree_sha": self.tree,
            "qualification_identity": "d" * 64,
            "created_at_epoch": 2,
        }
        self.write_artifacts({**self.final_payload, "created_at_epoch": 1})
        self.events = []
        self.issue_number = 175
        self.branch = "fix/witness-bootstrap"
        self.bundle_digest = None
        for name, value in (("ROOT", self.root), ("CONTEXT", self.context)):
            patcher = mock.patch.object(REPOCTL, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def git(self, *args):
        result = subprocess.run(
            ["git", *args],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def write_artifacts(self, qualification):
        for path, payload in (
            (self.raw, qualification),
            (self.archived_raw, qualification),
            (
                self.audit,
                {"head_sha": self.head, "base_sha": self.base, "status": "PASS"},
            ),
            (
                self.archived_audit,
                {"head_sha": self.head, "base_sha": self.base, "status": "PASS"},
            ),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(evidence_bundle.canonical_bytes(payload))

    def snapshot(self):
        merged = "merge" in self.events
        return {
            "number": self.issue_number,
            "state": "MERGED" if merged else "OPEN",
            "merged": merged,
            "merged_at": "2026-10-01T00:00:00Z" if merged else None,
            "draft": False,
            "head_sha": self.head,
            "head_branch": self.branch,
            "base": "main",
            "base_sha": self.base,
            "merge_commit_sha": MERGE if merged else "",
        }

    def run_finish(
        self,
        *,
        mutate=None,
        witness_error=None,
        post_error=None,
        bundle_error=None,
        during_bundle=None,
        witness_digests=None,
    ):
        def fresh(*_args):
            self.events.append("qualification")
            self.write_artifacts(self.final_payload)
            if mutate:
                mutate()

        def run(argv, **_kwargs):
            if argv[:3] == ["gh", "pr", "merge"]:
                self.events.append("merge")
                self.assertIn("witness", self.events)
                self.assertEqual(self.head, argv[argv.index("--match-head-commit") + 1])
            code = (
                2
                if argv[:2] == ["git", "ls-remote"]
                else 1
                if argv[:2] == ["git", "show-ref"]
                else 0
            )
            return subprocess.CompletedProcess(argv, code, stdout="", stderr="")

        def witness(root, *, pr_number, snapshot, qualification):
            self.events.append("witness")
            self.assertNotIn("merge", self.events)
            self.assertEqual(self.final_payload, qualification)
            self.assertEqual(self.snapshot(), snapshot)
            self.assertEqual(self.issue_number, pr_number)
            verified = evidence_bundle.verify_bundle(
                root,
                self.head,
                expected_identity={
                    "base_sha": self.base,
                    "head_sha": self.head,
                    "tree_sha": self.tree,
                    "qualification_identity": self.final_payload[
                        "qualification_identity"
                    ],
                },
            )
            self.bundle_digest = verified["manifest_digest"]
            if witness_error:
                raise witness_error
            destination = self.context / "evidence/pre-merge/witness.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": 1,
                "kind": "PreMergeQualificationWitness",
                "pr": pr_number,
                "base_sha": self.base,
                "head_sha": self.head,
                "head_tree_sha": self.tree,
                "qualification_identity": qualification["qualification_identity"],
                "evidence_sha256": evidence_bundle.digest_file(self.raw),
                "manifest_sha256": verified["manifest_digest"],
            }
            payload.update(witness_digests or {})
            destination.write_bytes(evidence_bundle.canonical_bytes(payload))
            return destination

        def post_proof(root, *, pr_number, snapshot, qualification):
            self.events.append("post-proof")
            self.assertIn("merge", self.events)
            self.assertIn("cleanup", self.events)
            self.assertTrue(snapshot["merged"])
            self.assertEqual(self.final_payload, qualification)
            self.assertEqual(self.issue_number, pr_number)
            self.assertEqual(self.root, root)
            if post_error:
                raise post_error
            return self.context / "evidence/post-merge" / f"{MERGE}.json"

        def metadata(*_args):
            value = self.snapshot()
            return {**value, "is_draft": False, "base_ref": "main"}

        reviews = {
            kind: {"status": "PASS", "blocking_findings": 0, "head_sha": self.head}
            for kind in ("code", "security")
        }
        patches = {
            "git": mock.Mock(side_effect=self.git),
            "run": mock.Mock(side_effect=run),
            "_require_trusted_pr_execution": mock.Mock(
                return_value={"trusted_root": self.root}
            ),
            "toolchain_closure": mock.Mock(return_value=0),
            "repository_delivery_policy": mock.Mock(
                return_value={"default_branch": "main", "merge": {"method": "merge"}}
            ),
            "_github_repository_identity": mock.Mock(
                return_value=("owner", "owner/repo")
            ),
            "_remote_ref_sha": mock.Mock(return_value=self.head),
            "commit_provenance_check": mock.Mock(return_value=0),
            "remote_commit_provenance_check": mock.Mock(return_value=0),
            "_fresh_qualification_for_finish": mock.Mock(side_effect=fresh),
            "_pr_loop_qualification": mock.Mock(
                return_value={
                    "status": "PASS",
                    "compatibility_digest": "sha256:" + "e" * 64,
                    "evidence": str(self.archived_raw.relative_to(self.root)),
                    "performance_audit": str(
                        self.archived_audit.relative_to(self.root)
                    ),
                }
            ),
            "_valid_exact_evidence": mock.Mock(
                side_effect=lambda _base, _head, *, evidence_path=None: (
                    evidence_path or self.raw
                )
            ),
            "_valid_performance_audit": mock.Mock(
                side_effect=lambda _base, _head, *, audit_path=None: (
                    audit_path or self.audit
                )
            ),
            "_qualification_audit_path": mock.Mock(return_value=self.audit),
            "qualification_workflow": mock.Mock(
                return_value={"merge_authoritative": True, "performance_audit_runs": 1}
            ),
            "output": mock.Mock(
                return_value=json.dumps(
                    [{"number": self.issue_number, "url": "https://example.invalid/pr"}]
                )
            ),
            "github_pull_request_metadata": mock.Mock(side_effect=metadata),
            "chatgpt_review_readiness": mock.Mock(return_value=(True, "exact reviews")),
            "pull_request_authority_evidence": mock.Mock(
                return_value=(reviews, {"status": "PASS"})
            ),
            "_github_pr_snapshot": mock.Mock(
                side_effect=lambda *_args: self.snapshot()
            ),
            "classify_merge_risk": mock.Mock(
                return_value={"classification": "SENSITIVE"}
            ),
            "_github_unresolved_review_threads": mock.Mock(return_value=0),
            "_github_branch_protection_status": mock.Mock(
                return_value=(True, "protected")
            ),
            "_github_required_checks_status": mock.Mock(return_value=(True, "checked")),
            "_finish_pr_post_merge_tasks": mock.Mock(
                side_effect=lambda: (self.events.append("cleanup") or 0, 0)
            ),
        }
        create_bundle = evidence_bundle.create_bundle

        def create_after_replacement(*args, **kwargs):
            during_bundle()
            return create_bundle(*args, **kwargs)

        with contextlib.ExitStack() as stack:
            for name, replacement in patches.items():
                stack.enter_context(mock.patch.object(REPOCTL, name, replacement))
            stack.enter_context(
                mock.patch.object(REPOCTL.shutil, "which", return_value="gh")
            )
            stack.enter_context(
                mock.patch.object(
                    post_merge_verify, "write_pre_merge_witness", side_effect=witness
                )
            )
            stack.enter_context(
                mock.patch.object(
                    post_merge_verify, "write_post_merge_proof", side_effect=post_proof
                )
            )
            if bundle_error:
                stack.enter_context(
                    mock.patch.object(
                        evidence_bundle, "create_bundle", side_effect=bundle_error
                    )
                )
            elif during_bundle:
                stack.enter_context(
                    mock.patch.object(
                        evidence_bundle,
                        "create_bundle",
                        side_effect=create_after_replacement,
                    )
                )
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return REPOCTL.finish_pr("main")

    def test_final_base_qualification_is_bundled_before_signed_witness_and_merge(self):
        stale = evidence_bundle.create_bundle(
            self.root,
            base_sha=self.base,
            head_sha=self.head,
            tree_sha=self.tree,
            qualification_identity=self.final_payload["qualification_identity"],
            toolchain_digest=evidence_bundle.digest_file(
                self.root / "config/contracts/toolchain-lock.json"
            ),
            gate_evidence=[str(self.audit.relative_to(self.root))],
        )
        self.assertEqual(0, self.run_finish())
        self.assertEqual(
            ["qualification", "witness", "merge", "cleanup", "post-proof"], self.events
        )
        self.assertNotEqual(stale["manifest_digest"], self.bundle_digest)
        manifest = evidence_bundle._read_json(
            self.root / f".context/evidence/{self.head}/manifest.json"
        )
        self.assertEqual(
            evidence_bundle.digest_file(self.raw),
            manifest["evidence_digests"][str(self.raw.relative_to(self.root))],
        )
        self.assertEqual(
            evidence_bundle.digest_file(self.audit),
            manifest["evidence_digests"][str(self.audit.relative_to(self.root))],
        )

    def test_missing_canonical_qualification_blocks_before_witness_or_merge(self):
        self.assertNotEqual(0, self.run_finish(mutate=self.raw.unlink))
        self.assertEqual(["qualification"], self.events)

    def test_canonical_qualification_must_match_base_archive(self):
        self.assertNotEqual(
            0,
            self.run_finish(
                mutate=lambda: self.raw.write_text("{}\n", encoding="utf-8")
            ),
        )
        self.assertEqual(["qualification"], self.events)

    def test_canonical_audit_must_match_base_archive(self):
        self.assertNotEqual(
            0,
            self.run_finish(
                mutate=lambda: self.audit.write_text("{}\n", encoding="utf-8")
            ),
        )
        self.assertEqual(["qualification"], self.events)

    def test_bundle_failure_blocks_before_witness_or_merge(self):
        self.assertNotEqual(
            0,
            self.run_finish(
                bundle_error=evidence_bundle.EvidenceBundleError("bundle corrupt")
            ),
        )
        self.assertEqual(["qualification"], self.events)

    def test_witness_signature_failure_blocks_merge(self):
        self.assertNotEqual(
            0,
            self.run_finish(
                witness_error=post_merge_verify.PostMergeError("signature unavailable")
            ),
        )
        self.assertEqual(["qualification", "witness"], self.events)

    def test_replacement_during_bundle_cannot_change_captured_raw_or_audit(self):
        for path in (self.raw, self.audit):
            with self.subTest(artifact=str(path.relative_to(self.root))):
                self.events.clear()

                def replace(artifact=path):
                    payload = json.loads(artifact.read_bytes())
                    payload["created_at_epoch"] = 3
                    artifact.write_bytes(evidence_bundle.canonical_bytes(payload))

                self.assertNotEqual(0, self.run_finish(during_bundle=replace))
                self.assertEqual(["qualification"], self.events)

    def test_returned_witness_cannot_change_qualification_or_manifest_digest(self):
        for field in ("evidence_sha256", "manifest_sha256"):
            with self.subTest(field=field):
                self.events.clear()
                self.assertNotEqual(
                    0,
                    self.run_finish(witness_digests={field: "sha256:" + "9" * 64}),
                )
                self.assertEqual(["qualification", "witness"], self.events)

    def test_post_merge_proof_failure_does_not_report_completion(self):
        self.assertNotEqual(
            0,
            self.run_finish(
                post_error=post_merge_verify.PostMergeError("post-merge proof failed")
            ),
        )
        self.assertEqual(
            ["qualification", "witness", "merge", "cleanup", "post-proof"], self.events
        )


if __name__ == "__main__":
    unittest.main()
