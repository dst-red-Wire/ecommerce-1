"""Repoctl PR completion requires independent post-merge proof."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
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
    def snapshot(self):
        return {
            "number": 171, "state": "MERGED", "merged": True,
            "merged_at": "2026-09-30T10:00:00Z", "head_sha": HEAD,
            "head_branch": "feat/verified-pr", "base": "main",
            "base_sha": BASE, "merge_commit_sha": MERGE,
        }

    def proof(self, **overrides):
        result = {
            "schema_version": 2, "kind": "PostMergeVerification",
            "status": "PASS", "pr": 171, "base_sha": BASE,
            "head_sha": HEAD, "head_tree_sha": "d" * 40,
            "qualification_identity": "e" * 64, "merge_sha": MERGE,
            "merge_tree_sha": "f" * 40, "recomputed_tree_sha": "f" * 40,
            "main_sha": MERGE,
            "merge_signature": {"status": "VERIFIED", "fingerprint": "1" * 40},
            "signature_verified": True, "main_contains_change": True,
            "qualified_tree_matches": True, "clean_worktree": True,
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
            mock.patch.object(REPOCTL, "run",
                              return_value=subprocess.CompletedProcess(["git"], 0)),
            mock.patch.object(REPOCTL, "branch_cleanup", return_value=0),
            mock.patch.object(REPOCTL, "_roadmap_followup_after_merge", return_value=0),
            mock.patch.object(REPOCTL, "roadmap_check", return_value=roadmap_check),
            mock.patch.object(REPOCTL, "_github_pr_snapshot", return_value=snapshot),
            mock.patch.object(
                REPOCTL, "pull_request_authority_evidence",
                return_value=({"code": {}, "security": {}}, {}),
            ),
            mock.patch(
                "issue_completion.complete_work_item",
                return_value={"status": issue_status, "issue": 170, "errors": []},
            ),
            mock.patch.object(
                post_merge_verify, "read_post_merge_proof",
                side_effect=proof if isinstance(proof, Exception) else None,
                return_value=None if isinstance(proof, Exception) else proof,
            ) as read_proof,
            contextlib.redirect_stdout(output),
        ):
            code = REPOCTL._pr_loop_post_merge(
                "gh", "owner/repo", snapshot, result, dry_run=False, json_output=True
            )
        return code, json.loads(output.getvalue()), read_proof

    def test_pr_loop_refuses_done_when_signed_proof_is_missing(self):
        code, result, read_proof = self.post_merge(
            proof=post_merge_verify.PostMergeError("signed proof missing")
        )
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PASS", result["merge_result"])
        self.assertEqual("FAIL", result["post_merge_result"])
        self.assertEqual("VERIFY_POST_MERGE", result["next_action"])
        read_proof.assert_called_once_with(
            REPOCTL.ROOT, MERGE, expected_pr=171,
            expected_head=HEAD, snapshot=self.snapshot()
        )

    def test_pr_loop_refuses_done_when_proof_reader_returns_fail(self):
        code, result, _ = self.post_merge(proof=self.proof(status="FAIL"))
        self.assertEqual(1, code)
        self.assertNotEqual("DONE", result["state"])
        self.assertNotEqual("PASS", result["post_merge_result"])

    def test_pr_loop_refuses_pass_with_unverified_signature_flag(self):
        code, result, _ = self.post_merge(
            proof=self.proof(signature_verified=False)
        )
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("FAIL", result["post_merge_result"])
        self.assertEqual("VERIFY_POST_MERGE", result["next_action"])

    def test_pr_loop_refuses_done_when_roadmap_is_pending(self):
        code, result, read_proof = self.post_merge(
            proof=self.proof(), roadmap_check=1
        )
        self.assertEqual(1, code)
        self.assertEqual("MERGED", result["state"])
        self.assertEqual("PENDING_ROADMAP_PR", result["roadmap_result"])
        self.assertEqual("PENDING", result["post_merge_result"])
        self.assertEqual("FIX_ROADMAP_SYNC", result["next_action"])
        read_proof.assert_not_called()

    def test_pr_loop_refuses_done_when_work_item_close_is_unverified(self):
        code, result, _ = self.post_merge(
            proof=self.proof(), issue_status="BLOCKED"
        )
        self.assertEqual(1, code)
        self.assertEqual("VERIFIED", result["state"])
        self.assertEqual("CLOSE_WORK_ITEM", result["next_action"])
        self.assertEqual("PASS", result["post_merge_result"])
        self.assertEqual("BLOCKED", result["work_item_completion"]["status"])

    def test_pr_loop_done_requires_revalidated_signed_pass(self):
        code, result, read_proof = self.post_merge(proof=self.proof())
        self.assertEqual(0, code)
        self.assertEqual("DONE", result["state"])
        self.assertEqual("PASS", result["post_merge_result"])
        self.assertEqual("NONE", result["next_action"])
        self.assertEqual(
            f".context/evidence/post-merge/{MERGE}.json",
            result["post_merge_evidence"],
        )
        read_proof.assert_called_once()

    def finish_json(self, *, through_public_command):
        before = {"number": 171, "headRefOid": HEAD}
        after = {
            "state": "MERGED", "mergedAt": "2026-09-30T10:00:00Z",
            "headRefOid": HEAD, "mergeCommit": {"oid": MERGE},
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
            mock.patch.object(REPOCTL, "output",
                              side_effect=[json.dumps(before), json.dumps(after)]),
            mock.patch.object(
                REPOCTL, "finish_pr",
                side_effect=dispatch if through_public_command
                else merged_without_post_merge_proof,
            ),
            contextlib.redirect_stdout(output),
        ):
            code = (
                REPOCTL.finish_pr("main", json_output=True)
                if through_public_command else REPOCTL._finish_pr_json("main")
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


if __name__ == "__main__":
    unittest.main()

