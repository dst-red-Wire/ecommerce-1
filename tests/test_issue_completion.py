"""Issue closure requires independent exact-head proofs and a GitHub readback."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import issue_completion, issue_lifecycle
from tests.test_work_package import valid_package

ROOT = Path(__file__).resolve().parents[1]
BASE, HEAD, TREE, MERGE = "a" * 40, "b" * 40, "c" * 40, "d" * 40


class IssueCompletionTests(unittest.TestCase):
    def setUp(self):
        self.package = valid_package()
        self.path = (
            f"config/work-packages/{self.package['milestone']}/"
            f"{self.package['id']}.yaml"
        )
        self.pr_snapshot = {
            "number": 171,
            "state": "MERGED",
            "merged": True,
            "merged_at": "2026-09-30T10:00:00Z",
            "base": "main",
            "base_sha": BASE,
            "head_sha": HEAD,
            "head_branch": "feat/issue-close",
            "merge_commit_sha": MERGE,
        }
        self.proof = {
            "schema_version": 2,
            "kind": "PostMergeVerification",
            "status": "PASS",
            "pr": 171,
            "base_sha": BASE,
            "head_sha": HEAD,
            "head_tree_sha": TREE,
            "merge_sha": MERGE,
            "qualification_identity": "e" * 64,
            "merge_tree_sha": "f" * 40,
            "recomputed_tree_sha": "f" * 40,
            "main_sha": MERGE,
            "signature_verified": True,
            "main_contains_change": True,
            "qualified_tree_matches": True,
            "clean_worktree": True,
            "roadmap_sync": "PASS",
            "merge_signature": {"status": "VERIFIED", "fingerprint": "1" * 40},
            "branch_cleanup": {"local": "DELETED", "remote": "DELETED"},
            "qualification_witness": {
                "evidence_sha256": "sha256:" + "2" * 64,
                "manifest_sha256": "sha256:" + "3" * 64,
            },
            "errors": [],
        }
        self.qualification = {
            "schema_version": 5,
            "status": "PASS",
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "base_sha": BASE,
            "head_sha": HEAD,
            "head_tree_sha": TREE,
            "qualification_identity": "e" * 64,
            "changed_paths": [
                "scripts/work_package.py",
                "tests/test_work_package.py",
            ],
            "gates": [
                {"gate": "governance", "status": "PASS"},
                {"gate": "contracts", "status": "PASS"},
            ],
            "historical_verification": {
                "status": "VERIFIED",
                "merge_sha": MERGE,
                "evidence_sha256": "sha256:" + "2" * 64,
                "bundle_digest": "sha256:" + "3" * 64,
            },
        }
        self.head_snapshot = {
            "authority": "git-qualified-head-snapshot",
            "head_sha": HEAD,
            "tree_sha": TREE,
            "paths": sorted(
                {
                    self.path,
                    "tests/test_work_package.py",
                    "config/contracts/roadmap-policy.yaml",
                    "config/contracts/qualification-execution-policy.yaml",
                }
            ),
            "qualification_policy": {
                "kind": "QualificationExecutionPolicy",
                "status": "enforced",
                "gates": {
                    "governance": {"owned_tests": ["tests/test_work_package.py"]},
                    "contracts": {"owned_tests": []},
                },
            },
        }
        self.code = {
            "provider": "ChatGPT",
            "kind": "code",
            "head_sha": HEAD,
            "status": "PASS",
            "blocking_findings": 0,
            "comment_id": 101,
            "source": "github-pr-comment",
        }
        self.security = {
            **self.code,
            "kind": "security",
            "comment_id": 102,
        }
        issue_marker = {
            "category": "work-item",
            "milestone": self.package["milestone"],
            "tracker_issue": self.package["tracker_issue"],
            "work_package_id": self.package["id"],
            "work_package_path": self.path,
        }
        self.issue_body = (
            "<!-- ecommerce-work-item:v1 "
            + json.dumps(issue_marker, sort_keys=True, separators=(",", ":"))
            + " -->"
        )
        self.pr = {
            "number": 171,
            "state": "closed",
            "merged_at": "2026-09-30T10:00:00Z",
            "merge_commit_sha": MERGE,
            "head": {"sha": HEAD},
            "base": {"sha": BASE},
            "body": issue_lifecycle.format_pr_work_item_marker(self.package),
        }
        self.issue_state = "open"
        self.issue_readback_state = None
        self.requests: list[tuple[str, bool]] = []
        self.bundle_digest = "sha256:" + "3" * 64
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.manifest_path = Path(temporary.name) / "manifest.json"
        self.runtime_verdict = None

    def github(self, _root, _gh, _repository, endpoint, *, close=False):
        self.requests.append((endpoint, close))
        if endpoint == "pulls/171" and not close:
            return copy.deepcopy(self.pr)
        if endpoint == "issues/32" and not close:
            return {
                "number": 32,
                "state": "open",
                "pull_request": None,
            }
        if endpoint == "issues/170":
            if close:
                self.issue_state = "closed"
                return {"number": 170, "state": "closed"}
            state = (
                self.issue_readback_state
                if self.issue_readback_state is not None
                else self.issue_state
            )
            return {
                "number": 170,
                "state": state,
                "body": self.issue_body,
                "pull_request": None,
            }
        raise AssertionError(f"unexpected GitHub request: {endpoint}, close={close}")

    def git_show(self, command, **kwargs):
        self.assertEqual(["git", "show", f"{HEAD}:{self.path}"], command)
        self.assertEqual(ROOT, kwargs["cwd"])
        return subprocess.CompletedProcess(
            command, 0, stdout=yaml.safe_dump(self.package), stderr=""
        )

    def complete(self, *, runtime=None, recovery=None, operation=None):
        with (
            mock.patch.object(
                issue_completion.post_merge_verify,
                "read_post_merge_proof",
                return_value=self.proof,
            ) as read_proof,
            mock.patch.object(
                issue_completion.post_merge_verify,
                "load_historical_qualification",
                return_value=self.qualification,
            ) as historical,
            mock.patch.object(
                issue_completion.issue_lifecycle,
                "read_qualified_head_snapshot",
                return_value=self.head_snapshot,
            ),
            mock.patch.object(
                issue_completion.evidence_bundle,
                "verify_bundle",
                return_value={
                    "status": "PASS",
                    "authority": "bundle-integrity-only",
                    "manifest_digest": self.bundle_digest,
                },
            ) as bundle,
            mock.patch.object(
                issue_completion.evidence_bundle,
                "_safe_file",
                return_value=self.manifest_path,
            ),
            mock.patch.object(
                issue_completion.runtime_authority,
                "verify_historical_runtime_proof",
                side_effect=lambda *_args, **_kwargs: (
                    self.runtime_verdict
                    or {"status": "FAIL", "reason": "producer evidence unavailable"}
                ),
            ),
            mock.patch.object(
                issue_completion, "_github_json", side_effect=self.github
            ),
            mock.patch.object(
                issue_completion.subprocess, "run", side_effect=self.git_show
            ),
        ):
            result = (
                operation()
                if operation is not None
                else issue_completion.complete_work_item(
                    ROOT,
                    "gh",
                    "owner/repo",
                    self.pr_snapshot,
                    self.proof,
                    self.code,
                    self.security,
                    runtime=runtime,
                    recovery=recovery,
                )
            )
        return result, read_proof, historical, bundle

    def test_closes_only_after_verified_projection_and_reads_back_closed(self):
        result, read_proof, historical, bundle = self.complete()
        self.assertEqual("CLOSED", result["status"], result["errors"])
        self.assertEqual("CLOSED", result["projection"]["status"])
        self.assertTrue(result["mutation_attempted"])
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(1, self.requests.count(("issues/170", True)))
        self.assertEqual(2, self.requests.count(("issues/170", False)))
        read_proof.assert_called_once_with(
            ROOT,
            MERGE,
            expected_pr=171,
            expected_head=HEAD,
            snapshot=self.pr_snapshot,
        )
        historical.assert_called_once()
        bundle.assert_called_once()

    def test_already_closed_is_idempotent_only_with_closed_projection(self):
        self.issue_state = "closed"
        result, _, _, _ = self.complete()
        self.assertEqual("CLOSED", result["status"], result["errors"])
        self.assertFalse(result["mutation_attempted"])
        self.assertFalse(result["mutation_performed"])
        self.assertNotIn(("issues/170", True), self.requests)

    def test_missing_signed_proof_never_calls_github(self):
        with mock.patch.object(
            issue_completion, "_github_json", side_effect=self.github
        ):
            result = issue_completion.complete_work_item(
                ROOT,
                "gh",
                "owner/repo",
                self.pr_snapshot,
                None,
                self.code,
                self.security,
            )
        self.assertEqual("BLOCKED", result["status"])
        self.assertFalse(result["mutation_attempted"])
        self.assertEqual([], self.requests)

    def test_generic_pass_review_cannot_close_issue(self):
        self.code = {"status": "PASS", "head_sha": HEAD}
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("code review" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_qualified_package_marker_mismatch_blocks_before_mutation(self):
        self.package["work_item_issue"] = 999
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(
            any("work package differs" in error for error in result["errors"])
        )
        self.assertNotIn(("issues/170", True), self.requests)

    def test_required_acceptance_gate_failure_blocks(self):
        self.qualification["gates"][0]["status"] = "FAIL"
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("acceptance" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_fresh_github_relation_mismatch_blocks(self):
        self.issue_body = "<!-- ecommerce-work-item:v1 {} -->"
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("relation" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_runtime_required_fails_closed_without_historical_producer(self):
        self.package["execution"]["runtime_required"] = True
        self.package["acceptance"]["runtime_evidence"] = [
            ".context/evidence/m25-readiness.json"
        ]
        result, _, _, _ = self.complete(runtime={"status": "PASS", "head_sha": HEAD})
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(
            any(
                "caller-supplied runtime/recovery" in error
                for error in result["errors"]
            )
        )
        self.assertNotIn(("issues/170", True), self.requests)

    def runtime_fixture(self):
        relative = issue_completion.runtime_authority._LAB_PATH
        digest = "sha256:" + "9" * 64
        self.package["execution"]["runtime_required"] = True
        self.package["acceptance"]["runtime_evidence"] = [relative]
        self.runtime_verdict = {
            "status": "PASS",
            "reason": "",
            "producer": "scripts/m25_runtime_evidence.py:validate",
            "proof_type": "lab-readiness",
            "head_sha": HEAD,
            "head_tree_sha": TREE,
            "evidence_path": relative,
            "evidence_digest": digest,
            "recovery": "NOT_REQUIRED",
        }
        identity = issue_completion.evidence_bundle.digest_bytes(
            issue_completion.evidence_bundle.canonical_bytes(
                {"runtime_evidence": [digest]}
            )
        )
        manifest = {
            "base_sha": BASE,
            "head_sha": HEAD,
            "tree_sha": TREE,
            "runtime_identity": identity,
            "runtime_evidence": [{"path": relative, "sha256": digest}],
        }
        self.write_manifest(manifest)
        return manifest

    def write_manifest(self, manifest):
        encoded = issue_completion.evidence_bundle.canonical_bytes(manifest)
        self.manifest_path.write_bytes(encoded)
        self.bundle_digest = issue_completion.evidence_bundle.digest_bytes(encoded)
        self.proof["qualification_witness"]["manifest_sha256"] = self.bundle_digest
        self.qualification["historical_verification"]["bundle_digest"] = (
            self.bundle_digest
        )

    def test_runtime_required_can_close_from_historical_producer_and_exact_bundle(self):
        self.runtime_fixture()
        result, _, _, _ = self.complete()
        self.assertEqual("CLOSED", result["status"], result["errors"])
        self.assertEqual("PASS", result["projection"]["proofs"]["runtime"])
        self.assertEqual(1, self.requests.count(("issues/170", True)))

    def test_runtime_missing_or_misbound_producer_never_patches_github(self):
        for change in (
            {"status": "FAIL", "reason": "missing protected producer"},
            {"producer": "unregistered"},
            {"head_sha": "0" * 40},
            {"head_tree_sha": "0" * 40},
            {"evidence_digest": "sha256:" + "0" * 64},
        ):
            with self.subTest(change=change):
                self.runtime_fixture()
                self.runtime_verdict.update(change)
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertNotIn(("issues/170", True), self.requests)

    def test_runtime_bundle_missing_reference_wrong_identity_or_recovery_blocks(self):
        for change in (
            {"runtime_evidence": []},
            {"runtime_identity": "self-declared"},
            {"head_sha": "0" * 40},
        ):
            with self.subTest(change=change):
                manifest = self.runtime_fixture()
                manifest.update(change)
                self.write_manifest(manifest)
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertNotIn(("issues/170", True), self.requests)
        self.runtime_fixture()
        self.package["execution"]["recovery_required"] = True
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("recovery producer" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_dependency_closed_issue_without_signed_proof_does_not_authorize(self):
        self.issue_state = "closed"
        with (
            tempfile.TemporaryDirectory() as directory,
            (
                mock.patch.object(
                    issue_completion.work_package,
                    "resolve_dependencies",
                    return_value=[self.package],
                )
            ),
        ):
            result, _, _, _ = self.complete(
                operation=lambda: issue_completion.verify_dependencies(
                    Path(directory),
                    "gh",
                    "owner/repo",
                    {"dependencies": [self.package["id"]]},
                )
            )
        self.assertEqual("BLOCKED", result["status"], result)
        self.assertTrue(any("signed verified" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_dependency_closure_is_read_only_and_reuses_complete_proof_verification(
        self,
    ):
        from scripts import chatgpt_review_dispatcher

        self.issue_state = "closed"
        reviews = {
            "code": {**self.code, "created_at": "2026-09-30T10:00:00Z"},
            "security": {**self.security, "created_at": "2026-09-30T10:01:00Z"},
        }
        with (
            mock.patch.object(
                issue_completion.work_package,
                "resolve_dependencies",
                return_value=[self.package],
            ),
            mock.patch.object(
                issue_completion,
                "_dependency_candidate",
                return_value=(self.pr_snapshot, self.proof),
            ),
            mock.patch.object(
                chatgpt_review_dispatcher,
                "github_owner_marker_lookup",
                side_effect=lambda _binding, kind, **_kwargs: reviews[kind],
            ),
        ):
            result, read_proof, historical, bundle = self.complete(
                operation=lambda: issue_completion.verify_dependencies(
                    ROOT, "gh", "owner/repo", {"dependencies": [self.package["id"]]}
                )
            )
        self.assertEqual("PASS", result["status"], result["errors"])
        self.assertEqual("CLOSED", result["dependencies"][0]["status"])
        read_proof.assert_called_once()
        historical.assert_called_once()
        bundle.assert_called_once()
        self.assertNotIn(("issues/170", True), self.requests)

    def test_dependency_open_issue_is_never_closed_as_a_side_effect(self):
        with mock.patch.object(
            issue_completion.work_package,
            "resolve_dependencies",
            return_value=[self.package],
        ):
            result, _, _, _ = self.complete(
                operation=lambda: issue_completion.verify_dependencies(
                    ROOT, "gh", "owner/repo", {"dependencies": [self.package["id"]]}
                )
            )
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("not CLOSED" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_missing_dependency_blocks_primary_closure_before_patch(self):
        self.package["dependencies"] = ["missing-canonical-dependency"]
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertNotIn(("issues/170", True), self.requests)

    def test_unverified_bundle_digest_blocks(self):
        self.proof["qualification_witness"]["manifest_sha256"] = "sha256:" + "4" * 64
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("bundle" in error for error in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_post_patch_missing_readback_is_unknown(self):
        self.issue_readback_state = "open"
        result, _, _, _ = self.complete()
        self.assertEqual("UNKNOWN", result["status"])
        self.assertTrue(result["mutation_attempted"])
        self.assertTrue(result["mutation_performed"])
        self.assertNotEqual("CLOSED", result["projection"]["status"])


if __name__ == "__main__":
    unittest.main()
