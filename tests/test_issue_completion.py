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
        self.runtime_calls = []
        self.preflight_changes = {}
        self.preflight_error = None
        self.preflight_calls = []
        self.write_manifest({
            "base_sha": BASE, "head_sha": HEAD, "tree_sha": TREE,
            "gate_evidence": [{
                "path": f".context/evidence/preflight/{HEAD}.json",
                "sha256": "sha256:" + "8" * 64,
            }],
        })

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
        self.assertEqual(ROOT, kwargs["cwd"])
        if command == ["git", "show", "-s", "--format=%ct", MERGE]:
            return subprocess.CompletedProcess(command, 0, stdout="1790762400", stderr="")
        self.assertEqual(["git", "show", f"{HEAD}:{self.path}"], command)
        serialized = yaml.safe_dump(self.package)
        return subprocess.CompletedProcess(
            command, 0,
            stdout=serialized if kwargs.get("text") else serialized.encode(), stderr=""
        )

    def preflight(self, _root, **kwargs):
        self.preflight_calls.append(kwargs)
        if self.preflight_error:
            raise ValueError(self.preflight_error)
        return {
            "status": "PASS", "head_sha": HEAD, "head_tree_sha": TREE,
            "base_sha": BASE,
            "producer": "scripts/delivery_preflight.py:run_preflight",
            "authority": "historical-preflight-verification",
            "historical_verification": "VERIFIED",
            "work_package_id": self.package["id"],
            "work_package_digest": issue_completion.evidence_bundle.digest_bytes(
                yaml.safe_dump(self.package).encode()
            ),
            "work_item_issue": self.package["work_item_issue"],
            "milestone": self.package["milestone"],
            "evidence_path": f".context/evidence/preflight/{HEAD}.json",
            "evidence_digest": "sha256:" + "8" * 64,
            "producer_fingerprint": "sha256:" + "9" * 64,
            "generated_at_epoch": 1790762300,
            **self.preflight_changes,
        }

    def historical_runtime(self, *args, **kwargs):
        self.runtime_calls.append((args, kwargs))
        return self.runtime_verdict or {"status": "FAIL", "reason": "producer evidence unavailable"}

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
                issue_completion.delivery_preflight,
                "verify_historical_preflight",
                side_effect=self.preflight,
            ),
            mock.patch.object(
                issue_completion.runtime_authority,
                "verify_historical_runtime_proof",
                side_effect=self.historical_runtime,
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

    def test_required_preflight_is_verified_with_signed_bundle_and_git_identity(self):
        result, _, _, _ = self.complete()
        self.assertEqual("CLOSED", result["status"], result["errors"])
        self.assertEqual("PASS", result["projection"]["proofs"]["preflight"])
        self.assertEqual(1, len(self.preflight_calls))
        call = self.preflight_calls[0]
        self.assertEqual(f".context/evidence/preflight/{HEAD}.json", call["proof_path"])
        self.assertEqual("sha256:" + "8" * 64, call["expected_sha256"])
        self.assertEqual(HEAD, call["expected_head_sha"])
        self.assertEqual(BASE, call["expected_base_sha"])
        self.assertEqual(TREE, call["expected_head_tree_sha"])
        self.assertEqual("feat/issue-close", call["expected_branch"])
        self.assertEqual(1790762400, call["merge_epoch"])
        self.assertEqual(
            issue_completion.evidence_bundle.digest_bytes(yaml.safe_dump(self.package).encode()),
            call["expected_package_digest"],
        )

    def test_real_base_preflight_receipt_survives_merge_and_rejects_tampering(self):
        from tests.test_delivery_preflight import DeliveryPreflightTests

        fixture = DeliveryPreflightTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        package_path = fixture.root / self.path
        package_path.parent.mkdir(parents=True)
        package_bytes = yaml.safe_dump(self.package).encode()
        package_path.write_bytes(package_bytes)
        fixture.git("add", self.path)
        fixture.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "qualified package",
        )
        fixture.head = fixture.git("rev-parse", "HEAD")
        fixture.tree = fixture.git("rev-parse", "HEAD^{tree}")
        original_arguments = fixture.verification_arguments

        def arguments(capabilities=None, parameters=None):
            return {
                **original_arguments(capabilities, parameters),
                "expected_package_id": self.package["id"],
                "expected_package_digest": issue_completion.evidence_bundle.digest_bytes(package_bytes),
                "expected_issue": self.package["work_item_issue"],
                "expected_milestone": self.package["milestone"],
            }

        fixture.verification_arguments = arguments
        generated = fixture.bound_result()
        path = issue_completion.delivery_preflight.write_preflight(fixture.root, generated)
        current = issue_completion.delivery_preflight.verify_preflight(
            fixture.root, **arguments(), expected_result=generated,
        )
        self.assertEqual("PASS", issue_lifecycle.preflight_proof_state(
            current,
            {"state": "OPEN", "head_sha": fixture.head, "base_sha": fixture.base},
            self.package, {"head_tree_sha": fixture.tree},
        ))
        fixture.git("switch", "-q", "-c", "main", fixture.base)
        fixture.git(
            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "merge", "--no-ff", "-qm", "merge proof",
            fixture.branch,
        )
        merge = fixture.git("rev-parse", "HEAD")
        proof = {
            "head_sha": fixture.head, "head_tree_sha": fixture.tree,
            "base_sha": fixture.base, "merge_sha": merge,
        }
        manifest = {
            "head_sha": fixture.head, "tree_sha": fixture.tree,
            "base_sha": fixture.base,
            "gate_evidence": [{
                "path": str(path.relative_to(fixture.root)),
                "sha256": issue_completion.evidence_bundle.digest_bytes(path.read_bytes()),
            }],
        }
        manifest_path = fixture.root / f".context/evidence/{fixture.head}/manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_bytes = issue_completion.evidence_bundle.canonical_bytes(manifest)
        manifest_path.write_bytes(manifest_bytes)
        digest = issue_completion.evidence_bundle.digest_bytes(manifest_bytes)
        result = issue_completion._historical_preflight(
            fixture.root, self.package, proof, digest, {"head_branch": fixture.branch},
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("historical-preflight-verification", result["authority"])
        self.assertEqual("PASS", issue_lifecycle.preflight_proof_state(
            result,
            {"state": "MERGED", "head_sha": fixture.head, "base_sha": fixture.base},
            self.package, {"head_tree_sha": fixture.tree},
        ))
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "signed bundle digest"):
            issue_completion._historical_preflight(
                fixture.root, self.package, proof, digest, {"head_branch": fixture.branch},
            )
        original = copy.deepcopy(current["payload"])
        for changes, message in (
            ({"generated_at_epoch": 1}, "stale"),
            ({"source_sha": "0" * 40}, "source_sha"),
            ({"head_tree_sha": "0" * 40}, "head_tree_sha"),
            ({"producer": {**original["producer"], "path": "scripts/unregistered.py"}}, "producer"),
        ):
            with self.subTest(changes=changes):
                payload = {**original, **changes}
                fixture.rewrite_evidence(path, payload)
                manifest["gate_evidence"][0]["sha256"] = issue_completion.evidence_bundle.digest_bytes(path.read_bytes())
                encoded = issue_completion.evidence_bundle.canonical_bytes(manifest)
                manifest_path.write_bytes(encoded)
                with self.assertRaisesRegex(ValueError, message):
                    issue_completion._historical_preflight(
                        fixture.root, self.package, proof,
                        issue_completion.evidence_bundle.digest_bytes(encoded),
                        {"head_branch": fixture.branch},
                    )

    def test_missing_or_ambiguous_preflight_bundle_reference_never_closes(self):
        manifest = json.loads(self.manifest_path.read_bytes())
        reference = manifest["gate_evidence"][0]
        for entries in ([], [reference, reference]):
            with self.subTest(entries=entries):
                self.write_manifest({**manifest, "gate_evidence": entries})
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertFalse(result["mutation_attempted"])
        self.assertEqual([], self.preflight_calls)
        self.assertNotIn(("issues/170", True), self.requests)

    def test_stale_or_invalid_preflight_producer_never_closes(self):
        for reason in ("preflight is stale at merge", "preflight producer fingerprint differs", "preflight bytes differ from signed digest"):
            with self.subTest(reason=reason):
                self.preflight_error = reason
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertIn(reason, result["errors"])
                self.assertFalse(result["mutation_attempted"])
        self.assertNotIn(("issues/170", True), self.requests)

    def test_preflight_wrong_sha_tree_package_or_producer_never_closes(self):
        for change in (
            {"status": "FAIL"}, {"head_sha": "0" * 40},
            {"head_tree_sha": "0" * 40}, {"base_sha": "0" * 40},
            {"producer": "unregistered"}, {"authority": "digest-only"},
            {"work_package_digest": "sha256:" + "0" * 64},
            {"evidence_digest": "sha256:" + "0" * 64},
        ):
            with self.subTest(change=change):
                self.preflight_changes = change
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertFalse(result["mutation_attempted"])
        self.assertNotIn(("issues/170", True), self.requests)

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
            "gate_evidence": [{
                "path": f".context/evidence/preflight/{HEAD}.json",
                "sha256": "sha256:" + "8" * 64,
            }],
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

    def native_runtime_fixture(self):
        manifest = self.runtime_fixture()
        relative = issue_completion.runtime_authority._NATIVE_RECOVERY_PATH
        self.package["execution"]["recovery_required"] = True
        self.package["acceptance"]["runtime_evidence"] = [relative]
        self.runtime_verdict.update(
            producer=issue_completion.runtime_authority._NATIVE_PRODUCER,
            proof_type="native-host-recovery", environment="host",
            evidence_path=relative,
            runtime_identity={"kind": "virtualbox-vm", "id": "11111111-1111-1111-1111-111111111111"},
            recovery={phase: "PASS" for phase in issue_completion.runtime_authority._RECOVERY_PHASES},
        )
        manifest["runtime_evidence"][0]["path"] = relative
        self.write_manifest(manifest)
        return manifest

    def test_native_recovery_closes_only_work_item_from_exact_historical_producer(self):
        self.native_runtime_fixture()
        result, _, _, _ = self.complete()
        self.assertEqual("CLOSED", result["status"], result["errors"])
        self.assertEqual("PASS", result["projection"]["proofs"]["runtime"])
        self.assertEqual("PASS", result["projection"]["proofs"]["recovery"])
        self.assertEqual(1, self.requests.count(("issues/170", True)))
        self.assertNotIn(("issues/32", True), self.requests)
        self.assertEqual(1, len(self.runtime_calls))
        args, kwargs = self.runtime_calls[0]
        self.assertEqual(
            (ROOT, "M2.5", HEAD, issue_completion.runtime_authority._NATIVE_RECOVERY_PATH), args,
        )
        self.assertEqual({
            "base_sha": BASE, "head_tree_sha": TREE,
            "evidence_digest": "sha256:" + "9" * 64, "recovery_required": True,
        }, kwargs)

    def test_native_recovery_missing_or_failed_phase_never_closes(self):
        for phase in issue_completion.runtime_authority._RECOVERY_PHASES:
            for missing in (True, False):
                with self.subTest(phase=phase, missing=missing):
                    self.native_runtime_fixture()
                    if missing:
                        del self.runtime_verdict["recovery"][phase]
                    else:
                        self.runtime_verdict["recovery"][phase] = "FAIL"
                    result, _, _, _ = self.complete()
                    self.assertEqual("BLOCKED", result["status"], result)
                    self.assertFalse(result["mutation_attempted"])
                    self.assertTrue(any("recovery producer" in reason for reason in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)
        self.assertNotIn(("issues/32", True), self.requests)

    def test_native_recovery_wrong_authority_or_exact_identity_never_closes(self):
        for change in (
            {"producer": "scripts/m25_runtime_evidence.py:validate"},
            {"producer": "unregistered"},
            {"proof_type": "lab-readiness"},
            {"environment": "production"}, {"environment": "lab"},
            {"runtime_identity": None},
            {"runtime_identity": {"kind": "virtualbox-vm", "id": "short"}},
            {"head_sha": "0" * 40}, {"head_tree_sha": "0" * 40},
            {"evidence_digest": "sha256:" + "0" * 64},
            {"evidence_path": issue_completion.runtime_authority._LAB_PATH},
            {"recovery": "NOT_REQUIRED"},
            {"status": "FAIL", "reason": "protected readback unavailable"},
        ):
            with self.subTest(change=change):
                self.native_runtime_fixture()
                self.runtime_verdict.update(change)
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertFalse(result["mutation_attempted"])
        self.assertNotIn(("issues/170", True), self.requests)

    def test_native_recovery_requires_registered_path_and_actual_bundle_reference(self):
        for change in (
            {"runtime_evidence": []},
            {"runtime_identity": "declared"},
            {"runtime_evidence": [{
                "path": ".context/evidence/unregistered.json", "sha256": "sha256:" + "9" * 64,
            }]},
        ):
            with self.subTest(change=change):
                manifest = self.native_runtime_fixture()
                manifest.update(change)
                self.write_manifest(manifest)
                result, _, _, _ = self.complete()
                self.assertEqual("BLOCKED", result["status"], result)
                self.assertFalse(result["mutation_attempted"])
        self.native_runtime_fixture()
        self.package["execution"]["recovery_required"] = False
        result, _, _, _ = self.complete()
        self.assertEqual("BLOCKED", result["status"], result)
        self.assertTrue(any("LAB runtime producer path" in reason for reason in result["errors"]))
        self.assertNotIn(("issues/170", True), self.requests)

    def test_caller_supplied_native_recovery_cannot_authorize_closure(self):
        self.native_runtime_fixture()
        result, _, _, _ = self.complete(recovery={
            "status": "PASS", "head_sha": HEAD,
            "capture": "PASS", "restore": "PASS", "restore_verification": "PASS",
        })
        self.assertEqual("BLOCKED", result["status"], result)
        self.assertEqual([], self.runtime_calls)
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

    def test_dependency_closed_issue_still_requires_historical_preflight(self):
        from scripts import chatgpt_review_dispatcher

        self.issue_state = "closed"
        reviews = {
            "code": {**self.code, "created_at": "2026-09-30T10:00:00Z"},
            "security": {**self.security, "created_at": "2026-09-30T10:01:00Z"},
        }
        with (
            mock.patch.object(
                issue_completion.work_package, "resolve_dependencies",
                return_value=[self.package],
            ),
            mock.patch.object(
                issue_completion, "_dependency_candidate",
                return_value=(self.pr_snapshot, self.proof),
            ),
            mock.patch.object(
                chatgpt_review_dispatcher, "github_owner_marker_lookup",
                side_effect=lambda _binding, kind, **_kwargs: reviews[kind],
            ),
        ):
            for reason in ("preflight missing", "preflight stale", "unregistered producer"):
                with self.subTest(reason=reason):
                    self.preflight_error = reason
                    result, _, _, _ = self.complete(
                        operation=lambda: issue_completion.verify_dependencies(
                            ROOT, "gh", "owner/repo", {"dependencies": [self.package["id"]]}
                        )
                    )
                    self.assertEqual("BLOCKED", result["status"], result)
                    self.assertTrue(any(reason in error for error in result["errors"]))
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
