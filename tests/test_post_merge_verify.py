from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import evidence_bundle, issue_lifecycle, post_merge_verify

SOURCE_ROOT = Path(__file__).resolve().parents[1]


class PostMergeVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_home = tempfile.TemporaryDirectory()
        cls.gpg_home = Path(cls.key_home.name) / "gnupg"
        cls.gpg_home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(cls.gpg_home)}
        result = subprocess.run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Post Merge Tests <post-merge@example.test>",
                "ed25519",
                "sign",
                "1d",
            ],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        listing = subprocess.check_output(
            ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
            env=env,
            text=True,
        )
        cls.fingerprint = next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        )
        secondary = subprocess.run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Other Signer <other@example.test>",
                "ed25519",
                "sign",
                "1d",
            ],
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if secondary.returncode:
            raise RuntimeError(secondary.stderr)
        listing = subprocess.check_output(
            ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
            env=env,
            text=True,
        )
        cls.untrusted_fingerprint = next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:") and line.split(":")[9] != cls.fingerprint
        )

    @classmethod
    def tearDownClass(cls):
        cls.key_home.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.root = Path(self.workspace.name) / "repo"
        self.remote = Path(self.workspace.name) / "remote.git"
        self.environment = mock.patch.dict(
            os.environ, {"GNUPGHOME": str(self.gpg_home)}
        )
        self.environment.start()
        fixture_options = {
            "test_unsigned_merge_fails_even_with_github_merged": {
                "signed_merge": False,
            },
            "test_unexpected_merge_tree_fails": {
                "unexpected_merge": True,
            },
            "test_branch_cleanup_required_by_policy": {
                "delete_branches": False,
            },
            "test_historical_qualification_rejects_missing_global_gate": {
                "missing_global_gate": True,
            },
        }
        self._create_repo(**fixture_options.get(self._testMethodName, {}))

    def tearDown(self):
        self.environment.stop()
        self.workspace.cleanup()

    def git(self, *args: str, repo: Path | None = None, check: bool = True) -> str:
        target = repo or self.root
        result = subprocess.run(
            ["git", "-C", str(target), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if check and result.returncode:
            raise AssertionError(f"git {args}: {result.stderr}")
        return result.stdout.strip()

    def _create_repo(
        self,
        *,
        signed_merge: bool = True,
        unexpected_merge: bool = False,
        delete_branches: bool = True,
        missing_global_gate: bool = False,
    ) -> None:
        self.git(
            "init", "--bare", "-q", str(self.remote), repo=Path(self.workspace.name)
        )
        self.git(
            "init", "-q", "-b", "main", str(self.root), repo=Path(self.workspace.name)
        )
        self.git("config", "user.name", "Post Merge Tests")
        self.git("config", "user.email", "post-merge@example.test")
        self.git("config", "user.signingkey", self.fingerprint)
        self.git("config", "gpg.program", "gpg")
        self.git("config", "commit.gpgsign", "true")
        self.git("remote", "add", "origin", str(self.remote))
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        policy = self.root / "config/contracts/review-policy.yaml"
        policy.parent.mkdir(parents=True)
        shutil.copyfile(SOURCE_ROOT / "config/contracts/review-policy.yaml", policy)
        for relative in (
            "config/contracts/ci-evidence.yaml",
            "config/contracts/qualification-execution-policy.yaml",
            "config/contracts/toolchain-lock.json",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, destination)
        lock = yaml.safe_load(
            (SOURCE_ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        )
        lock["repository_governance"]["automation_signing"]["automation_key"][
            "fingerprint"
        ] = self.fingerprint
        (self.root / "architecture.lock.yaml").write_text(
            yaml.safe_dump(lock, sort_keys=False), encoding="utf-8"
        )
        script = self.root / "scripts/roadmap_sync.py"
        script.parent.mkdir()
        script.write_text(
            "import os\nimport sys\n"
            "sys.exit(1 if os.environ.get('FAIL_ROADMAP') == '1' else 0)\n",
            encoding="utf-8",
        )
        (self.root / "base.txt").write_text("base\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.git("push", "-q", "-u", "origin", "main")
        self.git("switch", "-q", "-c", "feat/post-merge")
        (self.root / "feature.txt").write_text("feature\n", encoding="utf-8")
        self.git("add", "feature.txt")
        self.git("commit", "-qm", "feature")
        self.head = self.git("rev-parse", "HEAD")
        self.head_tree = self.git("rev-parse", f"{self.head}^{{tree}}")
        self.git("push", "-q", "-u", "origin", "feat/post-merge")
        policy_data = yaml.safe_load(
            (
                self.root / "config/contracts/qualification-execution-policy.yaml"
            ).read_text(encoding="utf-8")
        )
        globals_ = [
            name
            for name, definition in policy_data["gates"].items()
            if definition.get("scope") == "global"
        ]
        if missing_global_gate:
            globals_ = globals_[1:]
        evidence = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_sha": self.base,
            "head_sha": self.head,
            "head_tree_sha": self.head_tree,
            "qualification_identity": "a" * 64,
            "created_at_epoch": time.time(),
            "changed_paths": ["feature.txt"],
            "verification": {"execution_profile": "full", "runtime_scope": []},
            "gates": [
                {
                    "gate": name,
                    "status": "PASS",
                    "duration_seconds": 0.1,
                    "execution": "fresh",
                    "cache_mode": "fresh",
                    "scope": "global",
                    "parallel_safe": False,
                    "parallel_group": "global",
                    "started_at_monotonic_offset": 0.0,
                    "exit_code": 0,
                }
                for name in globals_
            ],
        }
        evidence_file = self.root / ".context/evidence" / f"{self.head}.json"
        evidence_file.parent.mkdir(parents=True)
        evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
        self.evidence_sha256 = evidence_bundle.digest_file(evidence_file)
        self.bundle_result = evidence_bundle.create_bundle(
            self.root,
            base_sha=self.base,
            head_sha=self.head,
            tree_sha=self.head_tree,
            qualification_identity="a" * 64,
            toolchain_digest=evidence_bundle.digest_file(
                self.root / "config/contracts/toolchain-lock.json"
            ),
        )
        if self._testMethodName.startswith("test_recovery_"):
            self.pre_merge_witness = post_merge_verify.write_pre_merge_witness(
                self.root,
                pr_number=171,
                snapshot={
                    "number": 171,
                    "state": "OPEN",
                    "merged": False,
                    "base_sha": self.base,
                    "head_sha": self.head,
                },
                qualification=evidence,
            )
        self.git("switch", "-q", "main")
        if signed_merge:
            self.git(
                "merge",
                "-q",
                "--no-ff",
                "--gpg-sign",
                "-m",
                "Merge PR",
                "feat/post-merge",
            )
        else:
            self.git(
                "-c",
                "commit.gpgsign=false",
                "merge",
                "-q",
                "--no-ff",
                "--no-gpg-sign",
                "-m",
                "Merge PR",
                "feat/post-merge",
            )
        if unexpected_merge:
            (self.root / "unexpected.txt").write_text("extra\n", encoding="utf-8")
            self.git("add", "unexpected.txt")
            self.git(
                "commit",
                "-q",
                "--amend",
                "--no-edit",
                f"--gpg-sign={self.fingerprint}",
            )
        self.merge = self.git("rev-parse", "HEAD")
        if signed_merge:
            self.git("verify-commit", self.merge)
        self.git("push", "-q", "origin", "main")
        self.git("fetch", "-q", "origin")
        if delete_branches:
            self.git("push", "-q", "origin", "--delete", "feat/post-merge")
            self.git("branch", "-d", "feat/post-merge")
        self.snapshot = {
            "number": 171,
            "state": "MERGED",
            "merged": True,
            "merged_at": "2026-09-30T10:00:00Z",
            "draft": False,
            "base": "main",
            "base_sha": self.base,
            "head_sha": self.head,
            "head_branch": "feat/post-merge",
            "merge_commit_sha": self.merge,
        }
        self.qualification = {
            "schema_version": 5,
            "evidence_kind": "exact_commit",
            "exact_commit_evidence": True,
            "status": "PASS",
            "base_sha": self.base,
            "head_sha": self.head,
            "head_tree_sha": self.head_tree,
            "qualification_identity": "a" * 64,
        }

    def historical(self, **overrides) -> dict:
        witness = {
            "base_sha": self.base,
            "head_sha": self.head,
            "head_tree_sha": self.head_tree,
            "merge_sha": self.merge,
            "qualification_identity": "a" * 64,
            "evidence_sha256": self.evidence_sha256,
            "manifest_sha256": self.bundle_result["manifest_digest"],
        }
        witness.update(overrides)
        return post_merge_verify.load_historical_qualification(self.root, **witness)

    def test_signature_verifies_parsed_snapshot_despite_path_replacement(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        signed = path.read_bytes()
        tampered = json.loads(signed)
        tampered["main_sha"] = self.base
        path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n")
        verify = post_merge_verify._verify_detached_signature

        def swap(root, content_path, *args, **kwargs):
            if content_path == path:
                path.write_bytes(signed)
            return verify(root, content_path, *args, **kwargs)

        with (
            mock.patch.object(
                post_merge_verify, "_verify_detached_signature", side_effect=swap
            ),
            self.assertRaisesRegex(
                post_merge_verify.PostMergeError, "signature did not verify"
            ),
        ):
            post_merge_verify.read_post_merge_proof(
                self.root, self.merge, snapshot=self.snapshot
            )

    def test_historical_digest_authenticates_the_same_parsed_bytes(self):
        path = self.root / ".context/evidence" / f"{self.head}.json"
        original = path.read_bytes()
        altered = json.loads(original)
        altered["non_authoritative_extension"] = "unsigned bytes"
        path.write_text(json.dumps(altered))
        parse = post_merge_verify._strict_json

        def swap(candidate, **kwargs):
            payload = parse(candidate, **kwargs)
            if candidate == path:
                path.write_bytes(original)
            return payload

        with (
            mock.patch.object(post_merge_verify, "_strict_json", side_effect=swap),
            self.assertRaisesRegex(post_merge_verify.PostMergeError, "bytes differ"),
        ):
            post_merge_verify.load_historical_qualification(
                self.root,
                base_sha=self.base,
                head_sha=self.head,
                head_tree_sha=self.head_tree,
                merge_sha=self.merge,
                qualification_identity="a" * 64,
                evidence_sha256=self.evidence_sha256,
                manifest_sha256=self.bundle_result["manifest_digest"],
            )

    def test_signed_historical_proof_reads_from_feature_without_head_execution(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        self.git("switch", "-q", "-c", "feat/dependency-consumer")
        sentinel = self.root / ".context/head-roadmap-executed"
        (self.root / "scripts/roadmap_sync.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n"
        )
        self.git("add", "scripts/roadmap_sync.py")
        self.git("commit", "-qm", "untrusted future roadmap implementation")
        proof = post_merge_verify.read_post_merge_proof(
            self.root,
            self.merge,
            expected_pr=171,
            expected_head=self.head,
            snapshot=self.snapshot,
        )
        self.assertEqual(proof["status"], "PASS")
        self.assertTrue(path.is_file())
        self.assertFalse(sentinel.exists())
        direct = post_merge_verify.verify_post_merge(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        self.assertEqual(direct["status"], "FAIL")

    def test_recovery_rebuilds_missing_proof_after_transient_writer_failure(self):
        with (
            mock.patch.object(
                post_merge_verify,
                "write_post_merge_proof",
                side_effect=OSError("temporary write failure"),
            ),
            self.assertRaises(OSError),
        ):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )
        proof = post_merge_verify.recover_post_merge_proof(
            self.root, pr_number=171, snapshot=self.snapshot
        )
        self.assertEqual(proof["status"], "PASS")
        self.assertEqual(proof["head_sha"], self.head)
        self.assertEqual(
            proof,
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            ),
        )

    def test_recovery_missing_witness_cannot_promote_retained_bundle(self):
        self.pre_merge_witness.unlink()
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "witness.*missing"
        ):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )

    def test_recovery_unsigned_witness_is_rejected(self):
        self.pre_merge_witness.with_suffix(".json.sig").unlink()
        with self.assertRaises(post_merge_verify.PostMergeError):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )

    def test_recovery_wrong_pr_cannot_borrow_signed_witness(self):
        snapshot = {**self.snapshot, "number": 172}
        with self.assertRaises(post_merge_verify.PostMergeError):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=172, snapshot=snapshot
            )

    def test_recovery_changed_qualification_cannot_borrow_signed_witness(self):
        path = self.root / ".context/evidence" / f"{self.head}.json"
        data = json.loads(path.read_text())
        data["created_at_epoch"] += 1
        path.write_text(json.dumps(data))
        with self.assertRaises(
            (post_merge_verify.PostMergeError, evidence_bundle.EvidenceBundleError)
        ):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )

    def test_recovery_untrusted_signer_cannot_authorize_witness(self):
        signature = self.pre_merge_witness.with_suffix(".json.sig")
        signature.unlink()
        self.git("config", "user.signingkey", self.untrusted_fingerprint)
        post_merge_verify._detached_sign(
            self.root, self.pre_merge_witness, signature, self.untrusted_fingerprint
        )
        with self.assertRaises(post_merge_verify.PostMergeError):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )

    def test_recovery_existing_invalid_proof_is_never_overwritten(self):
        path = self.root / post_merge_verify.OUTPUT_RELATIVE / f"{self.merge}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        content = b'{"status":"PASS"}\n'
        path.write_bytes(content)
        with self.assertRaises(post_merge_verify.PostMergeError):
            post_merge_verify.recover_post_merge_proof(
                self.root, pr_number=171, snapshot=self.snapshot
            )
        self.assertEqual(path.read_bytes(), content)

    def test_historical_qualification_uses_trusted_digest_and_exact_bundle(self):
        result = self.historical()
        self.assertEqual("PASS", result["status"])
        self.assertEqual("VERIFIED", result["historical_verification"]["status"])
        self.assertEqual(
            self.evidence_sha256, result["historical_verification"]["evidence_sha256"]
        )

    def test_historical_qualification_rejects_tampered_bytes(self):
        path = self.root / ".context/evidence" / f"{self.head}.json"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "differ from trusted witness"
        ):
            self.historical()

    def test_historical_qualification_rejects_missing_witness(self):
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "trusted qualification evidence digest"
        ):
            self.historical(evidence_sha256="")

    def test_historical_qualification_rejects_missing_manifest_witness(self):
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "trusted evidence bundle digest"
        ):
            self.historical(manifest_sha256="")

    def test_historical_qualification_rejects_tampered_manifest(self):
        path = self.root / ".context/evidence" / self.head / "manifest.json"
        path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        with self.assertRaisesRegex(post_merge_verify.PostMergeError, "bundle invalid"):
            self.historical()

    def test_historical_qualification_rejects_rewritten_valid_bundle(self):
        directory = self.root / ".context/evidence" / self.head
        manifest = directory / "manifest.json"
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["runtime_identity"] = "rewritten"
        content = evidence_bundle.canonical_bytes(payload)
        manifest.write_bytes(content)
        (directory / "manifest.sha256").write_text(
            evidence_bundle.digest_bytes(content) + "\n", encoding="ascii"
        )
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "bundle integrity is unverified"
        ):
            self.historical()

    def test_historical_qualification_rejects_wrong_tree(self):
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "head tree differs from Git"
        ):
            self.historical(head_tree_sha="f" * 40)

    def test_historical_qualification_rejects_missing_global_gate(self):
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "missing global gates"
        ):
            self.historical()

    def verify(self) -> dict:
        return post_merge_verify.verify_post_merge(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )

    def test_real_signed_merge_and_clean_git_facts_write_immutable_proof(self):
        result = self.verify()
        self.assertEqual("PASS", result["status"], result["errors"])
        self.assertEqual(self.merge, result["merge_sha"])
        self.assertEqual(result["merge_tree_sha"], result["recomputed_tree_sha"])
        for fact in (
            "signature_verified",
            "main_contains_change",
            "qualified_tree_matches",
            "clean_worktree",
        ):
            self.assertIs(result[fact], True)
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        self.assertEqual(
            self.root / ".context/evidence/post-merge" / f"{self.merge}.json", path
        )
        proof = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(2, proof["schema_version"])
        self.assertEqual("PASS", proof["status"])
        self.assertEqual(
            "PASS", issue_lifecycle.post_merge_state(proof, self.head, self.merge)
        )
        for fact in (
            "signature_verified",
            "main_contains_change",
            "qualified_tree_matches",
            "clean_worktree",
        ):
            self.assertIs(proof[fact], True)
        self.assertEqual(result["merge_sha"], proof["merge_sha"])
        self.assertEqual(
            self.evidence_sha256, proof["qualification_witness"]["evidence_sha256"]
        )
        self.assertTrue(path.with_suffix(".json.sig").is_file())
        self.assertEqual(
            path,
            post_merge_verify.write_post_merge_proof(
                self.root,
                pr_number=171,
                snapshot=self.snapshot,
                qualification=self.qualification,
            ),
        )
        path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "overwrite forbidden"
        ):
            post_merge_verify.write_post_merge_proof(
                self.root,
                pr_number=171,
                snapshot=self.snapshot,
                qualification=self.qualification,
            )

    def test_restart_revalidates_signed_proof_and_current_github(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        before = path.read_bytes()
        result = post_merge_verify.read_post_merge_proof(
            self.root,
            self.merge,
            expected_pr=171,
            expected_head=self.head,
            snapshot=self.snapshot,
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual(before, path.read_bytes())

    def test_recovery_requires_fresh_external_github_snapshot(self):
        post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "fresh external GitHub"
        ):
            post_merge_verify.read_post_merge_proof(self.root, self.merge)

    def test_recovery_rejects_missing_detached_signature(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        path.with_suffix(".json.sig").unlink()
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "signature is missing"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=self.snapshot,
            )

    def test_recovery_rejects_tampered_signed_proof(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        proof = json.loads(path.read_text(encoding="utf-8"))
        proof["main_sha"] = "f" * 40
        path.write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "signature did not verify"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=self.snapshot,
            )

    def test_recovery_rejects_valid_signature_from_untrusted_key(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        signature = path.with_suffix(".json.sig")
        replacement = subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                self.untrusted_fingerprint,
                "--output",
                str(signature),
                "--detach-sign",
                str(path),
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(0, replacement.returncode, replacement.stderr)
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "historical signing authority"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=self.snapshot,
            )

    def test_recovery_rejects_false_signed_fact_flag(self):
        path = post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        proof = json.loads(path.read_text(encoding="utf-8"))
        proof["clean_worktree"] = False
        path.write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "verified fact flags"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=self.snapshot,
            )

    def test_recovery_rejects_rewritten_qualification_bundle(self):
        post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        path = self.root / ".context/evidence" / self.head / "manifest.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["runtime_identity"] = "rewritten"
        content = evidence_bundle.canonical_bytes(payload)
        path.write_bytes(content)
        (path.parent / "manifest.sha256").write_text(
            evidence_bundle.digest_bytes(content) + "\n", encoding="ascii"
        )
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "bundle integrity is unverified"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=self.snapshot,
            )

    def test_recovery_rejects_changed_github_identity(self):
        post_merge_verify.write_post_merge_proof(
            self.root,
            pr_number=171,
            snapshot=self.snapshot,
            qualification=self.qualification,
        )
        snapshot = {**self.snapshot, "head_sha": "f" * 40}
        with self.assertRaisesRegex(
            post_merge_verify.PostMergeError, "GitHub PR identity differs"
        ):
            post_merge_verify.read_post_merge_proof(
                self.root,
                self.merge,
                snapshot=snapshot,
            )

    def test_github_merged_state_cannot_replace_exact_head(self):
        self.snapshot["head_sha"] = "f" * 40
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("qualification base/head" in error for error in result["errors"])
        )
        self.assertFalse((self.root / ".context/evidence/post-merge").exists())

    def test_unsigned_merge_fails_even_with_github_merged(self):
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("signature did not verify" in error for error in result["errors"])
        )
        self.assertIsNot(result.get("signature_verified"), True)

    def test_unexpected_merge_tree_fails(self):
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("tree differs" in error for error in result["errors"]), result["errors"]
        )

    def test_qualified_head_tree_mismatch_fails(self):
        self.qualification["head_tree_sha"] = "f" * 40
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("qualified head tree differs" in error for error in result["errors"])
        )

    def test_branch_cleanup_required_by_policy(self):
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("remote branch was not deleted" in error for error in result["errors"])
        )

    def test_dirty_worktree_fails(self):
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("worktree is not clean" in error for error in result["errors"])
        )

    def test_roadmap_check_failure_fails_without_proof(self):
        with mock.patch.dict(os.environ, {"FAIL_ROADMAP": "1"}):
            result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertTrue(
            any("roadmap sync check" in error for error in result["errors"])
        )
        self.assertFalse((self.root / ".context/evidence/post-merge").exists())


if __name__ == "__main__":
    unittest.main()
