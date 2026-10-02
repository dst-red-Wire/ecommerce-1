"""Unit tests for the pure runner authority boundary; no runtime proof is issued."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scripts import runner_authority as authority


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


IMAGE_DIGEST = digest(b"unit-test-image-identity")
IMAGE = "harbor.ecommerce.local/ecommerce/runner@" + IMAGE_DIGEST
SOURCE_SHA = "a" * 40
TARGET_SHA = "b" * 40


def test_identity() -> authority.AuthorityIdentity:
    return authority.AuthorityIdentity(
        SOURCE_SHA, IMAGE, digest(b"policy"), digest(b"validator"), digest(b"toolchain")
    )


def test_binding() -> authority.ProofBinding:
    return authority.ProofBinding(
        authority.CANONICAL_REPOSITORY, 185, TARGET_SHA, "test-campaign"
    )


def proof(
    name: str, identity: authority.AuthorityIdentity, binding: authority.ProofBinding
) -> dict:
    # The fixture is in-memory unit data; it is not runtime evidence.
    return {
        "proof_name": name,
        "verdict": "PASS",
        "authority_id": identity.authority_id,
        "authority_source_sha": identity.authority_source_sha,
        "target_repository": binding.target_repository,
        "target_pr": binding.target_pr,
        "target_sha": binding.target_sha,
        "runner_image": identity.runner_image,
        "runner_image_digest": identity.runner_image_digest,
        "policy_digest": identity.policy_digest,
        "campaign_id": binding.campaign_id,
        "validator_identity": identity.validator_digest,
        "toolchain_digest": identity.toolchain_digest,
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "evidence_references": [
            {"path": f".context/runtime/{name}.json", "sha256": digest(name.encode())}
        ],
    }


def proofs(
    identity: authority.AuthorityIdentity, binding: authority.ProofBinding
) -> dict:
    return {name: proof(name, identity, binding) for name in authority.REQUIRED_PROOFS}


def verified_for_unit_test(_proof, _identity, _binding) -> bool:
    return True


class AuthorityIdentityTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_every_identity_input_invalidates_it(
        self,
    ) -> None:
        original = test_identity()
        self.assertEqual(original, test_identity())
        self.assertEqual(original.runner_image_digest, IMAGE_DIGEST)
        variants = [
            authority.AuthorityIdentity(
                "c" * 40,
                IMAGE,
                original.policy_digest,
                original.validator_digest,
                original.toolchain_digest,
            ),
            authority.AuthorityIdentity(
                SOURCE_SHA,
                "harbor.ecommerce.local/other/runner@" + IMAGE_DIGEST,
                original.policy_digest,
                original.validator_digest,
                original.toolchain_digest,
            ),
            authority.AuthorityIdentity(
                SOURCE_SHA,
                "harbor.ecommerce.local/ecommerce/runner@" + digest(b"other-image"),
                original.policy_digest,
                original.validator_digest,
                original.toolchain_digest,
            ),
            authority.AuthorityIdentity(
                SOURCE_SHA,
                IMAGE,
                digest(b"other-policy"),
                original.validator_digest,
                original.toolchain_digest,
            ),
            authority.AuthorityIdentity(
                SOURCE_SHA,
                IMAGE,
                original.policy_digest,
                digest(b"other-validator"),
                original.toolchain_digest,
            ),
            authority.AuthorityIdentity(
                SOURCE_SHA,
                IMAGE,
                original.policy_digest,
                original.validator_digest,
                digest(b"other-toolchain"),
            ),
        ]
        self.assertEqual(len({item.authority_id for item in [original, *variants]}), 7)

    def test_mutable_or_non_harbor_references_are_rejected(self) -> None:
        for image in (
            "harbor.ecommerce.local/ecommerce/runner:latest",
            "harbor.ecommerce.local/ecommerce/runner:stable@" + IMAGE_DIGEST,
            "harbor.ecommerce.local/ecommerce/runner",
            "docker.io/ecommerce/runner@" + IMAGE_DIGEST,
            "harbor.ecommerce.local/runner@" + IMAGE_DIGEST,
            "https://harbor.ecommerce.local/ecommerce/runner@" + IMAGE_DIGEST,
            "harbor.ecommerce.local/ecommerce/runner@sha256:" + "A" * 64,
        ):
            with (
                self.subTest(image=image),
                self.assertRaises(authority.RunnerAuthorityError),
            ):
                authority.AuthorityIdentity(
                    SOURCE_SHA, image, digest(b"p"), digest(b"v")
                )

    def test_registry_parameter_cannot_redirect_authority(self) -> None:
        with self.assertRaises(authority.RunnerAuthorityError):
            authority.AuthorityIdentity(
                SOURCE_SHA,
                "docker.io/ecommerce/runner@" + IMAGE_DIGEST,
                digest(b"policy"),
                digest(b"validator"),
                harbor_registry="docker.io",
            )

    def test_optional_toolchain_still_affects_fingerprint(self) -> None:
        with_toolchain = test_identity()
        without = authority.AuthorityIdentity(
            SOURCE_SHA,
            IMAGE,
            with_toolchain.policy_digest,
            with_toolchain.validator_digest,
        )
        self.assertNotEqual(without.authority_id, with_toolchain.authority_id)


class ActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = test_identity()
        self.binding = test_binding()
        self.records = proofs(self.identity, self.binding)

    def check(self, records=None, **kwargs) -> authority.ActivationResult:
        return authority.verify_activation(
            self.identity,
            self.binding,
            self.records if records is None else records,
            approved_main_sha=kwargs.get("approved_main_sha", SOURCE_SHA),
            evidence_verifier=kwargs.get("evidence_verifier", verified_for_unit_test),
        )

    def test_public_activation_never_accepts_synthetic_pass_or_stub_callback(
        self,
    ) -> None:
        callback = mock.Mock(return_value=True)
        result = self.check(evidence_verifier=callback)
        self.assertEqual(result.runner_authority, "NOT_ACTIVE")
        self.assertEqual(set(result.proof_statuses.values()), {"NOT_PROVEN"})
        self.assertIn("not implemented", " ".join(result.blockers))
        callback.assert_not_called()
        stale_main = self.check(approved_main_sha="c" * 40)
        self.assertEqual(stale_main.runner_authority, "NOT_ACTIVE")
        self.assertIn("approved main SHA", " ".join(stale_main.blockers))
        for kwargs in (
            {"evidence_verifier": None},
            {"evidence_verifier": lambda *_: False},
            {"evidence_verifier": lambda *_: True},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.check(**kwargs).runner_authority, "NOT_ACTIVE")
        missing = dict(self.records)
        missing.pop(authority.REQUIRED_PROOFS[0])
        self.assertEqual(self.check(missing).runner_authority, "NOT_ACTIVE")
        extra = {**self.records, "unrequested-proof": {}}
        self.assertEqual(self.check(extra).runner_authority, "NOT_ACTIVE")

    def test_identity_sha_campaign_and_verdict_tampering_fail_closed(self) -> None:
        mutations = {
            "authority_id": digest(b"false-authority"),
            "authority_source_sha": "c" * 40,
            "target_repository": "someone/else",
            "target_pr": 184,
            "target_sha": "c" * 40,
            "runner_image": "harbor.ecommerce.local/ecommerce/old-runner@"
            + IMAGE_DIGEST,
            "runner_image_digest": digest(b"old-image"),
            "policy_digest": digest(b"old-policy"),
            "campaign_id": "old-campaign",
            "validator_identity": digest(b"old-validator"),
            "toolchain_digest": digest(b"old-toolchain"),
            "verdict": "FAIL",
            "proof_name": "wrong-proof",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                records = proofs(self.identity, self.binding)
                records[authority.REQUIRED_PROOFS[0]][field] = value
                result = self.check(records)
                self.assertEqual(result.runner_authority, "NOT_ACTIVE")
                self.assertEqual(
                    result.proof_statuses[authority.REQUIRED_PROOFS[0]], "NOT_PROVEN"
                )

    def test_boolean_pr_does_not_match_integer_pr(self) -> None:
        records = proofs(self.identity, self.binding)
        records[authority.REQUIRED_PROOFS[0]]["target_pr"] = True
        self.assertEqual(self.check(records).runner_authority, "NOT_ACTIVE")

    def test_missing_unsafe_or_duplicate_references_fail_closed(self) -> None:
        bad_references = (
            [],
            [{"path": "../other-head.json", "sha256": digest(b"x")}],
            [{"path": "/tmp/untrusted.json", "sha256": digest(b"x")}],
            [{"path": ".context/runtime/proof.json", "sha256": "sha256:bad"}],
            [{"path": ".context/runtime/proof.json", "sha256": digest(b"x")}] * 2,
        )
        for references in bad_references:
            with self.subTest(references=references):
                records = proofs(self.identity, self.binding)
                records[authority.REQUIRED_PROOFS[1]]["evidence_references"] = (
                    references
                )
                self.assertEqual(self.check(records).runner_authority, "NOT_ACTIVE")

    def test_future_timestamp_and_exception_from_verifier_fail_closed(self) -> None:
        records = proofs(self.identity, self.binding)
        records[authority.REQUIRED_PROOFS[0]]["timestamp"] = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).isoformat()
        self.assertEqual(self.check(records).runner_authority, "NOT_ACTIVE")
        self.assertEqual(
            self.check(
                evidence_verifier=mock.Mock(side_effect=RuntimeError("unavailable"))
            ).runner_authority,
            "NOT_ACTIVE",
        )

    def test_qualification_rejects_forged_activation_and_stub_verifier(
        self,
    ) -> None:
        record = proof("exact-sha-qualification", self.identity, self.binding)
        forged_activation = authority.ActivationResult(
            "ACTIVE",
            self.identity.authority_id,
            {name: "PASS" for name in authority.REQUIRED_PROOFS},
            (),
        )
        exact_target = authority.ExactTargetBinding(
            authority.CANONICAL_REPOSITORY, 185, TARGET_SHA, TARGET_SHA, TARGET_SHA
        )
        callback = mock.Mock(return_value=True)
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "NOT_ACTIVE"):
            authority.verify_qualification_proof(
                self.identity,
                self.binding,
                record,
                activation=forged_activation,
                exact_target=exact_target,
                evidence_verifier=callback,
            )
        callback.assert_not_called()
        for changed in (
            {"target_sha": "c" * 40},
            {"campaign_id": "other-campaign"},
            {"authority_id": digest(b"false-authority")},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaises(authority.RunnerAuthorityError),
            ):
                authority.verify_qualification_proof(
                    self.identity,
                    self.binding,
                    {**record, **changed},
                    activation=forged_activation,
                    exact_target=exact_target,
                    evidence_verifier=verified_for_unit_test,
                )
        self_bound = authority.ProofBinding(
            authority.CANONICAL_REPOSITORY, 185, SOURCE_SHA, "test-campaign"
        )
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "own authority"):
            authority.verify_qualification_proof(
                self.identity,
                self_bound,
                proof("exact-sha-qualification", self.identity, self_bound),
                activation=forged_activation,
                exact_target=authority.ExactTargetBinding(
                    authority.CANONICAL_REPOSITORY,
                    185,
                    SOURCE_SHA,
                    SOURCE_SHA,
                    SOURCE_SHA,
                ),
                evidence_verifier=verified_for_unit_test,
            )
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "NOT_ACTIVE"):
            authority.verify_qualification_proof(
                self.identity,
                self.binding,
                record,
                activation=self.check(evidence_verifier=None),
                exact_target=exact_target,
                evidence_verifier=verified_for_unit_test,
            )
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "exact PR HEAD"):
            authority.verify_qualification_proof(
                self.identity,
                self.binding,
                record,
                activation=forged_activation,
                exact_target=authority.ExactTargetBinding(
                    authority.CANONICAL_REPOSITORY,
                    184,
                    TARGET_SHA,
                    TARGET_SHA,
                    TARGET_SHA,
                ),
                evidence_verifier=verified_for_unit_test,
            )


class ExactTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "checkout"
        self.root.mkdir()
        self.git("init", "-q")
        (self.root / "source.txt").write_text("target source\n", encoding="utf-8")
        self.git("add", "source.txt")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "target",
        )
        self.sha = self.git("rev-parse", "HEAD")

    def git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-C", str(self.root), *args],
            check=True,
            text=True,
            capture_output=True,
        )
        return result.stdout.strip()

    def snapshot(self, sha: str | None = None) -> dict:
        repository = authority.CANONICAL_REPOSITORY
        return {
            "number": 185,
            "state": "open",
            "draft": False,
            "head": {
                "sha": self.sha if sha is None else sha,
                "repo": {"full_name": repository},
            },
            "base": {"ref": "main", "repo": {"full_name": repository}},
        }

    def resolve(self, expected: str | None = None, reader=None):
        return authority.resolve_exact_target(
            authority.CANONICAL_REPOSITORY,
            185,
            self.sha if expected is None else expected,
            self.root,
            SOURCE_SHA,
            github_reader=reader or (lambda _repo, _pr: self.snapshot()),
        )

    def test_exact_pr_head_and_checkout_are_required(self) -> None:
        resolved = self.resolve()
        self.assertEqual(resolved.expected_sha, self.sha)
        self.assertEqual(resolved.github_pr_head_sha, self.sha)
        self.assertEqual(resolved.checked_out_sha, self.sha)
        with self.assertRaises(authority.RunnerAuthorityError):
            self.resolve(expected="c" * 40)
        with self.assertRaises(authority.RunnerAuthorityError):
            self.resolve(reader=lambda _repo, _pr: self.snapshot("c" * 40))
        (self.root / "source.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(authority.RunnerAuthorityError):
            self.resolve()

    def test_hidden_index_flags_cannot_mask_target_mutation(self) -> None:
        self.git("update-index", "--assume-unchanged", "source.txt")
        (self.root / "source.txt").write_text(
            "changed target bytes\n", encoding="utf-8"
        )
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "assume-unchanged"):
            self.resolve()

    def test_github_drift_and_self_validation_are_rejected(self) -> None:
        calls = iter((self.snapshot(), self.snapshot("c" * 40)))
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "STALE_SHA"):
            self.resolve(reader=lambda _repo, _pr: next(calls))
        with self.assertRaisesRegex(
            authority.RunnerAuthorityError, "cannot validate its own"
        ):
            authority.resolve_exact_target(
                authority.CANONICAL_REPOSITORY,
                185,
                self.sha,
                self.root,
                self.sha,
                github_reader=lambda _repo, _pr: self.snapshot(),
            )

    def test_revalidation_after_campaign_rejects_new_github_head(self) -> None:
        binding = self.resolve()
        self.assertEqual(
            authority.revalidate_exact_target(
                binding,
                self.root,
                SOURCE_SHA,
                github_reader=lambda _repo, _pr: self.snapshot(),
            ),
            binding,
        )
        with self.assertRaises(authority.RunnerAuthorityError):
            authority.revalidate_exact_target(
                binding,
                self.root,
                SOURCE_SHA,
                github_reader=lambda _repo, _pr: self.snapshot("c" * 40),
            )

    def test_authority_identity_uses_clean_committed_files(self) -> None:
        policy = self.root / "config/contracts/qualification-execution-policy.yaml"
        validator = self.root / "scripts/runner_authority.py"
        toolchain = self.root / "config/contracts/toolchain-lock.json"
        for path, content in (
            (policy, b"policy: unit fixture\n"),
            (validator, b"validator unit fixture\n"),
            (toolchain, b"{}\n"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "authority inputs",
        )
        source_sha = self.git("rev-parse", "HEAD")
        identity = authority.identity_from_trusted_checkout(
            self.root, source_sha, IMAGE
        )
        self.assertEqual(identity.policy_digest, digest(policy.read_bytes()))
        self.assertEqual(identity.validator_digest, digest(validator.read_bytes()))
        self.assertEqual(identity.toolchain_digest, digest(toolchain.read_bytes()))
        self.git(
            "update-index",
            "--assume-unchanged",
            "config/contracts/qualification-execution-policy.yaml",
        )
        policy.write_text("policy: changed\n", encoding="utf-8")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "assume-unchanged"):
            authority.identity_from_trusted_checkout(self.root, source_sha, IMAGE)
        with (
            mock.patch.object(authority, "_reject_hidden_index_flags"),
            self.assertRaisesRegex(
                authority.RunnerAuthorityError, "bytes differ from committed HEAD"
            ),
        ):
            authority.identity_from_trusted_checkout(self.root, source_sha, IMAGE)
        policy.write_bytes(b"policy: unit fixture\n")
        self.git(
            "update-index",
            "--no-assume-unchanged",
            "config/contracts/qualification-execution-policy.yaml",
        )
        self.git(
            "update-index", "--skip-worktree", "config/contracts/toolchain-lock.json"
        )
        toolchain.unlink()
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        with self.assertRaisesRegex(authority.RunnerAuthorityError, "skip-worktree"):
            authority.identity_from_trusted_checkout(self.root, source_sha, IMAGE)


class AuthorityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "runner_authority": {
                "runner_image": {
                    "registry_authority": "harbor",
                    "immutable_digest_required": True,
                    "live_pull_proof_required": True,
                },
                "activation": {
                    "required_proofs": list(authority.REQUIRED_PROOFS),
                    "pass_rule": "all",
                    "missing": "NOT_ACTIVE",
                },
                "source": {
                    "branch": "main",
                    "merged_only": True,
                    "self_validation": "forbidden",
                },
                "execution_budget": {
                    "global_timeout_required": True,
                    "subprocess_timeout_required": True,
                    "cpu_limit_required": True,
                    "memory_limit_required": True,
                    "concurrency_limit_required": True,
                    "descendants_cleanup_required": True,
                    "aggregate_cgroup_limits_required": True,
                    "pid_namespace_required": True,
                },
                "workload_secrets": "forbidden",
            }
        }

    def test_exact_contract_is_accepted_and_every_critical_field_is_enforced(
        self,
    ) -> None:
        import copy

        authority.validate_authority_contract(self.policy)
        mutations = (
            (("runner_image", "registry_authority"), "docker.io"),
            (("runner_image", "immutable_digest_required"), False),
            (("runner_image", "live_pull_proof_required"), 1),
            (
                ("activation", "required_proofs"),
                list(reversed(authority.REQUIRED_PROOFS)),
            ),
            (("activation", "pass_rule"), "any"),
            (("activation", "missing"), "PASS"),
            (("source", "branch"), "feature"),
            (("source", "merged_only"), False),
            (("source", "self_validation"), "allowed"),
            (("execution_budget", "global_timeout_required"), False),
            (("execution_budget", "subprocess_timeout_required"), False),
            (("execution_budget", "cpu_limit_required"), False),
            (("execution_budget", "memory_limit_required"), False),
            (("execution_budget", "concurrency_limit_required"), False),
            (("execution_budget", "descendants_cleanup_required"), False),
            (("execution_budget", "aggregate_cgroup_limits_required"), False),
            (("execution_budget", "pid_namespace_required"), False),
            (("workload_secrets",), "allowed"),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.policy)
                node = changed["runner_authority"]
                for part in path[:-1]:
                    node = node[part]
                node[path[-1]] = value
                with self.assertRaises(authority.RunnerAuthorityError):
                    authority.validate_authority_contract(changed)

    def test_missing_and_extra_control_keys_fail_closed(self) -> None:
        import copy

        for section, field in (
            ("runner_image", "registry_authority"),
            ("activation", "required_proofs"),
            ("source", "branch"),
            ("execution_budget", "global_timeout_required"),
        ):
            with self.subTest(section=section, field=field):
                changed = copy.deepcopy(self.policy)
                del changed["runner_authority"][section][field]
                with self.assertRaises(authority.RunnerAuthorityError):
                    authority.validate_authority_contract(changed)
        changed = copy.deepcopy(self.policy)
        changed["runner_authority"]["alternate_activation"] = {"pass_rule": "any"}
        with self.assertRaises(authority.RunnerAuthorityError):
            authority.validate_authority_contract(changed)
        with self.assertRaises(authority.RunnerAuthorityError):
            authority.validate_authority_contract({})


if __name__ == "__main__":
    unittest.main()
