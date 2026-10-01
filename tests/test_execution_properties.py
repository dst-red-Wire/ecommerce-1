import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_execution_properties", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(REPOCTL)


class ExecutionPropertiesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.registry = REPOCTL.execution_properties_contracts(ROOT)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        lock = self.root / "config/contracts/toolchain-lock.json"
        lock.parent.mkdir(parents=True)
        lock.write_bytes((ROOT / "config/contracts/toolchain-lock.json").read_bytes())
        (self.root / ".gitignore").write_text(".context/\n", encoding="utf-8")
        for command in (
            ["git", "init", "-q"],
            ["git", "add", "."],
            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"],
        ):
            subprocess.run(command, cwd=self.root, capture_output=True, check=True)
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True,
            capture_output=True, check=True,
        ).stdout.strip()

    def valid_ansible_evidence(self):
        artifact = self.root / ".context/evidence" / self.head / "ansible.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(
            json.dumps({"source_sha": self.head, "kind": "ExecutionArtifact"}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
        evidence = {
            "implementation": "ansible",
            "gate": "ansible",
            "status": "PASS",
            "observed_at": "2026-09-25T00:00:00Z",
            "source_sha": self.head,
            "toolchain_digest": "sha256:" + hashlib.sha256(
                (self.root / "config/contracts/toolchain-lock.json").read_bytes()
            ).hexdigest(),
            "artifact_digest": digest,
            "second_apply_changes": 0,
            "changed": 0,
            "timeout_seconds": 300,
            "retry_limit": 3,
            "capture_digest": digest,
            "restore_verification": True,
        }
        evidence["evidence_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return evidence

    def test_canonical_policy_registry_and_runtime_evidence_pass(self):
        self.assertEqual([], REPOCTL.execution_properties_violations(self.policy, self.registry))
        self.assertEqual(
            [],
            REPOCTL.execution_evidence_violations(
                self.policy, self.registry, self.valid_ansible_evidence(), root=self.root
            ),
        )
        matrix = REPOCTL.execution_properties_matrix(self.registry)
        self.assertIn("| packer |", matrix)
        self.assertIn("| qce |", matrix)

    def assertEvidenceRejected(self, mutate, expected):
        evidence = self.valid_ansible_evidence()
        mutate(evidence)
        violations = REPOCTL.execution_evidence_violations(
            self.policy, self.registry, evidence, root=self.root
        )
        self.assertTrue(any(expected in item for item in violations), violations)

    def assertRegistryRejected(self, mutate, expected):
        registry = copy.deepcopy(self.registry)
        mutate(registry)
        violations = REPOCTL.execution_properties_violations(self.policy, registry)
        self.assertTrue(any(expected in item for item in violations), violations)

    def test_recovery_authority_requires_mutation_classes_and_proof_fields(self):
        for field in ("required_mutation_classes", "proof_fields", "proof_success_status"):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy["properties"]["recovery"].pop(field)
                violations = REPOCTL.execution_properties_violations(policy, self.registry)
                self.assertTrue(
                    any(f"recovery.{field}" in item for item in violations), violations
                )

    def test_recovery_authority_rejects_weakened_proof(self):
        policy = copy.deepcopy(self.policy)
        policy["properties"]["recovery"]["required_mutation_classes"].remove("production")
        policy["properties"]["recovery"]["proof_fields"].remove("recovery.restore_verification")
        policy["properties"]["recovery"]["proof_success_status"] = "DECLARED"
        violations = REPOCTL.execution_properties_violations(policy, self.registry)
        for field in ("required_mutation_classes", "proof_fields", "proof_success_status"):
            self.assertTrue(
                any(f"recovery.{field}" in item for item in violations), violations
            )

    def test_missing_source_sha_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.pop("source_sha"), "source_sha")

    def test_mutable_latest_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.update(tool_version="latest"), "mutable latest")

    def test_missing_artifact_digest_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.pop("artifact_digest"), "artifact_digest")

    def test_nonzero_second_apply_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.update(second_apply_changes=1), "second apply")

    def test_missing_runtime_evidence_declaration_fails_closed(self):
        self.assertRegistryRejected(
            lambda x: x["implementations"]["ansible"]["evidence"].update(runtime_required=False),
            "runtime evidence",
        )

    def test_static_proven_claim_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.update(completion_status="PROVEN"), "PROVEN")

    def test_unknown_tool_fails_closed(self):
        def mutate(registry):
            registry["implementations"]["mystery"] = copy.deepcopy(
                registry["implementations"]["ansible"]
            )
            registry["implementations"]["mystery"].pop("authority_ref")

        self.assertRegistryRejected(mutate, "canonical authority references")

    def test_dangling_authority_fragment_fails_closed(self):
        self.assertRegistryRejected(
            lambda registry: registry["implementations"]["harbor"].update(
                authority_ref="architecture.lock.yaml#platform.harbor"
            ),
            "unresolved canonical authority_ref",
        )

    def test_digest_shape_without_content_match_fails_closed(self):
        for field, expected in (
            ("toolchain_digest", "toolchain_digest does not match"),
            ("artifact_digest", "artifact_digest does not match"),
            ("evidence_digest", "evidence_digest does not match"),
        ):
            with self.subTest(field=field):
                self.assertEvidenceRejected(
                    lambda evidence, field=field: evidence.update({field: "sha256:" + "a" * 64}),
                    expected,
                )

    def test_source_sha_must_match_checkout(self):
        self.assertEvidenceRejected(
            lambda evidence: evidence.update(source_sha="a" * 40),
            "source_sha does not match",
        )

    def test_tampered_artifact_and_dirty_checkout_fail_closed(self):
        evidence = self.valid_ansible_evidence()
        artifact = self.root / ".context/evidence" / self.head / "ansible.json"
        artifact.write_text("tampered\n", encoding="utf-8")
        self.assertIn(
            "runtime evidence artifact_digest does not match the canonical artifact",
            REPOCTL.execution_evidence_violations(
                self.policy, self.registry, evidence, root=self.root
            ),
        )
        (self.root / "config/contracts/toolchain-lock.json").write_text("{}\n", encoding="utf-8")
        self.assertIn(
            "runtime evidence checkout contains uncommitted inputs",
            REPOCTL.execution_evidence_violations(
                self.policy, self.registry, evidence, root=self.root
            ),
        )

    def test_unknown_property_fails_closed(self):
        self.assertRegistryRejected(
            lambda x: x["implementations"]["ansible"]["relationships"].update(telepathy=["implements"]),
            "unknown property",
        )

    def test_missing_drift_mechanism_fails_closed(self):
        self.assertRegistryRejected(
            lambda x: x["implementations"]["opentofu"]["evidence"]["required_fields"].remove("drift_detected"),
            "drift detection",
        )

    def test_missing_timeout_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.pop("timeout_seconds"), "timeout")

    def test_missing_locking_fails_closed(self):
        self.assertRegistryRejected(
            lambda x: x["implementations"]["opentofu"]["evidence"]["required_fields"].remove("locking"),
            "locking",
        )

    def test_unverified_restore_fails_closed(self):
        self.assertEvidenceRejected(lambda x: x.update(restore_verification=False), "not verified")

    def test_changed_nonzero_fails_idempotence(self):
        self.assertEvidenceRejected(lambda x: x.update(changed=1), "changed is not zero")

    def test_retry_limit_must_be_a_nonnegative_integer(self):
        for value in ("forever", -2, True):
            with self.subTest(value=value):
                self.assertEvidenceRejected(
                    lambda evidence, value=value: evidence.update(retry_limit=value),
                    "nonnegative integer",
                )


if __name__ == "__main__":
    unittest.main()
