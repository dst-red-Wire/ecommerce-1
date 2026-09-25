import copy
import importlib.util
from pathlib import Path
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

    def valid_ansible_evidence(self):
        digest = "sha256:" + "a" * 64
        return {
            "implementation": "ansible",
            "gate": "ansible",
            "status": "PASS",
            "observed_at": "2026-09-25T00:00:00Z",
            "source_sha": "b" * 40,
            "toolchain_digest": digest,
            "artifact_digest": digest,
            "evidence_digest": digest,
            "second_apply_changes": 0,
            "changed": 0,
            "timeout_seconds": 300,
            "retry_limit": 3,
            "capture_digest": digest,
            "restore_verification": True,
        }

    def test_canonical_policy_registry_and_runtime_evidence_pass(self):
        self.assertEqual([], REPOCTL.execution_properties_violations(self.policy, self.registry))
        self.assertEqual(
            [],
            REPOCTL.execution_evidence_violations(
                self.policy, self.registry, self.valid_ansible_evidence()
            ),
        )
        matrix = REPOCTL.execution_properties_matrix(self.registry)
        self.assertIn("| packer |", matrix)
        self.assertIn("| qce |", matrix)

    def assertEvidenceRejected(self, mutate, expected):
        evidence = self.valid_ansible_evidence()
        mutate(evidence)
        violations = REPOCTL.execution_evidence_violations(self.policy, self.registry, evidence)
        self.assertTrue(any(expected in item for item in violations), violations)

    def assertRegistryRejected(self, mutate, expected):
        registry = copy.deepcopy(self.registry)
        mutate(registry)
        violations = REPOCTL.execution_properties_violations(self.policy, registry)
        self.assertTrue(any(expected in item for item in violations), violations)

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

        self.assertRegistryRejected(mutate, "unknown")

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


if __name__ == "__main__":
    unittest.main()
