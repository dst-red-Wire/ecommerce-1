from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TektonTriggerRuntimePrerequisiteTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_runtime_contract_is_fail_closed_and_runtime_values_are_not_faked(self):
        contract = self.read("config/contracts/tekton-trigger-runtime.yaml")
        self.assertIn("status: exact-prerequisites", contract)
        self.assertIn("pipelines: tekton.dev/v1", contract)
        self.assertIn("triggers: triggers.tekton.dev/v1beta1", contract)
        self.assertIn("immutable_digest_required: true", contract)
        self.assertIn("registry_authority: harbor", contract)
        self.assertIn("source: openbao-via-eso", contract)
        self.assertIn("plaintext_in_git_forbidden: true", contract)
        self.assertIn("default_deny_required: true", contract)
        self.assertIn("trigger_manifests: blocked-until-prerequisites-proven", contract)
        self.assertIn("static_contract_is_runtime_proof: false", contract)
        self.assertNotIn("namespace: tekton-pipelines", contract)
        self.assertNotIn("harbor.example", contract)

    def test_ci_topology_references_the_runtime_contract(self):
        topology = self.read("config/contracts/ci-topology.yaml")
        self.assertIn(
            "runtime_prerequisites_contract: config/contracts/tekton-trigger-runtime.yaml",
            topology,
        )


if __name__ == "__main__":
    unittest.main()
