from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TektonAffectedContractTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_top_level_pipeline_fans_out_only_classifier_results(self):
        pipeline = self.read("platform/tekton/pipelines/affected.yaml")
        self.assertIn("name: ecommerce-affected", pipeline)
        self.assertIn("$(tasks.classify.results.components[*])", pipeline)
        self.assertIn("name: global-gates", pipeline)
        self.assertIn("finally:", pipeline)
        self.assertIn("name: finalize-evidence", pipeline)

    def test_tekton_uses_repository_controller_not_shell_wrappers(self):
        paths = [
            "platform/tekton/tasks/affected-components.yaml",
            "platform/tekton/tasks/component-gates.yaml",
            "platform/tekton/tasks/finalize-evidence.yaml",
        ]
        for path in paths:
            content = self.read(path)
            self.assertIn("scripts/repoctl.py", content, path)
            self.assertNotIn(".sh", content, path)

    def test_ci_evidence_contract_fails_closed(self):
        contract = self.read("config/contracts/ci-evidence.yaml")
        self.assertIn("signature_required: true", contract)
        self.assertIn("verification_failure_behavior: full-reexecution", contract)
        self.assertIn("missing_remote_evidence_behavior: full-reexecution", contract)
        self.assertIn("forge_status_binds_exact_commit_sha: true", contract)


if __name__ == "__main__":
    unittest.main()
