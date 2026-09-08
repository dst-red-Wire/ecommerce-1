from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TektonSourceCheckoutContractTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def test_checkout_task_uses_native_git_commands_without_shell(self):
        task = self.read("platform/tekton/tasks/source-checkout.yaml")
        self.assertIn("name: ecommerce-source-checkout", task)
        self.assertEqual(5, task.count("command: [git]"))
        self.assertIn("args: [fetch, --no-tags, --depth=1, origin, $(params.base)]", task)
        self.assertIn("args: [fetch, --no-tags, --depth=2, origin, $(params.head)]", task)
        self.assertIn("args: [checkout, --detach, $(params.head)]", task)
        self.assertNotIn("script:", task)
        self.assertNotIn(".sh", task)

    def test_affected_pipeline_owns_checkout_before_classification(self):
        pipeline = self.read("platform/tekton/pipelines/affected.yaml")
        self.assertIn("- name: repo-url", pipeline)
        checkout = pipeline.index("    - name: source-checkout")
        classify = pipeline.index("    - name: classify")
        self.assertLess(checkout, classify)
        classify_block = pipeline[classify : pipeline.index("    - name: global-gates")]
        self.assertIn("runAfter: [source-checkout]", classify_block)
        self.assertIn("name: ecommerce-source-checkout", pipeline)

    def test_source_checkout_is_in_kustomization(self):
        kustomization = self.read("platform/tekton/kustomization.yaml")
        self.assertIn("tasks/source-checkout.yaml", kustomization)

    def test_ci_topology_binds_checkout_to_immutable_trigger_shas(self):
        topology = self.read("config/contracts/ci-topology.yaml")
        self.assertIn("source_checkout:", topology)
        self.assertIn("owner: tekton-affected-pipeline", topology)
        self.assertIn("base_input: immutable-commit-sha", topology)
        self.assertIn("head_input: immutable-commit-sha", topology)
        self.assertIn("exact_head_guard: repoctl-tekton-plan", topology)

    def test_trigger_readme_no_longer_lists_workspace_clone_as_missing(self):
        readme = self.read("platform/tekton/triggers/README.md")
        self.assertIn("Source checkout is already owned by `ecommerce-affected`", readme)
        self.assertNotIn("workspace/clone strategy, ingress", readme)


if __name__ == "__main__":
    unittest.main()
