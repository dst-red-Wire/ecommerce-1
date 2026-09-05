import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ToolchainAutomationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads(
            (ROOT / "config/toolchain/toolchain.lock.json").read_text(encoding="utf-8")
        )
        cls.renovate = json.loads(
            (ROOT / "renovate.json").read_text(encoding="utf-8")
        )

    def test_lock_is_exact_and_has_unique_tool_ids(self):
        self.assertEqual("exact", self.lock["status"])
        ids = [tool["id"] for tool in self.lock["tools"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_reproducibility_and_authority_policies(self):
        policy = self.lock["policy"]
        self.assertTrue(policy["forbid_latest"])
        self.assertTrue(policy["cloud_mutation_requires_human_gate"])
        for tool in self.lock["tools"]:
            if tool["installer"] in {"pipx", "verified-release"}:
                self.assertRegex(tool["version"], r"^\d+\.\d+(?:\.\d+)?$")
            if tool["installer"] == "pipx":
                self.assertTrue(tool["package"].endswith(f"=={tool['version']}"))

    def test_required_capability_tools_are_owned(self):
        ids = {tool["id"] for tool in self.lock["tools"]}
        self.assertTrue(
            {"pre-commit", "molecule", "terraform", "tflint", "trivy", "checkov"}
            <= ids
        )

    def test_molecule_dependencies_are_pinned(self):
        injections = self.lock["pipx_injections"]
        self.assertIn(
            {"venv": "molecule", "package": "molecule-plugins[docker]==26.7.15"},
            injections,
        )
        self.assertIn(
            {"venv": "molecule", "package": "pytest-testinfra==10.2.2"},
            injections,
        )

    def test_nonstandard_version_commands_are_explicit(self):
        tools = {tool["id"]: tool for tool in self.lock["tools"]}
        expected = {
            "kubectl": ["version", "--client=true", "--output=yaml"],
            "helm": ["version", "--short"],
            "kustomize": ["version"],
            "kubeconform": ["-v"],
            "opa": ["version"],
        }
        for tool_id, arguments in expected.items():
            self.assertEqual(arguments, tools[tool_id]["version_args"])

    def test_renovate_never_merges(self):
        self.assertFalse(self.renovate["automerge"])
        self.assertTrue(self.renovate["dependencyDashboard"])
        self.assertIn("docker:pinDigests", self.renovate["extends"])

    def test_pre_commit_reuses_repository_gates(self):
        text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        for gate in ("ci-governance.sh", "ci-automation.sh", "ci-lint.sh", "ci-security.sh"):
            self.assertIn(gate, text)

    def test_git_hook_installation_is_an_explicit_operation(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/install-git-hooks.sh").read_text(encoding="utf-8")
        self.assertIn("hooks-install:", makefile)
        self.assertIn("pre-commit install --hook-type pre-commit", installer)

    def test_terraform_tests_cannot_apply(self):
        test_file = ROOT / "platform/terraform/environments/mgmt/tests/contracts.tftest.hcl"
        text = test_file.read_text(encoding="utf-8")
        self.assertIn("command = plan", text)
        self.assertNotIn("command = apply", text)

    def test_terraform_ip_checks_use_supported_functions(self):
        checks = (
            ROOT / "platform/terraform/environments/mgmt/checks.tf"
        ).read_text(encoding="utf-8")
        self.assertNotIn("cidrcontains(", checks)
        self.assertIn('endswith(local.mgmt_segments[segment].cidr, "/24")', checks)
        self.assertEqual(4, checks.count("cidrhost("))


if __name__ == "__main__":
    unittest.main()
