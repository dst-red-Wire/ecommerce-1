import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_m1_review", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(REPOCTL)


class M1ReviewClosureTests(unittest.TestCase):
    def test_ansible_codegen_uses_supported_go_target(self):
        tasks = (ROOT / "platform/ansible/roles/api_codegen/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("api-generate, --target, go", tasks)
        self.assertNotIn("api-generate, --target, all", tasks)

    def test_contract_generation_propagates_codegen_failure(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        contracts = source[source.index("def contracts(") : source.index("def repository_shell_paths(")]
        self.assertIn('result = api_generate("go")', contracts)
        self.assertIn("if result:\n            return result", contracts)
        self.assertNotIn('api_generate("all")', contracts)

        with (
            mock.patch.object(REPOCTL, "require"),
            mock.patch.object(REPOCTL, "run"),
            mock.patch.object(REPOCTL, "run_ruby_tests"),
            mock.patch.object(REPOCTL, "api_generate", return_value=23) as generate,
        ):
            self.assertEqual(23, REPOCTL.contracts(generate=True))
        generate.assert_called_once_with("go")

    def test_frontend_gate_reconciles_go_and_checks_templ_drift_in_temporary_tree(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        frontend = source[source.index("def frontend(") : source.index("def site(")]
        self.assertIn('ensure_developer("go,cgo")', frontend)
        self.assertIn("TemporaryDirectory", frontend)
        self.assertIn("frontend templ generated code is stale", frontend)


if __name__ == "__main__":
    unittest.main()
