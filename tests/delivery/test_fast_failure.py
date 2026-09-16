import importlib.util
from pathlib import Path
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FastFailureContractTest(unittest.TestCase):
    def test_preflight_precedes_expensive_governance(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        gates = source.split("def _global_gate_commands", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(gates.index('("preflight"'), gates.index('("governance"'))

    def test_preflight_checks_capabilities_and_changed_syntax(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        body = source.split("def preflight", 1)[1].split("\ndef ", 1)[0]
        for marker in ('"gitleaks"', '"go"', '"terraform"', '"ansible-playbook"', '"py_compile"', '"ruby", "-c"'):
            self.assertIn(marker, body)

    def test_tofu_only_runner_passes_preflight(self):
        spec = importlib.util.spec_from_file_location("preflight_test", ROOT / "scripts/repoctl.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with (
            mock.patch.object(module, "affected", return_value=["platform:terraform"]),
            mock.patch.object(module, "changed_paths", return_value=[]),
            mock.patch.object(module.shutil, "which", side_effect=lambda name: "/bin/tofu" if name == "tofu" else None),
            mock.patch.object(module, "require") as require,
        ):
            self.assertEqual(0, module.preflight("base", "head"))
            self.assertIn(mock.call("tofu"), require.call_args_list)
            self.assertNotIn(mock.call("terraform"), require.call_args_list)

    def test_tekton_classification_depends_on_preflight(self):
        import yaml

        task = yaml.safe_load((ROOT / "platform/tekton/tasks/affected-components.yaml").read_text())
        self.assertEqual(["preflight", "classify"], [step["name"] for step in task["spec"]["steps"]])
        pipeline = yaml.safe_load((ROOT / "platform/tekton/pipelines/affected.yaml").read_text())
        for task in pipeline["spec"]["tasks"]:
            if task["name"] in ("global-gates", "affected-component-gates"):
                self.assertEqual(["classify"], task["runAfter"])

    def test_preflight_is_in_global_timing_inventory(self):
        spec = importlib.util.spec_from_file_location("preflight_perf_test", ROOT / "scripts/performance_audit.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        timing = module.tekton_critical_path(
            [
                {"gate": "preflight", "status": "PASS", "duration_seconds": 7},
                {"gate": "governance", "status": "PASS", "duration_seconds": 5},
                {"gate": "system", "status": "PASS", "duration_seconds": 10},
            ]
        )
        self.assertEqual(12, timing["global_branch_seconds"])
        self.assertEqual(12, timing["critical_path_estimate_seconds"])


if __name__ == "__main__":
    unittest.main()
