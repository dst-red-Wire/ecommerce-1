import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("templ_scope_bootstrap", ROOT / "scripts/capability_bootstrap.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class TemplScopeTests(unittest.TestCase):
    def test_exact_version_output(self):
        self.assertTrue(MODULE.templ_version_matches("v0.3.1020\n", "", "0.3.1020"))
        for output, error in [("v0.3.10201", ""), ("v0.3.1020-other", ""), ("", "v0.3.1020"), ("v0.3.1020", "warning")]:
            self.assertFalse(MODULE.templ_version_matches(output, error, "0.3.1020"))

    def test_ansible_generator_tasks_have_separate_tag(self):
        import yaml

        tasks = yaml.safe_load((ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text())
        for task in tasks:
            if "templ generator" in task.get("name", ""):
                self.assertIn("templ", task["tags"])
                self.assertNotIn("go", task["tags"])
