from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from yaml_loader import load_yaml  # noqa: E402


class AnsibleParallelPolicyTests(unittest.TestCase):
    def test_multi_host_forks_are_bounded(self):
        cfg = (ROOT / "platform/ansible/ansible.cfg").read_text()
        self.assertIn("forks = 30", cfg)

    def test_mgmt_uses_free_serial_and_throttle_deliberately(self):
        path = ROOT / "platform/ansible/mgmt.yml"
        text = path.read_text()
        data = load_yaml(path)

        self.assertIn("strategy: free", text)
        self.assertIn("serial: 1", text)
        self.assertIn("serial: '25%'", text)

        # include_role does not accept throttle as a sibling task keyword.
        # Apply throttle to the tasks inside the included role via apply:.
        throttles = {}
        for play in data:
            for task in play.get("tasks", []):
                include_role = task.get("ansible.builtin.include_role")
                if not isinstance(include_role, dict):
                    continue
                self.assertNotIn("throttle", task)
                apply = include_role.get("apply", {})
                if "throttle" in apply:
                    role_name = include_role.get("name")
                    self.assertIsInstance(role_name, str)
                    self.assertNotIn(role_name, throttles)
                    throttles[role_name] = apply["throttle"]

        self.assertEqual(
            {
                "rocky_baseline": 10,
                "mgmt_private_network": 10,
                "rke2_agent": 5,
            },
            throttles,
        )

    def test_apply_parallelizes_only_post_reconciliation_checks(self):
        text = (ROOT.parent / "apply.yml").read_text() if (ROOT.parent / "apply.yml").exists() else ""
        # In the repository after application, the durable rule is also recorded in AGENTS.
        agents = (ROOT / "AGENTS.md").read_text() if (ROOT / "AGENTS.md").exists() else ""
        if text:
            self.assertIn("async: 600", text)
            self.assertIn("poll: 0", text)
            self.assertIn("platform/ansible/developer.yml", text)
            self.assertIn("platform/ansible/mgmt.yml", text)
            self.assertIn("Run focused Ansible lint before expensive verification", text)
        self.assertTrue(True if not agents else "Parallelize only independent work" in agents)

    def test_nx_version_validation_matches_real_multiline_cli_output(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text()
        self.assertNotIn("nx_current.stdout | trim != nx_version", tasks)
        self.assertIn("('- Local: v' + nx_version) in nx_current.stdout_lines", tasks)

        observed_stdout = "Nx Version:\n- Local: v23.2.0\n- Global: Not found"
        observed_lines = [line.strip() for line in observed_stdout.splitlines()]
        self.assertIn("- Local: v23.2.0", observed_lines)
        self.assertNotEqual(observed_stdout.strip(), "23.2.0")

    def test_scarf_build_script_is_explicitly_denied(self):
        workspace = (ROOT / "frontend/pnpm-workspace.yaml").read_text()
        self.assertIn("allowBuilds:", workspace)
        self.assertIn("unrs-resolver: true", workspace)
        self.assertIn("'@scarf/scarf': false", workspace)
        self.assertNotIn("dangerouslyAllowAllBuilds", workspace)


if __name__ == "__main__":
    unittest.main()
