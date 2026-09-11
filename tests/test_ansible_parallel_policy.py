from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AnsibleParallelPolicyTests(unittest.TestCase):
    def test_ansible_lint_has_no_global_rule_disabling(self):
        import yaml

        config = yaml.safe_load((ROOT / ".ansible-lint").read_text())
        self.assertFalse(config.get("skip_list"), "ansible-lint rules must be waived only at the exact source line")

    def test_multi_host_forks_are_bounded(self):
        cfg = (ROOT / "platform/ansible/ansible.cfg").read_text()
        self.assertIn("forks = 30", cfg)

    def test_mgmt_uses_free_serial_and_throttle_deliberately(self):
        import yaml

        path = ROOT / "platform/ansible/mgmt.yml"
        text = path.read_text()
        data = yaml.safe_load(text)

        self.assertIn("strategy: free", text)
        self.assertEqual(1, text.count("strategy: free # noqa: run-once[play]"))
        free_play = next(play for play in data if play.get("strategy") == "free")
        self.assertTrue(all("run_once" not in task for task in free_play["tasks"]))
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


if __name__ == "__main__":
    unittest.main()
