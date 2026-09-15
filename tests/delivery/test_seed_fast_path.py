from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SeedFastPathContractTest(unittest.TestCase):
    def test_seed_uses_lock_digest_and_pip_integrity_check(self):
        source = (ROOT / "scripts/capability_bootstrap.py").read_text(encoding="utf-8")
        body = source.split("def seed_environment", 1)[1].split("\ndef main", 1)[0]
        self.assertIn(".requirements-lock.sha256", body)
        self.assertIn('"pip", "check"', body)
        self.assertIn('"--require-hashes"', body)
        self.assertLess(body.index("if ready:"), body.index('"pip", "install"'))

    def test_context_tools_parent_is_created_by_ansible(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn('- "{{ local_share }}/tools"', tasks)


if __name__ == "__main__":
    unittest.main()
