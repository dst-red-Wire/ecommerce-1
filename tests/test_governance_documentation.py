import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class GovernanceDocumentationTest(unittest.TestCase):
    def test_agent_policy_has_one_shell_authority_model(self):
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("Repeatable or stateful workstation and host changes belong to Ansible.", text)
        self.assertIn("Stateless repository orchestration belongs to `scripts/repoctl.py`.", text)
        self.assertNotIn("Write portable POSIX `sh`", text)
        self.assertNotIn("repository shell helpers", text)

    def test_active_docs_do_not_restore_legacy_automation(self):
        checks = {
            "README.md": r"scripts/ci-\*\.sh",
            "docs/project/CODEX_HANDOFFS.md": r"shared POSIX `sh` helpers|shared repository scripts factored",
            "docs/api/README.md": r"bootstrap CI Woodpecker",
        }
        for relative, forbidden in checks.items():
            with self.subTest(relative=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIsNone(re.search(forbidden, text, flags=re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
