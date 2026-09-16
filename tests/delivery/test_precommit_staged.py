from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PrecommitStagedContractTest(unittest.TestCase):
    def test_hooks_declare_explicit_stages(self):
        config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("stages: [pre-commit]", config)
        self.assertIn("stages: [pre-push]", config)

    def test_fast_hook_materializes_only_the_index(self):
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        function = controller.split("def precommit()", 1)[1].split("\ndef prepush()", 1)[0]
        self.assertIn('"--cached"', function)
        self.assertIn('"checkout-index"', function)
        self.assertNotIn("verify_change", function)
        self.assertIn('"gitleaks"', function)


if __name__ == "__main__":
    unittest.main()
