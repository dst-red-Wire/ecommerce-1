from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
