import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ProductCgoRaceContract(unittest.TestCase):
    def test_service_gate_uses_explicit_cgo_race_tests(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('env["CGO_ENABLED"] = "1"', text)
        self.assertIn('["go", "test", "-race", "./..."]', text)
        self.assertIn('"-tags=integration"', text)

    def test_static_service_work_is_cached_but_runtime_tests_stay_fresh(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        policy = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("service-static:{service}", text)
        static_start = text.index("def static_checks()")
        runtime_test = text.index('["go", "test", "-race", "./..."]')
        self.assertLess(static_start, runtime_test)
        self.assertIn('run(["go", "vet", "./..."]', text[static_start:runtime_test])
        self.assertIn('run(["go", "build", "./..."]', text[static_start:runtime_test])
        declaration = policy["gates"]["service:*"]["runtime_capabilities"]
        self.assertEqual("testcontainers", declaration[0]["name"])
        self.assertEqual(
            "forbidden", policy["runtime_orchestration"]["rules"]["dynamic_state_cache"]
        )

    def test_cgo_compiler_is_reconciled_by_ansible(self):
        text = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("build-essential", text)
        self.assertRegex(text, r"tags: \[[^\]]*go[^\]]*cgo[^\]]*\]")


if __name__ == "__main__":
    unittest.main()
