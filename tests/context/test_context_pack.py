import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("context_pack", ROOT / "scripts/context-pack.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class RoutingTests(unittest.TestCase):
    def test_architecture_task_routes_l2_even_without_diff(self):
        self.assertEqual(MOD.route("change Tekton control-plane", []), "L2")

    def test_domain_task_routes_l1_even_without_diff(self):
        self.assertEqual(MOD.route("add product OpenAPI operation", []), "L1")

    def test_local_helper_routes_l0(self):
        self.assertEqual(MOD.route("fix local helper", ["scripts/harmless-local-helper.py"]), "L0")

    def test_detects_service_from_task(self):
        self.assertIn("inventory", MOD.detect_services("fix inventory reservation", []))

    def test_service_contract_contains_reverse_consumers_and_public_api(self):
        contract = json.loads(MOD.service_contract("product"))
        self.assertIn("direct_sync_consumers", contract)
        self.assertIn("public_api", contract)

    def test_byte_budget(self):
        out = MOD.bounded("x" * 1000, 200)
        self.assertLessEqual(len(out.encode()), 200)
        self.assertIn("TRUNCATED", out)


if __name__ == "__main__":
    unittest.main()
