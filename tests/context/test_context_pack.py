import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("context_pack", ROOT / "scripts/context-pack.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

class RoutingTests(unittest.TestCase):
    def test_architecture_routes_l2(self):
        self.assertEqual(MOD.route(["architecture.lock.yaml"]), "L2")
    def test_domain_routes_l1(self):
        self.assertEqual(MOD.route(["config/contracts/dependency-map.yaml"]), "L1")
    def test_local_routes_l0(self):
        self.assertEqual(MOD.route(["scripts/harmless-local-helper.sh"]), "L0")
    def test_detects_service_from_task(self):
        self.assertIn("inventory", MOD.detect_services("fix inventory reservation", []))
    def test_byte_budget(self):
        out = MOD.bounded("x" * 1000, 200)
        self.assertLessEqual(len(out.encode()), 220)
        self.assertIn("TRUNCATED", out)

if __name__ == "__main__":
    unittest.main()
