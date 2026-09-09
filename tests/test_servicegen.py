import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("servicegen", ROOT / "scripts/servicegen.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class ServicegenTest(unittest.TestCase):
    # Unit-only servicegen sub-contract fixture; it is deliberately not a global architecture lock.
    def make_subcontract_root(self, milestone="M2-golden-service-product"):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        (root / "config/contracts").mkdir(parents=True)
        (root / "services").mkdir()
        (root / "architecture.lock.yaml").write_text(
            "business:\n"
            "  services: [product, inventory]\n"
            "machine_contracts:\n"
            "  public_api_contracts: config/contracts/public-api-contracts.yaml\n",
            encoding="utf-8",
        )
        (root / "config/contracts/public-api-contracts.yaml").write_text(
            f"current_milestone: {milestone}\n", encoding="utf-8"
        )
        return temp, root

    def test_m2_blocks_mutation(self):
        temp, root = self.make_subcontract_root()
        self.addCleanup(temp.cleanup)
        self.assertTrue(MOD.blocked_by_golden_milestone(root))

    def test_future_milestone_allows_generator(self):
        temp, root = self.make_subcontract_root("M3-preprod-infrastructure")
        self.addCleanup(temp.cleanup)
        self.assertFalse(MOD.blocked_by_golden_milestone(root))
        MOD.validate_service(root, "inventory")
        self.assertIn("services/inventory/go.mod", MOD.build_files("inventory"))

    def test_unknown_service_rejected(self):
        temp, root = self.make_subcontract_root()
        self.addCleanup(temp.cleanup)
        with self.assertRaises(ValueError):
            MOD.validate_service(root, "warehouse")


if __name__ == "__main__":
    unittest.main()
