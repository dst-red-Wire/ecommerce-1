from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProductCgoRaceContract(unittest.TestCase):
    def test_product_gate_reconciles_cgo_before_race_tests(self):
        text = (ROOT / "scripts/ci-product.sh").read_text()
        self.assertIn("./scripts/ensure-cgo-toolchain.sh", text)
        self.assertIn("CGO_ENABLED=1 go test -race ./...", text)
        self.assertIn(
            "CGO_ENABLED=1 go test -race -tags=integration ./internal/infrastructure/postgres -count=1",
            text,
        )

    def test_cgo_reconciler_uses_distro_build_toolchain(self):
        text = (ROOT / "scripts/ensure-cgo-toolchain.sh").read_text()
        self.assertIn("command -v cc", text)
        self.assertIn("build-essential", text)
        self.assertIn("CGO_ENABLED=1 go env CGO_ENABLED", text)
        self.assertNotIn("go env -w CGO_ENABLED", text)

    def test_workstation_bootstrap_keeps_c_compiler_reproducible(self):
        text = (ROOT / "scripts/bootstrap-workstation.sh").read_text()
        self.assertIn("build-essential", text)


if __name__ == "__main__":
    unittest.main()
