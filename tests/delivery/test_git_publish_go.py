from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GoToolchainDeliveryTests(unittest.TestCase):
    def test_go_toolchain_is_pinned(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text()
        self.assertIn("GO_VERSION=1.26.6", versions)
        self.assertIn(
            "GO_SHA256_LINUX_AMD64=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89",
            versions,
        )

    def test_publish_repairs_go_before_doctor(self):
        script = (ROOT / "scripts/git-publish.sh").read_text()
        ensure = script.index("./scripts/ensure-go-toolchain.sh")
        doctor = script.index("make workstation-doctor")
        self.assertLess(ensure, doctor)

    def test_publish_runs_contracts_and_tests(self):
        script = (ROOT / "scripts/git-publish.sh").read_text()
        self.assertIn("make contracts", script)
        self.assertIn("make test", script)

    def test_go_module_is_product_only_for_m2a(self):
        modules = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.glob("services/*/go.mod"))
        self.assertEqual(modules, ["services/product/go.mod"])

    def test_product_service_claims_postgres_as_authoritative_persistence(self):
        readme = (ROOT / "services/product/README.md").read_text()
        self.assertIn("The authoritative runtime store is PostgreSQL.", readme)
        self.assertIn("Memory mode must be selected explicitly.", readme)


if __name__ == "__main__":
    unittest.main()
