from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from architecture_authority import load_yaml


class M1ServiceSkeletonTests(unittest.TestCase):
    def test_every_canonical_service_owns_migrations_tests_and_container_build(self):
        lock = load_yaml(ROOT / "architecture.lock.yaml")
        for name in lock["business"]["services"]:
            service = ROOT / "services" / name
            with self.subTest(service=name):
                self.assertTrue((service / "go.mod").is_file())
                self.assertTrue((service / "migrations").is_dir())
                self.assertTrue((service / "tests").is_dir())
                self.assertTrue(
                    (service / "Containerfile").is_file() or (service / "Dockerfile").is_file()
                )


if __name__ == "__main__":
    unittest.main()
