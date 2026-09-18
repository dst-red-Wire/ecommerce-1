from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-architecture-boundaries.rb"


class ArchitectureBoundariesAuthorityTest(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["ARCHITECTURE_BOUNDARIES_ROOT"] = str(root)
        return subprocess.run(
            ["ruby", str(VALIDATOR)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def copy_contracts(self, temp_root: Path) -> None:
        shutil.copytree(ROOT / "config", temp_root / "config")
        shutil.copytree(ROOT / "contracts", temp_root / "contracts")
        shutil.copy2(ROOT / "architecture.lock.yaml", temp_root / "architecture.lock.yaml")

    def test_repository_boundaries_pass(self) -> None:
        result = self.run_validator(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_identity_authority_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="boundary-governance-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            path = root / "config/contracts/identity-boundary-policy.yaml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("authority: keycloak", "authority: spire", 1), encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("human identity authority must be keycloak", result.stderr)

    def test_rollout_split_authority_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="boundary-governance-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            path = root / "config/contracts/progressive-delivery-policy.yaml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("traffic_shift_execution: istio", "traffic_shift_execution: kong", 1), encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Istio must remain canary traffic shift authority", result.stderr)

    def test_egress_runtime_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="boundary-governance-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            path = root / "config/contracts/egress-runtime-policy.yaml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("port: 443", "port: 80", 1), encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("external egress port must be 443", result.stderr)

    def test_commerce_authority_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="boundary-governance-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            path = root / "config/contracts/commerce-transaction-policy.yaml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("authority: checkout", "authority: order", 1), encoding="utf-8")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checkout must remain transaction orchestration authority", result.stderr)


if __name__ == "__main__":
    unittest.main()
