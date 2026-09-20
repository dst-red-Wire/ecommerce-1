from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-service-mesh-policy.rb"
POLICY = ROOT / "config" / "contracts" / "service-mesh-policy.yaml"
LOCK = ROOT / "architecture.lock.yaml"


class ServiceMeshGovernanceTest(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["SERVICE_MESH_POLICY_ROOT"] = str(root)
        return subprocess.run(
            ["ruby", str(VALIDATOR)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def copy_contracts(self, temp_root: Path) -> Path:
        (temp_root / "config" / "contracts").mkdir(parents=True)
        shutil.copy2(LOCK, temp_root / "architecture.lock.yaml")
        shutil.copy2(POLICY, temp_root / "config" / "contracts" / "service-mesh-policy.yaml")
        return temp_root / "config" / "contracts" / "service-mesh-policy.yaml"

    def test_repository_mesh_policy_passes(self) -> None:
        result = self.run_validator(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_dataplane_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-governance-") as tmp:
            temp_root = Path(tmp)
            policy_path = self.copy_contracts(temp_root)
            text = policy_path.read_text(encoding="utf-8")
            original = (
                "  catalog:\n"
                "    l7: {routing: false, authorization: false, traffic_policy: false}\n"
                "    dataplane: ztunnel-only\n"
            )
            mutated = (
                "  catalog:\n"
                "    l7: {routing: false, authorization: false, traffic_policy: false}\n"
                "    dataplane: waypoint-required\n"
            )
            self.assertIn(original, text)
            policy_path.write_text(text.replace(original, mutated, 1), encoding="utf-8")
            result = self.run_validator(temp_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("catalog: dataplane must be ztunnel-only", result.stderr)

    def test_true_l7_without_justification_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mesh-governance-") as tmp:
            temp_root = Path(tmp)
            policy_path = self.copy_contracts(temp_root)
            text = policy_path.read_text(encoding="utf-8")
            original = (
                "  product:\n"
                "    l7: {routing: false, authorization: false, traffic_policy: false}\n"
                "    dataplane: ztunnel-only\n"
            )
            mutated = (
                "  product:\n"
                "    l7: {routing: true, authorization: false, traffic_policy: false}\n"
                "    dataplane: waypoint-required\n"
            )
            self.assertIn(original, text)
            policy_path.write_text(text.replace(original, mutated, 1), encoding="utf-8")
            result = self.run_validator(temp_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("product: true L7 capability requires non-empty justification list", result.stderr)


if __name__ == "__main__":
    unittest.main()
