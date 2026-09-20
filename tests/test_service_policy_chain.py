from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-service-policy-chain.rb"
class ServicePolicyChainTest(unittest.TestCase):
    def registered_machine_contracts(self) -> list[str]:
        script = (
            "require 'yaml'; require 'json'; "
            "lock=YAML.safe_load(File.read(ARGV[0]), aliases: false); "
            "registry=lock.fetch('machine_contracts'); "
            "raise 'machine_contracts must be a mapping' unless registry.is_a?(Hash); "
            "print JSON.generate(registry.values)"
        )
        result = subprocess.run(
            ["ruby", "-e", script, str(ROOT / "architecture.lock.yaml")],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = json.loads(result.stdout)
        self.assertTrue(all(isinstance(path, str) and path for path in paths))
        return sorted(set(paths))

    def copy_contracts(self, temp_root: Path) -> None:
        relatives = ["architecture.lock.yaml", *self.registered_machine_contracts()]
        for relative in relatives:
            source = ROOT / relative
            self.assertTrue(source.is_file(), relative)
            destination = temp_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["SERVICE_POLICY_CHAIN_ROOT"] = str(root)
        return subprocess.run(
            ["ruby", str(VALIDATOR)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def mutate(self, root: Path, relative: str, before: str, after: str) -> None:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(before, text)
        path.write_text(text.replace(before, after, 1), encoding="utf-8")

    def test_repository_policy_chain_passes(self) -> None:
        result = self.run_validator(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_authz_caller_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="policy-chain-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            self.mutate(root, "config/contracts/service-authz-policy.yaml", "allowed_callers: [checkout]", "allowed_callers: []")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("allowed_callers must match dependency-map callers", result.stderr)

    def test_external_egress_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="policy-chain-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            self.mutate(root, "config/contracts/egress-policy.yaml", "id: stripe", "id: unknown-psp")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("egress destinations must match sync_external", result.stderr)

    def test_waypoint_scope_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="policy-chain-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            self.mutate(root, "config/contracts/waypoint-scope.yaml", "  payment:\n    scope: service", "  checkout:\n    scope: service")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("payment: waypoint-required service must have waypoint-scope assignment", result.stderr)
            self.assertIn("checkout: ztunnel-only service must not have waypoint-scope assignment", result.stderr)

    def test_resilience_class_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="policy-chain-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            self.mutate(root, "config/contracts/service-resilience-policy.yaml", "catalog: {class: internal-read}", "catalog: {class: interactive}")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("resilience class", result.stderr)

    def test_observability_mesh_mode_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="policy-chain-") as tmp:
            root = Path(tmp)
            self.copy_contracts(root)
            self.mutate(root, "config/contracts/mesh-observability-policy.yaml", "catalog: {mesh_mode: ztunnel-only", "catalog: {mesh_mode: waypoint-required")
            result = self.run_validator(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("observability mesh_mode", result.stderr)


if __name__ == "__main__":
    unittest.main()
