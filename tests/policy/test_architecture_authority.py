from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-service-policy-chain.rb"
EDGE_POLICY = ROOT / "config" / "contracts" / "edge-protocol-policy.yaml"


class ServicePolicyArchitectureAuthorityTest(unittest.TestCase):
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

    def copy_repository_contracts(self, temp_root: Path) -> None:
        shutil.copy2(ROOT / "architecture.lock.yaml", temp_root / "architecture.lock.yaml")
        shutil.copytree(ROOT / "config", temp_root / "config")
        shutil.copytree(ROOT / "contracts", temp_root / "contracts")

    def test_repository_service_policy_chain(self) -> None:
        result = self.run_validator(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_http1_reenable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="edge-policy-") as tmp:
            temp_root = Path(tmp)
            self.copy_repository_contracts(temp_root)
            edge = temp_root / "config" / "contracts" / "edge-protocol-policy.yaml"
            text = edge.read_text(encoding="utf-8")
            self.assertIn("    http1: false\n    http2: true\n    http3: true\n", text)
            edge.write_text(
                text.replace(
                    "    http1: false\n    http2: true\n    http3: true\n",
                    "    http1: true\n    http2: true\n    http3: true\n",
                    1,
                ),
                encoding="utf-8",
            )
            result = self.run_validator(temp_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Caddy HTTP/1 must be disabled", result.stderr)

    def test_http3_requires_udp_443_to_caddy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="edge-policy-") as tmp:
            temp_root = Path(tmp)
            self.copy_repository_contracts(temp_root)
            edge = temp_root / "config" / "contracts" / "edge-protocol-policy.yaml"
            text = edge.read_text(encoding="utf-8")
            self.assertIn("      protocol: udp\n      port: 443\n", text)
            edge.write_text(
                text.replace("      protocol: udp\n      port: 443\n", "      protocol: tcp\n      port: 443\n", 1),
                encoding="utf-8",
            )
            result = self.run_validator(temp_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HTTP/3 requires UDP/443 listener to Caddy", result.stderr)

    def test_http3_termination_before_caddy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="edge-policy-") as tmp:
            temp_root = Path(tmp)
            self.copy_repository_contracts(temp_root)
            edge = temp_root / "config" / "contracts" / "edge-protocol-policy.yaml"
            text = edge.read_text(encoding="utf-8")
            self.assertIn("    path: [internet, dns-gslb, caddy-coraza]\n", text)
            edge.write_text(
                text.replace(
                    "    path: [internet, dns-gslb, caddy-coraza]\n",
                    "    path: [internet, dns-gslb, haproxy, caddy-coraza]\n",
                    1,
                ),
                encoding="utf-8",
            )
            result = self.run_validator(temp_root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HTTP/3 QUIC path must not include haproxy as a terminating HTTP layer", result.stderr)


if __name__ == "__main__":
    unittest.main()
