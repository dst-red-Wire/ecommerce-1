from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-service-policy-chain.rb"


class ServicePolicyArchitectureAuthorityTest(unittest.TestCase):
    def test_repository_service_policy_chain(self) -> None:
        env = os.environ.copy()
        env["SERVICE_POLICY_CHAIN_ROOT"] = str(ROOT)
        result = subprocess.run(
            ["ruby", str(VALIDATOR)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
