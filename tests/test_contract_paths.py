from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from contract_paths import ContractPathError, machine_contract_path  # noqa: E402


class ContractPathResolutionTests(unittest.TestCase):
    def write_lock(self, root: Path, relative: str) -> None:
        (root / "architecture.lock.yaml").write_text(
            yaml.safe_dump({"machine_contracts": {"network_plan": relative}}),
            encoding="utf-8",
        )

    def test_redirected_machine_contract_is_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "config" / "alternate" / "network.yaml"
            contract.parent.mkdir(parents=True)
            contract.write_text("status: exact\n", encoding="utf-8")
            self.write_lock(root, "config/alternate/network.yaml")

            self.assertEqual(contract.resolve(), machine_contract_path(root, "network_plan"))

    def test_missing_machine_contract_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_lock(root, "config/missing.yaml")

            with self.assertRaises(ContractPathError):
                machine_contract_path(root, "network_plan")

    def test_outside_repository_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / "outside-contract.yaml"
            outside.write_text("status: exact\n", encoding="utf-8")
            try:
                self.write_lock(root, "../outside-contract.yaml")
                with self.assertRaises(ContractPathError):
                    machine_contract_path(root, "network_plan")
            finally:
                outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
