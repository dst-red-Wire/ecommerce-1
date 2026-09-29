"""The RKE2 fixture must use an observed, recent VirtualBox backend."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rke2_virtualbox_backend as backend


class Rke2VirtualBoxBackendTests(unittest.TestCase):
    def test_nem_takes_precedence_over_native_marker(self):
        self.assertEqual("NEM", backend.classify_log(
            "HM: HMR3Init: VT-x w/ nested paging\nNEM: WHvCapabilityCodeHypervisorPresent is TRUE"
        ))
        with self.assertRaisesRegex(ValueError, "unclassified"):
            backend.classify_log("VirtualBox started")

    def test_probe_binds_running_fixture_host_capacity_and_current_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "VBox.log"
            log.write_text("NEM: WHvCapabilityCodeHypervisorPresent is TRUE\n")
            info = "\r\n".join((
                'UUID="12345678-1234-1234-1234-123456789abc"',
                'VMState="running"', "cpus=4", "memory=4096",
                f'LogFldr="{temporary}"',
            ))

            def fake_run(argv):
                if argv[1] == "showvminfo":
                    return info
                if argv[1] == "--version":
                    return "7.2.18r175117"
                if argv[0] == backend.POWERSHELL:
                    return json.dumps({"hypervisor_present": True, "logical_processors": 8})
                if argv[0] == "wslpath":
                    return temporary
                raise AssertionError(argv)

            with mock.patch.object(backend, "_run", side_effect=fake_run):
                result = backend.probe(
                    "ecommerce-mgmt-test-proof", expected_cpus=4,
                    expected_memory=4096, expected_version="7.2.18",
                    minimum_log_mtime=time.time() - 1,
                )
                self.assertEqual("NEM", result["virtualbox_backend"])
                self.assertEqual(8, result["host_logical_processors"])
                with self.assertRaisesRegex(ValueError, "stale"):
                    backend.probe("ecommerce-mgmt-test-proof", expected_cpus=4,
                                  expected_memory=4096, expected_version="7.2.18",
                                  minimum_log_mtime=time.time() + 10)


if __name__ == "__main__":
    unittest.main()
