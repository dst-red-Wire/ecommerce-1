import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

BOOT_SPEC = importlib.util.spec_from_file_location("m1_residual_bootstrap", ROOT / "scripts/capability_bootstrap.py")
BOOT = importlib.util.module_from_spec(BOOT_SPEC)
assert BOOT_SPEC and BOOT_SPEC.loader
sys.modules[BOOT_SPEC.name] = BOOT
BOOT_SPEC.loader.exec_module(BOOT)

CTL_SPEC = importlib.util.spec_from_file_location("m1_residual_repoctl", ROOT / "scripts/repoctl.py")
CTL = importlib.util.module_from_spec(CTL_SPEC)
assert CTL_SPEC and CTL_SPEC.loader
CTL_SPEC.loader.exec_module(CTL)


class M1ResidualTest(unittest.TestCase):
    def test_templ_version_requires_exact_clean_output(self):
        version = BOOT.load_versions()["TEMPL_VERSION"]
        self.assertTrue(BOOT.templ_version_matches(f"v{version}\n", "", version))
        self.assertFalse(BOOT.templ_version_matches(f"templ version v{version}\n", "", version))
        self.assertFalse(BOOT.templ_version_matches(f"v{version}0\n", "", version))
        self.assertFalse(BOOT.templ_version_matches(f"v{version}\n", "warning\n", version))

    @unittest.skipIf(os.name == "nt", "POSIX ownership/mode regression")
    def test_seed_path_rejects_replaceable_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            self.assertTrue(BOOT.seed_path_is_private(safe))
            safe.chmod(0o777)
            self.assertFalse(BOOT.seed_path_is_private(safe))
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            self.assertFalse(BOOT.seed_path_is_private(link))

    def test_evidence_freshness_is_bounded_and_schema_is_exact(self):
        self.assertTrue(CTL._supported_evidence_schema({"schema_version": 5}, 5))
        for bad in (None, "5", True, 5.0, 6):
            self.assertFalse(CTL._supported_evidence_schema({"schema_version": bad}, 5))
        self.assertTrue(CTL._fresh_evidence({"created_at_epoch": time.time()}))
        self.assertFalse(CTL._fresh_evidence({"created_at_epoch": time.time() - 90000}))
        self.assertFalse(CTL._fresh_evidence({"created_at_epoch": time.time() + 60}))
        self.assertFalse(CTL._fresh_evidence({"created_at_epoch": float("nan")}))

    def test_prepush_reuses_only_canonical_exact_validation(self):
        evidence = ROOT / ".context/evidence/example.json"
        with (
            mock.patch.object(CTL, "git", return_value="h"),
            mock.patch.object(CTL, "_valid_exact_evidence", return_value=evidence) as validate,
            mock.patch.object(CTL, "verify_change") as verify,
        ):
            self.assertEqual(0, CTL.prepush())
            validate.assert_called_once_with("origin/main", "h")
            verify.assert_not_called()

    def test_prepush_requalifies_rejected_evidence(self):
        with (
            mock.patch.object(CTL, "git", return_value="h"),
            mock.patch.object(CTL, "_valid_exact_evidence", return_value=None),
            mock.patch.object(CTL, "verify_change", return_value=1) as verify,
        ):
            self.assertEqual(1, CTL.prepush())
            verify.assert_called_once_with("origin/main", "h")

    def test_capability_contract_contains_managed_templ_frontend_gate(self):
        contract = json.loads((ROOT / "config/toolchain/capabilities.json").read_text(encoding="utf-8"))
        templ = next(item for item in contract["capabilities"] if item["name"] == "templ")
        self.assertEqual("managed", templ["classification"])
        self.assertEqual("TEMPL_VERSION", templ["version_key"])
        self.assertEqual("ansible", contract["provision_owners"]["templ"])
        self.assertIn("templ", contract["gate_requirements"]["frontend"])

    def test_make_seed_uses_isolated_python_mode(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("$(PYTHON) -I -S scripts/capability_bootstrap.py seed", makefile)


if __name__ == "__main__":
    unittest.main()
