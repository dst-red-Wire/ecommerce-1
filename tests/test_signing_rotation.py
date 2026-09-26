"""Rotation boundaries: dates, drift, retries and forbidden transitions."""

import sys
import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import signing_rotation as rotation


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"info_days_before_expiry": 30, "warning_days_before_expiry": 14,
                       "delivery_block_days_before_expiry": 7}

    def test_date_boundaries(self):
        for days, verified, expected in ((31, False, "OK"), (30, False, "INFO"),
                                         (15, False, "INFO"), (14, False, "WARN"),
                                         (8, False, "WARN"), (7, False, "BLOCK"),
                                         (7, True, "WARN"), (0, True, "EXPIRED")):
            with self.subTest(days=days, verified=verified):
                self.assertEqual(rotation.classify(days, verified, self.policy), expected)

    def test_reuses_pending_key(self):
        data = {"new_fingerprint": "A" * 40, "public_key_path": "/tmp/public.asc"}
        with patch.object(rotation, "policy", return_value={}), \
             patch.object(rotation, "read_state", return_value=data), \
             patch.object(rotation, "validate_pending"), \
             patch.object(rotation, "run") as run:
            rotation.rotate()
        run.assert_not_called()

    def test_double_activation_forbidden(self):
        with patch.object(rotation, "policy", return_value={}), \
             patch.object(rotation, "read_state", return_value={"activated": True}), \
             patch.object(rotation, "validate_pending"), \
             patch.object(rotation, "remote_registration") as remote:
            with self.assertRaisesRegex(ValueError, "double activation"):
                rotation.activate()
        remote.assert_not_called()

    def test_activation_without_both_forges_forbidden(self):
        with patch.object(rotation, "policy", return_value={}), \
             patch.object(rotation, "read_state", return_value={"activated": False}), \
             patch.object(rotation, "validate_pending"), \
             patch.object(rotation, "remote_registration", return_value=(True, False)), \
             patch.object(rotation, "run") as run:
            with self.assertRaisesRegex(ValueError, "WAITING_FOR_REMOTE_KEY_REGISTRATION"):
                rotation.activate()
        run.assert_not_called()

    def test_retirement_before_activation_forbidden(self):
        with patch.object(rotation, "policy", return_value={}), \
             patch.object(rotation, "read_state", return_value={"activated": False}):
            with self.assertRaisesRegex(ValueError, "retirement before activation"):
                rotation.retire_old()

    def test_retirement_without_reboot_proof_forbidden(self):
        with patch.object(rotation, "policy", return_value={}), \
             patch.object(rotation, "read_state", return_value={"activated": True}), \
             patch.object(rotation, "validate_pending"), \
             patch.object(rotation.Path, "is_file", return_value=False):
            with self.assertRaisesRegex(ValueError, "reboot proof missing"):
                rotation.retire_old()

    def test_pending_fingerprint_mismatch(self):
        signing = {"personal_signing": {"fingerprint": "C" * 40},
                   "automation_key": {"fingerprint": "A" * 40, "pending_fingerprint": "D" * 40}}
        data = {"old_fingerprint": "A" * 40, "new_fingerprint": "B" * 40}
        with self.assertRaisesRegex(ValueError, "pending fingerprint differs"):
            rotation.validate_pending(signing, data)

    def test_missing_revocation_certificate(self):
        with patch.object(rotation, "run", return_value="/tmp/nonexistent-gpg-home"):
            with self.assertRaisesRegex(ValueError, "revocation certificate missing"):
                rotation.certificate("A" * 40)

    def test_public_export_recreated_after_tmp_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.asc"
            exported = rotation.PUBLIC + b"\nPUBLIC\n"
            with patch.object(rotation, "run", return_value=exported.decode()), \
                 patch.object(rotation, "PUBLIC", rotation.PUBLIC):
                result = rotation.ensure_public_export("A" * 40, path)
            self.assertEqual(result, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_bytes(), exported + b"\n")
            self.assertNotIn(bytes((80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89)), path.read_bytes())
            self.assertNotIn(bytes((83, 69, 67, 82, 69, 84, 32, 75, 69, 89)), path.read_bytes())

    def test_public_export_unsafe_paths_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"x")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.subTest(case="symlink"), self.assertRaisesRegex(ValueError, "unsafe"), \
                 patch.object(rotation, "run", return_value=(rotation.PUBLIC + b"\n").decode()):
                rotation.ensure_public_export("A" * 40, link)
            broad = Path(directory) / "broad"
            broad.write_bytes(rotation.PUBLIC + b"\n")
            broad.chmod(0o644)
            with self.subTest(case="broad permissions"), self.assertRaisesRegex(ValueError, "unsafe"), \
                 patch.object(rotation, "run", return_value=(rotation.PUBLIC + b"\n").decode()):
                rotation.ensure_public_export("A" * 40, broad)
            divergent = Path(directory) / "divergent"
            divergent.write_bytes(rotation.PUBLIC + b"\nOTHER\n")
            divergent.chmod(0o600)
            with self.subTest(case="divergent"), self.assertRaisesRegex(ValueError, "drift"), \
                 patch.object(rotation, "run", return_value=(rotation.PUBLIC + b"\nEXPECTED\n").decode()):
                rotation.ensure_public_export("A" * 40, divergent)

    def test_public_export_secret_material_rejected(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(rotation, "run", return_value="-----BEGIN PGP " + "".join(map(chr, (80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89))) + " BLOCK-----\n"):
            with self.assertRaisesRegex(ValueError, "invalid"):
                rotation.ensure_public_export("A" * 40, Path(directory) / "public.asc")

    def test_primary_fingerprint_ignores_subkeys(self):
        output = b"pub:::::::::\nfpr:::::::::" + b"A" * 40 + b":\nsub:::::::::\nfpr:::::::::" + b"B" * 40 + b":\nsub:::::::::\nfpr:::::::::" + b"C" * 40 + b":\n"
        process = type("Completed", (), {"returncode": 0, "stdout": output})()
        with patch.object(rotation.subprocess, "run", return_value=process):
            self.assertEqual(rotation.public_fingerprint("-----BEGIN PGP PUBLIC KEY BLOCK-----"), "A" * 40)

    def test_multiple_primary_fingerprints_rejected(self):
        output = b"pub:::::::::\nfpr:::::::::" + b"A" * 40 + b":\npub:::::::::\nfpr:::::::::" + b"B" * 40 + b":\n"
        process = type("Completed", (), {"returncode": 0, "stdout": output})()
        with patch.object(rotation.subprocess, "run", return_value=process):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                rotation.public_fingerprint("-----BEGIN PGP PUBLIC KEY BLOCK-----")

    def test_activation_retry_converges_existing_new_state(self):
        old, new = "A" * 40, "B" * 40
        data = {"old_fingerprint": old, "new_fingerprint": new, "activated": False,
                "activation": {"transition": "activating", "old_signer": old, "new_signer": new}}
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "architecture.lock.yaml"
            lock.write_text(f"      fingerprint: {new}\n")
            with patch.object(rotation, "ROOT", Path(directory)), \
                 patch.object(rotation, "policy", return_value={}), \
                 patch.object(rotation, "read_state", return_value=data), \
                 patch.object(rotation, "save_state") as save, \
                 patch.object(rotation, "run", side_effect=[new]):
                rotation.activate()
            self.assertTrue(data["activated"])
            self.assertEqual(data["old_key_status"], "overlap")
            self.assertNotIn("activation", data)
            save.assert_called_once()

    def test_overlap_boundary_is_exact(self):
        signing = {"rotation": {"overlap_max_days": 7}}
        data = {"activated": True, "retired_old": False, "new_fingerprint": "B" * 40,
                "activated_at": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()}
        with patch.object(rotation, "policy", return_value=signing), \
             patch.object(rotation, "read_state", return_value=data), \
             patch.object(rotation, "validate_pending"), \
             patch.object(Path, "is_file", return_value=False):
            with self.assertRaisesRegex(ValueError, "reboot proof missing"):
                rotation.retire_old()


if __name__ == "__main__":
    unittest.main()
