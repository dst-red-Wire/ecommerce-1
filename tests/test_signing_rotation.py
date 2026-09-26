"""Rotation boundaries: dates, drift, retries and forbidden transitions."""

import sys
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


if __name__ == "__main__":
    unittest.main()
