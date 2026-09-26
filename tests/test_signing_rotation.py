"""Rotation boundaries: dates, drift, retries and forbidden transitions."""

import sys
import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
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

    def test_secret_primary_fingerprints_ignore_subkeys(self):
        a, b, c, d = (letter * 40 for letter in "ABCD")
        records = (f"sec:::::::::\nfpr:::::::::{a}:\n"
                   f"ssb:::::::::\nfpr:::::::::{b}:\n"
                   f"ssb:::::::::\nfpr:::::::::{c}:\n"
                   f"sec:::::::::\nfpr:::::::::{d}:\n")
        found = rotation.secret_primary_fingerprints(records)
        self.assertEqual(found, {a, d})
        self.assertNotIn(b, found)
        self.assertNotIn(c, found)

    def test_secret_primary_fingerprints_fail_closed_on_malformed_primary(self):
        for records in ("sec:::::::::\nssb:::::::::\nfpr:::::::::" + "B" * 40 + ":",
                        "sec:::::::::\nfpr:::::::::not-a-fingerprint:",
                        "fpr:::::::::" + "A" * 40 + ":"):
            with self.subTest(records=records), self.assertRaises(ValueError):
                rotation.secret_primary_fingerprints(records)

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

    def _activation_fixture(self, directory, old, new, previous="null"):
        lock = Path(directory) / "architecture.lock.yaml"
        lock.write_text(f"      fingerprint: {old}\n      previous_fingerprint: {previous}\n"
                        "      rotation_status: pending_remote_verification\n"
                        "      uid: Operator <operator@example.test>\n"
                        f"  automation_signing_fingerprint: {old}\n")
        signing = {"automation_key": {"uid": "Operator <operator@example.test>",
                   "forge_identity": {"git_name": "Operator", "git_email": "operator@example.test"}}}
        journal = {"old_fingerprint": old, "new_fingerprint": new, "activated": False}
        signer = {"value": old}
        saved = {}

        def run(*args):
            if args[:4] == ("git", "config", "--local", "--get"):
                return signer["value"]
            if args[:3] == ("git", "config", "--local"):
                signer["value"] = args[-1]
                return ""
            if args == ("gpgconf", "--kill", "gpg-agent"):
                return ""
            raise AssertionError(args)

        def save(data):
            saved.clear()
            saved.update(data.copy())

        return lock, signing, journal, signer, saved, run, save

    def test_activation_rolls_back_if_lock_write_fails_after_signer_switch(self):
        self._assert_activation_rollback("lock")

    def test_activation_rolls_back_if_final_state_save_fails(self):
        self._assert_activation_rollback("state")

    def _assert_activation_rollback(self, failure):
        old, new = "A" * 40, "B" * 40
        with tempfile.TemporaryDirectory() as directory:
            lock, signing, journal, signer, saved, run, save = self._activation_fixture(directory, old, new)
            original = lock.read_text()
            write_text = Path.write_text
            failed = {"value": False}

            def fail_lock(path, content, *args, **kwargs):
                if path == lock and not failed["value"]:
                    failed["value"] = True
                    self.assertEqual(signer["value"], new)
                    self.assertEqual(saved["activation"]["transition"], "activating")
                    raise OSError("injected lock failure")
                return write_text(path, content, *args, **kwargs)

            def fail_state(data):
                if data.get("activated") and not failed["value"]:
                    failed["value"] = True
                    self.assertEqual(signer["value"], new)
                    self.assertIn(f"      fingerprint: {new}\n", lock.read_text())
                    raise OSError("injected state failure")
                save(data)

            with patch.object(rotation, "ROOT", Path(directory)), \
                 patch.object(rotation, "policy", return_value=signing), \
                 patch.object(rotation, "read_state", return_value=journal), \
                 patch.object(rotation, "validate_pending"), \
                 patch.object(rotation, "remote_registration", return_value=(True, True)), \
                 patch.object(rotation, "signed_probe", return_value="probe"), \
                 patch.object(rotation, "run", side_effect=run), \
                 patch.object(rotation, "save_state", side_effect=fail_state if failure == "state" else save), \
                 patch.object(Path, "write_text", fail_lock if failure == "lock" else write_text):
                with self.assertRaisesRegex(OSError, "injected"):
                    rotation.activate()
                self.assertEqual(signer["value"], old)
                self.assertEqual(lock.read_text(), original)
                self.assertEqual(saved["activation"]["transition"], "activation_failed_recovered")
                self.assertFalse(saved["activated"])
                rotation.activate()
                self.assertEqual(signer["value"], new)
                self.assertTrue(saved["activated"])
                self.assertNotIn("activation", saved)

    def test_previous_fingerprint_tracks_immediately_replaced_key_across_two_rotations(self):
        a, b, c = (letter * 40 for letter in "ABC")
        with tempfile.TemporaryDirectory() as directory:
            lock, signing, journal, signer, saved, run, save = self._activation_fixture(directory, a, b)
            with patch.object(rotation, "ROOT", Path(directory)), \
                 patch.object(rotation, "policy", return_value=signing), \
                 patch.object(rotation, "read_state", side_effect=lambda: journal), \
                 patch.object(rotation, "validate_pending"), \
                 patch.object(rotation, "remote_registration", return_value=(True, True)), \
                 patch.object(rotation, "signed_probe", return_value="probe"), \
                 patch.object(rotation, "run", side_effect=run), \
                 patch.object(rotation, "save_state", side_effect=save):
                rotation.activate()
                self.assertIn(f"      fingerprint: {b}\n", lock.read_text())
                self.assertIn(f"      previous_fingerprint: {a}\n", lock.read_text())
                lock.write_text(lock.read_text().replace("rotation_status: active_overlap",
                                                         "rotation_status: pending_remote_verification"))
                journal = {"old_fingerprint": b, "new_fingerprint": c, "activated": False}
                rotation.activate()
                self.assertIn(f"      fingerprint: {c}\n", lock.read_text())
                self.assertIn(f"      previous_fingerprint: {b}\n", lock.read_text())
                self.assertNotIn(f"      previous_fingerprint: {a}\n", lock.read_text())

    def _candidate_fixture(self, lifespan):
        old, candidate, generated = (letter * 40 for letter in "ABC")
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        created = int((now - timedelta(days=1)).timestamp())
        uid = "Operator <operator@example.test>"
        signing = {"automation_key": {"fingerprint": old,
                   "forge_identity": {"git_name": "Operator", "git_email": "operator@example.test"}},
                   "personal_signing": {"fingerprint": "D" * 40},
                   "rotation": {"validity_days": 90}}
        details = {old: {"created": created - 100, "expires": created + 10000, "uid": [uid]},
                   candidate: {"created": created, "expires": created + lifespan, "uid": [uid]},
                   generated: {"created": created, "expires": created + 90 * 86400, "uid": [uid]}}
        calls = {"list": 0, "generate": 0, "key": []}

        def run(*args, **kwargs):
            if args[:4] == ("git", "config", "--local", "--get"):
                return old
            if args[:3] == ("gpg", "--batch", "--with-colons"):
                calls["list"] += 1
                fingerprints = [old, candidate] + ([generated] if calls["list"] > 1 else [])
                return "\n".join(f"sec:::::::::\nfpr:::::::::{f}:\n"
                                 f"ssb:::::::::\nfpr:::::::::{chr(69 + index) * 40}:"
                                 for index, f in enumerate(fingerprints))
            if "--generate-key" in args:
                calls["generate"] += 1
                return ""
            raise AssertionError(args)

        class FixedDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        return old, candidate, generated, signing, details, calls, run, FixedDatetime

    def test_reused_candidate_exactly_90_days_is_accepted(self):
        self._assert_candidate_boundary(90 * 86400, accepted=True)

    def test_reused_candidate_over_90_days_is_rejected_before_lock_write(self):
        self._assert_candidate_boundary(90 * 86400 + 1, accepted=False)

    def test_rotate_never_treats_secret_subkey_fingerprint_as_candidate(self):
        calls = self._assert_candidate_boundary(90 * 86400, accepted=True)
        self.assertEqual(calls["key"], ["A" * 40, "B" * 40, "A" * 40, "B" * 40])

    def test_generated_key_diff_uses_only_primary_fingerprints(self):
        calls = self._assert_candidate_boundary(90 * 86400 + 1, accepted=False)
        self.assertEqual(calls["generate"], 1)
        self.assertNotIn("G" * 40, calls["key"])

    def _assert_candidate_boundary(self, lifespan, *, accepted):
        old, candidate, generated, signing, details, calls, run, clock = self._candidate_fixture(lifespan)
        def checked_key(fingerprint):
            calls["key"].append(fingerprint)
            return details[fingerprint]
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(rotation, "policy", return_value=signing), \
             patch.object(rotation, "read_state", return_value=None), \
             patch.object(rotation, "run", side_effect=run), \
             patch.object(rotation, "key", side_effect=checked_key), \
             patch.object(rotation, "certificate", return_value=Path(directory) / "cert.rev"), \
             patch.object(rotation, "ensure_public_export", return_value=Path(directory) / "public.asc"), \
             patch.object(rotation, "export_public", return_value=Path(directory) / "public.asc"), \
             patch.object(rotation, "write_pending_lock") as write_lock, \
             patch.object(rotation, "save_state"), \
             patch.object(rotation, "datetime", clock):
            rotation.rotate()
        expected = candidate if accepted else generated
        write_lock.assert_called_once_with(old, expected, details[expected]["expires"])
        self.assertEqual(calls["generate"], 0 if accepted else 1)
        if not accepted:
            self.assertNotEqual(write_lock.call_args.args[1], candidate)
        self.assertFalse({"E" * 40, "F" * 40, "G" * 40}.intersection(calls["key"]))
        return calls

    def test_retirement_allowed_at_exactly_seven_days(self):
        self._assert_retirement_boundary(timedelta(days=7), allowed=True)

    def test_retirement_rejected_at_seven_days_plus_one_second(self):
        self._assert_retirement_boundary(timedelta(days=7, seconds=1), allowed=False)

    def _assert_retirement_boundary(self, elapsed, *, allowed):
        now = datetime(2026, 1, 8, tzinfo=timezone.utc)
        new = "B" * 40
        data = {"activated": True, "retired_old": False, "new_fingerprint": new,
                "activated_at": (now - elapsed).isoformat()}
        reboot = {"status": "PASS", "observed_fingerprint": new, "passphrase_prompt": "none",
                  "baseline_windows_boot_utc": "2026-01-01T00:00:00Z",
                  "observed_windows_boot_utc": "2026-01-02T00:00:00Z", "signed_commit": "a" * 40}
        signing = {"rotation": {"overlap_max_days": 7}}

        class FixedDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / ".context/reboot-proof/result.json"
            proof.parent.mkdir(parents=True)
            proof.write_text(json.dumps(reboot))
            lock = root / "architecture.lock.yaml"
            lock.write_text("      rotation_status: active_overlap\n")
            verified = SimpleNamespace(returncode=0, stdout="", stderr=f"[GNUPG:] VALIDSIG {new}\n")
            with patch.object(rotation, "ROOT", root), \
                 patch.object(rotation, "policy", return_value=signing), \
                 patch.object(rotation, "read_state", return_value=data), \
                 patch.object(rotation, "validate_pending"), \
                 patch.object(rotation.subprocess, "run", return_value=verified), \
                 patch.object(rotation, "remote_commit_proof", return_value="c" * 40), \
                 patch.object(rotation, "save_state") as save, \
                 patch.object(rotation, "datetime", FixedDatetime):
                if allowed:
                    rotation.retire_old()
                    self.assertTrue(data["retired_old"])
                    self.assertIn("rotation_status: retired", lock.read_text())
                    save.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError, "overlap deadline exceeded"):
                        rotation.retire_old()
                    self.assertIn("rotation_status: active_overlap", lock.read_text())
                    save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
