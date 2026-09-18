"""Native Linux regressions and explicitly simulated Windows/Darwin API boundaries."""

import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import capability_bootstrap as bootstrap


class SeedPlatformBoundaries(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX ownership and simulated Darwin ACL discovery")
    def test_discovery_checks_candidate_owner_and_extended_acl_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            untrusted = root / "untrusted"
            untrusted.mkdir()
            candidate = untrusted / "python3"
            candidate.write_text("must never execute")
            candidate.chmod(0o755)
            trusted = root / "trusted"
            trusted.mkdir()
            expected = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
            (trusted / "python3").symlink_to(expected)
            environment = {"PATH": f"{untrusted}:{trusted}"}
            original = Path.lstat

            def foreign_owner(path):
                info = original(path)
                if path == candidate:
                    values = list(info)
                    values[4] = os.geteuid() + 10000
                    return os.stat_result(values)
                return info

            with mock.patch.object(Path, "lstat", foreign_owner), mock.patch.object(bootstrap.subprocess, "run") as run:
                self.assertEqual(str(expected), bootstrap.select_seed_python(root, environment))
                run.assert_not_called()
            with (
                mock.patch.object(bootstrap.sys, "platform", "darwin"),
                mock.patch.object(bootstrap, "seed_darwin_acl_is_private", side_effect=lambda path: path != candidate),
                mock.patch.object(bootstrap.subprocess, "run") as run,
            ):
                self.assertEqual(str(expected), bootstrap.select_seed_python(root, environment))
                run.assert_not_called()

    def test_system_directory_comes_from_secure_os_api(self):
        kernel = mock.Mock()

        def directory(buffer, capacity):
            self.assertEqual(32768, capacity)
            buffer.value = r"C:\Windows\System32"
            return len(buffer.value)

        kernel.GetSystemDirectoryW.side_effect = directory
        with mock.patch.object(bootstrap.ctypes, "WinDLL", return_value=kernel, create=True) as load:
            self.assertEqual(r"C:\Windows\System32", str(bootstrap.seed_windows_system_directory()))
        load.assert_called_once_with("kernel32.dll", use_last_error=True, winmode=0x800)
        for size in (0, 32768, 99999):
            with mock.patch.object(bootstrap.ctypes, "WinDLL", return_value=kernel, create=True):
                kernel.GetSystemDirectoryW.side_effect = None
                kernel.GetSystemDirectoryW.return_value = size
                with self.assertRaises(OSError):
                    bootstrap.seed_windows_system_directory()

    def test_windows_acl_does_not_execute_systemroot_or_module_path_overrides(self):
        trusted = Path("/trusted/Windows/System32")
        with (
            mock.patch.dict(
                os.environ,
                {
                    "SystemRoot": "/attacker",
                    "SYSTEMROOT": "/other-attacker",
                    "windir": "/attacker",
                    "PSModulePath": "/attacker/modules",
                },
            ),
            mock.patch.object(bootstrap, "seed_windows_system_directory", return_value=trusted),
            mock.patch.object(
                bootstrap.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="PRIVATE")
            ) as run,
        ):
            self.assertTrue(bootstrap.seed_windows_paths_are_private([(Path("/private"), False)]))
        self.assertEqual(str(trusted / "WindowsPowerShell/v1.0/powershell.exe"), run.call_args.args[0][0])
        environment = run.call_args.kwargs["env"]
        self.assertEqual(str(trusted.parent), environment["SystemRoot"])
        self.assertEqual(str(trusted / "WindowsPowerShell/v1.0/Modules"), environment["PSModulePath"])
        self.assertNotIn("SYSTEMROOT", environment)
        with (
            mock.patch.object(bootstrap, "seed_windows_system_directory", side_effect=OSError("unavailable")),
            mock.patch.object(bootstrap.subprocess, "run") as run,
        ):
            self.assertFalse(bootstrap.seed_windows_paths_are_private([(Path("/private"), False)]))
            run.assert_not_called()

    def darwin_api(self, entries, *, terminal_errno=errno.EINVAL):
        api = mock.Mock()
        api.acl_get_link_np.return_value = 123
        api.acl_valid.return_value = 0
        api.acl_free.return_value = 0
        cursor = iter(entries)
        current = None

        def entry(_acl, _index, output):
            nonlocal current
            current = next(cursor, None)
            if current is None:
                ctypes.set_errno(terminal_errno)
                return -1
            output._obj.value = 456
            return 0

        def tag(_entry, output):
            output._obj.value = current[0]
            return 0

        def permissions(_entry, output):
            output._obj.value = current[1]
            return 0

        api.acl_get_entry.side_effect = entry
        api.acl_get_tag_type.side_effect = tag
        api.acl_get_permset_mask_np.side_effect = permissions
        return api

    def test_darwin_acl_refuses_each_write_grant_and_accepts_read_or_deny(self):
        cases = [([], True), ([(2, 0xFFFF)], True), ([(1, (1 << 1) | (1 << 3))], True), ([(3, 0)], False)]
        cases += [([(1, 1 << bit)], False) for bit in (2, 4, 5, 6, 8, 10, 12, 13)]
        for entries, accepted in cases:
            with self.subTest(entries=entries):
                api = self.darwin_api(entries)
                with mock.patch.object(bootstrap.ctypes, "CDLL", return_value=api) as load:
                    self.assertEqual(accepted, bootstrap.seed_darwin_acl_is_private(Path("/private")))
                load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
                api.acl_get_link_np.assert_called_once_with(os.fsencode("/private"), 0x100)
                api.acl_free.assert_called_once_with(123)

    def test_darwin_acl_errors_fail_closed(self):
        for kind in ("unreadable", "invalid", "iterator", "tag", "permissions"):
            with self.subTest(kind=kind):
                api = self.darwin_api([(1, 0)], terminal_errno=errno.EIO if kind == "iterator" else errno.EINVAL)
                if kind == "unreadable":
                    api.acl_get_link_np.return_value = None
                elif kind == "invalid":
                    api.acl_valid.return_value = -1
                elif kind in ("tag", "permissions"):
                    function = api.acl_get_tag_type if kind == "tag" else api.acl_get_permset_mask_np
                    function.side_effect = None
                    function.return_value = -1
                with mock.patch.object(bootstrap.ctypes, "CDLL", return_value=api):
                    self.assertFalse(bootstrap.seed_darwin_acl_is_private(Path("/private")))
        with mock.patch.object(bootstrap.ctypes, "CDLL", side_effect=OSError("unavailable")):
            self.assertFalse(bootstrap.seed_darwin_acl_is_private(Path("/private")))

    @unittest.skipUnless(os.name == "posix", "POSIX mode fixture for simulated Darwin ACL")
    def test_mode_private_file_still_requires_darwin_acl_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            path.write_text("valid bytes")
            path.chmod(0o600)
            with (
                mock.patch.object(bootstrap.sys, "platform", "darwin"),
                mock.patch.object(bootstrap, "seed_darwin_acl_is_private", return_value=False) as acl,
            ):
                self.assertFalse(bootstrap.seed_path_is_private(path))
                acl.assert_called_once_with(path)

    @unittest.skipUnless(os.name == "posix", "Native POSIX lock object regressions")
    def test_identity_lock_rejects_directory_fifo_link_and_shared_permissions_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lock"
            lock.mkdir()
            with mock.patch.object(bootstrap.os, "open") as opened:
                with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "regular file"):
                    with bootstrap.identity_lock(lock):
                        self.fail("Directory lock acquired")
                opened.assert_not_called()
            lock.rmdir()
            os.mkfifo(lock)
            with mock.patch.object(bootstrap.os, "open") as opened:
                with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "regular file"):
                    with bootstrap.identity_lock(lock):
                        self.fail("FIFO lock acquired")
                opened.assert_not_called()
            lock.unlink()
            target = root / "target"
            target.write_text("unchanged")
            lock.symlink_to(target)
            with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "regular file"):
                with bootstrap.identity_lock(lock):
                    self.fail("Linked lock acquired")
            self.assertEqual("unchanged", target.read_text())
            lock.unlink()
            with bootstrap.identity_lock(lock):
                self.assertTrue(lock.is_file())
            lock.chmod(0o666)
            with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "private regular"):
                with bootstrap.identity_lock(lock):
                    self.fail("Mutable lock acquired")

    @unittest.skipUnless(os.name == "posix", "Native POSIX lock inode regression")
    def test_identity_lock_rejects_hardlink_and_replaced_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lock"
            target = root / "target"
            target.write_text("protected")
            os.link(target, lock)
            with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "private regular"):
                with bootstrap.identity_lock(lock):
                    self.fail("Hardlinked lock acquired")
            lock.unlink()
            real_open = os.open

            def replace_after_open(path, flags, mode):
                descriptor = real_open(path, flags, mode)
                Path(path).rename(root / "original-lock")
                Path(path).write_text("replacement")
                return descriptor

            with mock.patch.object(bootstrap.os, "open", side_effect=replace_after_open):
                with self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "private regular"):
                    with bootstrap.identity_lock(lock):
                        self.fail("Replaced lock inode acquired")
            self.assertEqual("protected", target.read_text())
            self.assertEqual("replacement", lock.read_text())

    def test_real_pinned_ansible_module_invokes_main_and_prints_exact_version(self):
        root = Path(__file__).resolve().parents[1]
        python = root / ".venv/qualification" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.is_file():
            self.skipTest("real canonical seed unavailable")
        expected = bootstrap.load_versions()["ANSIBLE_CORE_VERSION"]
        result = subprocess.run(
            [str(python), "-I", "-B", "-m", "ansible.cli.adhoc", "--version"],
            check=True,
            text=True,
            capture_output=True,
        )
        self.assertIn(f"[core {expected}]", result.stdout.splitlines()[0])
        bootstrap.verify_seed_ansible_version(python, expected)


if __name__ == "__main__":
    unittest.main()
