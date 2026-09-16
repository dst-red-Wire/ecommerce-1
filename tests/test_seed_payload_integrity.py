"""The trusted wheel, rather than mutable installed metadata, owns seed bytes."""

import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import capability_bootstrap as bootstrap


class SeedPayloadIntegrity(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(bootstrap, "interpreter_seed_wheels", return_value=[])
        patch.start()
        self.addCleanup(patch.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        self.seed = self.root / "seed"
        (self.seed / "bin").mkdir(parents=True)
        self.site = self.seed / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
        self.info = self.site / "sample-1.0.0.dist-info"
        self.info.mkdir(parents=True)
        self.payload = {
            "sample/__init__.py": b"value = 1\n",
            "sample-1.0.0.dist-info/METADATA": b"Name: sample\nVersion: 1.0.0\n",
            "sample-1.0.0.dist-info/entry_points.txt": b"[console_scripts]\nsample = sample:main\n",
        }
        self.wheel = self.wheels / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for path, data in self.payload.items():
                archive.writestr(path, data)
            archive.writestr("sample-1.0.0.dist-info/RECORD", "")
        digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.lock = f"sample==1.0.0 \\\n    --hash=sha256:{digest}\n"
        self.payload.update({"sample-1.0.0.dist-info/INSTALLER": b"pip\n", "sample-1.0.0.dist-info/REQUESTED": b""})
        for relative, trusted in bootstrap.seed_scaffold(self.seed).items():
            path = self.seed / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(trusted, str):
                path.symlink_to(trusted)
            else:
                path.write_bytes(trusted)
        self.install_payload()
        self.assertTrue(self.valid())

    def test_hardlinked_payload_is_rejected_even_with_expected_bytes(self):
        path = self.site / "sample/__init__.py"
        external = self.root / "external-module"
        path.rename(external)
        os.link(external, path)
        self.assertEqual(2, path.stat().st_nlink)
        self.assertFalse(self.valid())

    def test_hardlinked_wheel_is_rejected_before_it_can_define_payload(self):
        external = self.root / "external-wheel"
        os.link(self.wheel, external)
        self.assertEqual(2, self.wheel.stat().st_nlink)
        with self.assertRaisesRegex(ValueError, "regular single-link"):
            bootstrap.seed_wheels(self.wheels, self.lock)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            bootstrap.seed_wheels(self.wheels, self.lock, strict=False)
        self.assertFalse(self.valid())

    def test_group_or_world_writable_payload_is_rejected(self):
        path = self.site / "sample/__init__.py"
        for mode in (0o660, 0o666):
            with self.subTest(mode=mode):
                path.chmod(mode)
                self.assertFalse(self.valid())
        path.chmod(0o600)
        self.assertTrue(self.valid())
        self.site.chmod(0o777)
        self.assertFalse(self.valid())

    def test_payload_owned_by_another_uid_is_rejected(self):
        with mock.patch.object(bootstrap.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertFalse(self.valid())

    def test_writable_wheel_or_reference_directory_is_rejected(self):
        self.wheel.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "externally mutable"):
            bootstrap.seed_wheels(self.wheels, self.lock)
        self.wheel.chmod(0o600)
        self.wheels.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "externally mutable"):
            bootstrap.seed_wheels(self.wheels, self.lock)

    def test_mutable_tool_home_or_parent_is_refused_before_writes(self):
        cache = self.root / "mutable-cache"
        cache.mkdir()
        cache.chmod(0o777)
        for path in (cache, cache / "nested"):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "externally mutable"),
            ):
                bootstrap.validated_seed_tool_home(path)
        self.assertEqual([], list(cache.iterdir()))

    def test_seed_writes_restrictive_modes_and_restores_callers_umask(self):
        previous = os.umask(0)
        observed = []

        def prepare():
            current = os.umask(0o077)
            observed.append(current)
            return 0

        try:
            with mock.patch.object(bootstrap, "_seed_environment", side_effect=prepare):
                self.assertEqual(0, bootstrap.seed_environment())
            self.assertEqual([0o077], observed)
            self.assertEqual(0, os.umask(0))
        finally:
            os.umask(previous)

    def test_missing_tool_home_is_created_private_and_reused(self):
        configured = self.root / "new-parent/cache"
        self.assertEqual(configured, bootstrap.create_seed_tool_home(configured))
        identity = configured.stat().st_ino
        self.assertEqual(0o700, configured.stat().st_mode & 0o777)
        self.assertEqual(0o700, configured.parent.stat().st_mode & 0o777)
        self.assertEqual(configured, bootstrap.create_seed_tool_home(configured))
        self.assertEqual(identity, configured.stat().st_ino)

    def test_racing_tool_home_creator_is_checked_before_descendant_writes(self):
        configured = self.root / "raced-cache"
        original = os.mkdir

        def create(path, mode=0o777, **kwargs):
            if Path(path) == configured:
                original(path, mode, **kwargs)
                configured.chmod(0o777)
                raise FileExistsError("simulated competing root creation")
            return original(path, mode, **kwargs)

        with (
            mock.patch.object(bootstrap.os, "mkdir", side_effect=create),
            mock.patch.dict(os.environ, {"ECOMMERCE_TOOL_HOME": str(configured)}),
            self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "externally mutable"),
        ):
            bootstrap.seed_environment()
        self.assertEqual([], list(configured.iterdir()))

    def test_racing_tool_home_symlink_is_rejected_without_writing_through_it(self):
        configured = self.root / "raced-alias"
        external = self.root / "external-root"
        external.mkdir()
        original = os.mkdir

        def create(path, mode=0o777, **kwargs):
            if Path(path) == configured:
                configured.symlink_to(external, target_is_directory=True)
                raise FileExistsError("simulated symlink replacement")
            return original(path, mode, **kwargs)

        with (
            mock.patch.object(bootstrap.os, "mkdir", side_effect=create),
            mock.patch.dict(os.environ, {"ECOMMERCE_TOOL_HOME": str(configured)}),
            self.assertRaises(bootstrap.SeedGenerationBoundaryError),
        ):
            bootstrap.seed_environment()
        self.assertEqual([], list(external.iterdir()))

    def test_racing_tool_home_owner_is_rechecked_after_creation(self):
        configured = self.root / "foreign-root"
        original_mkdir = os.mkdir
        uid = os.geteuid()
        created = False

        def create(path, mode=0o777, **kwargs):
            nonlocal created
            original_mkdir(path, mode, **kwargs)
            if Path(path) == configured:
                created = True
                raise FileExistsError("simulated another UID winning creation")

        with (
            mock.patch.object(bootstrap.os, "mkdir", side_effect=create),
            mock.patch.object(bootstrap.os, "geteuid", side_effect=lambda: uid + 1 if created else uid),
            self.assertRaisesRegex(bootstrap.SeedGenerationBoundaryError, "externally mutable"),
        ):
            bootstrap.create_seed_tool_home(configured)
        self.assertEqual([], list(configured.iterdir()))

    def test_windows_acl_probe_fails_closed_and_passes_paths_only_as_data(self):
        import json

        paths = [(self.root / 'name & quoted" path', False), (self.root, True)]
        for code, output, accepted in ((0, "PRIVATE", True), (1, "", False), (0, "unexpected", False)):
            with (
                self.subTest(code=code, output=output),
                mock.patch.object(
                    bootstrap.subprocess, "run", return_value=mock.Mock(returncode=code, stdout=output)
                ) as run,
            ):
                self.assertEqual(accepted, bootstrap.seed_windows_paths_are_private(paths))
                command = run.call_args.args[0]
                self.assertIn("-EncodedCommand", command)
                self.assertFalse(any("name & quoted" in argument for argument in command))
                payload = json.loads(run.call_args.kwargs["input"])
                self.assertEqual(str(paths[0][0]), payload[0]["path"])
        with mock.patch.object(bootstrap.subprocess, "run", side_effect=OSError("unavailable ACL probe")):
            self.assertFalse(bootstrap.seed_windows_paths_are_private(paths))

    def test_checkout_reference_repairs_ordinary_file_and_directory(self):
        reference = self.root / "checkout/.venv/qualification"
        reference.parent.mkdir(parents=True)
        with mock.patch.object(bootstrap, "LOCAL_SEED_VENV", reference):
            for kind in ("file", "directory"):
                with self.subTest(kind=kind):
                    if kind == "file":
                        reference.write_text("stale bootstrap")
                    else:
                        reference.mkdir()
                        (reference / "stale").write_text("old environment")
                    bootstrap.publish_checkout_reference(self.seed)
                    self.assertEqual(self.seed, reference.resolve())
                    reference.unlink()
        quarantined = list(reference.parent.glob("*.quarantine"))
        self.assertEqual(1, len(quarantined))
        self.assertEqual("old environment", (quarantined[0] / "stale").read_text())

    def test_invalid_selector_directory_is_replaced_without_following_contents(self):
        selector = self.root / "identity.current"
        selector.mkdir()
        external = self.root / "keep"
        external.write_text("external data")
        (selector / "external").symlink_to(external)
        temporary = self.root / "candidate"
        temporary.symlink_to(self.seed, target_is_directory=True)
        with mock.patch.object(bootstrap.shutil, "rmtree", side_effect=AssertionError("unsafe recursive cleanup")):
            bootstrap.replace_seed_directory_reference(temporary, selector)
        quarantined = list(self.root.glob("*.quarantine"))
        self.assertEqual(1, len(quarantined))
        self.assertTrue((quarantined[0] / "external").is_symlink())
        self.assertEqual(self.seed, selector.resolve())
        self.assertEqual("external data", external.read_text())
        self.assertFalse(temporary.exists())

    def test_invalid_selector_is_restored_when_publication_fails(self):
        selector = self.root / "identity.current"
        selector.mkdir()
        (selector / "stale").write_text("recoverable")
        temporary = self.root / "candidate"
        temporary.symlink_to(self.seed, target_is_directory=True)
        original = os.replace

        def replace(source, destination):
            if source == temporary:
                raise OSError("publication failed")
            return original(source, destination)

        with mock.patch.object(bootstrap.os, "replace", side_effect=replace):
            with self.assertRaisesRegex(OSError, "publication failed"):
                bootstrap.replace_seed_directory_reference(temporary, selector)
        self.assertEqual("recoverable", (selector / "stale").read_text())
        self.assertTrue(temporary.is_symlink())

    def test_windows_junction_publication_needs_no_symlink_privilege(self):
        import types

        reference = self.root / "checkout/.venv/qualification"
        replacement = self.root / "replacement"
        replacement.mkdir()
        calls = []

        def junction(target, link):
            calls.append((target, link))
            os.symlink(target, link, target_is_directory=True)

        with (
            mock.patch.object(bootstrap, "seed_windows", return_value=True),
            mock.patch.dict(sys.modules, {"_winapi": types.SimpleNamespace(CreateJunction=junction)}),
            mock.patch.object(bootstrap, "LOCAL_SEED_VENV", reference),
            mock.patch.object(Path, "symlink_to", side_effect=PermissionError("no symlink privilege")),
        ):
            bootstrap.publish_checkout_reference(self.seed)
            bootstrap.publish_checkout_reference(replacement)
        self.assertEqual(2, len(calls))
        self.assertEqual(replacement, reference.resolve())
        self.assertTrue(self.seed.is_dir())

    def test_windows_reference_swap_failure_restores_published_generation(self):
        import types

        reference = self.root / "checkout/.venv/qualification"
        replacement = self.root / "replacement"
        replacement.mkdir()
        original_replace = os.replace

        def replace(source, destination):
            if str(source).endswith(".tmp") and destination == reference:
                raise OSError("simulated junction rename failure")
            return original_replace(source, destination)

        with (
            mock.patch.object(bootstrap, "seed_windows", return_value=True),
            mock.patch.dict(
                sys.modules,
                {
                    "_winapi": types.SimpleNamespace(
                        CreateJunction=lambda target, link: os.symlink(target, link, target_is_directory=True)
                    )
                },
            ),
            mock.patch.object(bootstrap, "LOCAL_SEED_VENV", reference),
        ):
            bootstrap.publish_checkout_reference(self.seed)
            with mock.patch.object(bootstrap.os, "replace", side_effect=replace):
                with self.assertRaisesRegex(OSError, "simulated junction"):
                    bootstrap.publish_checkout_reference(replacement)
        self.assertEqual(self.seed, reference.resolve())
        self.assertTrue(replacement.is_dir())
        self.assertEqual(["qualification"], sorted(path.name for path in reference.parent.iterdir()))

    def test_symlinked_tool_home_or_ancestor_is_rejected_before_writes(self):
        external = self.root / "external-cache"
        external.mkdir()
        alias = self.root / "cache-alias"
        alias.symlink_to(external, target_is_directory=True)
        for configured in (alias, alias / "nested"):
            with (
                self.subTest(configured=configured),
                mock.patch.dict(os.environ, {"ECOMMERCE_TOOL_HOME": str(configured)}),
            ):
                with self.assertRaises(bootstrap.SeedGenerationBoundaryError):
                    bootstrap.seed_environment()
            self.assertEqual([], list(external.iterdir()))

    def test_activation_script_tampering_is_rejected(self):
        (self.seed / "bin/activate").write_text("echo compromised\n")
        self.assertFalse(self.valid())

    def test_external_python_symlink_is_rejected(self):
        python = self.seed / "bin/python"
        python.unlink()
        python.symlink_to(self.root / "untrusted-python")
        self.assertFalse(self.valid())

    def test_venv_configuration_tampering_is_rejected(self):
        config = self.seed / "pyvenv.cfg"
        config.write_text(
            config.read_text().replace("include-system-site-packages = false", "include-system-site-packages = true")
        )
        self.assertFalse(self.valid())

    def test_checkout_parent_symlink_cannot_write_outside(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        external = self.root / "external"
        external.mkdir()
        (checkout / ".venv").symlink_to(external, target_is_directory=True)
        with mock.patch.object(bootstrap, "LOCAL_SEED_VENV", checkout / ".venv/qualification"):
            with self.assertRaises(bootstrap.SeedGenerationBoundaryError):
                bootstrap.publish_checkout_reference(self.seed)
        self.assertEqual([], list(external.iterdir()))

    def install_payload(self):
        from pip._internal.operations.install.wheel import PipScriptMaker

        maker = PipScriptMaker(None, str(self.seed / "bin"))
        maker.executable = str(self.seed / "bin/python")
        maker.variants = {""}
        maker.clobber = True
        maker.set_mode = True
        launcher = Path(maker.make("sample = sample:main")[0])
        self.payload[os.path.relpath(launcher, self.site)] = launcher.read_bytes()
        rows = []
        for relative, data in self.payload.items():
            path = self.site / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            rows.append([relative, "sha256=" + digest, str(len(data))])
        rows.append(["sample-1.0.0.dist-info/RECORD", "", ""])
        output = io.StringIO()
        csv.writer(output).writerows(rows)
        (self.info / "RECORD").write_text(output.getvalue())

    def valid(self):
        return bootstrap.validate_seed_payload(self.seed, self.wheels, self.lock)

    def test_intact_offline_reuse(self):
        self.assertTrue(self.valid())
        self.assertTrue(self.valid())

    def test_modified_module_even_with_updated_record(self):
        (self.site / "sample/__init__.py").write_bytes(b"value = 2\n")
        self.assertFalse(self.valid())
        record = self.info / "RECORD"
        record.write_text(record.read_text().replace("sample/__init__.py", "sample/other.py"))
        self.assertFalse(self.valid())

    def test_missing_module(self):
        (self.site / "sample/__init__.py").unlink()
        self.assertFalse(self.valid())

    def test_metadata_and_record_tampering(self):
        for name in ("METADATA", "RECORD", "INSTALLER"):
            with self.subTest(name=name):
                path = self.info / name
                old = path.read_bytes()
                path.write_bytes(b"untrusted\n")
                self.assertFalse(self.valid())
                path.write_bytes(old)

    def test_unexpected_payloads(self):
        for relative in ("sample/injected.py", "injected.pth", "extra.py", "sample/extra.pyc"):
            with self.subTest(relative=relative):
                path = self.site / relative
                path.write_bytes(b"untrusted\n")
                self.assertFalse(self.valid())
                path.unlink()

    def test_missing_or_modified_reference(self):
        original = self.wheel.read_bytes()
        self.wheel.write_bytes(b"invalid archive")
        self.assertFalse(self.valid())
        self.wheel.unlink()
        self.assertFalse(self.valid())
        self.wheel.write_bytes(original)
        self.assertTrue(self.valid())

    def test_generated_bytecode_is_verified(self):
        import py_compile

        source = self.site / "sample/__init__.py"
        bytecode = Path(py_compile.compile(str(source), doraise=True))
        self.assertTrue(self.valid())
        bytecode.write_bytes(bytecode.read_bytes()[:16] + b"corrupt")
        self.assertFalse(self.valid())

    def test_generated_entrypoint_requires_execution_permission(self):
        launcher = self.seed / "bin/sample"
        launcher.chmod(0o644)
        self.assertFalse(self.valid())
        launcher.chmod(0o755)
        self.assertTrue(self.valid())

    def test_installer_specific_script_template(self):
        from pip._internal.operations.install.wheel import PipScriptMaker

        # Models installer overrides such as pip 26, independently of the
        # distlib base template shipped by the test interpreter's pip.
        template = "# pip installer override\n" + PipScriptMaker.script_template
        with mock.patch.object(PipScriptMaker, "script_template", template):
            self.install_payload()
            self.assertTrue(self.valid())

    def test_arbitrary_python_alias_is_not_scaffold(self):
        alias = self.seed / "bin/untrusted-python"
        alias.symlink_to(sys.executable)
        self.assertFalse(self.valid())

    def test_wheel_tags_must_match_running_interpreter(self):
        incompatible = self.wheels / "sample-1.0.0-cp999-cp999-any.whl"
        self.wheel.rename(incompatible)
        self.assertFalse(self.valid())
        with self.assertRaisesRegex(ValueError, "incomplete"):
            bootstrap.seed_wheels(self.wheels, self.lock, strict=False)

    def test_clean_reference_recovery_filters_extras_duplicates_and_invalid_wheels(self):
        shutil.copyfile(self.wheel, self.wheels / "sample-1.0.0-1-py3-none-any.whl")
        shutil.copyfile(self.wheel, self.wheels / "sample-1.0.0-cp999-cp999-any.whl")
        (self.wheels / "extra-1.0.0-py3-none-any.whl").write_bytes(b"untrusted")
        (self.wheels / "invalid.whl").write_bytes(b"untrusted")
        self.assertFalse(self.valid())
        candidate = self.root / "candidate"
        candidate.mkdir()
        self.assertTrue(bootstrap.copy_seed_reference(self.wheels, candidate, self.lock))
        self.assertEqual(1, len(list(candidate.iterdir())))
        bootstrap.publish_seed_reference(candidate, self.wheels)
        self.assertTrue(self.valid())
        self.assertFalse(candidate.exists())

    def test_invalid_wheel_directory_is_quarantined_without_recursive_cleanup(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        shutil.copyfile(self.wheel, candidate / self.wheel.name)
        external = self.wheels / "mounted-child"
        external.mkdir()
        (external / "preserve").write_text("external mount contents")
        with mock.patch.object(bootstrap.shutil, "rmtree", side_effect=AssertionError("mount traversal")):
            bootstrap.publish_seed_reference(candidate, self.wheels)
        self.assertTrue(self.valid())
        quarantined = list(self.root.glob("*.quarantine"))
        self.assertEqual(1, len(quarantined))
        self.assertEqual("external mount contents", (quarantined[0] / "mounted-child/preserve").read_text())

    def test_failed_reference_publication_restores_previous_directory(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        shutil.copyfile(self.wheel, candidate / self.wheel.name)
        real_replace = os.replace

        def fail_publication(source, target):
            if source == candidate:
                raise OSError("controlled reference publication failure")
            return real_replace(source, target)

        with mock.patch.object(bootstrap.os, "replace", side_effect=fail_publication):
            with self.assertRaisesRegex(OSError, "controlled"):
                bootstrap.publish_seed_reference(candidate, self.wheels)
        self.assertTrue(self.valid())
        self.assertTrue(candidate.exists())

    def test_reference_path_replaced_by_file_can_be_repaired(self):
        candidate = self.root / "candidate"
        self.wheels.rename(candidate)
        self.wheels.write_bytes(b"corrupted reference")
        bootstrap.publish_seed_reference(candidate, self.wheels)
        self.assertTrue(self.valid())


class GeneratedLauncherIntegrity(unittest.TestCase):
    def test_only_installation_timestamps_can_differ(self):
        stream = io.BytesIO(b"synthetic launcher and shebang\n")
        stream.seek(0, 2)
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("__main__.py", "print('trusted')\n")
        expected = stream.getvalue()
        actual = bytearray(expected)
        with zipfile.ZipFile(io.BytesIO(expected)) as archive:
            offsets = (archive.getinfo("__main__.py").header_offset + 10, archive.start_dir + 12)
        for offset in offsets:
            actual[offset : offset + 4] = b"abcd"
        self.assertTrue(bootstrap.seed_launcher_matches(bytes(actual), expected))
        actual[0] ^= 1
        self.assertFalse(bootstrap.seed_launcher_matches(bytes(actual), expected))
        self.assertFalse(bootstrap.seed_launcher_matches(expected + b"injected", expected))
