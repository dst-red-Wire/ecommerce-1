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
