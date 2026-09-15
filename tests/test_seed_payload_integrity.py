"""The trusted wheel, rather than mutable installed metadata, owns seed bytes."""

import base64
import csv
import hashlib
import io
from pathlib import Path
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
        }
        self.wheel = self.wheels / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for path, data in self.payload.items():
                archive.writestr(path, data)
            archive.writestr("sample-1.0.0.dist-info/RECORD", "")
        digest = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.lock = f"sample==1.0.0 \\\n    --hash=sha256:{digest}\n"
        self.payload.update({"sample-1.0.0.dist-info/INSTALLER": b"pip\n", "sample-1.0.0.dist-info/REQUESTED": b""})
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
        self.assertTrue(self.valid())

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
