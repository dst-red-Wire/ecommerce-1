import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_controller_bootstrap", ROOT / "scripts/native_controller_bootstrap.py"
)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class NativeControllerBootstrapTest(unittest.TestCase):
    def test_payload_is_bound_to_exact_sha_and_rejects_tampering(self):
        source_sha = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "source.bundle": b"bundle",
                "bootstrap.py": b"bootstrap",
                "oras": b"oras",
                "assets/rpm-keys/rocky-10-public.asc": b"key",
                "wheels/ansible.whl": b"wheel",
            }
            digests = {}
            for relative, body in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
                digests[relative] = hashlib.sha256(body).hexdigest()
            document = {
                "schema": 1,
                "source_sha": source_sha,
                "source_branch": "feat/packer-dual-host-rocky-image-pipeline",
                "files": digests,
            }
            (root / "payload.json").write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(source_sha, BOOTSTRAP.verify_payload(root, source_sha)["source_sha"])
            with self.assertRaises(BOOTSTRAP.BootstrapError):
                BOOTSTRAP.verify_payload(root, "b" * 40)
            (root / "oras").write_bytes(b"changed")
            with self.assertRaises(BOOTSTRAP.BootstrapError):
                BOOTSTRAP.verify_payload(root, source_sha)
            (root / "oras").unlink()
            (root / "oras").symlink_to(root / "bootstrap.py")
            with self.assertRaises(BOOTSTRAP.BootstrapError):
                BOOTSTRAP.verify_payload(root, source_sha)

    def test_payload_rejects_escaping_path_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "payload"
            root.mkdir()
            outside = Path(directory) / "outside"
            outside.write_bytes(b"outside")
            digest = hashlib.sha256(b"outside").hexdigest()
            required = (
                "source.bundle", "bootstrap.py", "oras",
                "assets/rpm-keys/rocky-10-public.asc",
            )
            for name in required:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"outside")
            document = {
                "schema": 1,
                "source_sha": "a" * 40,
                "source_branch": "feat/packer-dual-host-rocky-image-pipeline",
                "files": {name: digest for name in (*required, "../outside")},
            }
            (root / "payload.json").write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(BOOTSTRAP.BootstrapError):
                BOOTSTRAP.verify_payload(root, "a" * 40)


if __name__ == "__main__":
    unittest.main()
