"""Artifact reuse is decided by verified bytes and semantic image inputs."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rocky_box_catalog as catalog


class RockyBoxCatalogTests(unittest.TestCase):
    def test_verified_box_reused_and_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "build" / "rocky-10.2-rke2-virtualbox.box"
            artifact.parent.mkdir()
            artifact.write_bytes(b"verified virtualbox fixture")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            inputs = {"packer_template_digest": "a" * 64, "inputs_digest": "b" * 64}
            (artifact.parent / "packer.log").write_text("Packer build PASS\n", encoding="utf-8")
            manifest = {
                "schema": 1,
                "box_filename": artifact.name,
                "box_sha256": digest,
                "box_size_bytes": artifact.stat().st_size,
                "packer_log_sha256": catalog.digest_file(artifact.parent / "packer.log"),
                "source_sha": "f" * 40,
                "source_tree_sha": "e" * 40,
                "rocky_version": "10.2",
                "virtualbox_version": "7.2.18",
                "native_vtx": "PASS",
                "nem_detected": False,
                "packer_build": "PASS",
                "build_timestamp": "2026-09-26T21:12:32.4291380Z",
                "staging_manifest_sha256": "c" * 64,
                **inputs,
            }
            (artifact.parent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (artifact.parent / "SHA256SUMS").write_text(f"{digest}  {artifact.name}\n", encoding="utf-8")
            with (patch.object(catalog, "build_inputs", return_value=inputs),
                  patch.object(catalog, "image_identity", return_value=("10.2", artifact.name, "7.2.18")),
                  patch.object(catalog, "source_tree", return_value="e" * 40)):
                self.assertEqual(catalog.verify(artifact, "f" * 40)["box_sha256"], digest)
                self.assertEqual(catalog.find_matching_box("f" * 40, root), artifact)
                for key, bad in (("rocky_version", "9.8"), ("native_vtx", "NOT_EXECUTED"),
                                 ("nem_detected", True), ("packer_build", "FAIL"),
                                 ("source_tree_sha", "f" * 40), ("virtualbox_version", "7.2.17")):
                    with self.subTest(key=key):
                        changed = {**manifest, key: bad}
                        (artifact.parent / "manifest.json").write_text(json.dumps(changed), encoding="utf-8")
                        with self.assertRaises(ValueError):
                            catalog.verify(artifact, "f" * 40)
                (artifact.parent / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with (patch.object(catalog, "build_inputs", return_value={**inputs, "inputs_digest": "c" * 64}),
                  patch.object(catalog, "image_identity", return_value=("10.2", artifact.name, "7.2.18")),
                  patch.object(catalog, "source_tree", return_value="e" * 40)):
                with self.assertRaisesRegex(ValueError, "inputs changed"):
                    catalog.verify(artifact, "f" * 40)
                with self.assertRaisesRegex(ValueError, "found 0"):
                    catalog.find_matching_box("f" * 40, root)
            artifact.write_bytes(b"tampered virtualbox fixture")
            with (patch.object(catalog, "build_inputs", return_value=inputs),
                  patch.object(catalog, "image_identity", return_value=("10.2", artifact.name, "7.2.18")),
                  patch.object(catalog, "source_tree", return_value="e" * 40)):
                with self.assertRaisesRegex(ValueError, "digest is invalid"):
                    catalog.verify(artifact, "f" * 40)
                with self.assertRaisesRegex(ValueError, "found 0"):
                    catalog.find_matching_box("f" * 40, root)


if __name__ == "__main__":
    unittest.main()
