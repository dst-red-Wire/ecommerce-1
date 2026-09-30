"""Artifact reuse is decided by verified bytes and semantic image inputs."""

from __future__ import annotations

import copy
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
                  patch.object(catalog, "semantic_build_inputs", return_value=inputs),
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
                  patch.object(catalog, "semantic_build_inputs", return_value=inputs),
                  patch.object(catalog, "image_identity", return_value=("10.2", artifact.name, "7.2.18")),
                  patch.object(catalog, "source_tree", return_value="e" * 40)):
                with self.assertRaisesRegex(ValueError, "inputs changed"):
                    catalog.verify(artifact, "f" * 40)
                with self.assertRaisesRegex(ValueError, "found 0"):
                    catalog.find_matching_box("f" * 40, root)
            artifact.write_bytes(b"tampered virtualbox fixture")
            with (patch.object(catalog, "build_inputs", return_value=inputs),
                  patch.object(catalog, "semantic_build_inputs", return_value=inputs),
                  patch.object(catalog, "image_identity", return_value=("10.2", artifact.name, "7.2.18")),
                  patch.object(catalog, "source_tree", return_value="e" * 40)):
                with self.assertRaisesRegex(ValueError, "digest is invalid"):
                    catalog.verify(artifact, "f" * 40)
                with self.assertRaisesRegex(ValueError, "found 0"):
                    catalog.find_matching_box("f" * 40, root)

    def test_legacy_manifest_accepts_unrelated_tool_removal_but_rejects_image_tool_change(self) -> None:
        original_sha, current_sha = "1" * 40, "2" * 40
        contract = (catalog.ROOT / "config/contracts/machine-image-lock.yaml").read_bytes()
        current_lock = json.loads((catalog.ROOT / catalog.TOOLCHAIN_LOCK).read_text(encoding="utf-8"))
        original_lock = copy.deepcopy(current_lock)
        original_lock["versions"]["IPERF3_VERSION"] = "3.16"
        original_lock["tools"]["iperf3"] = {"version_ref": "IPERF3_VERSION"}

        def source_file(sha: str, relative: str) -> bytes:
            if relative == catalog.TOOLCHAIN_LOCK:
                return json.dumps(original_lock if sha == original_sha else current_lock).encode("utf-8")
            if relative == "config/contracts/machine-image-lock.yaml":
                return contract
            return f"unchanged:{relative}".encode("utf-8")

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(catalog, "source_file", side_effect=source_file), \
                patch.object(catalog, "source_tree", return_value="e" * 40):
            root = Path(temporary)
            artifact = root / "build" / "rocky-10.2-rke2-virtualbox.box"
            artifact.parent.mkdir()
            artifact.write_bytes(b"native verified box")
            (artifact.parent / "packer.log").write_text("Packer build PASS\n", encoding="utf-8")
            historical = catalog.build_inputs(original_sha)
            self.assertNotEqual(historical["inputs_digest"], catalog.build_inputs(current_sha)["inputs_digest"])
            self.assertEqual(catalog.semantic_build_inputs(original_sha),
                             catalog.semantic_build_inputs(current_sha))
            manifest = {
                "schema": 1, "source_sha": original_sha, "source_tree_sha": "e" * 40,
                "rocky_version": "10.2", "virtualbox_version": "7.2.18",
                "native_vtx": "PASS", "nem_detected": False, "packer_build": "PASS",
                "build_timestamp": "2026-09-26T21:12:32.4291380Z",
                "box_filename": artifact.name, "box_sha256": catalog.digest_file(artifact),
                "box_size_bytes": artifact.stat().st_size,
                "staging_manifest_sha256": "c" * 64,
                "packer_log_sha256": catalog.digest_file(artifact.parent / "packer.log"),
                **historical,
            }
            manifest_path = artifact.parent / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (artifact.parent / "SHA256SUMS").write_text(
                f"{manifest['box_sha256']}  {artifact.name}\n", encoding="utf-8"
            )
            retained_manifest = manifest_path.read_bytes()
            self.assertEqual(catalog.find_matching_box(current_sha, root), artifact)
            self.assertEqual(manifest_path.read_bytes(), retained_manifest)

            current_lock["versions"]["KUBE_BENCH_VERSION"] = "99.0.0"
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                catalog.verify(artifact, current_sha)
            with self.assertRaisesRegex(ValueError, "found 0"):
                catalog.find_matching_box(current_sha, root)

            current_lock["versions"]["KUBE_BENCH_VERSION"] = original_lock["versions"]["KUBE_BENCH_VERSION"]
            current_lock["versions"]["PACKER_VERSION"] = "99.0.0"
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                catalog.verify(artifact, current_sha)

            current_lock["versions"]["PACKER_VERSION"] = original_lock["versions"]["PACKER_VERSION"]
            current_lock["tools"]["kube-bench"] = []
            with self.assertRaisesRegex(ValueError, "toolchain tool kube-bench must be an object"):
                catalog.verify(artifact, current_sha)

    def test_malformed_catalog_entries_fail_closed_without_hiding_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "build" / "manifest.json"
            manifest.parent.mkdir()
            manifest.write_text("[]", encoding="utf-8")
            with patch.object(catalog, "semantic_build_inputs", return_value={}):
                with self.assertRaisesRegex(ValueError, "found 0"):
                    catalog.find_matching_box("f" * 40, root)
                with patch.object(Path, "read_text", side_effect=PermissionError("access denied")):
                    with self.assertRaises(PermissionError):
                        catalog.find_matching_box("f" * 40, root)
            with self.assertRaisesRegex(ValueError, "box manifest must be an object"):
                catalog.verify(root / "build" / "box.box", "f" * 40)

        contract = (catalog.ROOT / "config/contracts/machine-image-lock.yaml").read_bytes()
        with patch.object(catalog, "source_file", side_effect=lambda _sha, relative:
                          b"[]" if relative == catalog.TOOLCHAIN_LOCK else contract):
            with self.assertRaisesRegex(ValueError, "toolchain lock must be an object"):
                catalog.semantic_build_inputs("f" * 40)
        with patch.object(catalog, "source_file", return_value=b"packer_image: []"):
            with self.assertRaisesRegex(ValueError, "Packer image must be an object"):
                catalog.semantic_build_inputs("f" * 40)


if __name__ == "__main__":
    unittest.main()
