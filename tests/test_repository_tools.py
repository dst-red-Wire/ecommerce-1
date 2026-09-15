import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repository_tools", ROOT / "scripts/repository_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


class RepositoryToolsTest(unittest.TestCase):
    def test_committed_authority_pins_supported_platforms(self):
        versions = TOOLS.load_versions()
        self.assertEqual("4.53.6", versions["YQ_VERSION"])
        self.assertEqual("1.28.0", versions["OASDIFF_VERSION"])
        for tool in ("YQ", "OASDIFF"):
            for arch in ("AMD64", "ARM64"):
                key = f"{tool}_SHA256_LINUX_{arch}" + ("_TARGZ" if tool == "OASDIFF" else "")
                self.assertRegex(versions[key], r"^[0-9a-f]{64}$")

    def test_bad_cached_checksum_fails_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            cached = Path(directory) / "artifact"
            cached.write_bytes(b"wrong")
            with mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=AssertionError("no network")):
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch for cached"):
                    TOOLS._verified_cache("https://invalid.example/artifact", cached, "0" * 64)

    def test_verified_cache_is_idempotent_and_offline(self):
        payload = b"release artifact"
        expected = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            cached = Path(directory) / "artifact"
            response = mock.MagicMock()
            response.__enter__.return_value = io.BytesIO(payload)
            with mock.patch.object(TOOLS.urllib.request, "urlopen", return_value=response) as download:
                self.assertEqual(cached, TOOLS._verified_cache("https://example.invalid/artifact", cached, expected))
                self.assertEqual(cached, TOOLS._verified_cache("https://example.invalid/artifact", cached, expected))
            self.assertEqual(1, download.call_count)

    def test_wrong_installed_version_requires_reprovisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "yq"
            binary.write_text("#!/bin/sh\necho yq version v0.0.0\n", encoding="utf-8")
            binary.chmod(0o755)
            self.assertFalse(TOOLS._version_matches(binary, ["--version"], "4.53.6"))

    def test_wrong_local_version_is_reprovisioned_from_verified_cache(self):
        good = b"#!/usr/bin/env python3\nprint('yq version v4.53.6')\n"
        digest = hashlib.sha256(good).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            versions = root / "versions.env"
            versions.write_text(
                "\n".join(
                    (
                        "YQ_VERSION=4.53.6",
                        f"YQ_SHA256_LINUX_AMD64={digest}",
                        "OASDIFF_VERSION=1.28.0",
                        "OASDIFF_SHA256_LINUX_AMD64_TARGZ=" + "1" * 64,
                        "OASDIFF_BINARY_SHA256_LINUX_AMD64=" + "2" * 64,
                    )
                ),
                encoding="utf-8",
            )
            cache = root / "cache" / "yq-4.53.6-linux-amd64"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(good)
            installed = root / "bin" / "yq"
            installed.parent.mkdir(parents=True)
            installed.write_text("#!/usr/bin/env python3\nprint('yq version v0.0.0')\n", encoding="utf-8")
            installed.chmod(0o755)
            with (
                mock.patch.object(TOOLS, "TOOLS_ROOT", root),
                mock.patch.object(TOOLS, "VERSIONS_FILE", versions),
                mock.patch.object(TOOLS, "normalized_platform", return_value=("linux", "amd64")),
                mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=AssertionError("offline cache expected")),
            ):
                TOOLS.provision(("yq",))
            self.assertEqual(digest, TOOLS.sha256(installed))
            self.assertTrue(TOOLS._version_matches(installed, ["--version"], "4.53.6"))

    def test_oasdiff_archive_member_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "tool.tar.gz"
            source = Path(directory) / "oasdiff"
            source.write_bytes(b"binary")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(source, arcname="oasdiff")
            with tarfile.open(archive_path, "r:gz") as archive:
                self.assertEqual(["oasdiff"], [member.name for member in archive.getmembers()])

    def test_make_uses_checkout_tools_not_home_or_system(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        context_pack = (ROOT / "scripts/context-pack.py").read_text(encoding="utf-8")
        self.assertIn("REPOSITORY_BIN := $(CURDIR)/.tools/bin", makefile)
        self.assertIn("context: tools-yq", makefile)
        self.assertIn("nx-graph: tools-yq", makefile)
        self.assertIn("ci: tools-oasdiff", makefile)
        self.assertIn('ROOT / ".tools" / "bin" / "yq"', context_pack)
        self.assertNotIn('Path.home() / ".local" / "bin" / "yq"', context_pack)

    def test_repoctl_exposes_checkout_bin_to_direct_callers(self):
        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('REPOSITORY_BIN = ROOT / ".tools" / "bin"', repoctl)
        self.assertIn('f"{REPOSITORY_BIN}:', repoctl)


if __name__ == "__main__":
    unittest.main()
