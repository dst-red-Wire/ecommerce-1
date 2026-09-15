"""Session-independent archive acquisition and capability-platform regressions.

All artifacts and destinations are temporary; HTTP is loopback-only. Platform cases
exercise contract dispatch, not native execution on machines absent from this test.
"""

import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import itertools
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from test_pr86_five_active import fixture, collections, bootstrap


class ArchiveAcquisitionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="qualification-acquire-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        archive, data = fixture(self.root)
        self.item = data["collections"][0]
        self.payload = archive.read_bytes()
        self.target = self.root / "empty-cache" / archive.name
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", str(len(owner.payload)))
                self.end_headers()
                self.wfile.write(owner.payload)

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        worker.start()

        def close():
            self.server.shutdown()
            self.server.server_close()
            worker.join(timeout=5)

        self.addCleanup(close)
        real_urlopen = collections.urllib.request.build_opener(collections.urllib.request.ProxyHandler({})).open
        expected = f"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/test-fixture-{self.item['version']}.tar.gz"

        def local_transport(request, timeout):
            self.assertEqual(expected, request.full_url)
            return real_urlopen(f"http://127.0.0.1:{self.server.server_port}/archive", timeout=timeout)

        for patch in (
            mock.patch.object(collections, "archive_path", return_value=self.target),
            mock.patch.object(collections.urllib.request, "urlopen", side_effect=local_transport),
            mock.patch.object(collections.time, "sleep"),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def acquire(self, offline=False):
        with contextlib.redirect_stdout(io.StringIO()):
            collections.acquire(self.item, offline=offline)

    def test_cold_acquisition_then_warm_offline_reuse_without_transfer(self):
        self.assertFalse(self.target.parent.exists())
        self.acquire()
        collections.validate_archive(self.item, self.target)
        before = (self.target.stat().st_ino, self.target.stat().st_mtime_ns, self.target.read_bytes())
        self.acquire(offline=True)
        self.acquire()
        self.assertEqual(before, (self.target.stat().st_ino, self.target.stat().st_mtime_ns, self.target.read_bytes()))
        self.assertEqual(["/archive"], self.requests)
        self.assertEqual([], list(self.target.parent.glob("*.part")))

    def test_corrupt_cached_archive_is_reacquired_from_locked_payload(self):
        self.acquire()
        self.target.write_bytes(b"corrupt cached artifact")
        self.acquire()
        collections.validate_archive(self.item, self.target)
        self.assertEqual(2, len(self.requests))

    def test_truncated_or_same_size_tampered_transfer_never_publishes(self):
        original = self.payload
        for payload in (original[:-1], bytes([original[0] ^ 1]) + original[1:]):
            with self.subTest(size=len(payload)):
                self.payload = payload
                self.requests.clear()
                with self.assertRaisesRegex(RuntimeError, "acquisition failed"):
                    self.acquire()
                self.assertEqual(3, len(self.requests))
                self.assertFalse(self.target.exists())
                self.assertEqual([], list(self.target.parent.glob("*.part")))

    def test_missing_archive_offline_never_uses_transport(self):
        with self.assertRaisesRegex(RuntimeError, "missing locked archive"):
            self.acquire(offline=True)
        self.assertEqual([], self.requests)
        self.assertFalse(self.target.exists())


class PlatformContractTests(unittest.TestCase):
    def test_docker_platform_matrix_rejects_uncontracted_probes_and_provisioning(self):
        data = bootstrap.load_contract()
        item = next(c for c in data["capabilities"] if c["name"] == "docker-client-installed")
        cases = list(itertools.product(data["supported"]["os"], data["supported"]["arch"]))
        cases += [("plan9", "amd64"), ("linux", "mips")]
        for system, arch in cases:
            with self.subTest(system=system, arch=arch):
                allowed = (
                    system in data["supported"]["os"]
                    and arch in data["supported"]["arch"]
                    and f"{system}/{arch}" in item["platforms"]
                )
                runner = mock.Mock(side_effect=AssertionError("platform matrix must not mutate the workstation"))
                auditor = bootstrap.Auditor(copy.deepcopy(data), runner=runner, which=lambda _: None)
                probed = []

                def check(capability, name=None):
                    probed.append(capability["name"])
                    if capability["name"] == item["name"]:
                        self.assertTrue(allowed, "unsupported Docker platform was probed")
                    return bootstrap.Result("PASS", "simulated installed capability")

                with mock.patch.object(auditor, "check", side_effect=check):
                    result = auditor.run(bootstrap=True, os_name=system, arch=arch, profile="runtime")
                self.assertEqual("PASS" if allowed else "UNSUPPORTED", result[item["name"]].state)
                self.assertEqual(allowed, item["name"] in probed)
                runner.assert_not_called()

    def test_platform_aliases_and_execution_contexts(self):
        cases = [
            ("Linux", "x86_64", "microsoft-standard-WSL2", {}, ("linux", "amd64", "wsl2")),
            ("Linux", "aarch64", "generic", {"CI": "1"}, ("linux", "arm64", "ci")),
            ("Darwin", "arm64", "darwin", {}, ("darwin", "arm64", "native")),
            ("macos", "x64", "darwin", {}, ("darwin", "amd64", "native")),
            ("Windows", "AMD64", "windows", {}, ("windows", "amd64", "native")),
            ("Linux", "x86_64", "microsoft", {"BOOTSTRAP_CONTEXT": "ci"}, ("linux", "amd64", "ci")),
        ]
        for system, arch, release, env, expected in cases:
            with (
                self.subTest(expected=expected),
                mock.patch.dict(os.environ, env, clear=True),
                mock.patch.object(bootstrap.platform, "release", return_value=release),
            ):
                self.assertEqual(expected, bootstrap.normalized_platform(system, arch))
