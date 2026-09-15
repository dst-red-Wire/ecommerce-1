"""Payload/generation and Docker boundary regressions for the five active findings."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from test_ansible_collections import COLLECTION_MOD as collections
from test_docker_product_preflight import REPOCTL as ctl
from test_capability_bootstrap import MOD as bootstrap


def fixture(root):
    """A checksum-locked archive with Galaxy's actual file/symlink representation."""
    archive = root / "fixture.tar.gz"
    contents = {
        "MANIFEST.json": json.dumps(
            {"collection_info": {"namespace": "test", "name": "fixture", "version": "1.0.0", "dependencies": {}}}
        ).encode(),
        "FILES.json": b'{"files":[]}',
        "plugins/module.py": b"original payload\n",
    }
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ["plugins"]:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            bundle.addfile(info)
        for name, content in contents.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            bundle.addfile(info, io.BytesIO(content))
        info = tarfile.TarInfo("plugins/alias.py")
        info.type = tarfile.SYMTYPE
        info.linkname = "module.py"
        bundle.addfile(info)
    item = {
        "name": "test.fixture",
        "version": "1.0.0",
        "dependencies": {},
        "size": archive.stat().st_size,
        "sha256": collections.digest(archive),
    }
    data = {"installer": {"ansible_core": "2.19.8"}, "collections": [item]}
    return archive, data


class CollectionIntegrityGenerationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive, self.data = fixture(self.root)
        for patcher in [
            mock.patch.object(collections, "TOOL_HOME", self.root / "tools"),
            mock.patch.object(collections, "load_lock", return_value=self.data),
            mock.patch.object(collections, "archive_path", return_value=self.archive),
            mock.patch.object(
                collections,
                "installer_provenance",
                return_value={"ansible_core": "2.19.8", "executable": "/locked/ansible-galaxy"},
            ),
        ]:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.destination = collections.paths()[1]

    def extracted(self, command, **kwargs):
        destination = Path(command[command.index("--collections-path") + 1]) / "ansible_collections/test/fixture"
        destination.mkdir(parents=True)
        with tarfile.open(self.archive) as bundle:
            bundle.extractall(destination, filter="data")
        return subprocess.CompletedProcess(command, 0)

    def prepare(self):
        with mock.patch.object(collections.subprocess, "run", side_effect=self.extracted):
            collections.prepare(offline=True)
        return collections.selected_path()

    def test_payload_and_inventory_corruption_repair_preserves_readers(self):
        for corruption in (
            "deleted",
            "modified",
            "inventory",
            "both",
            "escape",
            "type",
            "extra-file",
            "extra-dir",
            "bytecode",
        ):
            with self.subTest(corruption=corruption):
                old = self.prepare()
                payload = old / "ansible_collections/test/fixture/plugins/module.py"
                inventory = payload.parent.parent / "FILES.json"
                late_file = payload.parent.parent / "MANIFEST.json"
                late_contents = late_file.read_bytes()
                if corruption == "deleted":
                    payload.unlink()
                if corruption in ("modified", "both"):
                    payload.write_text("corrupt")
                if corruption in ("inventory", "both"):
                    inventory.write_text('{"files":[],"forged":true}')
                if corruption == "escape":
                    payload.unlink()
                    payload.symlink_to(self.root / "outside")
                if corruption == "type":
                    payload.unlink()
                    payload.mkdir()
                if corruption == "extra-file":
                    (payload.parent / "unverified.py").write_text("unverified plugin")
                if corruption == "extra-dir":
                    (payload.parent / "unverified").mkdir()
                if corruption == "bytecode":
                    (payload.parent / "__pycache__").mkdir()
                    (payload.parent / "__pycache__/module.cpython-312.pyc").write_bytes(b"unverified")
                self.assertFalse(collections.installed_ok(self.data, old))
                new = self.prepare()
                self.assertNotEqual(old, new)
                self.assertEqual(late_contents, late_file.read_bytes())
                self.assertTrue(old.is_dir())
                self.assertTrue(collections.installed_ok(self.data, new))

    def test_warm_reuse_does_not_acquire_or_install(self):
        old = self.prepare()
        with mock.patch.object(collections, "acquire") as acquire, mock.patch.object(collections, "install") as install:
            collections.prepare(offline=True)
        acquire.assert_not_called()
        install.assert_not_called()
        self.assertEqual(old, collections.selected_path())

    def test_failed_candidate_and_interrupted_preparation_preserve_published_tree(self):
        old = self.prepare()
        (old / "ansible_collections/test/fixture/plugins/module.py").unlink()
        generations = old.parent
        interrupted = generations / "generation-interrupted"
        interrupted.mkdir()
        before = set(generations.iterdir())
        with mock.patch.object(
            collections.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "installer")
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                collections.prepare(offline=True)
        self.assertEqual(before, set(generations.iterdir()))
        self.assertEqual(old, collections.selected_path())
        selector = self.destination.with_suffix(".current")
        selector.with_name(f".{selector.name}.{os.getpid()}.tmp").symlink_to(interrupted)
        self.assertNotEqual(old, self.prepare())
        self.assertTrue(interrupted.exists())

    def test_legacy_migration_keeps_assigned_paths_and_other_identities(self):
        new = self.prepare()
        selector = self.destination.with_suffix(".current")
        selector.unlink()
        shutil.copytree(new, self.destination, symlinks=True)
        legacy = collections.selected_path()
        other = self.destination.parent / "other-identity"
        other.mkdir()
        (legacy / "ansible_collections/test/fixture/plugins/module.py").unlink()
        self.assertNotEqual(legacy, self.prepare())
        self.assertTrue((legacy / "ansible_collections/test/fixture/MANIFEST.json").is_file())
        self.assertTrue(other.is_dir())

    def test_missing_or_invalid_archive_fails_offline(self):
        self.prepare()
        for content in (b"invalid", None):
            if content is None:
                self.archive.unlink(missing_ok=True)
            else:
                self.archive.write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, "missing locked archive"):
                collections.prepare(offline=True)


class DockerConfigurationTests(unittest.TestCase):
    def test_invalid_urls_are_rejected_before_daemon_calls(self):
        for endpoint in (
            "tcp://user:synthetic-secret@host:abc",
            "tcp://host:-1",
            "tcp://host:65536",
            "tcp://user:synthetic-secret@[broken:2376",
        ):
            with self.subTest(endpoint=endpoint), mock.patch.object(ctl, "run") as run:
                with self.assertRaises(ctl.DockerCapabilityError) as raised:
                    ctl.docker_preflight("docker", {"DOCKER_HOST": endpoint})
                self.assertNotIn("synthetic-secret", str(raised.exception))
                run.assert_not_called()
                self.assertNotIn("synthetic-secret", ctl._safe_docker_detail(endpoint, {"DOCKER_HOST": endpoint}))

    def test_real_gate_entry_reports_controlled_failure(self):
        with (
            mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://user:synthetic-secret@[broken"}),
            mock.patch.object(ctl, "ensure_developer"),
            mock.patch.object(ctl, "canonical_services", return_value=["product"]),
            mock.patch.object(ctl.shutil, "which", return_value="/docker"),
            mock.patch.object(ctl, "run") as run,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = ctl.service_check("product")
            self.assertEqual(2, result)
            self.assertIn("PLATFORM NOT CAPABLE", output.getvalue())
            self.assertNotIn("Traceback", output.getvalue())
            self.assertNotIn("synthetic-secret", output.getvalue())
            run.assert_not_called()

    def test_supported_endpoints(self):
        for endpoint in (
            "unix:///run/docker.sock",
            "tcp://daemon:2376",
            "https://[2001:db8::1]:2376",
            "ssh://user@daemon:22",
        ):
            env, identity = ctl.docker_test_environment(
                "docker",
                {
                    "DOCKER_HOST": endpoint,
                    "TESTCONTAINERS_HOST_OVERRIDE": "daemon",
                    "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.1",
                },
            )
            self.assertEqual(endpoint, env["DOCKER_HOST"])
            self.assertNotIn("user@", identity)

    def test_audit_uses_runtime_selected_client_and_pin(self):
        contract = bootstrap.load_contract()
        auditor = bootstrap.Auditor(contract)
        item = next(x for x in contract["capabilities"] if x["name"] == "docker-client-installed")
        expected = bootstrap.load_versions()["DOCKER_CLIENT_VERSION"]
        for output, rc, state in [
            (f"Docker version {expected}, build test", 0, "PASS"),
            ("Docker version 1.0.0, build test", 0, "FAIL"),
            ("invalid", 126, "FAIL"),
        ]:
            with (
                mock.patch.object(auditor, "resolve_repoctl_runtime", return_value="/selected/docker"),
                mock.patch.object(
                    auditor, "runner", return_value=subprocess.CompletedProcess([], rc, output, "")
                ) as run,
            ):
                self.assertEqual(state, auditor.check(item).state)
                self.assertEqual(["/selected/docker", "--version"], run.call_args.args[0])
        with mock.patch.object(auditor, "resolve_repoctl_runtime", return_value=None):
            self.assertEqual("FAIL", auditor.check(item).state)


class DockerSelectedPathTests(unittest.TestCase):
    def test_multiple_clients_do_not_hide_selected_version_drift(self):
        contract = bootstrap.load_contract()
        item = next(x for x in contract["capabilities"] if x["name"] == "docker-client-installed")
        version = bootstrap.load_versions()["DOCKER_CLIENT_VERSION"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            managed, system = root / "managed", root / "system"
            for folder, value in ((managed, "1.0.0"), (system, version)):
                folder.mkdir()
                binary = folder / "docker"
                binary.write_text(f"#!/usr/bin/python3\nprint('Docker version {value}, build fixture')\n")
                binary.chmod(0o755)
            with (
                mock.patch.object(bootstrap, "MANAGED_BIN_DIRS", [managed]),
                mock.patch.dict(os.environ, {"PATH": str(managed) + os.pathsep + str(system)}),
            ):
                auditor = bootstrap.Auditor(contract)
                self.assertEqual("FAIL", auditor.check(item).state)
                self.assertFalse(ctl.developer_state_ready("docker_client"))
                (managed / "docker").write_text(
                    f"#!/usr/bin/python3\nprint('Docker version {version}, build fixture')\n"
                )
                self.assertEqual("PASS", auditor.check(item).state)
                self.assertTrue(ctl.developer_state_ready("docker_client"))
                (managed / "docker").write_bytes(b"truncated executable")
                self.assertEqual("FAIL", auditor.check(item).state)
                self.assertFalse(ctl.developer_state_ready("docker_client"))


class DockerMalformedSubprocessTests(unittest.TestCase):
    def test_real_make_entry_and_unrelated_json_output(self):
        root = Path(__file__).resolve().parents[1]
        for endpoint in (
            "tcp://a:1@daemon:abc",
            "tcp://fixture-user:fixture-secret@daemon:abc",
            "tcp://daemon:-1",
            "tcp://daemon:65536",
            "tcp://fixture-user:fixture-secret@[broken:2376",
        ):
            with self.subTest(case=endpoint):
                env = dict(os.environ, DOCKER_HOST=endpoint)
                self.assertEqual('{"a":1,"ok":true}', ctl._safe_docker_detail('{"a":1,"ok":true}', env))
                result = subprocess.run(
                    ["make", "service-check", "SERVICE=product"],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                output = result.stdout + result.stderr
                self.assertNotEqual(0, result.returncode)
                self.assertIn("PLATFORM NOT CAPABLE", output)
                for forbidden in ("Traceback", "fixture-secret", "fixture-user"):
                    self.assertNotIn(forbidden, output)


class ReviewFollowupTests(unittest.TestCase):
    def test_collection_closure_rejects_additional_namespaces_and_collections(self):
        case = CollectionIntegrityGenerationTests()
        case.setUp()
        try:
            for relative in ("unlisted", "ansible_collections/unknown", "ansible_collections/test/extra"):
                old = case.prepare()
                (old / relative).mkdir()
                self.assertFalse(collections.installed_ok(case.data, old))
                self.assertNotEqual(old, case.prepare())
        finally:
            case.doCleanups()

    def test_dependent_docker_probes_use_validated_client_outside_path(self):
        contract = bootstrap.load_contract()
        version = bootstrap.load_versions()["DOCKER_CLIENT_VERSION"]
        calls = []

        def runner(command):
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                f"Docker version {version}, build fixture" if command[-1] == "--version" else "Server 29.7.2",
                "",
            )

        auditor = bootstrap.Auditor(contract, runner=runner, which=lambda command: None)
        with mock.patch.object(auditor, "resolve_repoctl_runtime", return_value="/validated/docker"):
            for name in ("docker-client-installed", "docker-user-access", "docker-daemon-ready", "docker"):
                self.assertEqual("PASS", auditor.check(auditor.graph.items[name], name).state)
        self.assertEqual([["/validated/docker", "--version"], *[["/validated/docker", "info"]] * 3], calls)

    def test_env_check_cannot_bootstrap_when_seed_is_absent(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shutil.copy2(root / "Makefile", target / "Makefile")
            (target / "config/toolchain").mkdir(parents=True)
            shutil.copy2(root / "config/toolchain/versions.env", target / "config/toolchain/versions.env")
            # A trap records any attempted Python reconciliation. A read-only audit
            # must fail on the missing seed before invoking it.
            trap = target / "python-trap"
            trap.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nPath('unexpected-reconciliation').touch()\n")
            trap.chmod(0o755)
            result = subprocess.run(["make", "env-check", f"PYTHON={trap}"], cwd=target, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("BLOCKED qualification seed missing", result.stderr + result.stdout)
            self.assertFalse((target / "unexpected-reconciliation").exists())
            self.assertFalse((target / ".venv").exists())

    def test_qualify_orders_reconciliation_before_audit_even_with_parallel_make(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            shutil.copy2(root / "Makefile", target / "Makefile")
            (target / "config/toolchain").mkdir(parents=True)
            shutil.copy2(root / "config/toolchain/versions.env", target / "config/toolchain/versions.env")
            # Executed targets assert the dependency order; -j must not fan out
            # bootstrap and audit as independent prerequisites.
            extra = target / "order.mk"
            extra.write_text(
                "include Makefile\nseed:\n\t@true\nbootstrap:\n\t@touch prepared\nenv-check:\n\t@test -f prepared\n\t@touch audited\n"
            )
            trap = target / "qualification-python"
            trap.write_text("#!/usr/bin/python3\nfrom pathlib import Path\nassert Path('audited').exists()\n")
            trap.chmod(0o755)
            result = subprocess.run(
                ["make", "-j4", "-f", str(extra), "qualify", f"QUALIFICATION_PYTHON={trap}", "MAKE=make -f order.mk"],
                cwd=target,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
