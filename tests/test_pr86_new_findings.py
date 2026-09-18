"""Regression coverage for the second PR86 review (simulated endpoints/platforms)."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_docker_product_preflight import REPOCTL as ctl, completed
from test_ansible_collections import COLLECTION_MOD as collections
from test_architecture_authority import copy_fixture_tree


class NewFindings(unittest.TestCase):
    def test_make_without_seed_or_python_supports_mixed_independent_goals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(ctl.ROOT / "Makefile", root / "Makefile")
            with (root / "Makefile").open("a") as makefile:
                makefile.write("\nplain:\n\t@echo PASS independent\nneeds-ansible:\n\t@$(ANSIBLE_LOCAL) --version\n")
            binaries = root / ".local/bin"
            binaries.mkdir(parents=True)
            for name in ("ruff", "gofmt", "echo"):
                executable = binaries / name
                executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
                executable.chmod(0o755)
            result = subprocess.run(
                [shutil.which("make"), "-j4", "format-check", "plain"],
                cwd=root,
                env={**os.environ, "HOME": str(root), "PATH": str(binaries)},
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("python3", result.stderr)
            self.assertFalse((root / ".venv").exists())
            required = subprocess.run(
                [shutil.which("make"), "needs-ansible"],
                cwd=root,
                env={**os.environ, "HOME": str(root), "PATH": str(binaries)},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(0, required.returncode)
            self.assertIn("python3", required.stderr)

    def test_tekton_and_git_make_consumers_use_collection_wrapper(self):
        for target in ("tekton-proof", "git-local-reconcile"):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", "-n", target], cwd=ctl.ROOT, text=True, capture_output=True, check=True
                )
                self.assertIn("scripts/ansible_collections.py run-playbook --", result.stdout)

    def test_controller_rejects_provider_in_effective_path_and_absolute_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good, bad = root / "good", root / "bad"
            for folder, version in ((good, "2.20.3"), (bad, "0.0.0")):
                folder.mkdir()
                for name in ("ansible-galaxy", "ansible-playbook"):
                    executable = folder / name
                    executable.write_text(
                        f"#!{sys.executable}\nimport sys\nprint({name + ' [core ' + version + ']'!r})\n"
                    )
                    executable.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": str(good)}):
                for command, path in (("ansible-playbook", bad), (str(bad / "ansible-playbook"), good)):
                    with self.subTest(command=command), self.assertRaisesRegex(RuntimeError, "mismatch"):
                        ctl.run([command, "--version"], env={**os.environ, "PATH": str(path)}, capture=True)
                result = ctl.run(["ansible-playbook", "--version"], env={**os.environ, "PATH": str(good)}, capture=True)
                self.assertIn("2.20.3", result.stdout)

    def test_invalid_collection_identity_fails_when_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lock.json"
            lock.write_text("{}")
            with mock.patch.object(collections, "LOCK", lock):
                with self.assertRaisesRegex(RuntimeError, "invalid or missing locked"):
                    collections.prepare()

    def test_gate_does_not_export_hook_index_to_foreign_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor, foreign = root / "donor", root / "foreign"
            for path in (donor, foreign):
                subprocess.run(["git", "init", "-q", str(path)], check=True)
            (donor / "owned").write_text("preserved")
            subprocess.run(["git", "add", "owned"], cwd=donor, check=True)
            index = donor / ".git/index"
            before = index.read_bytes()
            script = "import pathlib,subprocess; root=pathlib.Path(" + repr(str(foreign)) + "); "
            script += "(root/'fixture').write_text('fixture'); subprocess.run(['git','add','.'],cwd=root,check=True)"
            env = {
                **os.environ,
                "GIT_INDEX_FILE": str(index),
                "GIT_DIR": str(donor / ".git"),
                "GIT_WORK_TREE": str(donor),
            }
            with mock.patch.object(ctl, "ROOT", donor), mock.patch.object(ctl, "CONTEXT", donor / "context"):
                self.assertTrue(ctl._run_gate("isolated-git", [sys.executable, "-c", script], [], env))
            self.assertEqual(before, index.read_bytes())
            files = subprocess.check_output(["git", "ls-files"], cwd=foreign, text=True)
            self.assertEqual("fixture\n", files)

    def test_context_clears_foreign_tls(self):
        context = [{"Endpoints": {"docker": {"Host": "unix:///run/docker.sock"}}}]
        original = {"DOCKER_CONTEXT": "selected", "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/foreign"}
        with mock.patch.object(ctl, "run", side_effect=[completed("selected"), completed(json.dumps(context))]):
            env, _ = ctl.docker_test_environment("docker", original)
        self.assertNotIn("DOCKER_CERT_PATH", env)
        self.assertNotIn("DOCKER_TLS_VERIFY", env)
        self.assertEqual("/foreign", original["DOCKER_CERT_PATH"])

    def test_context_tls_requires_certificates_and_overwrites_foreign_values(self):
        with tempfile.TemporaryDirectory() as directory:
            certs = Path(directory) / "docker"
            certs.mkdir()
            context = [
                {
                    "Endpoints": {"docker": {"Host": "tcp://daemon.example:2376"}},
                    "Storage": {"TLSPath": directory},
                    "TLSMaterial": {"docker": ["ca.pem", "cert.pem", "key.pem"]},
                }
            ]
            original = {
                "DOCKER_CONTEXT": "selected",
                "DOCKER_CERT_PATH": "/foreign",
                "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.10",
            }
            with mock.patch.object(ctl, "run", side_effect=[completed("selected"), completed(json.dumps(context))]):
                with self.assertRaisesRegex(ctl.DockerCapabilityError, "missing required TLS"):
                    ctl.docker_test_environment("docker", original)
            for name in ("ca.pem", "cert.pem", "key.pem"):
                (certs / name).touch()
            with mock.patch.object(ctl, "run", side_effect=[completed("selected"), completed(json.dumps(context))]):
                env, _ = ctl.docker_test_environment("docker", original)
            self.assertEqual(str(certs), env["DOCKER_CERT_PATH"])
            self.assertEqual("1", env["DOCKER_TLS_VERIFY"])

    def test_remote_requires_authorized_non_wildcard_address_before_creation(self):
        for address in ("", "0.0.0.0", "::", "bad", "224.0.0.1", "::ffff:0.0.0.0", "::ffff:224.0.0.1"):
            with self.subTest(address=address), mock.patch.object(ctl, "run") as run:
                with self.assertRaises(ctl.DockerCapabilityError):
                    ctl.docker_runtime_proof(
                        "docker",
                        {"DOCKER_HOST": "tcp://daemon:2376", "ECOMMERCE_DOCKER_BIND_ADDRESS": address},
                        "pinned",
                    )
                run.assert_not_called()
        for address in ("192.0.2.10", "2001:db8::10"):
            self.assertEqual(
                address,
                ctl.docker_bind_address({"DOCKER_HOST": "tcp://daemon:2376", "ECOMMERCE_DOCKER_BIND_ADDRESS": address}),
            )

    def test_remote_publication_and_inspection_use_authorized_ipv4_or_ipv6(self):
        for address in ("192.0.2.10", "2001:db8::10"):
            with self.subTest(address=address):
                commands, inspections = [], set()

                def fake(command, **kwargs):
                    commands.append((command, kwargs["env"]))
                    if command[1] == "run":
                        return completed("container-id")
                    if command[1] == "port":
                        return completed(f"[{address}]:49123" if ":" in address else f"{address}:49123")
                    if command[1:3] in (["container", "inspect"], ["volume", "inspect"]):
                        kind = command[1]
                        if kind in inspections:
                            return completed(stderr="No such resource", returncode=1)
                        inspections.add(kind)
                        labels = {"ecommerce-1.product-qualification": "owned"}
                        return completed(
                            json.dumps([{"Id": "container-id", "Config": {"Labels": labels}, "Labels": labels}])
                        )
                    return completed()

                env = {
                    "DOCKER_HOST": "tcp://daemon.example:2376",
                    "DOCKER_TLS_VERIFY": "1",
                    "DOCKER_CERT_PATH": "/context/certs",
                    "ECOMMERCE_DOCKER_BIND_ADDRESS": address,
                    "TESTCONTAINERS_HOST_OVERRIDE": "client-reachable.example",
                }
                with (
                    mock.patch.object(ctl, "run", side_effect=fake),
                    mock.patch.object(ctl.uuid, "uuid4", return_value=mock.Mock(hex="owned")),
                    mock.patch.object(ctl.socket, "create_connection", return_value=mock.MagicMock()) as connect,
                ):
                    ctl.docker_runtime_proof("docker", env, "postgres@sha256:pinned")
                command, actual = next((command, env) for command, env in commands if command[1] == "run")
                publication = f"[{address}]::5432" if ":" in address else f"{address}::5432"
                self.assertEqual(publication, command[command.index("--publish") + 1])
                self.assertEqual("1", actual["DOCKER_TLS_VERIFY"])
                self.assertEqual("/context/certs", actual["DOCKER_CERT_PATH"])
                self.assertNotIn(actual["POSTGRES_PASSWORD"], " ".join(command))
                self.assertGreaterEqual(len(actual["POSTGRES_PASSWORD"]), 32)
                connect.assert_called_once_with(("client-reachable.example", 49123), timeout=1)

    def test_warm_collections_reject_wrong_provider_without_acquisition(self):
        with (
            mock.patch.object(collections, "installed_ok", return_value=True),
            mock.patch.object(collections, "installer_provenance", side_effect=RuntimeError("provider mismatch")),
            mock.patch.object(collections, "acquire") as acquire,
            mock.patch.object(collections, "install") as install,
        ):
            with self.assertRaisesRegex(RuntimeError, "provider mismatch"):
                collections.prepare(offline=True)
            acquire.assert_not_called()
            install.assert_not_called()

    def test_fixture_copy_portable_and_independent(self):
        for native in (False, True):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, target = root / "source", root / "target"
                source.mkdir()
                (source / "data").write_text("original")
                (source / "data").chmod(0o640)
                (source / "link").symlink_to("data")
                with mock.patch("shutil.which", return_value=shutil.which("cp") if native else None):
                    copy_fixture_tree(source, target)
                (target / "data").write_text("mutation")
                self.assertEqual("original", (source / "data").read_text())
                self.assertTrue((target / "link").is_symlink())
                self.assertEqual(0o640, (target / "data").stat().st_mode & 0o777)

    def test_partial_unsupported_copy_falls_back_but_permissions_fail(self):
        for diagnostic in ("unrecognized option --reflink", "permission denied"):
            with self.subTest(diagnostic=diagnostic), tempfile.TemporaryDirectory() as directory:
                source, target = Path(directory) / "source", Path(directory) / "target"
                source.mkdir()
                (source / "data").write_text("source")

                def fake(command, **kwargs):
                    if "--version" in command:
                        return completed("cp (GNU coreutils)")
                    target.mkdir()
                    (target / "partial").touch()
                    return subprocess.CompletedProcess(command, 1, "", diagnostic)

                with mock.patch("shutil.which", return_value="cp"), mock.patch("subprocess.run", side_effect=fake):
                    if "permission" in diagnostic:
                        with self.assertRaises(subprocess.CalledProcessError):
                            copy_fixture_tree(source, target)
                    else:
                        copy_fixture_tree(source, target)
                        self.assertFalse((target / "partial").exists())
                        self.assertEqual("source", (target / "data").read_text())
