import io
import os
import json
import subprocess
import sys
import tempfile
import traceback
import contextlib
from pathlib import Path
from unittest import TestCase, mock
from test_docker_product_preflight import REPOCTL as ctl, completed
from test_ansible_collections import COLLECTION_MOD as collections

sys.path.insert(0, str(ctl.ROOT / "scripts"))
import capability_bootstrap as bootstrap


class ReviewRegressions(TestCase):
    def test_r1_executed_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed, managed, system = root / ".venv/qualification/bin", root / ".local/bin", root / "system"
            names = ("python", "ansible", "ansible-playbook", "ansible-galaxy", "ruff", "go", "docker", "terraform")
            for directory in (seed, managed, system):
                directory.mkdir(parents=True)
                for name in names:
                    if directory == seed and name in ("go", "docker", "terraform"):
                        continue
                    binary = directory / name
                    binary.write_text(f"#!{sys.executable}\nprint({str(binary)!r})\n")
                    binary.chmod(0o755)
            with mock.patch.object(ctl, "ROOT", root), mock.patch.object(Path, "home", return_value=root):
                env = dict(os.environ, PATH=ctl.execution_path(str(system)))
                for name in names:
                    expected = (managed if name in ("go", "docker", "terraform") else seed) / name
                    self.assertEqual(str(expected), ctl.run([name], env=env, capture=True).stdout.strip())

    def test_r2_simulated_python_matrix(self):
        for version, typing, clib in (("3.12", True, True), ("3.13", False, True), ("3.14", False, False)):
            expected = bootstrap.seed_requirements(
                bootstrap.SEED_LOCK.read_text(), {"python_version": version, "python_full_version": version + ".0"}
            )
            self.assertEqual(typing, "typing-extensions" in expected)
            self.assertEqual(clib, "ruamel-yaml-clib" in expected)
            self.assertEqual("2.20.3", expected["ansible-core"])

    def test_r2_versions_and_pip_check_remain_required(self):
        with mock.patch.object(bootstrap, "seed_requirements", return_value={"synthetic": "1.0"}):
            with mock.patch("importlib.metadata.version", return_value="2.0"):
                self.assertFalse(bootstrap.validate_seed_lock(str(bootstrap.SEED_LOCK)))
            with (
                mock.patch("importlib.metadata.version", return_value="1.0"),
                mock.patch.object(bootstrap.subprocess, "run", return_value=completed(returncode=1)),
            ):
                self.assertFalse(bootstrap.validate_seed_lock(str(bootstrap.SEED_LOCK)))

    def test_r4_both_variables_host_wins_without_changing_input(self):
        original = {
            "DOCKER_HOST": "tcp://daemon.example:2376",
            "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.10",
            "DOCKER_CONTEXT": "foreign",
            "DOCKER_TLS_VERIFY": "1",
            "TESTCONTAINERS_HOST_OVERRIDE": "ports.example",
        }
        with mock.patch.object(ctl, "run", return_value=completed("default")) as run:
            env, _ = ctl.docker_test_environment("docker", original)
        self.assertNotIn("DOCKER_CONTEXT", env)
        run.assert_not_called()
        self.assertEqual("foreign", original["DOCKER_CONTEXT"])
        self.assertEqual("1", env["DOCKER_TLS_VERIFY"])
        self.assertEqual("ports.example", env["TESTCONTAINERS_HOST_OVERRIDE"])

    def test_r4_context_only_preserves_tls(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "docker").mkdir()
            for name in ("ca.pem", "cert.pem", "key.pem"):
                (Path(tmp) / "docker" / name).touch()
            entry = [{"Endpoints": {"docker": {"Host": "tcp://daemon.example:2376"}}, "Storage": {"TLSPath": tmp}}]
            with mock.patch.object(ctl, "run", side_effect=[completed("selected"), completed(json.dumps(entry))]):
                env, _ = ctl.docker_test_environment(
                    "docker", {"DOCKER_CONTEXT": "selected", "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.10"}
                )
            self.assertNotIn("DOCKER_CONTEXT", env)
            self.assertEqual("1", env["DOCKER_TLS_VERIFY"])
            self.assertEqual(str(Path(tmp) / "docker"), env["DOCKER_CERT_PATH"])

    def test_r5_every_phase_redacts_outputs_exceptions_and_diagnostic_files(self):
        endpoint = "tcp://synthetic-user:synthetic-password@daemon.example:2376"
        raw = endpoint + " token=synthetic-token"
        env = dict(os.environ, DOCKER_HOST=endpoint)
        for phase in ("context", "version", "pull", "image", "run", "port", "logs", "rm", "volume"):
            for timeout in (False, True):
                for capture in (False, True):
                    out, err = io.StringIO(), io.StringIO()
                    effect = (
                        subprocess.TimeoutExpired(["docker", phase], 1, output=raw.encode(), stderr=raw.encode())
                        if timeout
                        else None
                    )
                    with (
                        mock.patch.object(
                            ctl.subprocess, "run", side_effect=effect, return_value=completed(raw, raw, 1)
                        ),
                        contextlib.redirect_stdout(out),
                        contextlib.redirect_stderr(err),
                    ):
                        try:
                            ctl.run(["docker", phase], env=env, capture=capture)
                        except (RuntimeError, subprocess.TimeoutExpired) as exc:
                            diagnostic = traceback.format_exc() + str(vars(exc))
                    with tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp) / "diagnostic.log"
                        path.write_text(out.getvalue() + err.getvalue() + diagnostic)
                        for secret in ("synthetic-user", "synthetic-password", "synthetic-token"):
                            self.assertNotIn(secret, path.read_text())

    def test_r6_partial_creation_and_foreign_collision(self):
        for foreign, cleanup_fails in ((False, False), (True, False), (False, True)):
            commands, removed = [], set()

            def run(cmd, **kwargs):
                commands.append(cmd)
                if cmd[1] == "run":
                    raise RuntimeError("controlled initial failure")
                if cmd[1:3] in (["container", "inspect"], ["volume", "inspect"]):
                    kind = cmd[1]
                    if kind in removed:
                        return completed(stderr="No such resource", returncode=1)
                    labels = {"ecommerce-1.product-qualification": "foreign" if foreign else "owned"}
                    return completed(json.dumps([{"Id": "owned-id", "Config": {"Labels": labels}, "Labels": labels}]))
                if cmd[1] == "rm":
                    if cleanup_fails:
                        raise RuntimeError("controlled cleanup failure")
                    removed.add("container")
                if cmd[1:3] == ["volume", "rm"]:
                    self.assertIn("container", removed)
                    removed.add("volume")
                return completed()

            with (
                mock.patch.object(ctl.uuid, "uuid4", return_value=mock.Mock(hex="owned")),
                mock.patch.object(ctl, "run", side_effect=run),
            ):
                with self.assertRaisesRegex(ctl.DockerCapabilityError, "controlled initial failure") as error:
                    ctl.docker_runtime_proof("docker", {}, "unused")
            if foreign:
                self.assertFalse(any("rm" in cmd for cmd in commands))
            elif not cleanup_fails:
                self.assertEqual({"container", "volume"}, removed)
            if foreign or cleanup_fails:
                self.assertIn("cleanup failed", str(error.exception))

    def test_r7_make_identity_without_sha256sum_and_calculation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sha256sum"
            binary.write_text(f"#!{sys.executable}\nraise SystemExit(99)\n")
            binary.chmod(0o755)
            makefile = "include Makefile\npr86-identity:\n\t@$(PYTHON) scripts/ansible_collections.py identity\n"
            env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"])
            result = subprocess.run(
                ["make", "-s", "-f", "-", "pr86-identity"],
                input=makefile,
                cwd=ctl.ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(collections.identity(), result.stdout.strip())
            result = subprocess.run(
                ["make", "-s", "-f", "-", "pr86-identity", "PYTHON=false"],
                input=makefile,
                cwd=ctl.ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Error", result.stderr)

    def test_r8_cold_and_warm_cache_readiness(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(os.environ, {"TF_PLUGIN_CACHE_DIR": str(Path(tmp) / "providers")}),
            mock.patch.object(
                ctl.shutil, "which", side_effect=lambda name: "/managed/terraform" if name == "terraform" else None
            ),
            mock.patch.object(
                ctl,
                "run",
                return_value=completed(json.dumps({"terraform_version": ctl.pinned_versions()["TERRAFORM_VERSION"]})),
            ),
        ):
            self.assertFalse(ctl.developer_state_ready("terraform"))
            (Path(tmp) / "providers").mkdir()
            self.assertTrue(ctl.developer_state_ready("terraform"))

    def test_r9_actual_installer_executable_version(self):
        data = collections.load_lock()
        for version in (data["installer"]["ansible_core"], "0.0.0"):
            with tempfile.TemporaryDirectory() as tmp:
                binary = Path(tmp) / "ansible-galaxy"
                binary.write_text(f'#!{sys.executable}\nprint("ansible-galaxy [core {version}]")\n')
                binary.chmod(0o755)
                playbook = Path(tmp) / "ansible-playbook"
                playbook.write_text(f'#!{sys.executable}\nprint("ansible-playbook [core {version}]")\n')
                playbook.chmod(0o755)
                with mock.patch.dict(os.environ, {"PATH": tmp}):
                    if version == "0.0.0":
                        with self.assertRaisesRegex(RuntimeError, "installer mismatch"):
                            collections.installer_provenance(data)
                    else:
                        self.assertEqual(str(binary), collections.installer_provenance(data)["executable"])

    def test_r9_existing_install_without_provenance_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp)
            (destination / ".ecommerce-collections.json").write_text(json.dumps({"identity": collections.identity()}))
            self.assertFalse(collections.installed_ok(collections.load_lock(), destination))

    def test_r5_redacted_inspection_remains_valid_json(self):
        document = [{"Config": {"Env": ["POSTGRES_PASSWORD=synthetic-password"]}}]
        safe = ctl._safe_docker_detail(json.dumps(document), {})
        self.assertNotIn("synthetic-password", safe)
        self.assertEqual([{"Config": {"Env": ["POSTGRES_PASSWORD=[REDACTED]"]}}], json.loads(safe))

    def test_r3_r8_tagged_directory_initialization_uses_configured_paths(self):
        import yaml

        tasks = yaml.safe_load((ctl.ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text())
        initialization = next(task for task in tasks if task["name"] == "Create user-local tool directories")
        for tag in ("docker_client", "terraform"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                variables = {
                    name: str(root / name)
                    for name in ("local_bin", "local_share", "local_cache", "terraform_plugin_cache")
                }
                play = [
                    {
                        "name": "Test isolated initialization",
                        "hosts": "localhost",
                        "gather_facts": False,
                        "vars": variables,
                        "tasks": [initialization],
                    }
                ]
                path = root / "play.yml"
                path.write_text(yaml.safe_dump(play))
                for phase in ("cold", "warm"):
                    result = subprocess.run(
                        ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path), "--tags", tag],
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    for directory in variables.values():
                        self.assertTrue(Path(directory).is_dir(), (tag, phase, directory))
                    if phase == "warm":
                        self.assertIn("changed=0", result.stdout)
