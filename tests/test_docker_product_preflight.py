import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_docker_preflight", ROOT / "scripts/repoctl.py")
REPOCTL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(REPOCTL)


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class DockerProductPreflightTests(unittest.TestCase):
    def test_context_endpoint_is_exported_for_cli_and_testcontainers(self):
        context = [{"Endpoints": {"docker": {"Host": "unix:///run/docker.sock"}}, "Storage": {}}]
        with mock.patch.object(REPOCTL, "run", side_effect=[completed("project\n"), completed(json.dumps(context))]):
            env, identity = REPOCTL.docker_test_environment("docker", {"PATH": "/bin"})
        self.assertEqual("unix:///run/docker.sock", env["DOCKER_HOST"])
        self.assertIn("source=context:project", identity)

    def test_explicit_remote_endpoint_wins_and_sets_reachable_host(self):
        with mock.patch.object(REPOCTL, "run", return_value=completed("ignored-context\n")):
            env, identity = REPOCTL.docker_test_environment("docker", {"DOCKER_HOST": "tcp://docker.example.test:2376"})
        self.assertEqual("tcp://docker.example.test:2376", env["DOCKER_HOST"])
        self.assertEqual("docker.example.test", env["TESTCONTAINERS_HOST_OVERRIDE"])
        self.assertIn("mode=remote source=DOCKER_HOST", identity)

    def test_remote_loopback_requires_explicit_testcontainers_override(self):
        with (
            mock.patch.object(REPOCTL, "run", return_value=completed("default\n")),
            self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "TESTCONTAINERS_HOST_OVERRIDE"),
        ):
            REPOCTL.docker_test_environment("docker", {"DOCKER_HOST": "tcp://127.0.0.1:2376"})

    def test_daemon_absent_is_distinct_from_client_or_context_failure(self):
        calls = [
            completed("default\n"),
            completed(json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}])),
            completed(stderr="Cannot connect to the Docker daemon", returncode=1),
        ]
        with (
            mock.patch.object(REPOCTL, "run", side_effect=calls),
            self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "local daemon absent or stopped"),
        ):
            REPOCTL.docker_preflight("docker", {})

    def test_socket_permission_failure_is_classified_without_secret_values(self):
        calls = [
            completed("default\n"),
            completed(json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}])),
            completed(stderr="permission denied token=must-not-be-copied", returncode=1),
        ]
        with mock.patch.object(REPOCTL, "run", side_effect=calls):
            with self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "socket inaccessible"):
                REPOCTL.docker_preflight("docker", {})

    def test_server_timeout_is_bounded_and_diagnostic(self):
        calls = [
            completed("default\n"),
            completed(json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}])),
            subprocess.TimeoutExpired(["docker", "info"], 10),
        ]
        with (
            mock.patch.object(REPOCTL, "run", side_effect=calls),
            self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "timed out after 10s"),
        ):
            REPOCTL.docker_preflight("docker", {})

    def test_runtime_proof_cleans_only_its_exact_container_and_volume(self):
        commands = []
        inspected = set()

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[1:3] in (["container", "inspect"], ["volume", "inspect"]):
                kind = command[1]
                if kind in inspected:
                    return completed(stderr="No such resource", returncode=1)
                inspected.add(kind)
                labels = {"ecommerce-1.product-qualification": "owned"}
                return completed(json.dumps([{"Id": "container-id", "Config": {"Labels": labels}, "Labels": labels}]))
            if command[1] == "run":
                return completed("container-id\n")
            if command[1] == "port":
                return completed("127.0.0.1:49123\n")
            return completed()

        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        with (
            mock.patch.object(REPOCTL.uuid, "uuid4", return_value=mock.Mock(hex="owned")),
            mock.patch.object(REPOCTL, "run", side_effect=fake_run),
            mock.patch.object(REPOCTL.socket, "create_connection", return_value=connection),
        ):
            REPOCTL.docker_runtime_proof("docker", {}, "postgres@sha256:pinned")
        self.assertIn(["docker", "rm", "--force", "container-id"], commands)
        self.assertIn(["docker", "volume", "rm", "ecommerce-product-qualification-owned"], commands)
        self.assertFalse(any("prune" in command for command in commands))

    def test_ryuk_digest_mismatch_fails_without_retagging(self):
        image = "docker.io/testcontainers/ryuk:0.14.0@sha256:" + "a" * 64
        with mock.patch.object(
            REPOCTL,
            "run",
            side_effect=[
                completed("sha256:" + "b" * 64),
                completed("sha256:" + "c" * 64),
            ],
        ) as run:
            with self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "tag differs"):
                REPOCTL.docker_ryuk_image_proof("docker", {}, image)
        self.assertTrue(all(call.args[0][1:3] == ["image", "inspect"] for call in run.call_args_list))

    def test_ryuk_missing_digest_is_pulled_and_verified_against_tag(self):
        image = "docker.io/testcontainers/ryuk:0.14.0@sha256:" + "a" * 64
        identity = "sha256:" + "b" * 64
        with mock.patch.object(
            REPOCTL,
            "run",
            side_effect=[
                completed(returncode=1),
                completed(),
                completed(identity),
                completed(identity),
            ],
        ) as run:
            REPOCTL.docker_ryuk_image_proof("docker", {}, image)
        self.assertEqual(["docker", "pull", image], run.call_args_list[1].args[0])
        self.assertEqual(120, run.call_args_list[1].kwargs["timeout"])

    def test_ryuk_unpinned_reference_fails_before_daemon_access(self):
        with mock.patch.object(REPOCTL, "run") as run:
            with self.assertRaisesRegex(REPOCTL.DockerCapabilityError, "immutable SHA-256"):
                REPOCTL.docker_ryuk_image_proof("docker", {}, "testcontainers/ryuk:0.14.0")
        run.assert_not_called()

    def test_endpoint_logging_removes_embedded_credentials(self):
        self.assertEqual(
            "tcp://daemon.example:2376", REPOCTL._safe_docker_endpoint("tcp://user:secret@daemon.example:2376")
        )
        detail = REPOCTL._safe_docker_detail(
            "cannot connect tcp://user:secret@daemon.example:2376",
            {"DOCKER_HOST": "tcp://user:secret@daemon.example:2376"},
        )
        self.assertNotIn("user", detail)
        self.assertNotIn("secret", detail)


if __name__ == "__main__":
    unittest.main()
