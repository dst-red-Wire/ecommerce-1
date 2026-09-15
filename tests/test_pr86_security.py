"""Transport and remote-reaper boundaries must fail before Docker API calls."""

import json
import unittest
from unittest import mock

from test_docker_product_preflight import REPOCTL as ctl, completed


class DockerSecurityTests(unittest.TestCase):
    def test_network_transport_without_verified_tls_never_contacts_daemon(self):
        for scheme in ("tcp", "http", "https"):
            for verification in ("", "0", "false"):
                with self.subTest(scheme=scheme, verification=verification), mock.patch.object(ctl, "run") as run:
                    with self.assertRaisesRegex(ctl.DockerCapabilityError, "verified TLS"):
                        ctl.docker_preflight(
                            "docker", {"DOCKER_HOST": f"{scheme}://daemon:2376", "DOCKER_TLS_VERIFY": verification}
                        )
                    run.assert_not_called()

    def test_plaintext_context_is_rejected_after_local_inspection(self):
        context = [{"Endpoints": {"docker": {"Host": "tcp://daemon:2375"}}}]
        with mock.patch.object(ctl, "run", side_effect=[completed("selected"), completed(json.dumps(context))]) as run:
            with self.assertRaisesRegex(ctl.DockerCapabilityError, "verified TLS"):
                ctl.docker_preflight("docker", {"DOCKER_TLS_VERIFY": "1"})
        self.assertEqual(
            [["docker", "context", "show"], ["docker", "context", "inspect", "selected"]],
            [c.args[0] for c in run.call_args_list],
        )

    def test_verified_tls_resolution_is_preserved(self):
        with mock.patch.object(ctl, "run") as run:
            env, _ = ctl.docker_test_environment(
                "docker",
                {
                    "DOCKER_HOST": "tcp://daemon:2376",
                    "DOCKER_TLS_VERIFY": "1",
                    "DOCKER_CERT_PATH": "/approved/certs",
                    "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.10",
                },
            )
        self.assertEqual("1", env["DOCKER_TLS_VERIFY"])
        self.assertEqual("/approved/certs", env["DOCKER_CERT_PATH"])
        run.assert_not_called()

    def test_secure_remote_transport_cannot_waive_ryuk_boundary(self):
        for scheme in ("tcp", "http", "https", "ssh"):
            with self.subTest(scheme=scheme), mock.patch.object(ctl, "run") as run:
                with self.assertRaisesRegex(ctl.DockerCapabilityError, "Ryuk interface binding"):
                    ctl.docker_preflight(
                        "docker",
                        {
                            "DOCKER_HOST": f"{scheme}://daemon:2376",
                            "DOCKER_TLS_VERIFY": "1",
                            "ECOMMERCE_DOCKER_BIND_ADDRESS": "192.0.2.10",
                            "TESTCONTAINERS_HOST_OVERRIDE": "daemon",
                        },
                    )
                run.assert_not_called()


class NamedPipeSecurityTests(unittest.TestCase):
    def test_remote_and_noncanonical_named_pipes_never_contact_daemon(self):
        for endpoint in (
            "npipe:////server/pipe/docker_engine",
            "npipe:////127.0.0.1/pipe/docker_engine",
            "npipe://server/pipe/docker_engine",
            "npipe:////./pipe/../server/pipe",
            "npipe:////%2e/pipe/docker_engine",
            "npipe:////./pipe/%2e%2e",
            "npipe:////./pipe/docker_engine?host=server",
        ):
            with self.subTest(endpoint=endpoint), mock.patch.object(ctl, "run") as run:
                with self.assertRaises(ctl.DockerCapabilityError):
                    ctl.docker_preflight("docker", {"DOCKER_HOST": endpoint})
                run.assert_not_called()

    def test_canonical_local_named_pipe_can_reach_preflight(self):
        endpoint = "npipe:////./pipe/docker_engine"
        with mock.patch.object(ctl, "run", return_value=completed('"server-version"')) as run:
            env, _ = ctl.docker_preflight("docker", {"DOCKER_HOST": endpoint})
        self.assertEqual(endpoint, env["DOCKER_HOST"])
        run.assert_called_once()
        self.assertEqual(["docker", "version", "--format", "{{json .Server.Version}}"], run.call_args.args[0])

    def test_remote_named_pipe_context_is_refused_after_local_inspection(self):
        context = [{"Endpoints": {"docker": {"Host": "npipe:////server/pipe/docker_engine"}}}]
        with mock.patch.object(ctl, "run", side_effect=[completed("remote"), completed(json.dumps(context))]) as run:
            with self.assertRaisesRegex(ctl.DockerCapabilityError, "canonical local named pipe"):
                ctl.docker_preflight("docker", {})
        self.assertEqual(2, run.call_count)
        self.assertTrue(all(call.args[0][1] == "context" for call in run.call_args_list))
