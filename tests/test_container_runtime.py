from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "repoctl_container_runtime_test", ROOT / "scripts/repoctl.py"
)
assert SPEC and SPEC.loader
REPOCTL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPOCTL)


class ContainerRuntimeContractTests(unittest.TestCase):
    def test_rootless_docker_packages_and_key_are_exactly_pinned(self):
        lock = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )
        versions = lock["versions"]
        expected = {
            "DOCKER_ENGINE_VERSION": "29.8.1",
            "DOCKER_ENGINE_PACKAGE_VERSION": "5:29.8.1-1~ubuntu.24.04~noble",
            "DOCKER_CONTAINERD_PACKAGE_VERSION": "2.3.5-1~ubuntu.24.04~noble",
            "DOCKER_UIDMAP_PACKAGE_VERSION": "1:4.13+dfsg1-4ubuntu3.2",
            "DOCKER_DBUS_USER_SESSION_PACKAGE_VERSION": "1.14.10-4ubuntu4.1",
            "DOCKER_SLIRP4NETNS_PACKAGE_VERSION": "1.2.1-1build2",
            "DOCKER_FUSE_OVERLAYFS_PACKAGE_VERSION": "1.13-1",
            "KIND_NODE_IMAGE": "docker.io/kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
            "TESTCONTAINERS_RYUK_IMAGE": "docker.io/testcontainers/ryuk:0.14.0@sha256:7c1a8a9a47c780ed0f983770a662f80deb115d95cce3e2daa3d12115b8cd28f0",
            "TESTCONTAINERS_POSTGRES_IMAGE": "docker.io/library/postgres:17.10-alpine3.22@sha256:b02d9b5bcf608c2719da32cdabee274a33841202487fd5dc9b065b63f886753f",
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(value, versions[key])
        postgres_test = (
            ROOT
            / "services/product/internal/infrastructure/postgres/store_integration_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f'const postgresTestImage = "{expected["TESTCONTAINERS_POSTGRES_IMAGE"]}"',
            postgres_test,
        )
        self.assertRegex(versions["DOCKER_APT_GPG_SHA256"], r"^[0-9a-f]{64}$")

        defaults = (
            ROOT
            / "platform/ansible/roles/developer_workstation/defaults/main.yml"
        ).read_text(encoding="utf-8")
        tasks = (
            ROOT
            / "platform/ansible/roles/developer_workstation/tasks/docker_rootless.yml"
        ).read_text(encoding="utf-8")
        for key in expected:
            if not key.startswith("DOCKER_"):
                continue
            self.assertIn(key, defaults)
        self.assertIn(
            'checksum: "sha256:{{ developer_workstation_docker_apt_gpg_sha256 }}"',
            tasks,
        )
        self.assertIn("allow_downgrade: true", tasks)
        self.assertIn("selection: hold", tasks)

        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('or value.startswith("~")', repoctl)
        self.assertNotIn('(\"<\", \">\", \"^\", \"~\", \"*\")', repoctl)

    def test_workstation_contract_selects_on_demand_rootless_engine(self):
        policy = REPOCTL.workstation_policy()
        runtime = policy["container_runtime"]
        self.assertEqual("docker-engine-rootless", runtime["provider"])
        self.assertEqual("on-demand", runtime["lifecycle"]["startup"])
        self.assertFalse(runtime["lifecycle"]["enabled_at_login"])
        self.assertEqual("stopped", runtime["lifecycle"]["ha_campaign_state"])
        self.assertEqual("disabled", runtime["security"]["rootful_daemon"])
        self.assertEqual("forbidden", runtime["security"]["tcp_socket"])
        self.assertTrue(runtime["security"]["ryuk_cleanup"])
        self.assertNotIn("DockerDesktop", policy["winget"]["packages"])
        REPOCTL.validate_workstation_projections(policy)

    def test_memory_summary_keeps_each_phase_and_peak_direction(self):
        samples = [
            {
                "phase": "testcontainers-postgresql",
                "windows_available_mib": 9000,
                "wsl_available_mib": 1200,
                "wsl_used_mib": 700,
                "runtime_process_rss_mib": 80,
            },
            {
                "phase": "testcontainers-postgresql",
                "windows_available_mib": 8700,
                "wsl_available_mib": 1000,
                "wsl_used_mib": 900,
                "runtime_process_rss_mib": 110,
            },
        ]
        result = REPOCTL._summarize_memory(samples)["testcontainers-postgresql"]
        self.assertEqual(2, result["sample_count"])
        self.assertEqual(8700, result["minimum_windows_available_mib"])
        self.assertEqual(1000, result["minimum_wsl_available_mib"])
        self.assertEqual(900, result["maximum_wsl_used_mib"])
        self.assertEqual(110, result["maximum_runtime_process_rss_mib"])

    def test_windows_memory_measurement_retries_transient_cim_failure(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="transient")
        recovered = subprocess.CompletedProcess([], 0, stdout="12288\n", stderr="")
        with (
            mock.patch.object(REPOCTL.shutil, "which", return_value="powershell.exe"),
            mock.patch.object(REPOCTL.subprocess, "run", side_effect=[failed, recovered]) as runner,
            mock.patch.object(REPOCTL.time, "sleep") as pause,
        ):
            self.assertEqual(12288, REPOCTL._windows_available_memory_mib())
        self.assertEqual(2, runner.call_count)
        pause.assert_called_once_with(0.25)

    def test_qualification_requires_ryuk_kind_cleanup_and_final_stop(self):
        source = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        qualification = source[
            source.index("def container_runtime_qualification(") : source.index(
                "def security()"
            )
        ]
        self.assertIn('"testcontainers/ryuk"', qualification)
        self.assertIn('pins["KIND_NODE_IMAGE"]', qualification)
        self.assertIn('pins["TESTCONTAINERS_RYUK_IMAGE"]', qualification)
        self.assertIn('pins["TESTCONTAINERS_POSTGRES_IMAGE"]', qualification)
        self.assertIn('"--image",\n                kind_node_image', qualification)
        self.assertIn('[kind, "delete", "cluster"', qualification)
        self.assertIn('_reconcile_rootless_docker("stopped")', qualification)
        self.assertIn("_wait_for_zero_containers", qualification)
        self.assertNotIn('[docker, "rm", "-f", *identifiers]', qualification)

    def test_qualification_does_not_stop_preexisting_rootless_service(self):
        active = subprocess.CompletedProcess([], 0, stdout="active\n", stderr="")
        with tempfile.TemporaryDirectory(dir=ROOT / ".context") as directory:
            report = Path(directory) / "runtime.json"
            with (
                mock.patch.object(REPOCTL, "run", return_value=active),
                mock.patch.object(REPOCTL, "_reconcile_rootless_docker") as reconcile,
                mock.patch.object(REPOCTL, "git", return_value="a" * 40),
                mock.patch.object(REPOCTL, "worktree_tree_sha", return_value="b" * 40),
            ):
                self.assertEqual(1, REPOCTL.container_runtime_qualification(str(report), False))
            reconcile.assert_not_called()
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("FAIL", result["status"])
            self.assertIn("rootless Docker user service must be inactive", result["failures"][0])

    def test_haproxy_preparation_stops_rootless_after_playbook_failure(self):
        inactive = subprocess.CompletedProcess([], 3, stdout="inactive\n", stderr="")
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        with (
            mock.patch.object(
                REPOCTL,
                "qualification_workflow",
                return_value={"preparation": "scripts/repoctl.py rke2-local-ha-prepare"},
            ),
            mock.patch.object(REPOCTL, "git", return_value=""),
            mock.patch.object(REPOCTL, "qualification_ansible_playbook", return_value="/venv/bin/ansible-playbook"),
            mock.patch.object(REPOCTL, "run", side_effect=[inactive, failed]) as runner,
            mock.patch.object(REPOCTL, "_reconcile_rootless_docker") as reconcile,
        ):
            self.assertEqual(1, REPOCTL.rke2_local_ha_prepare())
        self.assertEqual([mock.call("started"), mock.call("stopped")], reconcile.call_args_list)
        self.assertEqual("/venv/bin/ansible-playbook", runner.call_args_list[1].args[0][0])
        self.assertIn("DOCKER_HOST", runner.call_args_list[1].kwargs["env"])


if __name__ == "__main__":
    unittest.main()
