from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
TOOLCHAIN = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")


class DockerPublishBoundaryTest(unittest.TestCase):
    def test_docker_reconciliation_is_owned_by_ansible(self):
        self.assertIn("Probe Docker daemon", PLAYBOOK)
        self.assertIn("docker.exe", PLAYBOOK)
        self.assertIn("powershell.exe", PLAYBOOK)
        self.assertIn("retries: 30", PLAYBOOK)

    def test_service_gate_requests_docker_only_for_container_tests(self):
        self.assertIn('capabilities = ["go", "cgo"]', CONTROLLER)
        self.assertIn("needs_containers = any", CONTROLLER)
        self.assertIn('ensure_developer("docker_client")', CONTROLLER)
        self.assertIn("Docker client reconciliation did not publish an executable", CONTROLLER)
        self.assertIn("docker_preflight(docker)", CONTROLLER)
        self.assertIn("docker_runtime_proof(docker, docker_env, postgres_image)", CONTROLLER)
        self.assertIn("docker_ryuk_image_proof(docker, docker_env, ryuk_image)", CONTROLLER)
        self.assertIn('env["ECOMMERCE_RYUK_IMAGE"] = ryuk_image', CONTROLLER)
        self.assertNotIn('sysctl", "-n", "net.ipv4.ip_forward', CONTROLLER)
        self.assertNotIn("ensure-docker-daemon.sh", CONTROLLER)

    def test_missing_client_uses_one_pinned_client_only_install(self):
        self.assertIn("Download pinned Docker client archive", TOOLCHAIN)
        self.assertIn("Extract only the pinned Docker client", TOOLCHAIN)
        self.assertIn("docker_client_sha256", TOOLCHAIN)
        self.assertNotIn("systemd_service", TOOLCHAIN)


if __name__ == "__main__":
    unittest.main()
