from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")


class DockerPublishBoundaryTest(unittest.TestCase):
    def test_docker_reconciliation_is_owned_by_ansible(self):
        self.assertIn("Probe Docker daemon", PLAYBOOK)
        self.assertIn("docker.exe", PLAYBOOK)
        self.assertIn("powershell.exe", PLAYBOOK)
        self.assertIn("retries: 30", PLAYBOOK)

    def test_service_gate_treats_container_runtime_as_optional(self):
        self.assertIn('ensure_developer("go,cgo,sqlc")', CONTROLLER)
        self.assertIn("SKIP environnemental — aucun moteur de conteneurs utilisable", CONTROLLER)
        self.assertNotIn("ensure-docker-daemon.sh", CONTROLLER)


if __name__ == "__main__":
    unittest.main()
