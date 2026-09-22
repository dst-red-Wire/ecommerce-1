from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")


class DockerPublishBoundaryTest(unittest.TestCase):
    def test_docker_reconciliation_is_owned_by_ansible(self):
        self.assertIn("import_tasks: docker_rootless.yml", PLAYBOOK)
        self.assertIn("import_tasks: docker_rootless_state.yml", PLAYBOOK)
        state = (
            ROOT / "platform/ansible/roles/developer_workstation/tasks/docker_rootless_state.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("ansible.builtin.systemd_service", state)
        self.assertIn("developer_workstation_docker_rootless_service_state", state)
        self.assertIn("name=rootless", state)

    def test_service_gate_requests_docker_only_for_container_tests(self):
        self.assertIn('capabilities = ["go", "cgo"]', CONTROLLER)
        self.assertIn("needs_containers = any", CONTROLLER)
        self.assertIn("PLATFORM NOT CAPABLE: container integration", CONTROLLER)
        self.assertNotIn("ensure-docker-daemon.sh", CONTROLLER)


if __name__ == "__main__":
    unittest.main()
