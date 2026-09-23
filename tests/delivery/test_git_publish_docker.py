import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = (
    ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml"
).read_text(encoding="utf-8")
CONTROLLER = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
POLICY = yaml.safe_load(
    (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text(
        encoding="utf-8"
    )
)


class DockerPublishBoundaryTest(unittest.TestCase):
    def test_docker_reconciliation_is_owned_by_ansible(self):
        self.assertIn("Probe Docker daemon", PLAYBOOK)
        self.assertIn("docker.exe", PLAYBOOK)
        self.assertIn("powershell.exe", PLAYBOOK)
        self.assertIn("retries: 30", PLAYBOOK)

    def test_service_gate_requests_docker_only_for_container_tests(self):
        self.assertIn('capabilities = ["go", "cgo"]', CONTROLLER)
        declaration = POLICY["gates"]["service:*"]["runtime_capabilities"]
        self.assertEqual("testcontainers", declaration[0]["name"])
        self.assertEqual("testcontainers", declaration[0]["when"]["contains"])
        self.assertEqual(
            ["docker-runtime", "ip-forward"],
            POLICY["runtime_orchestration"]["capabilities"]["testcontainers"][
                "requires"
            ],
        )
        service_source = CONTROLLER[
            CONTROLLER.index("def service_check(") : CONTROLLER.index("\ndef security(")
        ]
        self.assertNotIn("docker_ready =", service_source)
        self.assertNotIn("net.ipv4.ip_forward", service_source)
        self.assertNotIn("ensure-docker-daemon.sh", CONTROLLER)


if __name__ == "__main__":
    unittest.main()
