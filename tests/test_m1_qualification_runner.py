import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = ROOT / "platform/ansible/roles/qualification_runner_host/defaults/main.yml"
TASKS = ROOT / "platform/ansible/roles/qualification_runner_host/tasks/main.yml"
PLAYBOOK = ROOT / "platform/ansible/qualification-runner.yml"
RUNBOOK = ROOT / "docs/project/M1_LINUX_QUALIFICATION_RUNNER.md"


def validate_contract(defaults: str, tasks: str, playbook: str, runbook: str) -> None:
    for package in (
        "docker.io",
        "build-essential",
        "git",
        "make",
        "python3",
        "python3-venv",
        "ruby",
    ):
        if f'- "{package}=' not in defaults:
            raise AssertionError(f"missing exact host package: {package}")
    required = (
        "snapshot.ubuntu.com/ubuntu/",
        'qualification_ubuntu_snapshot: "20250601T000000Z"',
        "ansible_facts.architecture == qualification_architecture",
        "net.ipv4.ip_forward=1",
        "argv: [sysctl, -n, net.ipv4.ip_forward]",
        "qualification_ip_forward.stdout != \"1\"",
        "argv: [docker, version]",
        "'Server:' not in qualification_docker_version.stdout",
        "argv: [docker, info]",
        'become_user: "{{ qualification_user }}"',
        "systemd_service",
        "enabled: true",
        "ansible.builtin.getent",
        "Remove mutable Ubuntu package sources",
        "allow_downgrade: true",
    )
    combined = defaults + tasks
    for marker in required:
        if marker not in combined:
            raise AssertionError(f"missing qualification contract marker: {marker}")
    if "qualification_sysctl_file: /etc/sysctl.d/" not in defaults:
        raise AssertionError("persistent repository-owned sysctl file is missing")
    lowered_playbook = playbook.lower()
    for future_platform in ("tekton", "harbor", "buildkit", "cosign"):
        if future_platform in lowered_playbook:
            raise AssertionError(f"M4 resource entered M1 scope: {future_platform}")
    immutable_sha = "58e10fdb7122f9f3302e3fc5534b07021f7cc37f"
    if f"git checkout --detach {immutable_sha}" not in runbook:
        raise AssertionError("qualification checkout is not pinned to the audited SHA")
    if "git checkout milestone/" in runbook or "git checkout infra/" in runbook:
        raise AssertionError("qualification checkout uses a mutable branch tip")


class QualificationRunnerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = DEFAULTS.read_text(encoding="utf-8")
        cls.tasks = TASKS.read_text(encoding="utf-8")
        cls.playbook = PLAYBOOK.read_text(encoding="utf-8")
        cls.runbook = RUNBOOK.read_text(encoding="utf-8")

    def test_complete_contract(self):
        validate_contract(self.defaults, self.tasks, self.playbook, self.runbook)

    def assert_mutation_rejected(self, **replacements):
        values = {
            "defaults": self.defaults,
            "tasks": self.tasks,
            "playbook": self.playbook,
            "runbook": self.runbook,
        }
        values.update(replacements)
        with self.assertRaises(AssertionError):
            validate_contract(**values)

    def test_mutation_remove_docker_server_verification(self):
        self.assert_mutation_rejected(
            tasks=self.tasks.replace("'Server:' not in qualification_docker_version.stdout", "false")
        )

    def test_newer_preinstalled_package_can_reconcile_to_exact_snapshot_pin(self):
        self.assertIn("allow_downgrade: true", self.tasks)
        self.assertIn('name: "{{ qualification_packages }}"', self.tasks)
        self.assertTrue(all("=" in package for package in self._declared_packages()))

    def test_mutation_disallow_pinned_snapshot_downgrade(self):
        self.assert_mutation_rejected(
            tasks=self.tasks.replace("allow_downgrade: true", "allow_downgrade: false")
        )

    def test_mutation_remove_non_root_docker_info_verification(self):
        start = self.tasks.index("- name: Verify Docker daemon information")
        self.assert_mutation_rejected(tasks=self.tasks[:start])

    def test_mutation_change_ip_forward_value(self):
        self.assert_mutation_rejected(tasks=self.tasks.replace("net.ipv4.ip_forward=1", "net.ipv4.ip_forward=0"))

    def test_mutation_remove_persistent_sysctl_file(self):
        self.assert_mutation_rejected(
            defaults=self.defaults.replace("qualification_sysctl_file: /etc/sysctl.d/", "qualification_sysctl_file: /tmp/")
        )

    def test_mutation_add_m4_resource(self):
        self.assert_mutation_rejected(playbook=self.playbook + "\n  - role: tekton\n")

    def test_mutation_checkout_branch_tip(self):
        sha = "58e10fdb7122f9f3302e3fc5534b07021f7cc37f"
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(f"git checkout --detach {sha}", "git checkout milestone/m1-monorepo-bootstrap")
        )

    def _declared_packages(self):
        return [
            line.strip()[3:-1]
            for line in self.defaults.splitlines()
            if line.strip().startswith('- "')
        ]


if __name__ == "__main__":
    unittest.main()
