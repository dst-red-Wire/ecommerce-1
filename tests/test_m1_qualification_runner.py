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
        "curl",
        "diffutils",
        "git",
        "gh",
        "make",
        "python3",
        "python3-venv",
        "ruby",
        "tar",
        "unzip",
    ):
        if f'- "{package}=' not in defaults:
            raise AssertionError(f"missing exact host package: {package}")
    required = (
        "snapshot.ubuntu.com/ubuntu/",
        'qualification_ubuntu_snapshot: "20250601T000000Z"',
        "ansible_facts.architecture == qualification_architecture",
        "net.ipv4.ip_forward=1",
        "argv: [sysctl, -n, net.ipv4.ip_forward]",
        'qualification_ip_forward.stdout != "1"',
        "argv: [docker, version]",
        "'Server:' not in qualification_docker_version.stdout",
        "argv: [docker, info]",
        'become_user: "{{ qualification_user }}"',
        "systemd_service",
        "enabled: true",
        "ansible.builtin.getent",
        "Remove mutable Ubuntu package sources",
        "allow_downgrade: true",
        "UID\n      1000-59999",
        'argv: [sudo, --non-interactive, "true"]',
        "argv: [sysctl, -w, net.ipv4.ip_forward=1]",
    )
    combined = defaults + tasks + playbook
    for marker in required:
        if marker not in combined:
            raise AssertionError(f"missing qualification contract marker: {marker}")
    if "qualification_sysctl_file: /etc/sysctl.d/" not in defaults:
        raise AssertionError("persistent repository-owned sysctl file is missing")
    lowered_playbook = playbook.lower()
    for future_platform in ("tekton", "harbor", "buildkit", "cosign"):
        if future_platform in lowered_playbook:
            raise AssertionError(f"M4 resource entered M1 scope: {future_platform}")
    if "qualification_pr_head:" in defaults or "qualification_pr_base:" in defaults:
        raise AssertionError("runner revisions must come from controller admission, not defaults")
    for marker in (
        "qualification_pr_head is defined",
        "qualification_pr_base is defined",
        "qualification_selected_head.stdout == qualification_pr_head",
        "Fetch the exact qualification head and base objects",
        "Reconcile the hash-locked qualification seed",
        "Reconcile the repository qualification toolchain",
    ):
        if marker not in combined:
            raise AssertionError(f"Ansible does not own runner reconciliation: {marker}")
    if 'git checkout --detach "$qualification_head"' not in runbook:
        raise AssertionError("qualification checkout is not pinned to the audited SHA")
    if "git checkout milestone/" in runbook or "git checkout infra/" in runbook:
        raise AssertionError("qualification checkout uses a mutable branch tip")

    if "set -euo pipefail\nreadonly QUALIFICATION_HEAD=" not in runbook:
        raise AssertionError("trusted admission must fail closed before provisioning")

    trust_markers = (
        "set -euo pipefail",
        "QUALIFICATION_HOST_FINGERPRINT=SHA256:",
        'case "$QUALIFICATION_HOST" in -*) exit 1 ;; esac',
        'ssh-keyscan -H -t ed25519 "$QUALIFICATION_HOST" > "$candidate_key"',
        'ssh-keygen -lf "$candidate_key" -E sha256',
        'test "$candidate_fingerprint" = "$QUALIFICATION_HOST_FINGERPRINT"',
        'cat "$candidate_key" > "$staged_known_hosts"',
        'mv "$staged_known_hosts" "$QUALIFICATION_KNOWN_HOSTS"',
        "ANSIBLE_HOST_KEY_CHECKING=True",
        "UserKnownHostsFile=$QUALIFICATION_KNOWN_HOSTS",
        "HostKeyAlias=$QUALIFICATION_HOST",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
    )
    trust_positions = []
    for marker in trust_markers:
        position = runbook.find(marker)
        if position < 0:
            raise AssertionError(f"missing SSH trust-chain marker: {marker}")
        trust_positions.append(position)
    if trust_positions != sorted(trust_positions):
        raise AssertionError("candidate host key is enrolled before fingerprint equality")

    remote_start = runbook.find('ssh -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" -o StrictHostKeyChecking=yes')
    remote_end = runbook.find("\nQUALIFICATION_RUNNER", remote_start + 1)
    if remote_start < 0 or remote_end < 0:
        raise AssertionError("qualification commands lack an explicit verified SSH context")
    remote_sequence = runbook[remote_start:remote_end]
    for command in (
        "whoami",
        "hostname",
        "uname -a",
        "docker version",
        "docker info",
        "sysctl -n net.ipv4.ip_forward",
        "git rev-parse HEAD",
        "$qualification_base",
        "git status --porcelain=v1",
        'test -z "$worktree_status"',
        "make seed",
        "make bootstrap",
        "make env-check",
        "$HOME/.local/bin/go test -race -tags=integration",
        'BASE="$qualification_base" make ci',
    ):
        if command not in remote_sequence:
            raise AssertionError(f"qualification command is not explicitly remote: {command}")

    single_use_markers = (
        "Require a fresh never-used qualification runner",
        "not qualification_consumed.stat.exists",
        "retries and runner reuse are forbidden",
        "Mark this runner consumed before PR-owned code executes",
        "one qualification attempt",
        "destroy the VM",
    )
    for marker in single_use_markers:
        if marker not in combined + runbook:
            raise AssertionError(f"missing single-use runner contract: {marker}")

    credential_markers = (
        "no cloud instance role",
        "managed-identity or metadata-service credentials",
        "no mounted provider secrets",
        "no CI/controller credentials copied onto it",
        "no access to internal credential-bearing services",
        "isolated, least-egress qualification network",
    )
    normalized_runbook = " ".join(runbook.split())
    for marker in credential_markers:
        if marker not in normalized_runbook:
            raise AssertionError(f"missing credential-isolation contract: {marker}")

    product_start = remote_sequence.find("cd services/product")
    post_bootstrap = remote_sequence.find("make env-check")
    final_head = remote_sequence.find(
        'test "$(git rev-parse HEAD)" = "$qualification_head"',
        post_bootstrap,
    )
    final_clean = remote_sequence.find('test -z "$post_bootstrap_status"', post_bootstrap)
    final_forwarding = remote_sequence.find('test "$(sysctl -n net.ipv4.ip_forward)" = "1"', post_bootstrap)
    if not (post_bootstrap < final_head < final_clean < final_forwarding < product_start):
        raise AssertionError("post-bootstrap fail-closed checks do not immediately precede Product")


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
        self.assert_mutation_rejected(tasks=self.tasks.replace("allow_downgrade: true", "allow_downgrade: false"))

    def test_mutation_remove_non_root_docker_info_verification(self):
        start = self.tasks.index("- name: Verify Docker daemon information")
        self.assert_mutation_rejected(tasks=self.tasks[:start])

    def test_mutation_change_ip_forward_value(self):
        self.assert_mutation_rejected(tasks=self.tasks.replace("net.ipv4.ip_forward=1", "net.ipv4.ip_forward=0"))

    def test_mutation_remove_persistent_sysctl_file(self):
        self.assert_mutation_rejected(
            defaults=self.defaults.replace(
                "qualification_sysctl_file: /etc/sysctl.d/", "qualification_sysctl_file: /tmp/"
            )
        )

    def test_mutation_add_m4_resource(self):
        self.assert_mutation_rejected(playbook=self.playbook + "\n  - role: tekton\n")

    def test_mutation_checkout_branch_tip(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(
                'git checkout --detach "$qualification_head"', "git checkout milestone/m1-monorepo-bootstrap"
            )
        )

    def test_mutation_remove_ssh_fingerprint_comparison(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(
                'test "$candidate_fingerprint" = "$QUALIFICATION_HOST_FINGERPRINT"',
                'echo "$candidate_fingerprint"',
            )
        )

    def test_mutation_remove_remote_execution_context(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(
                'ssh -o UserKnownHostsFile="$QUALIFICATION_KNOWN_HOSTS" -o StrictHostKeyChecking=yes',
                "bash -se",
            )
        )

    def test_mutation_remove_controller_fail_closed_mode(self):
        self.assert_mutation_rejected(runbook=self.runbook.replace("set -euo pipefail", "set -uo pipefail", 1))

    def test_mutation_allow_forwarded_ssh_agent(self):
        self.assert_mutation_rejected(runbook=self.runbook.replace("ForwardAgent=no", "ForwardAgent=yes"))

    def test_mutation_use_default_ci_base(self):
        self.assert_mutation_rejected(runbook=self.runbook.replace('BASE="$qualification_base" make ci', "make ci"))

    def test_mutation_reuse_general_known_hosts(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(
                'cat "$candidate_key" > "$staged_known_hosts"',
                'cat ~/.ssh/known_hosts "$candidate_key" > "$staged_known_hosts"',
            )
        )

    def test_mutation_allow_dirty_remote_checkout(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace('test -z "$worktree_status"', 'echo "$worktree_status"')
        )

    def test_mutation_accept_reusable_tainted_runner(self):
        self.assert_mutation_rejected(
            playbook=self.playbook.replace(
                "not qualification_consumed.stat.exists", "qualification_consumed.stat.exists"
            )
        )

    def test_mutation_remove_post_bootstrap_worktree_check(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace('test -z "$post_bootstrap_status"', 'echo "$post_bootstrap_status"')
        )

    def test_mutation_remove_post_bootstrap_exact_head_check(self):
        marker = 'test "$(git rev-parse HEAD)" = "$qualification_head"'
        position = self.runbook.index(marker, self.runbook.index("make env-check"))
        mutated = self.runbook[:position] + "git rev-parse HEAD" + self.runbook[position + len(marker) :]
        self.assert_mutation_rejected(runbook=mutated)

    def test_mutation_replace_final_ip_forward_assertion_with_print(self):
        self.assert_mutation_rejected(
            runbook=self.runbook.replace(
                'test "$(sysctl -n net.ipv4.ip_forward)" = "1"',
                "sysctl -n net.ipv4.ip_forward",
            )
        )

    def test_mutation_remove_credential_isolation_requirement(self):
        self.assert_mutation_rejected(runbook=self.runbook.replace("no cloud instance role", "ordinary cloud host"))

    def _declared_packages(self):
        return [line.strip()[3:-1] for line in self.defaults.splitlines() if line.strip().startswith('- "')]


if __name__ == "__main__":
    unittest.main()
