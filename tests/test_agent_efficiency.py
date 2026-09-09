import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AgentEfficiencyContractTest(unittest.TestCase):
    def test_delivery_consumes_exact_evidence_not_hardcoded_pass_claims(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("exact_commit_evidence", text)
        self.assertIn(".context/evidence/", text)
        self.assertNotIn("- governance: PASS", text)

    def test_frontend_uses_turbo_but_keeps_pnpm(self):
        package = json.loads((ROOT / "frontend/package.json").read_text(encoding="utf-8"))
        self.assertEqual("pnpm@11.24.0", package["packageManager"])
        self.assertEqual("turbo run typecheck", package["scripts"]["typecheck"])
        self.assertEqual("2.10.12", package["devDependencies"]["turbo"])

    def test_bazel_and_nx_are_not_tekton_replacements(self):
        topology = (ROOT / "config/contracts/ci-topology.yaml").read_text(encoding="utf-8")
        self.assertIn("ci: tekton", topology)
        self.assertIn("role: local-verification-entrypoint", topology)
        self.assertIn("role: derived-contract-graph-visualization", topology)
        self.assertIn("role: frontend-task-scheduling-and-local-cache", topology)

    def test_node_and_corepack_are_reconciled_by_ansible(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text(encoding="utf-8")
        self.assertIn(
            "NODE_SHA256_LINUX_X64=2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2", versions
        )
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Download pinned Node archive", tasks)
        self.assertIn("Link Node and Corepack commands", tasks)

    def test_ansible_bootstrap_is_versioned_and_self_hosting(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("ANSIBLE_CORE_VERSION=2.21.4", versions)
        self.assertIn("ANSIBLE_LINT_VERSION=26.8.0", versions)
        self.assertIn("pipx run --spec ansible-core==$(ANSIBLE_CORE_VERSION)", makefile)
        self.assertIn("ansible-core=={{ ansible_core_version }}", tasks)
        self.assertIn("ansible-lint=={{ ansible_lint_version }}", tasks)
        self.assertIn("Validate canonical ansible-playbook version and path", tasks)
        self.assertIn('argv: ["{{ local_bin }}/ansible-playbook", --version]', tasks)
        self.assertIn("export PATH := $(HOME)/.local/bin:$(PATH)", makefile)

    def test_bootstrap_is_single_cross_linux_idempotent_contract(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        playbook = (ROOT / "platform/ansible/developer.yml").read_text(encoding="utf-8")
        workstation = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
        self.assertEqual(1, len([line for line in makefile.splitlines() if line.startswith("bootstrap:")]))
        self.assertNotIn("workstation-bootstrap:", makefile)
        self.assertNotIn("Require WSL2", playbook)
        self.assertIn("Detect WSL2 without making it a global prerequisite", playbook)
        self.assertIn("Reconcile pinned Ruby Psych YAML runtime", workstation)
        self.assertIn("Validate explicitly provisioned Ruby and Psych runtime", workstation)
        self.assertIn("- build-essential", workstation)
        self.assertIn("state: present", workstation)

    def test_prepush_reuses_evidence_only_for_current_base(self):
        text = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn('base_sha = git("rev-parse", "origin/main").strip()', text)
        self.assertIn('data.get("base_sha") == base_sha', text)

    def test_ansible_first_replaces_shell_automation(self):
        self.assertFalse(list((ROOT / "scripts").glob("*.sh")))
        self.assertTrue((ROOT / "platform/ansible/developer.yml").is_file())
        controller = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("Stateful workstation and", controller)

    def test_oasdiff_checksum_matches_downloaded_tarball_asset(self):
        versions = (ROOT / "config/toolchain/versions.env").read_text(encoding="utf-8")
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("OASDIFF_VERSION=1.28.0", versions)
        self.assertIn(
            "OASDIFF_SHA256_LINUX_AMD64_TARGZ=e0ef076f2cf953d922addc04be9c3851cf3ec18f7678d2b94d44cea23dca51b5",
            versions,
        )
        self.assertIn("oasdiff_{{ oasdiff_version }}_linux_amd64.tar.gz", tasks)
        self.assertIn('checksum: "sha256:{{ oasdiff_sha256 }}"', tasks)
        self.assertIn("Validate pinned oasdiff version", tasks)
        self.assertIn('argv: ["{{ local_bin }}/oasdiff", version]', tasks)

    def test_native_docker_readiness_is_checked_as_bootstrap_user(self):
        tasks = (ROOT / "platform/ansible/roles/developer_workstation/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Reconcile bootstrap user membership in the Docker group", tasks)
        self.assertIn("append: true", tasks)
        self.assertIn("Probe Docker daemon as the bootstrap user", tasks)
        self.assertIn("Wait until Docker daemon is usable by the bootstrap user", tasks)
        self.assertIn("Fail closed rather than claim Docker readiness in a stale login session", tasks)
        self.assertIn("docker_probe.rc != 0", tasks)
        self.assertIn("until: docker_ready.rc == 0", tasks)

    def test_isolated_nx_has_exact_fail_closed_build_approval(self):
        tasks = (ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("Write fail-closed PNPM build policy for isolated Nx", tasks)
        self.assertIn("strictDepBuilds: true", tasks)
        self.assertIn('"nx@{{ nx_version }}": true', tasks)
        self.assertIn("nx_pnpm_policy.changed", tasks)
        self.assertIn("Validate exact isolated Nx local version", tasks)
        self.assertNotIn("pnpm approve-builds", tasks)
        self.assertNotIn("dangerouslyAllowAllBuilds", tasks)


if __name__ == "__main__":
    unittest.main()
