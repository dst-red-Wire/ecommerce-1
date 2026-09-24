import copy
import importlib.util
import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_repoctl():
    spec = importlib.util.spec_from_file_location(
        "repoctl_opentofu_authority", ROOT / "scripts/repoctl.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


REPOCTL = load_repoctl()


class OpenTofuAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.toolchain = json.loads(
            (ROOT / "config/contracts/toolchain-lock.json").read_text(encoding="utf-8")
        )
        self.graph = json.loads(
            (ROOT / "config/toolchain/capabilities.json").read_text(encoding="utf-8")
        )
        self.architecture = yaml.safe_load(
            (ROOT / "architecture.lock.yaml").read_text(encoding="utf-8")
        )

    def test_opentofu_is_the_only_iac_cli_authority(self):
        self.assertEqual(
            {
                "authority": "opentofu",
                "command": "tofu",
                "terraform_cli": "forbidden",
                "provider_lock": ".terraform.lock.hcl",
            },
            self.architecture["tooling"]["iac"],
        )
        self.assertIn("opentofu", self.toolchain["tool_lifecycle"]["active"])
        self.assertFalse(
            any(
                name.replace("_", "-") in {"terraform", "terraform-cli"}
                for entries in self.toolchain["tool_lifecycle"].values()
                for name in entries
            )
        )
        self.assertFalse(
            any(key.startswith("TERRAFORM_") for key in self.toolchain["versions"])
        )
        capability = next(
            item for item in self.graph["capabilities"] if item["name"] == "opentofu"
        )
        self.assertEqual("tofu", capability["command"])
        self.assertFalse(
            any(
                item.get("command") == "terraform"
                for item in self.graph["capabilities"]
            )
        )
        self.assertEqual(
            {"tofu": "opentofu"},
            {
                command: owner
                for command, owner in self.graph["command_capabilities"].items()
                if command in {"tofu", "terraform"}
            },
        )

    def test_dual_iac_engine_mutation_fails_governance(self):
        toolchain = copy.deepcopy(self.toolchain)
        graph = copy.deepcopy(self.graph)
        toolchain["versions"]["HASHICORP_TERRAFORM_VERSION"] = "1.14.0"
        toolchain["tool_lifecycle"]["active"]["terraform-cli"] = {
            "capability": "terraform-cli",
            "version_ref": "HASHICORP_TERRAFORM_VERSION",
            "provision": {"type": "ansible", "tags": "opentofu"},
            "scenario_policy": "none",
        }
        toolchain["tools"]["terraform-cli"] = {
            "version_ref": "HASHICORP_TERRAFORM_VERSION",
            "binary": "/usr/local/bin/terraform",
            "version_command": ["/usr/local/bin/terraform", "version"],
        }
        graph["capabilities"].append(
            {
                "name": "terraform-cli",
                "requires": [],
                "command": "/usr/local/bin/terraform",
                "version_args": ["version"],
                "version_key": "HASHICORP_TERRAFORM_VERSION",
                "classification": "managed",
                "provision": {"type": "ansible", "tags": "opentofu"},
                "requirement": "required-static",
            }
        )
        graph["command_capabilities"]["/usr/local/bin/terraform"] = "terraform-cli"
        violations = REPOCTL.toolchain_closure_violations(
            toolchain, graph, root=ROOT, check_projections=False
        )
        self.assertIn(
            "OpenTofu must be the sole IaC engine lifecycle entry", violations
        )
        self.assertIn("Terraform CLI capability is forbidden", violations)
        self.assertIn(
            "Terraform CLI command is forbidden in the capability graph", violations
        )
        self.assertIn("Terraform CLI tool definition is forbidden", violations)
        self.assertIn("IaC command projection must expose tofu only", violations)

    def test_opentofu_compatibility_names_remain_valid_inputs(self):
        expected_names = ("terraform {", "registry.opentofu.org", ".terraform.lock.hcl")
        source = (ROOT / "platform/terraform/environments/mgmt/versions.tf").read_text(
            encoding="utf-8"
        )
        lockfile = (
            ROOT / "platform/terraform/environments/mgmt/.terraform.lock.hcl"
        ).read_text(encoding="utf-8")
        self.assertIn(expected_names[0], source)
        self.assertIn(expected_names[1], lockfile)
        self.assertEqual(".terraform.lock.hcl", expected_names[2])
        self.assertEqual(
            [],
            REPOCTL.toolchain_closure_violations(
                self.toolchain, self.graph, root=ROOT, check_projections=False
            ),
        )

    def test_release_is_checksum_and_signature_pinned(self):
        tool = self.toolchain["tools"]["opentofu"]
        versions = self.toolchain["versions"]
        self.assertRegex(versions[tool["sha256_ref"]], r"^[0-9a-f]{64}$")
        for key in (
            "checksums_sha256_ref",
            "gpg_signature_sha256_ref",
            "trust_anchor_sha256_ref",
        ):
            self.assertRegex(versions[tool["supply_chain"][key]], r"^[0-9a-f]{64}$")
        self.assertRegex(tool["supply_chain"]["gpg_fingerprint"], r"^[0-9A-F]{40}$")
        installer = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Verify the exact OpenTofu OpenPGP signing-key fingerprint", installer
        )
        self.assertIn(
            "Verify the OpenTofu checksum manifest signature offline", installer
        )
        self.assertIn("toolchain_offline", installer)
        self.assertNotIn("releases.hashicorp.com/terraform", installer)

    def test_ansible_reconciliation_removes_forbidden_terraform_cli(self):
        main_tasks = yaml.safe_load(
            (
                ROOT
                / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
            ).read_text(encoding="utf-8")
        )
        import_task = next(
            task
            for task in main_tasks
            if task["name"] == "Reconcile forbidden legacy IaC artifacts"
        )
        self.assertEqual(
            "opentofu_cleanup.yml", import_task["ansible.builtin.import_tasks"]
        )
        tasks = yaml.safe_load(
            (
                ROOT
                / "platform/ansible/roles/developer_toolchain/tasks/opentofu_cleanup.yml"
            ).read_text(encoding="utf-8")
        )
        by_name = {task["name"]: task for task in tasks}
        authority = by_name[
            "Require central OpenTofu-only authority before Terraform CLI removal"
        ]["ansible.builtin.assert"]["that"]
        self.assertIn(
            "developer_toolchain_architecture_lock.tooling.iac.terraform_cli == 'forbidden'",
            authority,
        )
        self.assertEqual(
            "absent",
            by_name["Remove the forbidden Terraform operating-system package"][
                "ansible.builtin.apt"
            ]["state"],
        )
        self.assertEqual(
            "{{ local_bin }}/terraform",
            by_name[
                "Remove forbidden Terraform CLI entry points from the managed user path"
            ]["ansible.builtin.file"]["path"],
        )
        self.assertEqual(
            "{{ developer_toolchain_forbidden_terraform_cli_system_paths }}",
            by_name[
                "Remove forbidden Terraform CLI entry points from system paths"
            ]["loop"],
        )
        discovery = by_name[
            "Discover stale repository-managed Terraform CLI artifacts"
        ]["ansible.builtin.find"]
        self.assertEqual(
            ["terraform-*", "terraform-provider-cache"], discovery["patterns"]
        )
        self.assertFalse(discovery["recurse"])
        self.assertEqual(
            "absent",
            by_name["Remove stale repository-managed Terraform CLI artifacts"][
                "ansible.builtin.file"
            ]["state"],
        )
        self.assertEqual(
            ["bash", "-lc", "command -v terraform"],
            by_name["Probe for a residual Terraform CLI on the effective path"][
                "ansible.builtin.command"
            ]["argv"],
        )
        self.assertIn(
            "developer_toolchain_terraform_cli_probe.rc != 0",
            by_name["Require Terraform CLI to be absent after reconciliation"][
                "ansible.builtin.assert"
            ]["that"],
        )

    def test_hcl_required_version_projects_the_central_pin(self):
        version = self.toolchain["versions"]["OPENTOFU_VERSION"]
        for relative in (
            "platform/terraform/environments/mgmt/versions.tf",
            "platform/terraform/environments/qualification/versions.tf",
        ):
            self.assertIn(
                f'required_version = "= {version}"',
                (ROOT / relative).read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
