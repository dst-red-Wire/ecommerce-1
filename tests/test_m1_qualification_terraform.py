import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "platform/terraform/environments/qualification"
MODULE = ROOT / "platform/terraform/modules/hcloud-qualification"
RUNNER_PATHS = (
    ROOT / "platform/ansible/qualification-runner.yml",
    ROOT / "platform/ansible/roles/qualification_runner_host",
    ROOT / "docs/project/M1_LINUX_QUALIFICATION_RUNNER.md",
    ROOT / "tests/test_m1_qualification_runner.py",
)


def validate_contract(files: dict[str, str]) -> None:
    combined = "\n".join(files.values())
    required = (
        'version = "= 1.68.0"',
        'source = "../../modules/hcloud-qualification"',
        'resource "hcloud_server" "qualification"',
        'resource "hcloud_firewall" "qualification"',
        'name              = var.image',
        'with_architecture = "x86"',
        'startswith(data.hcloud_image.qualification.os_version, "24.04")',
        'data.hcloud_server_type.qualification.architecture == "x86"',
        'variable "qualification_server_type"',
        'variable "qualification_ssh_key_id"',
        'variable "qualification_ssh_allowed_cidrs"',
        'for cidr in var.qualification_ssh_allowed_cidrs : can(cidrhost(cidr, 0)) && !endswith(cidr, "/0")',
        'name: ${qualification_user}',
        'sudo: ["ALL=(ALL) NOPASSWD:ALL"]',
        'ssh_authorized_keys:',
        'output "qualification_image_identity"',
        'qualification_user=${module.hcloud_qualification.user}',
    )
    for marker in required:
        if marker not in combined:
            raise AssertionError(f"missing qualification Terraform contract: {marker}")
    cidr_guard = '!endswith(cidr, "/0")'
    if cidr_guard not in files["environment/variables.tf"]:
        raise AssertionError("environment SSH CIDR validation is missing")
    if '!endswith(cidr, "/0")' not in files["module/main.tf"]:
        raise AssertionError("module SSH CIDR validation is missing")
    forbidden = (
        'provisioner "local-exec"', 'provisioner "remote-exec"',
        "null_resource", "terraform_remote_state", "hcloud_network",
        "HCLOUD_TOKEN", "private_key", "terraform apply",
    )
    cloud_init = files["module/cloud-init.yaml.tftpl"].lower()
    for marker in ("docker", "sysctl", "apt:", "packages:", "runcmd:", "curl"):
        if marker in cloud_init:
            raise AssertionError(f"cloud-init crossed the Ansible boundary: {marker}")
    source_without_docs = "\n".join(
        value for name, value in files.items() if not name.endswith("README.md")
    )
    for marker in forbidden:
        if marker in source_without_docs:
            raise AssertionError(f"forbidden qualification mechanism: {marker}")
    if combined.count('resource "hcloud_server"') != 1:
        raise AssertionError("qualification module must define exactly one server")


class QualificationTerraformContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {}
        for prefix, directory in (("environment", ENV), ("module", MODULE)):
            for path in directory.iterdir():
                if path.is_file() and path.name != ".terraform.lock.hcl":
                    cls.files[f"{prefix}/{path.name}"] = path.read_text(encoding="utf-8")

    def test_complete_contract(self):
        validate_contract(self.files)

    def assert_mutation_rejected(self, name: str, old: str, new: str):
        mutated = dict(self.files)
        mutated[name] = mutated[name].replace(old, new)
        with self.assertRaises(AssertionError):
            validate_contract(mutated)

    def test_security_and_boundary_mutations_are_rejected(self):
        mutations = (
            ("module/main.tf", 'startswith(data.hcloud_image.qualification.os_version, "24.04")', 'data.hcloud_image.qualification.os_flavor == "rocky"'),
            ("module/cloud-init.yaml.tftpl", "name: ${qualification_user}", "name: root"),
            ("environment/variables.tf", '!endswith(cidr, "/0")', "true"),
            ("module/main.tf", 'resource "hcloud_server" "qualification"', 'provisioner "remote-exec" {}\nresource "hcloud_server" "qualification"'),
            ("module/main.tf", 'resource "hcloud_server" "qualification"', 'provisioner "local-exec" {}\nresource "hcloud_server" "qualification"'),
            ("module/cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nruncmd: [docker install]"),
            ("module/cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nruncmd: [sysctl -w x=y]"),
            ("module/cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nHCLOUD_TOKEN: injected"),
            ("environment/outputs.tf", 'output "qualification_server_id"', 'output "private_key" {}\noutput "qualification_server_id"'),
            ("environment/outputs.tf", ' qualification_user=${module.hcloud_qualification.user}', ''),
            ("environment/main.tf", 'source = "../../modules/hcloud-qualification"', 'source = "../mgmt"\ndata "terraform_remote_state" "mgmt" {}'),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_rejected(*mutation)

    def test_canonical_runner_is_unchanged_from_base(self):
        base = os.environ.get("BASE", "")
        self.assertRegex(base, r"^[0-9a-f]{40}$", "BASE must be the authenticated full lowercase Git SHA")
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=ROOT
        )
        self.assertEqual(0, exists.returncode, "the exact BASE commit must exist")
        for path in RUNNER_PATHS:
            rel = path.relative_to(ROOT)
            result = subprocess.run(
                ["git", "diff", "--quiet", base, "--", str(rel)], cwd=ROOT
            )
            self.assertEqual(0, result.returncode, f"canonical #78 path changed: {rel}")


if __name__ == "__main__":
    unittest.main()
