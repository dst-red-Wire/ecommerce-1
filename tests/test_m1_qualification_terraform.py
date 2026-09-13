import os
import re
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
    main = files["module/main.tf"]
    gateway_bootstrap = files["module/gateway-cloud-init.yaml.tftpl"]
    required = (
        'version = "= 1.68.0"',
        'resource "hcloud_network" "qualification"',
        'resource "hcloud_network_subnet" "qualification"',
        'resource "hcloud_server" "runner"',
        'resource "hcloud_server" "gateway"',
        'resource "hcloud_server_network" "runner"',
        'resource "hcloud_server_network" "gateway"',
        'network_id = hcloud_network.qualification.id',
        'source_ips = var.ssh_allowed_cidrs',
        'source_ips = ["${var.runner_private_ip}/32"]',
        'destination_ips = ["${var.gateway_private_ip}/32"]',
        'ipv4_enabled = false',
        'ipv4_enabled = true',
        'acl allowed_domains dstdomain snapshot.ubuntu.com github.com',
        'http_access deny CONNECT !SSL_ports',
        'http_access allow runner allowed_domains',
        'http_access deny all',
        'squid=${squid_version}',
        'systemctl, is-active, --quiet, squid',
        'qualification_user=${module.hcloud_qualification.user}',
        'ProxyJump=ubuntu@${module.hcloud_qualification.gateway_ipv4}',
        'HTTP_PROXY',
        'HTTPS_PROXY',
        'NO_PROXY',
        '!endswith(cidr, "/0")',
    )
    for marker in required:
        if marker not in combined:
            raise AssertionError(f"missing qualification boundary: {marker}")

    if len(re.findall(r'resource\s+"hcloud_server"\s+"', main)) != 2:
        raise AssertionError("qualification module must define exactly two servers")
    if 'resource "hcloud_firewall" "runner"' not in main or 'resource "hcloud_firewall" "gateway"' not in main:
        raise AssertionError("independent runner and gateway firewalls are required")
    for name in ("environment/variables.tf", "module/main.tf"):
        if '!endswith(cidr, "/0")' not in files[name]:
            raise AssertionError(f"normalized zero-prefix CIDRs must be rejected in {name}")
    if "http_access allow all" in gateway_bootstrap:
        raise AssertionError("Squid policy must never allow all")
    if re.search(r"http_access allow (?:CONNECT|runner CONNECT)", gateway_bootstrap):
        raise AssertionError("Squid CONNECT must remain hostname allowlisted")
    if "HCLOUD_TOKEN" in gateway_bootstrap or "private_key" in gateway_bootstrap:
        raise AssertionError("gateway guest must receive no infrastructure secret")
    if re.search(r"git (?:clone|fetch|checkout)|github\.com/dst-red-Wire/ecommerce-1", gateway_bootstrap):
        raise AssertionError("gateway must receive no PR checkout")
    if re.search(r"hcloud-(?:mgmt|k8s|storage|backup)|terraform_remote_state", combined, re.I):
        raise AssertionError("qualification network must not attach to internal state or networks")
    for marker in ('provisioner "local-exec"', 'provisioner "remote-exec"', "null_resource", 'resource "terraform_data"'):
        if marker in combined:
            raise AssertionError(f"Terraform orchestration is forbidden: {marker}")


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
        self.assertIn(old, self.files[name], f"mutation fixture missing: {old}")
        mutated = dict(self.files)
        mutated[name] = mutated[name].replace(old, new, 1)
        with self.assertRaises(AssertionError):
            validate_contract(mutated)

    def test_egress_boundary_mutations_are_rejected(self):
        mutations = (
            ("module/main.tf", "ipv4_enabled = false", "ipv4_enabled = true"),
            ("module/main.tf", 'resource "hcloud_network" "qualification"', 'resource "removed_network" "qualification"'),
            ("module/main.tf", 'resource "hcloud_server" "gateway"', 'resource "removed_server" "gateway"'),
            ("module/main.tf", 'source_ips = ["${var.runner_private_ip}/32"]', 'source_ips = ["0.0.0.0/0"]'),
            ("module/gateway-cloud-init.yaml.tftpl", "http_access deny all", "http_access allow all"),
            ("module/gateway-cloud-init.yaml.tftpl", "http_access deny !runner", "http_access allow all\n      http_access deny !runner"),
            ("module/gateway-cloud-init.yaml.tftpl", "http_access allow runner allowed_domains", "http_access allow CONNECT"),
            ("module/main.tf", "network_id = hcloud_network.qualification.id", "network_id = hcloud-mgmt.id"),
            ("module/gateway-cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nHCLOUD_TOKEN: injected"),
            ("module/gateway-cloud-init.yaml.tftpl", "#cloud-config", "#cloud-config\nruncmd: [git clone https://github.com/dst-red-Wire/ecommerce-1]"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_mutation_rejected(*mutation)
        validate_contract(self.files)

    def test_admission_regressions_are_rejected(self):
        for name in ("environment/variables.tf", "module/main.tf"):
            if '!endswith(cidr, "/0")' in self.files[name]:
                self.assert_mutation_rejected(name, '!endswith(cidr, "/0")', "true")

    def test_canonical_runner_is_unchanged_from_base(self):
        base = os.environ.get("BASE", "")
        self.assertRegex(base, r"^[0-9a-f]{40}$", "BASE must be the authenticated full lowercase Git SHA")
        exists = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=ROOT)
        self.assertEqual(0, exists.returncode, "the exact BASE commit must exist")
        for path in RUNNER_PATHS:
            rel = path.relative_to(ROOT)
            result = subprocess.run(["git", "diff", "--quiet", base, "--", str(rel)], cwd=ROOT)
            self.assertEqual(0, result.returncode, f"canonical #78 path changed: {rel}")


if __name__ == "__main__":
    unittest.main()
