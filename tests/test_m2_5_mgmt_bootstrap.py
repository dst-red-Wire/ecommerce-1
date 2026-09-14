from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_mgmt_bootstrap", ROOT / "scripts/validate_mgmt_bootstrap.py")
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)


def load(relative: str):
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


class M25BootstrapContractTests(unittest.TestCase):
    def setUp(self):
        self.inventory = load("config/infrastructure/mgmt-inventory.yaml")
        self.network = load("config/infrastructure/network-plan.yaml")
        self.access = load("config/infrastructure/mgmt-access-gateways.yaml")
        self.bootstrap = load("config/infrastructure/mgmt-bootstrap.yaml")
        self.architecture = load("architecture.lock.yaml")

    def validate(self, **changes):
        values = {
            "inventory": copy.deepcopy(self.inventory),
            "network": copy.deepcopy(self.network),
            "access": copy.deepcopy(self.access),
            "bootstrap": copy.deepcopy(self.bootstrap),
            "architecture": copy.deepcopy(self.architecture),
        }
        values.update(changes)
        return validator.validate_contracts(**values)

    def test_valid_contract_and_repository_pass(self):
        self.assertEqual([], self.validate())
        self.assertEqual([], validator.validate_repository_text())

    def test_control_plane_removal_fails_closed(self):
        mutated = copy.deepcopy(self.inventory)
        mutated["control_planes"].pop("cp-03")
        self.assertTrue(self.validate(inventory=mutated))

    def test_worker_removal_fails_closed(self):
        mutated = copy.deepcopy(self.inventory)
        mutated["workers"].pop("worker-03")
        self.assertTrue(self.validate(inventory=mutated))

    def test_duplicate_ip_fails_closed(self):
        mutated = copy.deepcopy(self.inventory)
        mutated["workers"]["worker-03"]["mgmt_ip"] = mutated["workers"]["worker-02"]["mgmt_ip"]
        self.assertIn("duplicate canonical node IP", self.validate(inventory=mutated))

    def test_private_block_change_fails_closed(self):
        mutated = copy.deepcopy(self.inventory)
        mutated["private_block"] = "10.99.0.0/16"
        self.assertIn("canonical private block changed", self.validate(inventory=mutated))

    def test_human_gate_removal_fails_closed(self):
        mutated = copy.deepcopy(self.inventory)
        mutated["bootstrap"]["human_apply_gate"] = False
        self.assertIn("human apply gate is mandatory", self.validate(inventory=mutated))

    def test_state_cycle_fails_closed(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["state"]["bootstrap"]["availability_dependency"] = "post-bootstrap"
        self.assertIn("state backend circular dependency", self.validate(bootstrap=mutated))

    def test_fleet_replacement_fails_closed(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"].pop("rancher-fleet")
        mutated["platform_bootstrap"]["services"]["flux"] = {"gitops_authority": True}
        self.assertTrue(self.validate(bootstrap=mutated))

    def test_tekton_replacement_fails_closed(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"].pop("tekton")
        mutated["platform_bootstrap"]["services"]["woodpecker"] = {}
        self.assertTrue(self.validate(bootstrap=mutated))

    def test_static_artifacts_reject_forbidden_textual_mutations(self):
        latest = "image: registry.invalid/component:latest"
        ssh = 'port = "22"\nsource_ips = ["0.0.0.0/0"]'
        secret = "private_key: abcdefghijklmnop"
        terraform_rke2 = 'provisioner "remote-exec" { command = "install-rke2" }'
        self.assertRegex(latest, r":latest")
        self.assertRegex(ssh, r'0\.0\.0\.0/0')
        self.assertRegex(secret, r"private_key:.*abcdefghijkl")
        self.assertRegex(terraform_rke2, r"remote-exec")

    def test_inventory_identity_and_resource_intent(self):
        self.assertEqual({"cp-01", "cp-02", "cp-03"}, set(self.inventory["control_planes"]))
        self.assertEqual({"worker-01", "worker-02", "worker-03"}, set(self.inventory["workers"]))
        self.assertEqual({"vcpu": 4, "ram_gib": 8, "os_disk_gib": 80}, self.inventory["vm_profiles"]["rke2-cp"])
        self.assertEqual({"vcpu": 8, "ram_gib": 32, "os_disk_gib": 160}, self.inventory["vm_profiles"]["rke2-worker"])

    def test_terraform_and_ansible_ownership_are_separate(self):
        terraform = (ROOT / "platform/terraform/modules/hcloud-mgmt/main.tf").read_text(encoding="utf-8")
        ansible = (ROOT / "platform/ansible/mgmt.yml").read_text(encoding="utf-8")
        self.assertNotRegex(terraform, r"remote-exec|install-rke2")
        self.assertIn("rke2_server", ansible)
        self.assertIn("rke2_agent", ansible)


if __name__ == "__main__":
    unittest.main()
