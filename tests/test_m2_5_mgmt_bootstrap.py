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
        self.wireguard = load("config/contracts/mgmt-wireguard-access.yaml")

    def validate(self, **changes):
        values = {
            "inventory": copy.deepcopy(self.inventory),
            "network": copy.deepcopy(self.network),
            "access": copy.deepcopy(self.access),
            "bootstrap": copy.deepcopy(self.bootstrap),
            "architecture": copy.deepcopy(self.architecture),
            "wireguard": copy.deepcopy(self.wireguard),
        }
        values.update(changes)
        return validator.validate_contracts(**values)

    def test_valid_contract_and_repository_pass(self):
        self.assertEqual([], self.validate())
        self.assertEqual([], validator.validate_repository_text())

    def test_offline_bootstrap_contract_fails_closed_on_external_fallback(self):
        for section, key, value in (
            (None, "source", "cluster-hosted-harbor"),
            (None, "manifest_authorization", "self-approved"),
            ("network", "artifact_downloads_from_nodes", "allowed"),
            ("network", "wireguard_internet_nat", "allowed"),
            ("installation", "package_repositories", "default"),
            ("installation", "registry_default_endpoint_fallback", "enabled"),
        ):
            mutated = copy.deepcopy(self.bootstrap)
            target = mutated["offline_installation"]
            if section:
                target = target[section]
            target[key] = value
            with self.subTest(key=key):
                self.assertTrue(self.validate(bootstrap=mutated))

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

    def test_bootstrap_order_keeps_tekton_before_kratix(self):
        order = self.bootstrap["platform_bootstrap"]["order"]
        self.assertLess(order.index("tekton"), order.index("kratix"))
        mutated = copy.deepcopy(self.bootstrap)
        mutated_order = mutated["platform_bootstrap"]["order"]
        mutated_order.remove("tekton")
        mutated_order.append("tekton")
        self.assertIn(
            "platform bootstrap order must place Tekton wave 40 before Kratix wave 45",
            self.validate(bootstrap=mutated),
        )

    def test_external_secrets_removal_fails_closed(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"].pop("external-secrets")
        self.assertIn("platform bootstrap service set incomplete", self.validate(bootstrap=mutated))

    def test_external_secrets_openbao_dependency_mutation_fails(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"]["external-secrets"].pop("dependency")
        self.assertIn("External Secrets must retain its explicit OpenBao dependency", self.validate(bootstrap=mutated))

    def test_kratix_fleet_gitea_boundary_mutation_fails(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"]["kratix"]["deployment_owner"] = "direct-kubectl"
        self.assertIn(
            "Kratix must remain Fleet-deployed, Kustomize-composed, Helm-packaged and Gitea-backed",
            self.validate(bootstrap=mutated),
        )

    def test_kratix_activation_dependency_removal_fails(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["platform_bootstrap"]["services"]["kratix"]["activation_dependencies"].remove("cert-manager")
        self.assertIn("Kratix activation dependencies are incomplete", self.validate(bootstrap=mutated))

    def test_wireguard_transition_mutations_fail_closed(self):
        mutations = {
            "permanent bootstrap": ("permanent_use", "allowed"),
            "missing rotation": ("key_rotation", "copy-bootstrap-key"),
            "missing key cleanup": ("bootstrap_key_cleanup", "optional"),
            "missing peer cleanup": ("bootstrap_peer_staging_cleanup", "optional"),
            "missing SSH cleanup": ("bootstrap_public_ssh_cleanup", "optional"),
        }
        for label, (field, value) in mutations.items():
            mutated = copy.deepcopy(self.bootstrap)
            section = "bootstrap" if field == "permanent_use" else "transition"
            mutated["wireguard_authority"][section][field] = value
            with self.subTest(label=label):
                self.assertTrue(self.validate(bootstrap=mutated))

    def test_steady_authority_raw_environment_secret_mutation_fails(self):
        mutated = copy.deepcopy(self.bootstrap)
        mutated["wireguard_authority"]["steady_state"]["mode"] = "raw-environment-private-key"
        self.assertIn("steady WireGuard authority must use runtime OpenBao reads", self.validate(bootstrap=mutated))

    def test_bootstrap_transport_and_teardown_mutations_fail_closed(self):
        mutations = []
        public_node = copy.deepcopy(self.wireguard)
        public_node["phases"]["bootstrap"]["bootstrap_transport"]["public_ssh_node"] = "all-rke2-nodes"
        mutations.append(public_node)
        global_cidr = copy.deepcopy(self.wireguard)
        global_cidr["phases"]["bootstrap"]["bootstrap_transport"]["global_cidrs"] = "0.0.0.0/0"
        mutations.append(global_cidr)
        global_ipv6 = copy.deepcopy(self.wireguard)
        global_ipv6["phases"]["bootstrap"]["bootstrap_transport"]["global_cidrs"] = "::/0"
        mutations.append(global_ipv6)
        no_gate = copy.deepcopy(self.wireguard)
        no_gate["phases"]["bootstrap"]["bootstrap_transport"]["human_gate"] = "optional"
        mutations.append(no_gate)
        steady_ssh = copy.deepcopy(self.wireguard)
        steady_ssh["phases"]["steady_state"]["persistent_transport"]["public_ssh"] = "allowed"
        mutations.append(steady_ssh)
        copied_key = copy.deepcopy(self.wireguard)
        copied_key["transition"]["copying_bootstrap_key_to_openbao"] = "allowed"
        mutations.append(copied_key)
        no_cleanup = copy.deepcopy(self.wireguard)
        no_cleanup["transition"]["revocation_teardown"].pop("bootstrap_gateway_private_key")
        mutations.append(no_cleanup)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(self.validate(wireguard=mutation))

    def test_static_artifacts_reject_forbidden_textual_mutations(self):
        latest = "image: registry.invalid/component:latest"
        ssh = 'port = "22"\nsource_ips = ["0.0.0.0/0"]'
        secret = "private_key: abcdefghijklmnop"
        terraform_rke2 = 'provisioner "remote-exec" { command = "install-rke2" }'
        self.assertRegex(latest, r":latest")
        self.assertRegex(ssh, r"0\.0\.0\.0/0")
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
