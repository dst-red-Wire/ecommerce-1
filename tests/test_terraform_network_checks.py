import ipaddress
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
LOCALS = ROOT / "platform/terraform/environments/mgmt/locals.tf"
CHECKS = ROOT / "platform/terraform/environments/mgmt/checks.tf"
ENV_MAIN = ROOT / "platform/terraform/environments/mgmt/main.tf"
ENV_VARIABLES = ROOT / "platform/terraform/environments/mgmt/variables.tf"
ENV_OUTPUTS = ROOT / "platform/terraform/environments/mgmt/outputs.tf"
MODULE_MAIN = ROOT / "platform/terraform/modules/hcloud-mgmt/main.tf"
INVENTORY = ROOT / "config/infrastructure/mgmt-inventory.yaml"
NETWORK_PLAN = ROOT / "config/infrastructure/network-plan.yaml"


class TerraformNetworkChecksTest(unittest.TestCase):
    def test_management_inventory_addresses_belong_to_canonical_segments(self):
        inventory = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))
        segments = yaml.safe_load(NETWORK_PLAN.read_text(encoding="utf-8"))["vlans"]["mgmt"]

        for node in [*inventory["control_planes"].values(), *inventory["workers"].values()]:
            self.assertIn(ipaddress.ip_address(node["mgmt_ip"]), ipaddress.ip_network(segments[401]["cidr"]))
            self.assertIn(ipaddress.ip_address(node["k8s_ip"]), ipaddress.ip_network(segments[402]["cidr"]))
        for worker in inventory["workers"].values():
            self.assertIn(ipaddress.ip_address(worker["storage_ip"]), ipaddress.ip_network(segments[403]["cidr"]))
            self.assertIn(ipaddress.ip_address(worker["backup_ip"]), ipaddress.ip_network(segments[405]["cidr"]))

    def test_terraform_uses_standard_ipv4_interval_bounds(self):
        locals_text = LOCALS.read_text(encoding="utf-8")
        checks_text = CHECKS.read_text(encoding="utf-8")

        self.assertNotIn("cidrcontains", checks_text)
        self.assertIn("cidrhost(segment.cidr, 0)", locals_text)
        self.assertIn("cidrhost(segment.cidr, -1)", locals_text)
        self.assertIn("mgmt_segment_ipv4_bounds", checks_text)

    def test_hcloud_module_realizes_canonical_private_network(self):
        module_text = MODULE_MAIN.read_text(encoding="utf-8")

        self.assertIn('resource "hcloud_network_subnet" "segment"', module_text)
        self.assertIn("for_each = var.subnets", module_text)
        self.assertIn('subnet_id = hcloud_network_subnet.segment["401"].id', module_text)
        self.assertIn('resource "hcloud_server_network" "node"', module_text)
        self.assertIn("ip        = each.value.mgmt_ip", module_text)
        self.assertIn("alias_ips = compact([", module_text)
        self.assertIn("each.value.k8s_ip", module_text)
        self.assertIn('try(each.value.storage_ip, "")', module_text)
        self.assertIn('try(each.value.backup_ip, "")', module_text)
        self.assertIn("depends_on = [hcloud_network_subnet.segment]", module_text)

    def test_environment_derives_subnets_from_canonical_network_plan(self):
        main_text = ENV_MAIN.read_text(encoding="utf-8")
        variables_text = ENV_VARIABLES.read_text(encoding="utf-8")

        self.assertIn("for vlan, segment in local.mgmt_segments", main_text)
        self.assertIn("tostring(vlan) => segment.cidr", main_text)
        self.assertIn("network_zone = var.hcloud_network_zone", main_text)
        self.assertIn('variable "hcloud_network_zone"', variables_text)
        self.assertNotIn('network_zone = "eu-central"', main_text)

    def test_environment_reexports_management_provider_outputs(self):
        outputs_text = ENV_OUTPUTS.read_text(encoding="utf-8")

        self.assertIn('output "network_id"', outputs_text)
        self.assertIn("module.hcloud_mgmt.network_id", outputs_text)
        self.assertIn('output "servers"', outputs_text)
        self.assertIn("module.hcloud_mgmt.servers", outputs_text)
        self.assertIn('output "private_networks"', outputs_text)
        self.assertIn("module.hcloud_mgmt.private_networks", outputs_text)

    def test_provider_aliases_match_inventory_roles(self):
        inventory = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))

        for node in inventory["control_planes"].values():
            self.assertEqual([node["k8s_ip"]], [node["k8s_ip"]])
        for node in inventory["workers"].values():
            aliases = [node["k8s_ip"], node["storage_ip"], node["backup_ip"]]
            self.assertEqual(3, len(set(aliases)))


if __name__ == "__main__":
    unittest.main()
