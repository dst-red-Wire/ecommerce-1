import ipaddress
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
LOCALS = ROOT / "platform/terraform/environments/mgmt/locals.tf"
CHECKS = ROOT / "platform/terraform/environments/mgmt/checks.tf"
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


if __name__ == "__main__":
    unittest.main()
