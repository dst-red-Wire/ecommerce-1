from __future__ import annotations

import ipaddress
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
NETWORK_PLAN = ROOT / "config/infrastructure/network-plan.yaml"
POLICY = ROOT / "config/contracts/mgmt-wireguard-access.yaml"
DOC = ROOT / "docs/architecture/MGMT_WIREGUARD_ACCESS.md"
LOCK = ROOT / "architecture.lock.yaml"
EXACT_INDEX = ROOT / "docs/architecture/EXACT_TOPOLOGY_V2.md"


class WireGuardArchitectureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = yaml.safe_load(NETWORK_PLAN.read_text(encoding="utf-8"))
        cls.policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
        cls.wg = cls.network["wireguard"]["mgmt"]

    def test_tunnel_is_disjoint_from_every_versioned_network(self):
        tunnel = ipaddress.ip_network(self.wg["tunnel_cidr"])
        existing = []
        for site, cidr in self.network["address_domains"].items():
            existing.append((f"domain:{site}", ipaddress.ip_network(cidr)))
        for site, vlans in self.network["vlans"].items():
            for vlan, spec in vlans.items():
                existing.append((f"vlan:{site}:{vlan}", ipaddress.ip_network(spec["cidr"])))
        for site, cidrs in self.network["kubernetes"].items():
            for kind, cidr in cidrs.items():
                existing.append((f"kubernetes:{site}:{kind}", ipaddress.ip_network(cidr)))

        for label, network in existing:
            self.assertFalse(tunnel.overlaps(network), f"WireGuard tunnel overlaps {label}: {network}")

    def test_gateway_and_peer_pools_are_exact_and_separated(self):
        self.assertEqual("wg-01", self.wg["gateway_node"])
        self.assertEqual("10.243.1.41", self.wg["gateway_mgmt_ip"])
        self.assertEqual("10.246.0.0/24", self.wg["tunnel_cidr"])
        self.assertEqual("10.246.0.1", self.wg["gateway_tunnel_ip"])
        self.assertEqual("10.246.0.16/28", self.wg["operator_pool"])
        self.assertEqual("10.246.0.240/29", self.wg["break_glass_pool"])

        tunnel = ipaddress.ip_network(self.wg["tunnel_cidr"])
        gateway = ipaddress.ip_address(self.wg["gateway_tunnel_ip"])
        operator = ipaddress.ip_network(self.wg["operator_pool"])
        break_glass = ipaddress.ip_network(self.wg["break_glass_pool"])
        self.assertIn(gateway, tunnel)
        self.assertTrue(operator.subnet_of(tunnel))
        self.assertTrue(break_glass.subnet_of(tunnel))
        self.assertFalse(operator.overlaps(break_glass))
        self.assertNotIn(gateway, operator)
        self.assertNotIn(gateway, break_glass)

    def test_gateway_reservation_is_in_infrastructure_vm_range(self):
        allocation = self.network["static_allocations"]["mgmt"][401]["wg-01"]
        self.assertEqual(self.wg["gateway_mgmt_ip"], allocation)
        subnet = ipaddress.ip_network(self.network["vlans"]["mgmt"][401]["cidr"])
        address = ipaddress.ip_address(allocation)
        self.assertIn(address, subnet)
        host_offset = int(address) - int(subnet.network_address)
        self.assertGreaterEqual(host_offset, 40)
        self.assertLessEqual(host_offset, 99)

    def test_operator_routes_are_mgmt_only(self):
        self.assertEqual([self.network["address_domains"]["mgmt"]], self.wg["allowed_routes"])
        allowed = [ipaddress.ip_network(cidr) for cidr in self.wg["allowed_routes"]]
        for cidrs in self.network["kubernetes"].values():
            for cidr in cidrs.values():
                k8s = ipaddress.ip_network(cidr)
                self.assertTrue(all(not route.overlaps(k8s) for route in allowed))

    def test_public_endpoint_is_runtime_only_udp_wireguard(self):
        endpoint = self.wg["endpoint"]
        self.assertEqual("provider-runtime-output", endpoint["address_source"])
        self.assertEqual("udp", endpoint["protocol"])
        self.assertEqual(51820, endpoint["listen_port"])
        self.assertTrue(self.network["validation"]["public_ips_runtime_injected_only"])
        self.assertNotIn("address", endpoint)
        self.assertNotIn("ip", endpoint)

    def test_access_policy_preserves_control_plane_ownership_and_human_gates(self):
        self.assertEqual("exact", self.policy["status"])
        self.assertEqual("Z5", self.policy["gateway"]["trust_zone"])
        self.assertFalse(self.policy["gateway"]["kubernetes_member"])
        self.assertEqual("workforce", self.policy["access"]["identity_realm"])
        self.assertEqual("forbidden", self.policy["access"]["customer_identity"])
        self.assertEqual("deny", self.policy["access"]["default_forwarding"])
        self.assertEqual("forbidden", self.policy["secrets"]["git"])
        self.assertEqual("terraform", self.policy["ownership"]["provider_vm_network_firewall"])
        self.assertEqual("ansible", self.policy["ownership"]["rocky_wireguard_routing_firewall"])
        self.assertEqual("none", self.policy["ownership"]["kubernetes"])
        self.assertEqual(
            {
                "provider_apply": "required",
                "public_ingress_activation": "required",
                "routing_change": "required",
                "peer_or_key_change": "required",
            },
            self.policy["human_gates"],
        )

    def test_threat_model_has_all_required_boundaries_and_controls(self):
        expected = {
            "internet_scanning",
            "stolen_operator_key",
            "overbroad_routes",
            "gateway_compromise",
            "break_glass_misuse",
        }
        threats = self.policy["threat_model"]
        self.assertEqual(expected, set(threats))
        for name, threat in threats.items():
            self.assertTrue(threat["boundary"], name)
            self.assertGreaterEqual(len(threat["controls"]), 3, name)
            self.assertEqual(len(threat["controls"]), len(set(threat["controls"])), name)

    def test_contract_is_indexed_by_architecture_lock(self):
        lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(
            "docs/architecture/MGMT_WIREGUARD_ACCESS.md",
            lock["topology_contracts"]["mgmt_wireguard_access"],
        )
        self.assertEqual(
            "config/contracts/mgmt-wireguard-access.yaml",
            lock["machine_contracts"]["mgmt_wireguard_access"],
        )
        index = EXACT_INDEX.read_text(encoding="utf-8")
        self.assertIn("MGMT_WIREGUARD_ACCESS.md", index)
        self.assertIn("config/contracts/mgmt-wireguard-access.yaml", index)

    def test_exact_document_records_no_active_implementation(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("This architecture PR does not create a VM", text)
        self.assertIn("Terraform/OpenTofu owns provider resources", text)
        self.assertIn("Ansible owns Rocky Linux state", text)
        self.assertIn("No WireGuard key material is stored in Git", text)


if __name__ == "__main__":
    unittest.main()
