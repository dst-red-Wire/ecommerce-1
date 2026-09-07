from __future__ import annotations

import ipaddress
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
NETWORK_PLAN = ROOT / "config/infrastructure/network-plan.yaml"
POLICY = ROOT / "config/contracts/mgmt-wireguard-access.yaml"
ACCESS_GATEWAYS = ROOT / "config/infrastructure/mgmt-access-gateways.yaml"
DOC = ROOT / "docs/architecture/MGMT_WIREGUARD_ACCESS.md"
LOCK = ROOT / "architecture.lock.yaml"
EXACT_INDEX = ROOT / "docs/architecture/EXACT_TOPOLOGY_V2.md"


class WireGuardArchitectureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = yaml.safe_load(NETWORK_PLAN.read_text(encoding="utf-8"))
        cls.policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
        cls.gateway_inventory = yaml.safe_load(ACCESS_GATEWAYS.read_text(encoding="utf-8"))
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

    def test_dedicated_gateway_inventory_and_profile_are_exact(self):
        self.assertEqual("exact", self.gateway_inventory["status"])
        self.assertEqual("mgmt", self.gateway_inventory["site"])
        self.assertEqual("hetzner-cloud", self.gateway_inventory["provider"])
        self.assertEqual({"wireguard-gateway"}, set(self.gateway_inventory["vm_profiles"]))
        self.assertEqual(
            {"vcpu": 2, "ram_gib": 2, "os_disk_gib": 40},
            self.gateway_inventory["vm_profiles"]["wireguard-gateway"],
        )
        self.assertEqual({"wg-01"}, set(self.gateway_inventory["access_gateways"]))
        gateway = self.gateway_inventory["access_gateways"]["wg-01"]
        self.assertEqual("wireguard-gateway", gateway["profile"])
        self.assertEqual("wireguard-operator-access", gateway["role"])
        self.assertEqual("Z5", gateway["trust_zone"])
        self.assertEqual(401, gateway["mgmt_vlan"])
        self.assertEqual(self.wg["gateway_mgmt_ip"], gateway["mgmt_ip"])
        self.assertFalse(gateway["kubernetes_member"])
        self.assertEqual("provider-runtime-output", gateway["public_endpoint"])
        self.assertTrue(self.gateway_inventory["implementation"]["human_apply_gate"])
        self.assertEqual(
            "future-pr-after-contract-merge",
            self.gateway_inventory["implementation"]["terraform_wiring"],
        )

    def test_operator_routes_are_mgmt_only(self):
        self.assertEqual([self.network["address_domains"]["mgmt"]], self.wg["allowed_routes"])
        allowed = [ipaddress.ip_network(cidr) for cidr in self.wg["allowed_routes"]]
        for cidrs in self.network["kubernetes"].values():
            for cidr in cidrs.values():
                k8s = ipaddress.ip_network(cidr)
                self.assertTrue(all(not route.overlaps(k8s) for route in allowed))

    def test_return_path_is_exact_stateful_snat_on_wg01(self):
        policy = self.wg["return_path"]
        self.assertEqual("snat-on-wg01", policy["mode"])
        self.assertEqual(self.wg["tunnel_cidr"], policy["source_cidr"])
        self.assertEqual(self.network["address_domains"]["mgmt"], policy["destination_cidr"])
        self.assertEqual(self.wg["gateway_mgmt_ip"], policy["translated_source_ip"])
        self.assertEqual("wg-01", policy["downstream_source_identity"])
        self.assertEqual("wireguard-peer-audit-on-wg01", policy["operator_attribution"])
        self.assertEqual("required", policy["stateful_return"])
        translated = ipaddress.ip_address(policy["translated_source_ip"])
        self.assertIn(translated, ipaddress.ip_network(self.network["vlans"]["mgmt"][401]["cidr"]))

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
        self.assertEqual(
            "config/infrastructure/mgmt-access-gateways.yaml#access_gateways.wg-01",
            self.policy["gateway"]["inventory_source"],
        )
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

    def test_non_kubernetes_secret_delivery_is_exact(self):
        secrets = self.policy["secrets"]
        self.assertEqual("openbao", secrets["authority"])
        self.assertEqual("ansible", secrets["delivery"]["owner"])
        self.assertEqual("runtime-openbao-read", secrets["delivery"]["mode"])
        self.assertEqual("forbidden", secrets["delivery"]["kubernetes_eso"])
        self.assertEqual("root-0600", secrets["delivery"]["gateway_target_permissions"])
        self.assertEqual("runtime-injected-nonpersisted", secrets["delivery"]["openbao_auth"])
        self.assertEqual("kv", secrets["gateway_private_key"]["mount"])
        self.assertEqual("mgmt/wireguard/wg-01", secrets["gateway_private_key"]["path"])
        self.assertEqual("private_key", secrets["gateway_private_key"]["field"])
        self.assertEqual("operator-device", secrets["operator_peer_private_keys"]["authority"])
        self.assertEqual("forbidden", secrets["operator_peer_private_keys"]["central_storage"])
        self.assertEqual("openbao", secrets["break_glass_private_keys"]["authority"])
        self.assertEqual("separately-controlled", secrets["break_glass_private_keys"]["access"])

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
        self.assertEqual(
            "config/infrastructure/mgmt-access-gateways.yaml",
            lock["machine_contracts"]["mgmt_access_gateways"],
        )
        index = EXACT_INDEX.read_text(encoding="utf-8")
        self.assertIn("MGMT_WIREGUARD_ACCESS.md", index)
        self.assertIn("config/contracts/mgmt-wireguard-access.yaml", index)
        self.assertIn("config/infrastructure/mgmt-access-gateways.yaml", index)

    def test_exact_document_records_no_active_implementation(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("This architecture PR does not create a VM", text)
        self.assertIn("SNAT on `wg-01`", text)
        self.assertIn("Terraform/OpenTofu owns provider resources", text)
        self.assertIn("Ansible owns Rocky Linux state", text)
        self.assertIn("OpenBao is the secret authority", text)
        self.assertIn("operator peer private keys", text)


if __name__ == "__main__":
    unittest.main()
