#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from jinja2 import Environment, StrictUndefined

import yaml

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "platform/ansible/inventories/mgmt/inventory.rb"
NETWORK_PLAN = ROOT / "config/infrastructure/network-plan.yaml"
MGMT_INVENTORY = ROOT / "config/infrastructure/mgmt-inventory.yaml"
ROLE = ROOT / "platform/ansible/roles/mgmt_private_network/tasks/main.yml"
PLAYBOOK = ROOT / "platform/ansible/mgmt.yml"
BASELINE = ROOT / "platform/ansible/roles/rocky_baseline/tasks/main.yml"
RUNTIME_SCRIPT = ROOT / "scripts/mgmt_runtime_inventory.py"
MAKEFILE = ROOT / "Makefile"


def load_runtime_module():
    spec = importlib.util.spec_from_file_location("mgmt_runtime_inventory", RUNTIME_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MgmtPrivateNetworkTest(unittest.TestCase):
    def test_dynamic_inventory_derives_aliases_from_canonical_network_plan(self):
        network = yaml.safe_load(NETWORK_PLAN.read_text(encoding="utf-8"))
        inventory = yaml.safe_load(MGMT_INVENTORY.read_text(encoding="utf-8"))
        rendered = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT))
        hostvars = rendered["_meta"]["hostvars"]
        segments = network["vlans"]["mgmt"]

        def cidr(ip: str, segment: int) -> str:
            prefix = str(segments[segment]["cidr"]).split("/", 1)[1]
            return f"{ip}/{prefix}"

        for name, node in inventory["control_planes"].items():
            self.assertEqual(hostvars[name]["mgmt_ip"], node["mgmt_ip"])
            self.assertEqual(hostvars[name]["mgmt_private_alias_cidrs"], [cidr(node["k8s_ip"], 402)])

        for name, node in inventory["workers"].items():
            self.assertEqual(
                hostvars[name]["mgmt_private_alias_cidrs"],
                [cidr(node["k8s_ip"], 402), cidr(node["storage_ip"], 403), cidr(node["backup_ip"], 405)],
            )

    def test_transport_overlay_changes_only_ansible_transport_address(self):
        module = load_runtime_module()
        names, gateway, private_addresses = module.load_canonical(ROOT)
        raw = {
            "phase": "bootstrap",
            "gateway": {
                "name": gateway,
                "provider_public": "198.51.100.10",
                "private_address": private_addresses[gateway],
                "bootstrap_ssh": True,
            },
            "nodes": {
                name: {"provider_public": "", "private_address": private_addresses[name], "gateway": gateway}
                for index, name in enumerate(names)
            },
        }
        overlay = {
            "version": 2,
            "source": "test",
            "contains_secrets": False,
            **module.validate_transport(names, gateway, private_addresses, raw),
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "transport.json"
            path.write_text(json.dumps(overlay), encoding="utf-8")
            env = dict(os.environ, MGMT_TRANSPORT_INVENTORY=str(path))
            rendered = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT, env=env))
        self.assertEqual("198.51.100.10", rendered["_meta"]["hostvars"][gateway]["ansible_host"])
        self.assertEqual("bootstrap", rendered["_meta"]["hostvars"][gateway]["mgmt_transport_phase"])
        for name in names:
            self.assertIn("ProxyJump", rendered["_meta"]["hostvars"][name]["ansible_ssh_common_args"])

    def test_runtime_inventory_validates_exact_node_set_and_writes_no_secrets(self):
        module = load_runtime_module()
        names, gateway, _private_addresses = module.load_canonical(ROOT)
        self.assertEqual(6, len(names))
        self.assertEqual("wg-01", gateway)

    def test_role_preserves_dhcp_primary_and_reconciles_only_aliases(self):
        text = ROLE.read_text(encoding="utf-8")
        self.assertIn("mgmt_ip", text)
        self.assertIn("mgmt_private_alias_cidrs", text)
        self.assertIn("Hetzner DHCP must configure", text)
        self.assertIn("+ipv4.addresses", text)
        self.assertIn("nmcli", text)
        self.assertIn("device\n      - reapply", text)
        self.assertNotIn("ansible.builtin.shell", text)
        self.assertNotIn("ens10", text)
        self.assertNotIn("10.243.", text)
        for task in yaml.safe_load(text):
            argv = task.get("ansible.builtin.command", {}).get("argv", [])
            if "ipv4.method" in argv:
                self.assertEqual("ecommerce-offline-default", argv[3])
                self.assertNotIn("{{ mgmt_private_connection }}", argv)
                self.assertEqual("203.0.113.254/31", argv[argv.index("ipv4.addresses") + 1])

    def test_offline_egress_is_owned_default_deny_for_both_families(self):
        env = Environment(undefined=StrictUndefined)
        template = ROLE.parents[1] / "templates/mgmt-egress.nft.j2"
        network = yaml.safe_load(NETWORK_PLAN.read_text())
        output = env.from_string(template.read_text()).render(
            mgmt_private_block=network["address_domains"]["mgmt"],
            mgmt_pod_cidr=network["kubernetes"]["mgmt"]["pod_cidr"],
            mgmt_service_cidr=network["kubernetes"]["mgmt"]["service_cidr"],
            mgmt_internal_dns=["10.243.1.50"],
            mgmt_internal_ntp=["10.243.1.51"],
            mgmt_private_interface="eth1",
            mgmt_private_dhcp_server="10.243.0.1",
        )
        self.assertEqual(2, output.count("policy drop;"))
        self.assertNotIn("flush ruleset", output)
        self.assertIn("flush table inet ecommerce_mgmt_bootstrap", output)
        self.assertNotIn("masquerade", output)
        self.assertNotIn("0.0.0.0/0", output)
        self.assertIn("ip daddr 10.243.1.50 udp dport 53 accept", output)
        self.assertIn("ip daddr 10.243.1.51 udp dport 123 accept", output)
        for task in yaml.safe_load(ROLE.read_text()):
            if "ansible.builtin.dnf" in task:
                self.assertEqual("*", task["ansible.builtin.dnf"]["disablerepo"])

    def test_playbook_orders_network_reconciliation_before_rke2(self):
        text = PLAYBOOK.read_text(encoding="utf-8")
        self.assertLess(text.index("name: rocky_baseline"), text.index("name: mgmt_private_network"))
        self.assertLess(text.index("name: mgmt_private_network"), text.index("name: rke2_server"))

    def test_baseline_owns_networkmanager_prerequisites(self):
        text = BASELINE.read_text(encoding="utf-8")
        self.assertIn("NetworkManager", text)
        self.assertIn("iproute", text)
        self.assertIn("name: NetworkManager", text)

    def test_make_target_generates_runtime_transport_without_apply(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("mgmt-runtime-inventory", text)
        line = next(line for line in text.splitlines() if "scripts/mgmt_runtime_inventory.py" in line)
        self.assertNotIn("apply", line)
        self.assertNotIn("hcloud", line)

    def render_private_zone(self, node):
        inventory = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT))
        variables = dict(inventory["_meta"]["hostvars"][node])
        variables["hostvars"] = inventory["_meta"]["hostvars"]
        variables["groups"] = {"access_gateways": inventory["access_gateways"]["hosts"]}
        source = ROLE.parent.parent / "templates/mgmt-private.xml.j2"
        rendered = Environment(undefined=StrictUndefined).from_string(source.read_text()).render(**variables)
        return ET.fromstring(rendered), variables

    def test_private_host_firewall_replaces_complete_owned_zone(self):
        tasks = yaml.safe_load(ROLE.read_text())
        install = next(task for task in tasks if "ansible.builtin.template" in task)
        self.assertEqual("/etc/firewalld/zones/mgmt-private.xml", install["ansible.builtin.template"]["dest"])
        self.assertEqual("Reload private firewalld", install["notify"])
        flush = next(i for i, task in enumerate(tasks) if task.get("ansible.builtin.meta") == "flush_handlers")
        self.assertLess(tasks.index(install), flush)
        for node in ("cp-01", "worker-01"):
            zone, variables = self.render_private_zone(node)
            self.assertEqual("DROP", zone.attrib["target"])
            self.assertEqual(
                set(variables["mgmt_firewall_cidrs"].values()),
                {source.attrib["address"] for source in zone.findall("source")},
            )
            self.assertFalse(zone.findall("service"))
            self.assertFalse(zone.findall("port"))
            self.assertFalse(zone.findall("forward"))
            self.assertFalse(zone.findall("masquerade"))

    def test_control_plane_api_accepts_only_kubernetes_and_snat_gateway(self):
        zone, variables = self.render_private_zone("cp-01")
        self.assertIn("401", variables["mgmt_firewall_cidrs"])
        self.assertNotIn(401, variables["mgmt_firewall_cidrs"])
        gateway = variables["hostvars"][variables["groups"]["access_gateways"][0]]["mgmt_ip"] + "/32"
        api_sources = {
            rule.find("source").attrib["address"]
            for rule in zone.findall("rule")
            if rule.find("port") is not None and rule.find("port").attrib["port"] == "6443"
        }
        self.assertEqual({variables["mgmt_firewall_cidrs"]["402"], gateway}, api_sources)
        gateway_ports = [
            rule.find("port").attrib["port"]
            for rule in zone.findall("rule")
            if rule.find("source").attrib["address"] == gateway
        ]
        self.assertEqual(["6443"], gateway_ports)
        worker, _ = self.render_private_zone("worker-01")
        self.assertFalse(any(rule.find("source").attrib["address"] == gateway for rule in worker.findall("rule")))

    def test_zone_render_replaces_revoked_sources_and_rules(self):
        zone, variables = self.render_private_zone("cp-01")
        old_cidr = variables["mgmt_firewall_cidrs"]["402"]
        variables["mgmt_firewall_cidrs"]["402"] = "192.0.2.0/24"
        template = ROLE.parent.parent / "templates/mgmt-private.xml.j2"
        rendered = Environment(undefined=StrictUndefined).from_string(template.read_text()).render(**variables)
        self.assertNotIn(old_cidr, rendered)
        self.assertIn("192.0.2.0/24", rendered)
        self.assertNotIn("--add-rich-rule", ROLE.read_text())

    def test_wireguard_firewall_order_snat_and_desired_state(self):
        tasks = (ROOT / "platform/ansible/roles/wireguard_gateway/tasks/main.yml").read_text(encoding="utf-8")
        template = (ROOT / "platform/ansible/roles/wireguard_gateway/templates/wg0.conf.j2").read_text(encoding="utf-8")
        self.assertLess(tasks.index("Enable and start firewalld"), tasks.index("Render fail-closed WireGuard"))
        self.assertIn("--to-source", tasks)
        self.assertIn("wireguard_snat_source_cidr", tasks)
        self.assertIn("wireguard_snat_destination_cidr", tasks)
        self.assertNotIn("masquerade", tasks.lower())
        self.assertNotIn("masquerade", template.lower())
        service = tasks.split("Enable and start WireGuard desired state", 1)[1]
        self.assertIn("enabled: true", service)
        self.assertIn("state: started", service)

    def test_rke2_server_uses_canonical_cluster_and_service_cidrs(self):
        template = (ROOT / "platform/ansible/roles/rke2_server/templates/config.yaml.j2").read_text(encoding="utf-8")
        self.assertIn('cluster-cidr: "{{ rke2_cluster_cidr }}"', template)
        self.assertIn('service-cidr: "{{ rke2_service_cidr }}"', template)


if __name__ == "__main__":
    unittest.main()
