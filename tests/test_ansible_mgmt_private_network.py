#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

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
        names, gateway = module.load_canonical(ROOT)
        raw = {
            "phase": "bootstrap",
            "gateway": {
                "name": gateway,
                "provider_public": "198.51.100.10",
                "private_address": "10.243.1.41",
                "bootstrap_ssh": True,
            },
            "nodes": {
                name: {"provider_public": "", "private_address": f"10.243.1.{61 + index}", "gateway": gateway}
                for index, name in enumerate(names)
            },
        }
        overlay = {
            "version": 2,
            "source": "test",
            "contains_secrets": False,
            **module.validate_transport(names, gateway, raw),
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "transport.json"
            path.write_text(json.dumps(overlay), encoding="utf-8")
            env = dict(os.environ, MGMT_TRANSPORT_INVENTORY=str(path))
            rendered = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT, env=env))
        self.assertEqual("198.51.100.10", rendered["_meta"]["hostvars"][gateway]["ansible_host"])
        for name in names:
            self.assertIn("ProxyJump", rendered["_meta"]["hostvars"][name]["ansible_ssh_common_args"])

    def test_runtime_inventory_validates_exact_node_set_and_writes_no_secrets(self):
        module = load_runtime_module()
        names, gateway = module.load_canonical(ROOT)
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
        self.assertNotIn("ipv4.method", text)

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

    def test_private_host_firewall_is_persistent_and_segmented(self):
        text = ROLE.read_text(encoding="utf-8")
        self.assertIn("Enable and start private-network firewall authority", text)
        self.assertIn("--query-rich-rule", text)
        self.assertIn("--add-rich-rule", text)
        self.assertIn("--new-zone=mgmt-private", text)
        self.assertIn("--set-target=DROP", text)
        self.assertIn("--add-source=", text)
        for segment in (401, 402, 403, 405):
            self.assertIn(f"mgmt_firewall_cidrs[{segment}]", text)
        self.assertIn("mgmt_firewall_role == 'control-plane'", text)

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
