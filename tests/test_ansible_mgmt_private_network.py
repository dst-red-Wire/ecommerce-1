#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from yaml_loader import load_yaml  # noqa: E402

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
        network = load_yaml(NETWORK_PLAN)
        inventory = load_yaml(MGMT_INVENTORY)
        rendered = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT))
        hostvars = rendered["_meta"]["hostvars"]
        segments = network["vlans"]["mgmt"]

        def cidr(ip: str, segment: str) -> str:
            prefix = str(segments[segment]["cidr"]).split("/", 1)[1]
            return f"{ip}/{prefix}"

        for name, node in inventory["control_planes"].items():
            self.assertEqual(hostvars[name]["mgmt_ip"], node["mgmt_ip"])
            self.assertEqual(hostvars[name]["mgmt_private_alias_cidrs"], [cidr(node["k8s_ip"], "402")])

        for name, node in inventory["workers"].items():
            self.assertEqual(
                hostvars[name]["mgmt_private_alias_cidrs"],
                [cidr(node["k8s_ip"], "402"), cidr(node["storage_ip"], "403"), cidr(node["backup_ip"], "405")],
            )

    def test_transport_overlay_changes_only_ansible_transport_address(self):
        canonical = load_yaml(MGMT_INVENTORY)
        names = [*canonical["control_planes"].keys(), *canonical["workers"].keys()]
        hosts = {name: f"203.0.113.{index + 10}" for index, name in enumerate(names)}
        overlay = {"version": 1, "source": "test", "contains_secrets": False, "hosts": hosts}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "transport.json"
            path.write_text(json.dumps(overlay), encoding="utf-8")
            env = dict(os.environ, MGMT_TRANSPORT_INVENTORY=str(path))
            rendered = json.loads(subprocess.check_output(["ruby", str(INVENTORY)], text=True, cwd=ROOT, env=env))
        for name, transport in hosts.items():
            self.assertEqual(rendered["_meta"]["hostvars"][name]["ansible_host"], transport)
            self.assertNotEqual(rendered["_meta"]["hostvars"][name]["mgmt_ip"], transport)

    def test_runtime_inventory_validates_exact_node_set_and_writes_no_secrets(self):
        module = load_runtime_module()
        canonical = module.load_canonical_nodes(ROOT)
        servers = {
            name: {"id": index + 1, "ipv4": f"198.51.100.{index + 10}", "ipv6": "2001:db8::1"}
            for index, name in enumerate(canonical)
        }
        hosts = module.validate_servers(canonical, servers)
        self.assertEqual(sorted(hosts), canonical)
        with self.assertRaises(ValueError):
            module.validate_servers(canonical, {name: servers[name] for name in canonical[:-1]})
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "transport.json"
            module.write_overlay(output, hosts)
            text = output.read_text(encoding="utf-8")
            self.assertIn('"contains_secrets": false', text)
            self.assertNotIn("token", text.lower())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

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


if __name__ == "__main__":
    unittest.main()
