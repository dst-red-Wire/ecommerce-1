from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mgmt_runtime_inventory", ROOT / "scripts/mgmt_runtime_inventory.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)


class MgmtRuntimeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.nodes, self.gateway = module.load_canonical(ROOT)

    def transport(self, phase="bootstrap"):
        return {
            "phase": phase,
            "gateway": {
                "name": "wg-01",
                "provider_public": "198.51.100.10",
                "private_address": "10.243.1.41",
                "bootstrap_ssh": phase == "bootstrap",
            },
            "nodes": {
                name: {"provider_public": "", "private_address": f"10.243.1.{61 + i}", "gateway": "wg-01"}
                for i, name in enumerate(self.nodes)
            },
        }

    def test_bootstrap_overlay_is_complete_and_uses_private_nodes_via_proxyjump(self):
        value = module.validate_transport(self.nodes, self.gateway, self.transport())
        self.assertEqual({"wg-01", *self.nodes}, set(value["hosts"]))
        self.assertEqual("198.51.100.10", value["hosts"]["wg-01"]["ansible_host"])
        for name in self.nodes:
            self.assertTrue(value["hosts"][name]["ansible_host"].startswith("10.243.1."))
            self.assertIn("ProxyJump=198.51.100.10", value["hosts"][name]["ansible_ssh_common_args"])

    def test_steady_state_uses_private_addresses_and_forbids_public_ssh(self):
        value = module.validate_transport(self.nodes, self.gateway, self.transport("steady-state"))
        self.assertEqual("10.243.1.41", value["hosts"]["wg-01"]["ansible_host"])
        self.assertNotIn("ansible_ssh_common_args", value["hosts"][self.nodes[0]])
        mutated = self.transport("steady-state")
        mutated["gateway"]["bootstrap_ssh"] = True
        with self.assertRaisesRegex(ValueError, "must not retain public SSH"):
            module.validate_transport(self.nodes, self.gateway, mutated)

    def test_required_transport_mutations_fail_closed(self):
        mutations = []
        missing_gateway = self.transport()
        missing_gateway["gateway"] = {}
        mutations.append(missing_gateway)
        missing_node = self.transport()
        missing_node["nodes"].pop(self.nodes[-1])
        mutations.append(missing_node)
        public_node = self.transport()
        public_node["nodes"][self.nodes[0]]["provider_public"] = "198.51.100.20"
        mutations.append(public_node)
        empty_private = self.transport()
        empty_private["nodes"][self.nodes[0]]["private_address"] = ""
        mutations.append(empty_private)
        no_proxy = self.transport()
        no_proxy["nodes"][self.nodes[0]].pop("gateway")
        mutations.append(no_proxy)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    module.validate_transport(self.nodes, self.gateway, mutation)

    def test_overlay_is_non_secret_root_only(self):
        value = module.validate_transport(self.nodes, self.gateway, self.transport())
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "transport.json"
            module.write_overlay(output, value)
            payload = json.loads(output.read_text())
            self.assertFalse(payload["contains_secrets"])
            self.assertEqual("terraform-output:runtime_transport", payload["source"])
            self.assertEqual(0o600, output.stat().st_mode & 0o777)

    def test_unknown_provenance_fails(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, "unsupported"):
                module.write_overlay(Path(td) / "x", {}, "old-server-public-ip-model")


if __name__ == "__main__":
    unittest.main()
