from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "mgmt_runtime_inventory.py"
spec = importlib.util.spec_from_file_location("mgmt_runtime_inventory", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class MgmtRuntimeInventoryTests(unittest.TestCase):
    def show_doc(self, resources):
        return {
            "values": {
                "root_module": {
                    "child_modules": [
                        {
                            "address": "module.hcloud_mgmt",
                            "resources": resources,
                        }
                    ]
                }
            }
        }

    def server(self, name: str, ipv4: str = "198.51.100.10"):
        return {
            "mode": "managed",
            "type": "hcloud_server",
            "name": "node",
            "index": name,
            "values": {
                "id": f"id-{name}",
                "ipv4_address": ipv4,
                "ipv6_address": "2001:db8::1",
            },
        }

    def test_extract_servers_from_terraform_show_json(self):
        servers = module.extract_servers_from_show(
            self.show_doc([
                self.server("mgmt-cp-1", "198.51.100.11"),
                self.server("mgmt-worker-1", "198.51.100.12"),
            ])
        )

        self.assertEqual("198.51.100.11", servers["mgmt-cp-1"]["ipv4"])
        self.assertEqual("id-mgmt-worker-1", servers["mgmt-worker-1"]["id"])

    def test_missing_management_module_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "exactly one module.hcloud_mgmt"):
            module.extract_servers_from_show({"values": {"root_module": {"child_modules": []}}})

    def test_duplicate_server_index_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate MGMT hcloud_server index"):
            module.extract_servers_from_show(
                self.show_doc([
                    self.server("mgmt-cp-1"),
                    self.server("mgmt-cp-1", "198.51.100.20"),
                ])
            )

    def test_validate_servers_requires_exact_canonical_node_set(self):
        with self.assertRaisesRegex(ValueError, "node set mismatch"):
            module.validate_servers(
                ["mgmt-cp-1", "mgmt-worker-1"],
                {"mgmt-cp-1": {"ipv4": "198.51.100.11"}},
            )


if __name__ == "__main__":
    unittest.main()
