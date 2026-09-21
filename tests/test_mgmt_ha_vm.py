from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_ha_fixture_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
FIXTURE = ROOT / "platform/ansible/tests/mgmt_ha_vm"


class MgmtHaVmTests(unittest.TestCase):
    def test_contract_locks_six_node_topology_and_non_capacity_boundary(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        nodes = contract["nodes"]
        self.assertEqual(6, len(nodes))
        self.assertEqual(
            {"cp-01", "cp-02", "cp-03", "worker-01", "worker-02", "worker-03"},
            set(nodes),
        )
        self.assertEqual(
            {"192.168.22.61", "192.168.22.62", "192.168.22.63",
             "192.168.22.71", "192.168.22.72", "192.168.22.73"},
            {node["address"] for node in nodes.values()},
        )
        self.assertEqual(
            3,
            sum(node["role"] == "control-plane" for node in nodes.values()),
        )
        self.assertEqual(3, sum(node["role"] == "worker" for node in nodes.values()))
        self.assertEqual(6, contract["resources"]["simultaneous_nodes_required"])
        self.assertEqual(9984, contract["resources"]["aggregate_vm_memory_mib"])
        self.assertFalse(contract["capacity_production_claim"])
        self.assertFalse(contract["real_hetzner_network_claim"])
        self.assertFalse(contract["physical_failure_claim"])

    def test_haproxy_is_digest_pinned_and_hosted_outside_control_plane(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        endpoint = contract["ha_endpoint"]
        self.assertEqual(contract["nodes"]["worker-03"]["address"], endpoint["address"])
        self.assertEqual("worker-03", endpoint["host"])
        self.assertEqual(9345, endpoint["registration_port"])
        self.assertEqual(6443, endpoint["kubernetes_api_port"])
        self.assertRegex(
            endpoint["image"]["reference"],
            r"^docker\.io/library/haproxy@sha256:[0-9a-f]{64}$",
        )
        self.assertNotIn(":latest", endpoint["image"]["reference"])

    def test_cluster_campaign_contains_required_ha_proofs(self):
        source = (FIXTURE / "cluster.yml").read_text(encoding="utf-8")
        required = [
            "Join third control plane through HAProxy",
            "Join remaining workers through HAProxy",
            "Create on-demand etcd snapshot",
            "Stop one control plane deliberately",
            "Prove API write and etcd quorum through HAProxy with one CP down",
            "Restart stopped control plane",
            "Require all six owned Rocky VMs simultaneously running",
            "Probe simulated internal DNS and NTP",
            "public TCP egress to remain denied",
            "cilium_multinode",
        ]
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertIn("ha-cp-02", source)
        self.assertIn("imagePullPolicy: Never", source)
        self.assertIn("--digests", source)
        self.assertIn("offline.validation_services", source)

    def test_main_reuses_pr128_fixture_and_never_implicitly_rebuilds_bundle(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertIn("platform/ansible/tests/mgmt_offline_vm/main.yml", source)
        self.assertIn("Refuse to rebuild or download the #128 bundle implicitly", source)
        self.assertNotIn("build_bundle.yml", source)
        self.assertNotRegex(source, r"\bcurl\b|\bwget\b")
        self.assertIn("docker, pull", source)
        self.assertIn("sha256sum, --check", source)
        self.assertNotIn("vm_dns_fixture=", source)
        self.assertNotIn("vm_ntp_fixture=", source)

    def test_fixture_python_helpers_parse(self):
        for name in ("lab_services.py", "service_probe.py", "ha_probe.py"):
            with self.subTest(name=name):
                ast.parse((FIXTURE / name).read_text(encoding="utf-8"), filename=name)

    def test_no_unpinned_haproxy_reference_in_fixture(self):
        for path in FIXTURE.iterdir():
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for match in re.findall(r"docker\.io/library/haproxy[^\s\"']*", text):
                self.assertIn("@sha256:", match)


if __name__ == "__main__":
    unittest.main()
