from __future__ import annotations

import ast
import importlib.util
import ipaddress
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
        subnet = ipaddress.ip_network(contract["controller"]["subnet"])
        addresses = [ipaddress.ip_address(node["address"]) for node in nodes.values()]
        self.assertEqual(len(addresses), len(set(addresses)))
        self.assertTrue(all(address in subnet for address in addresses))
        self.assertNotIn(ipaddress.ip_address(contract["controller"]["host_address"]), addresses)
        self.assertEqual(
            3,
            sum(node["role"] == "control-plane" for node in nodes.values()),
        )
        self.assertEqual(3, sum(node["role"] == "worker" for node in nodes.values()))
        calculated_memory = sum(
            contract["resources"][
                "control_plane" if node["role"] == "control-plane" else "worker"
            ]["memory_mib"]
            for node in nodes.values()
        )
        self.assertGreater(calculated_memory, 0)
        self.assertEqual("constrained-functional-lab", contract["resources"]["mode"])
        self.assertFalse(contract["resources"]["vendor_minimum_capacity_profile"])
        self.assertFalse(contract["capacity_production_claim"])
        self.assertFalse(contract["real_hetzner_network_claim"])
        self.assertFalse(contract["physical_failure_claim"])

    def test_haproxy_is_digest_pinned_and_hosted_outside_control_plane(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        endpoint = contract["ha_endpoint"]
        self.assertIn(endpoint["host"], contract["nodes"])
        self.assertEqual("worker", contract["nodes"][endpoint["host"]]["role"])
        self.assertNotEqual(endpoint["registration_port"], endpoint["kubernetes_api_port"])
        self.assertTrue(1 <= endpoint["registration_port"] <= 65535)
        self.assertTrue(1 <= endpoint["kubernetes_api_port"] <= 65535)
        self.assertEqual(99, endpoint["run_as_user"])
        self.assertEqual(99, endpoint["run_as_group"])
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
        self.assertIn("ha_single_contract.services", source)
        self.assertIn("--etcd-local-only", source)
        self.assertIn("etcd_degraded_survivors", source)
        self.assertIn("simulated_service_proofs", source)
        self.assertIn("Server kubernetes_api/' ~ ha_failed_backend ~ ' is DOWN", source)

    def test_fixture_references_existing_authorities_without_copying_values(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        sources = contract["canonical_sources"]
        for key in (
            "local_vm_contract",
            "local_vm_entrypoint",
            "mgmt_bootstrap",
            "network_plan",
            "qualification_policy",
            "private_firewall_template",
            "egress_template",
            "egress_service_template",
        ):
            with self.subTest(source=key):
                self.assertTrue((ROOT / sources[key]).is_file())
        self.assertNotIn("rocky_box", contract)
        self.assertNotIn("offline", contract)
        self.assertNotIn("address", contract["ha_endpoint"])
        self.assertNotIn("address", contract["services"]["dns"])
        self.assertNotIn("address", contract["services"]["ntp"])

    def test_cluster_reuses_canonical_network_policy_templates(self):
        source = (FIXTURE / "cluster.yml").read_text(encoding="utf-8")
        for contract_key in (
            "private_firewall_template",
            "egress_template",
            "egress_service_template",
        ):
            with self.subTest(contract_key=contract_key):
                self.assertIn(f"ha_sources.{contract_key}", source)
        self.assertNotIn("table inet ecommerce_mgmt_bootstrap {", source)
        self.assertNotIn("--zone=trusted", source)

    def test_main_reuses_pr128_fixture_and_never_implicitly_rebuilds_bundle(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertIn("ha_sources.local_vm_entrypoint", source)
        self.assertIn("ha_single_fixture", source)
        self.assertIn("Refuse to rebuild or download the PR 128 bundle implicitly", source)
        self.assertNotIn("build_bundle.yml", source)
        self.assertNotRegex(source, r"\bcurl\b|\bwget\b")
        self.assertNotIn("docker, pull", source)
        self.assertIn("HAProxy preparation evidence", source)
        self.assertIn("sha256sum, --check", source)
        self.assertNotIn("docker\n          - image\n          - save\n          - --platform", source)
        self.assertNotIn("vm_dns_fixture=", source)
        self.assertNotIn("vm_ntp_fixture=", source)

    def test_inventory_uses_the_per_vm_ssh_config_alias_not_literal_address(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertEqual(2, source.count("ansible_host: {{ item.value.vm_name }}"))
        self.assertNotIn("ansible_host: {{ item.value.address }}", source)
        self.assertEqual(
            2,
            source.count(
                'ansible_ssh_common_args: "-F {{ ha_repo }}/.context/mgmt-offline-vm/'
                '{{ item.value.vm_name }}/ssh_config"'
            ),
        )

    def test_haproxy_runtime_identity_is_explicitly_non_root(self):
        source = (FIXTURE / "cluster.yml").read_text(encoding="utf-8")
        self.assertIn(
            "runAsUser: {{ mgmt_local_ha_contract.ha_endpoint.run_as_user }}",
            source,
        )
        self.assertIn(
            "runAsGroup: {{ mgmt_local_ha_contract.ha_endpoint.run_as_group }}",
            source,
        )
        self.assertIn("runAsNonRoot: true", source)
        main_source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertIn(
            "(ha_haproxy_preparation.content | b64decode | from_json).run_as_user",
            main_source,
        )
        self.assertIn(
            "(ha_haproxy_preparation.content | b64decode | from_json).run_as_group",
            main_source,
        )

    def test_ha_completion_is_published_only_after_source_check_and_cleanup(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        source_check = source.index("Require sources unchanged throughout HA campaign")
        cleanup = source.index("Require successful destruction of every owned HA VM")
        completion = source.index(
            "Publish completion marker only after source verification and full cleanup"
        )
        self.assertLess(source_check, cleanup)
        self.assertLess(cleanup, completion)
        self.assertIn("register: ha_destroy_results", source)
        self.assertIn("cleanup_complete", source)
        self.assertIn("source_manifest_sha256", source)
        self.assertIn("evidence_sha256", source)

        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("def _rke2_local_ha_completion_matches", repoctl)
        self.assertIn('["sha256sum", "--check", str(source_manifest)]', repoctl)
        self.assertIn('(state / "completion.json").unlink(missing_ok=True)', repoctl)
        self.assertIn(
            "_rke2_local_ha_completion_matches(state, evidence, head_sha)",
            repoctl,
        )

    def test_pr128_bundle_restore_is_explicit_offline_and_fail_closed(self):
        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        readme = (FIXTURE / "README.md").read_text(encoding="utf-8")
        self.assertIn("def rke2_local_ha_restore_bundle", repoctl)
        self.assertIn("source / \"manifest.json\"", repoctl)
        self.assertIn("refusing to overwrite existing evidence bytes", repoctl)
        self.assertIn("regular files only; links/directories are forbidden", repoctl)
        self.assertIn("source bundle file set differs from the approved lock", repoctl)
        self.assertIn("shutil.copy2", repoctl)
        self.assertIn("os.replace(staging, destination)", repoctl)
        restore_start = repoctl.index("def rke2_local_ha_restore_bundle")
        restore_end = repoctl.index("def rke2_local_ha_prepare", restore_start)
        restore_source = repoctl[restore_start:restore_end]
        self.assertNotIn("docker", restore_source)
        self.assertNotIn("build_bundle.yml", restore_source)
        self.assertNotIn("bundle_offline", restore_source)
        self.assertIn("rke2-local-ha-restore-bundle", makefile)
        self.assertIn("SOURCE=/absolute/path/to/pr128", readme)
        self.assertIn("No Docker, network, download, reconstruction", readme)

    def test_haproxy_preparation_is_digest_pinned_and_separate_from_qualification(self):
        source = (FIXTURE / "prepare_haproxy.yml").read_text(encoding="utf-8")
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        reference = contract["ha_endpoint"]["image"]["reference"]
        self.assertRegex(reference, r"@sha256:[0-9a-f]{64}$")
        self.assertIn("mgmt_local_ha_contract.ha_endpoint.image.reference", source)
        self.assertIn("docker, pull", source)
        self.assertIn("--network", source)
        self.assertIn("id -u haproxy", source)
        self.assertIn("id -g haproxy", source)
        self.assertIn("run_as_user", source)
        self.assertIn("run_as_group", source)
        self.assertIn("archive_sha256", source)
        self.assertNotIn(":latest", source)

    def test_fixture_python_helpers_parse(self):
        for name in ("lab_services.py", "service_probe.py", "ha_probe.py"):
            with self.subTest(name=name):
                ast.parse((FIXTURE / name).read_text(encoding="utf-8"), filename=name)

    def test_etcd_probe_binds_to_active_binary_and_checks_members_health_alarms(self):
        source = (FIXTURE / "ha_probe.py").read_text(encoding="utf-8")
        for marker in (
            "/proc",
            "member list",
            "endpoint health",
            "alarm list",
            "expected one etcdctl beside the active etcd binary",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_no_unpinned_haproxy_reference_in_fixture(self):
        for path in FIXTURE.iterdir():
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            for match in re.findall(r"docker\.io/library/haproxy[^\s\"']*", text):
                self.assertIn("@sha256:", match)


if __name__ == "__main__":
    unittest.main()
