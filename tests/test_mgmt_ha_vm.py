from __future__ import annotations

import ast
import hashlib
import importlib.util
import ipaddress
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repoctl_ha_fixture_test", ROOT / "scripts/repoctl.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
FIXTURE = ROOT / "platform/ansible/tests/mgmt_ha_vm"
GUARD_SPEC = importlib.util.spec_from_file_location("mgmt_ha_lifecycle_guard", FIXTURE / "lifecycle_guard.py")
assert GUARD_SPEC and GUARD_SPEC.loader
GUARD = importlib.util.module_from_spec(GUARD_SPEC)
GUARD_SPEC.loader.exec_module(GUARD)


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
        self.assertEqual(2560, contract["resources"]["control_plane"]["memory_mib"])
        self.assertEqual(1024, contract["resources"]["worker"]["memory_mib"])
        self.assertEqual(10752, calculated_memory)
        self.assertEqual(
            {
                "max_forks": 6,
                "vm_create_parallelism": 1,
                "cold_stage_parallelism": 2,
                "node_validation_parallelism": 4,
                "worker_join_parallelism": 2,
                "cleanup_parallelism": 2,
                "control_plane_parallelism": 1,
            },
            contract["execution"],
        )
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

    def test_address_collision_probe_is_bound_to_windows_host_only_source(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertEqual("/mnt/c/Windows/System32/ping.exe", contract["controller"]["windows_ping"])
        self.assertIn("mgmt_local_ha_contract.controller.windows_ping", source)
        self.assertIn("ansible_playbook_python", source)
        self.assertIn("subprocess.run(", source)
        self.assertIn("stdout=subprocess.DEVNULL", source)
        self.assertIn("stderr=subprocess.DEVNULL", source)
        self.assertIn("'-S',sys.argv[2],sys.argv[3]", source)
        self.assertIn("selected VirtualBox", source)
        self.assertIn("host-only source", source)
        self.assertNotIn('argv: [ping, -c, "1", -W, "1"', source)
        self.assertNotIn("MODULE_STRICT_UTF8_RESPONSE", source)

    def test_nested_vm_phases_are_bounded_parallel_and_json_safe(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        create_helper = (FIXTURE / "single_vm_action.yml").read_text(encoding="utf-8")
        cold_helper = (FIXTURE / "cold_stage_batch.yml").read_text(encoding="utf-8")
        destroy_helper = (FIXTURE / "destroy_vm_batch.yml").read_text(encoding="utf-8")

        self.assertIn(
            "Create each Rocky VM sequentially and fail fast before the next node",
            source,
        )
        self.assertIn("ansible.builtin.include_tasks: single_vm_action.yml", source)
        self.assertIn("ha_single_vm_action: create", source)
        self.assertNotIn("ha_single_vm_action: test", source)

        self.assertIn("Cold-stage the approved PR 128 bundle two VMs at a time", source)
        self.assertIn("ansible.builtin.include_tasks: cold_stage_batch.yml", source)
        self.assertIn("ha_cold_stage_batches", source)
        self.assertIn(
            'platform/ansible/tests/mgmt_ha_vm/cold_stage_batch.yml',
            source,
        )
        self.assertIn(
            'platform/ansible/tests/mgmt_ha_vm/destroy_vm_batch.yml',
            source,
        )
        self.assertIn("async: 1800", cold_helper)
        self.assertIn("poll: 0", cold_helper)
        self.assertIn("'vm_action': 'test'", cold_helper)

        self.assertIn("Destroy owned HA VMs two at a time while attempting all six", source)
        self.assertIn("ansible.builtin.include_tasks: destroy_vm_batch.yml", source)
        self.assertIn("ha_cleanup_batches", source)
        self.assertIn("async: 900", destroy_helper)
        self.assertIn("poll: 0", destroy_helper)
        self.assertIn("'vm_action': 'destroy'", destroy_helper)

        self.assertIn("ha_single_vm_common", create_helper)
        self.assertIn("| to_json", create_helper)
        self.assertIn("'vm_resume_owned_creation': false", create_helper)
        self.assertIn("'vm_resume_owned_creation': true", create_helper)
        self.assertIn("classify-create", create_helper)
        self.assertIn("create-{{ ha_node.key }}-initial.json", create_helper)
        self.assertIn("ha_single_vm_create_resume | bool", create_helper)
        self.assertIn(
            "Fail closed when fresh creation is not an owned bounded console timeout",
            create_helper,
        )

        for helper in (create_helper, cold_helper, destroy_helper):
            self.assertNotIn("vm_hostonly_adapter=", helper)
        self.assertNotIn('"vm_action=create"', source)
        self.assertNotIn('"vm_action=test"', source)
        self.assertNotIn('"vm_action=destroy"', source)

    def test_create_resume_is_exactly_once_and_fail_closed(self):
        success = {"rc": 0, "stdout": "", "stderr": "", "cmd": ["ansible-playbook"]}
        timeout = {
            "rc": 2,
            "stdout": (
                "TASK [Configure guest exclusively through its private local serial pipe]\n"
                'fatal: cmd=["transport.py", "console", "--script", "guest-access.txt"]\n'
                "Timed   out waiting for isolated VM console"
            ),
            "stderr": "",
            "cmd": ["ansible-playbook"],
        }
        owned = {"state": "owned"}
        self.assertFalse(GUARD.create_decision(success, owned)["resume"])
        self.assertTrue(GUARD.create_decision(timeout, owned)["resume"])

        for message in (
            "network unreachable",
            "Vagrant failed to validate",
            "VBoxManage: error: VERR_ACCESS_DENIED",
        ):
            with self.subTest(message=message):
                failed = {"rc": 1, "stdout": message, "stderr": "", "cmd": ["ansible-playbook"]}
                self.assertFalse(GUARD.create_decision(failed, owned)["resume"])
        self.assertFalse(GUARD.create_decision(timeout, {"state": "mismatch"})["resume"])

        create_helper = (FIXTURE / "single_vm_action.yml").read_text(encoding="utf-8")
        self.assertEqual(1, create_helper.count("vm_resume_owned_creation': true"))

    def test_cleanup_decisions_preserve_failures_and_bound_retry(self):
        def result(rc: int, text: str = "") -> dict:
            return {"rc": rc, "stdout": text, "stderr": "", "cmd": ["ansible-playbook"]}

        self.assertEqual(
            "pass",
            GUARD.cleanup_decision(result(0), {"state": "owned"})["resolution"],
        )
        for state in ("absent", "stale_identity"):
            with self.subTest(state=state):
                self.assertEqual(
                    "already-absent",
                    GUARD.cleanup_decision(result(1), {"state": state})["resolution"],
                )
        self.assertEqual(
            "retry",
            GUARD.cleanup_decision(
                result(1, "VBoxManage: error: machine is already locked for a session"),
                {"state": "owned"},
            )["resolution"],
        )
        self.assertEqual(
            "fail",
            GUARD.cleanup_decision(result(1, "permission denied"), {"state": "owned"})[
                "resolution"
            ],
        )
        self.assertEqual(
            "fail",
            GUARD.cleanup_decision(result(1, "already locked for a session"), {"state": "mismatch"})[
                "resolution"
            ],
        )

        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        retry = (FIXTURE / "retry_destroy_vm.yml").read_text(encoding="utf-8")
        self.assertIn("cleanup-final-vbox.json", source)
        self.assertIn("selectattr('rc', 'ne', 0)", source)
        self.assertNotIn("async:", retry)
        self.assertIn("ha_cleanup_decision.resolution == 'retry'", retry)
        self.assertIn("already-absent", retry)

    def test_ownership_probe_distinguishes_owned_absent_stale_and_mismatch(self):
        vm_name = "ecommerce-mgmt-test-ha-cp-01"
        uuid = "11111111-2222-3333-4444-555555555555"

        def completed(stdout: str, returncode: int = 0):
            return GUARD.subprocess.CompletedProcess([], returncode, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id"
            with mock.patch.object(GUARD.subprocess, "run", return_value=completed("")):
                self.assertEqual("absent", GUARD.probe_ownership("vbox", identity, vm_name)["state"])

            identity.write_text(uuid + "\n", encoding="utf-8")
            with mock.patch.object(GUARD.subprocess, "run", return_value=completed("")):
                self.assertEqual(
                    "stale_identity",
                    GUARD.probe_ownership("vbox", identity, vm_name)["state"],
                )

            listing = f'"{vm_name}" {{{uuid}}}\n'
            details = f'name="{vm_name}"\nUUID="{uuid}"\n'
            with mock.patch.object(
                GUARD.subprocess,
                "run",
                side_effect=(completed(listing), completed(details)),
            ):
                self.assertEqual("owned", GUARD.probe_ownership("vbox", identity, vm_name)["state"])

            mismatch_listing = f'"{vm_name}" {{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}}\n'
            with mock.patch.object(
                GUARD.subprocess,
                "run",
                return_value=completed(mismatch_listing),
            ):
                self.assertEqual(
                    "mismatch",
                    GUARD.probe_ownership("vbox", identity, vm_name)["state"],
                )

    def test_cluster_parallelism_matches_bounded_contract(self):
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        cluster = (FIXTURE / "cluster.yml").read_text(encoding="utf-8")

        self.assertIn(
            '- "{{ mgmt_local_ha_contract.execution.max_forks }}"',
            source,
        )
        self.assertIn("hosts: ha-worker-01,ha-worker-02", cluster)
        self.assertIn("strategy: free", cluster)
        self.assertIn(
            "Require worker join host-set to match bounded parallelism contract",
            cluster,
        )
        self.assertIn(
            "ansible_play_hosts_all | length == mgmt_local_ha_contract.execution.worker_join_parallelism",
            cluster,
        )
        self.assertNotIn(
            'throttle: "{{ mgmt_local_ha_contract.execution.worker_join_parallelism }}"',
            cluster,
        )
        self.assertNotIn(
            'serial: "{{ mgmt_local_ha_contract.execution.control_plane_parallelism }}"',
            cluster,
        )
        self.assertNotIn(
            'serial: "{{ mgmt_local_ha_contract.execution.worker_join_parallelism }}"',
            cluster,
        )
        self.assertEqual(
            4,
            cluster.count(
                'throttle: "{{ mgmt_local_ha_contract.execution.node_validation_parallelism }}"'
            ),
        )

        for play in (
            "Bootstrap first RKE2 control plane",
            "Join second RKE2 control plane directly to the bootstrap member",
            "Deploy HAProxy in front of the control planes",
            "Join third control plane through HAProxy",
            "Prove six-node HA, quorum, snapshot and recovery",
        ):
            self.assertIn(f"- name: {play}", cluster)

        self.assertGreaterEqual(cluster.count("hosts: ha-cp-01"), 4)
        self.assertEqual(1, cluster.count("hosts: ha-cp-02"))
        self.assertEqual(1, cluster.count("hosts: ha-cp-03"))
        self.assertNotIn("serial: 6", cluster)

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
        self.assertIn("ha_destroy_results: []", source)
        self.assertIn("ansible.builtin.include_tasks: destroy_vm_batch.yml", source)
        self.assertIn("ha_destroy_results | length == ha_nodes | length", source)
        self.assertIn("cleanup_complete", source)
        self.assertIn("source_manifest_sha256", source)
        self.assertIn("evidence_sha256", source)

        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        self.assertIn("def _rke2_local_ha_completion_matches", repoctl)
        self.assertIn("def _sha256_manifest_matches", repoctl)
        self.assertIn("return _sha256_manifest_matches(source_manifest)", repoctl)
        self.assertNotIn('["sha256sum",', repoctl)
        self.assertIn('(state / "completion.json").unlink(missing_ok=True)', repoctl)
        self.assertIn(
            "_rke2_local_ha_completion_matches(state, evidence, head_sha)",
            repoctl,
        )

    def test_source_manifest_verification_is_python_only_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("authoritative\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = root / "source.sha256"
            manifest.write_text(f"{digest}  {source}\n", encoding="utf-8")

            with mock.patch.object(MOD, "ROOT", root):
                self.assertTrue(MOD._sha256_manifest_matches(manifest))

                source.write_text("mutated\n", encoding="utf-8")
                self.assertFalse(MOD._sha256_manifest_matches(manifest))

                source.write_text("authoritative\n", encoding="utf-8")
                manifest.write_text(
                    f"{digest}  {source}\n{digest}  {source}\n",
                    encoding="utf-8",
                )
                self.assertFalse(MOD._sha256_manifest_matches(manifest))

                outside = root.parent / "outside-source.txt"
                outside.write_text("authoritative\n", encoding="utf-8")
                try:
                    manifest.write_text(
                        f"{hashlib.sha256(outside.read_bytes()).hexdigest()}  {outside}\n",
                        encoding="utf-8",
                    )
                    self.assertFalse(MOD._sha256_manifest_matches(manifest))
                finally:
                    outside.unlink(missing_ok=True)

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
