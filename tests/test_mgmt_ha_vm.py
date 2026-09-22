from __future__ import annotations

import ast
import hashlib
import importlib.util
import ipaddress
import os
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
OFFLINE_FIXTURE = ROOT / "platform/ansible/tests/mgmt_offline_vm"
PRIVILEGE_SPEC = importlib.util.spec_from_file_location(
    "mgmt_offline_privilege_probe", OFFLINE_FIXTURE / "privilege_probe.py"
)
assert PRIVILEGE_SPEC and PRIVILEGE_SPEC.loader
PRIVILEGE = importlib.util.module_from_spec(PRIVILEGE_SPEC)
PRIVILEGE_SPEC.loader.exec_module(PRIVILEGE)


class MgmtHaVmTests(unittest.TestCase):
    def test_qualification_ansible_controller_is_bound_to_repoctl_python(self):
        with tempfile.TemporaryDirectory() as directory:
            environment_bin = Path(directory) / ".venv" / "qualification" / "bin"
            environment_bin.mkdir(parents=True)
            python = environment_bin / "python"
            controller = environment_bin / "ansible-playbook"
            python.touch(mode=0o755)
            controller.touch(mode=0o755)

            def probe(command, **kwargs):
                stdout = "2.20.3\n" if command[0] == str(python) else "ansible-playbook [core 2.20.3]\n"
                return MOD.subprocess.CompletedProcess(command, 0, stdout, "")

            with (
                mock.patch.object(MOD.sys, "executable", str(python)),
                mock.patch.object(MOD, "pinned_versions", return_value={"ANSIBLE_CORE_VERSION": "2.20.3"}),
                mock.patch.object(MOD.subprocess, "run", side_effect=probe),
            ):
                self.assertEqual(str(controller), MOD.qualification_ansible_playbook())

    def test_qualification_ansible_controller_missing_has_no_path_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            python = Path(directory) / ".venv" / "qualification" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.touch(mode=0o755)
            with (
                mock.patch.object(MOD.sys, "executable", str(python)),
                mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/ansible-playbook") as which,
                self.assertRaisesRegex(RuntimeError, "missing or not executable"),
            ):
                MOD.qualification_ansible_playbook()
            which.assert_not_called()

    def test_qualification_ansible_controller_rejects_wrong_core_version(self):
        with tempfile.TemporaryDirectory() as directory:
            environment_bin = Path(directory) / ".venv" / "qualification" / "bin"
            environment_bin.mkdir(parents=True)
            python = environment_bin / "python"
            controller = environment_bin / "ansible-playbook"
            python.touch(mode=0o755)
            controller.touch(mode=0o755)
            wrong = MOD.subprocess.CompletedProcess([], 0, "2.16.3\n", "")
            with (
                mock.patch.object(MOD.sys, "executable", str(python)),
                mock.patch.object(MOD, "pinned_versions", return_value={"ANSIBLE_CORE_VERSION": "2.20.3"}),
                mock.patch.object(MOD.subprocess, "run", return_value=wrong),
                self.assertRaisesRegex(RuntimeError, "expected 2.20.3, actual 2.16.3"),
            ):
                MOD.qualification_ansible_playbook()

    def test_qualification_ansible_controller_rejects_wrong_cli_version(self):
        with tempfile.TemporaryDirectory() as directory:
            environment_bin = Path(directory) / ".venv" / "qualification" / "bin"
            environment_bin.mkdir(parents=True)
            python = environment_bin / "python"
            controller = environment_bin / "ansible-playbook"
            python.touch(mode=0o755)
            controller.touch(mode=0o755)
            probes = [
                MOD.subprocess.CompletedProcess([], 0, "2.20.3\n", ""),
                MOD.subprocess.CompletedProcess([], 0, "ansible-playbook [core 2.16.3]\n", ""),
            ]
            with (
                mock.patch.object(MOD.sys, "executable", str(python)),
                mock.patch.object(MOD, "pinned_versions", return_value={"ANSIBLE_CORE_VERSION": "2.20.3"}),
                mock.patch.object(MOD.subprocess, "run", side_effect=probes),
                self.assertRaisesRegex(RuntimeError, "expected 2.20.3, actual 2.16.3"),
            ):
                MOD.qualification_ansible_playbook()

    def test_qualification_ansible_controller_ignores_hostile_path(self):
        with tempfile.TemporaryDirectory() as directory:
            environment_bin = Path(directory) / ".venv" / "qualification" / "bin"
            environment_bin.mkdir(parents=True)
            python = environment_bin / "python"
            controller = environment_bin / "ansible-playbook"
            python.touch(mode=0o755)
            controller.touch(mode=0o755)

            def probe(command, **kwargs):
                stdout = "2.20.3\n" if command[0] == str(python) else "ansible-playbook [core 2.20.3]\n"
                return MOD.subprocess.CompletedProcess(command, 0, stdout, "")

            with (
                mock.patch.object(MOD.sys, "executable", str(python)),
                mock.patch.dict(os.environ, {"PATH": "/usr/bin"}),
                mock.patch.object(MOD, "pinned_versions", return_value={"ANSIBLE_CORE_VERSION": "2.20.3"}),
                mock.patch.object(MOD.subprocess, "run", side_effect=probe),
                mock.patch.object(MOD.shutil, "which", return_value="/usr/bin/ansible-playbook") as which,
            ):
                self.assertEqual(str(controller), MOD.qualification_ansible_playbook())
            which.assert_not_called()

    def test_rocky_inventory_keeps_system_python_interpreter(self):
        for relative in ("test.yml", "server.yml"):
            source = (ROOT / "platform/ansible/tests/mgmt_offline_vm" / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertIn("'ansible_python_interpreter': '/usr/bin/python3'", source)

    def test_rke2_read_only_polls_drop_become_while_mutations_remain_privileged(self):
        role = (ROOT / "platform/ansible/roles/rke2_server/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        def task(name: str) -> str:
            match = re.search(
                rf"(?ms)^- name: {re.escape(name)}\n(.*?)(?=^- name: |\Z)",
                role,
            )
            self.assertIsNotNone(match, name)
            return match.group(0)

        for name in (
            "Wait boundedly for the queued native RKE2 service job",
            "Wait boundedly for the native RKE2 service readiness notification",
        ):
            with self.subTest(name=name):
                self.assertIn("become: false", task(name))

        for name in (
            "Install pinned offline RKE2 binary",
            "Install native RKE2 server systemd unit",
            "Render RKE2 server configuration",
            "Enable RKE2 server",
        ):
            with self.subTest(name=name):
                self.assertNotIn("become: false", task(name))

        server = (OFFLINE_FIXTURE / "server.yml").read_text(encoding="utf-8")
        self.assertRegex(
            server,
            r"hosts: \{\{ vm_name \| to_json \}\}\n\s+become: true",
        )

    def test_single_vm_privilege_probes_are_bounded_noninteractive_and_cleaned(self):
        server = (OFFLINE_FIXTURE / "server.yml").read_text(encoding="utf-8")
        main = (OFFLINE_FIXTURE / "main.yml").read_text(encoding="utf-8")
        helper = (OFFLINE_FIXTURE / "privilege_probe.py").read_text(encoding="utf-8")
        for phase in ("before", "activating", "failure"):
            self.assertRegex(server, rf"(?m)^\s+- {phase}$")
        self.assertIn("path: /tmp", server)
        self.assertIn("prefix: ecommerce-rke2-", server)
        self.assertIn("'ansible_control_path_dir': vm_server_control_path.path", server)
        self.assertNotIn("vm_state ~ '/server-control-path'", server)
        self.assertIn("{{ vm_python | dirname }}/ansible", server)
        self.assertIn("--repetitions", server)
        self.assertIn("--command-timeout", server)
        self.assertNotIn("ansible_ssh_timeout", server)
        self.assertNotRegex(server, r"(?m)^\s*timeout\s*=")
        self.assertIn('"sudo_n_true": ssh_command', helper)
        self.assertIn('"sudo_n_id": ssh_command', helper)
        self.assertIn("sudo -n /usr/bin/true", helper)
        self.assertIn("sudo -n /usr/bin/id -u", helper)
        self.assertNotIn("--ask-become-pass", helper)
        self.assertNotIn("ansible_become_password", helper)
        self.assertIn('path: "{{ vm_server_control_path.path }}"', main)
        self.assertIn("when: vm_server_control_path.path is defined", main)
        self.assertIn("Remove invocation-owned RKE2 controller sockets after success or failure", main)

    def test_privilege_probe_statistics_and_classification_are_deterministic(self):
        samples = [
            {"rc": 0, "duration_seconds": value}
            for value in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
        ]
        summary = PRIVILEGE.summarize(samples)
        self.assertEqual(10, summary["count"])
        self.assertEqual(0, summary["failures"])
        self.assertEqual(0.55, summary["median_seconds"])
        self.assertEqual(1.0, summary["p95_seconds"])
        self.assertEqual(1.0, summary["max_seconds"])

        all_pass = {name: {"failures": 0} for name in PRIVILEGE.SUMMARY_PROBES}
        become_failure = {name: dict(value) for name, value in all_pass.items()}
        become_failure["ansible_become"] = {"failures": 1}
        self.assertEqual(
            "ansible-become-only-timeout",
            PRIVILEGE.classify(become_failure, stale_socket=False),
        )
        no_become_failure = {name: dict(value) for name, value in all_pass.items()}
        no_become_failure["ansible_no_become"] = {"failures": 1}
        self.assertEqual(
            "controlpersist-stale",
            PRIVILEGE.classify(no_become_failure, stale_socket=True),
        )
        sanitized = PRIVILEGE.sanitize(
            'token=abc password: xyz "secret": "value" Authorization=Bearer-value Bearer raw'
        )
        for value in ("abc", "xyz", "value", "Bearer-value", "raw"):
            self.assertNotIn(value, sanitized)

    def test_both_authoritative_rke2_launchers_use_bound_controller(self):
        tree = ast.parse((ROOT / "scripts/repoctl.py").read_text(encoding="utf-8"))
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name in (
            "rke2_local_virtualbox_qualification",
            "rke2_local_ha_qualification",
        ):
            calls = [
                node
                for node in ast.walk(functions[name])
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "qualification_ansible_playbook"
            ]
            with self.subTest(name=name):
                self.assertEqual(1, len(calls))

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
        self.assertEqual(
            2,
            source.count(
                'serial: "{{ mgmt_local_ha_contract.execution.node_validation_parallelism }}"'
            ),
        )

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

    def test_ha_fingerprints_shared_local_vm_sources_from_canonical_contract(self):
        contract = MOD.ruby_yaml(
            str(ROOT / "platform/ansible/tests/mgmt_offline_vm/contract.yml")
        )["mgmt_local_vm_contract"]
        main = (FIXTURE / "main.yml").read_text(encoding="utf-8")

        runtime_sources = contract["runtime_sources"]
        self.assertIn(
            "platform/ansible/tests/mgmt_offline_vm/create.yml",
            runtime_sources,
        )
        self.assertIn(
            "platform/ansible/tests/mgmt_offline_vm/transport.py",
            runtime_sources,
        )
        self.assertIn("ha_single_contract.runtime_sources", main)
        self.assertIn("ha_single_runtime_sources", main)
        self.assertIn("ha_single_source_hashes.stdout", main)
        self.assertNotIn(
            '"{{ ha_repo }}/platform/ansible/tests/mgmt_offline_vm/create.yml"',
            main,
        )


    def test_address_collision_probe_is_bound_to_windows_host_only_source(self):
        contract = MOD.ruby_yaml(str(FIXTURE / "contract.yml"))["mgmt_local_ha_contract"]
        source = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        self.assertEqual("/mnt/c/Windows/System32/ping.exe", contract["controller"]["windows_ping"])
        self.assertIn("mgmt_local_ha_contract.controller.windows_ping", source)
        self.assertIn("ansible_playbook_python", source)
        self.assertGreaterEqual(source.count("run-windows"), 5)
        self.assertIn("ha_lifecycle_guard", source)
        self.assertIn("-S", source)
        self.assertIn("selected VirtualBox", source)
        self.assertIn("host-only source", source)
        self.assertNotIn('argv: [ping, -c, "1", -W, "1"', source)
        self.assertNotIn("MODULE_STRICT_UTF8_RESPONSE", source)

    def test_windows_runner_retries_only_exact_wsl_interop_failure(self):
        transient = GUARD.subprocess.CompletedProcess(
            [],
            1,
            "",
            "WSL ERROR: UtilAcceptVsock:273: accept4 failed 110",
        )
        success = GUARD.subprocess.CompletedProcess([], 0, "ok", "")
        with (
            mock.patch.object(GUARD.subprocess, "run", side_effect=[transient, success]) as run,
            mock.patch.object(GUARD.time, "sleep") as sleep,
        ):
            self.assertEqual(0, GUARD.run_windows_command(["vbox", "list"]).returncode)
            self.assertEqual(2, run.call_count)
            sleep.assert_called_once_with(GUARD.WINDOWS_INTEROP_DELAY_SECONDS)

        permanent = GUARD.subprocess.CompletedProcess([], 1, "", "permission denied")
        with (
            mock.patch.object(GUARD.subprocess, "run", return_value=permanent) as run,
            mock.patch.object(GUARD.time, "sleep") as sleep,
        ):
            self.assertEqual(1, GUARD.run_windows_command(["vbox", "list"]).returncode)
            run.assert_called_once()
            sleep.assert_not_called()

        with (
            mock.patch.object(GUARD.subprocess, "run", return_value=transient) as run,
            mock.patch.object(GUARD.time, "sleep") as sleep,
        ):
            self.assertEqual(
                GUARD.WINDOWS_INTEROP_EXHAUSTED_RC,
                GUARD.run_windows_command(["vbox", "list"]).returncode,
            )
            self.assertEqual(GUARD.WINDOWS_INTEROP_ATTEMPTS, run.call_count)
            self.assertEqual(GUARD.WINDOWS_INTEROP_ATTEMPTS - 1, sleep.call_count)

        localized = GUARD.subprocess.CompletedProcess([], 1, b"r\x82ponse", b"")
        with mock.patch.object(GUARD.subprocess, "run", return_value=localized):
            result = GUARD.run_windows_command(["ping"])
            self.assertEqual(1, result.returncode)
            self.assertIn("�", result.stdout)

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

        attach_failure = {
            "rc": 2,
            "stdout": (
                "TASK [Attach only selected existing host-only network after guest output is denied]\n"
                "WSL ERROR: UtilAcceptVsock:273: accept4 failed 110"
            ),
            "stderr": "",
            "cmd": ["ansible-playbook"],
        }
        attach_decision = GUARD.create_decision(attach_failure, owned)
        self.assertFalse(attach_decision["resume"])
        self.assertEqual("repair-hostonly-attach", attach_decision["recovery"])
        self.assertEqual(
            "fail",
            GUARD.create_decision(attach_failure, {"state": "mismatch"})["recovery"],
        )

        create_helper = (FIXTURE / "single_vm_action.yml").read_text(encoding="utf-8")
        self.assertEqual(1, create_helper.count("vm_resume_owned_creation': true"))
        repair = (FIXTURE / "complete_vm_creation.yml").read_text(encoding="utf-8")
        self.assertNotIn("vm_resume_owned_creation", repair)
        self.assertIn("nic1=\\\"null\\\"", repair)
        self.assertIn("MGMT_CONSOLE_RESULT:0", repair)
        self.assertIn("guest_probe.py", repair)
        self.assertIn(
            "Restart only the exact recovered VM to realize the delayed host-only attachment",
            repair,
        )
        self.assertIn("ha_create_repair_ownership.uuid", repair)
        self.assertIn("restart_rc", repair)
        self.assertIn("console-proof", create_helper)
        self.assertIn("ha_single_vm_console_completed", create_helper)

    def test_console_proof_requires_success_and_one_exact_host_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            console = root / "console.log"
            known_hosts = root / "known_hosts"
            console.write_text(
                "MGMT_HOST_KEY:ssh-ed25519 AAAAC3NzaValidFixtureKey\n"
                "MGMT_CONSOLE_RESULT:0\n",
                encoding="utf-8",
            )
            self.assertTrue(
                GUARD.preserve_console_proof(console, known_hosts, "192.168.22.62")
            )
            self.assertEqual(
                "192.168.22.62 ssh-ed25519 AAAAC3NzaValidFixtureKey\n",
                known_hosts.read_text(encoding="utf-8"),
            )
            console.write_text("MGMT_CONSOLE_RESULT:1\n", encoding="utf-8")
            self.assertFalse(
                GUARD.preserve_console_proof(console, known_hosts, "192.168.22.62")
            )

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
            "retry",
            GUARD.cleanup_decision(
                result(1, "WSL ERROR: UtilAcceptVsock:273: accept4 failed 110"),
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
        self.assertIn("destroy-owned", retry)

    def test_owned_destroy_uses_only_proven_uuid_and_removes_identity(self):
        vm_name = "ecommerce-mgmt-test-ha-cp-02"
        uuid = "11111111-2222-3333-4444-555555555555"
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "id"
            identity.write_text(uuid + "\n", encoding="utf-8")
            inspected = GUARD.subprocess.CompletedProcess(
                [], 0, 'VMState="poweroff"\n', ""
            )
            removed = GUARD.subprocess.CompletedProcess([], 0, "removed\n", "")
            with (
                mock.patch.object(
                    GUARD,
                    "probe_ownership",
                    return_value={"state": "owned", "vm_name": vm_name, "uuid": uuid},
                ),
                mock.patch.object(
                    GUARD, "run_windows_command", side_effect=[inspected, removed]
                ) as run,
            ):
                result = GUARD.destroy_owned("vbox", identity, vm_name)
            self.assertEqual(0, result.returncode)
            self.assertFalse(identity.exists())
            self.assertEqual(
                [
                    mock.call(["vbox", "showvminfo", uuid, "--machinereadable"]),
                    mock.call(["vbox", "unregistervm", uuid, "--delete"]),
                ],
                run.call_args_list,
            )

    def test_cold_stage_retries_only_owned_final_wsl_postcondition(self):
        failure = {
            "rc": 2,
            "stdout": (
                "TASK [Verify native SELinux, egress denial, exact RPMs and staged image hashes]\n"
                "Connection timed out during banner exchange\n"
                "WSL ERROR: UtilAcceptVsock:273: accept4 failed 110"
            ),
            "stderr": "",
            "cmd": ["ansible-playbook"],
        }
        self.assertEqual(
            "retry-postcondition",
            GUARD.cold_stage_decision(failure, {"state": "owned"})["resolution"],
        )
        for result, ownership in (
            ({**failure, "stdout": "network unreachable"}, {"state": "owned"}),
            (failure, {"state": "mismatch"}),
        ):
            self.assertEqual("fail", GUARD.cold_stage_decision(result, ownership)["resolution"])

        cold = (FIXTURE / "cold_stage_batch.yml").read_text(encoding="utf-8")
        retry = (FIXTURE / "retry_cold_stage_vm.yml").read_text(encoding="utf-8")
        self.assertIn("async: 1800", cold)
        self.assertIn("classify-cold-stage", retry)
        self.assertIn("ha_cold_stage_role_result.trial.cold_trial | bool", retry)
        self.assertNotIn("vm_action", retry)

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

        sequential_phases = (
            "Bootstrap first RKE2 control plane",
            "Join second RKE2 control plane directly to the bootstrap member",
            "Wait for the first two control planes",
            "Join worker-03 directly so it can host the HAProxy endpoint",
            "Deploy HAProxy in front of the control planes",
            "Join third control plane through HAProxy",
        )
        phase_offsets = [cluster.index(f"- name: {phase}") for phase in sequential_phases]
        self.assertEqual(sorted(phase_offsets), phase_offsets)

    def test_cp02_readiness_retries_api_and_node_wait_fail_closed(self):
        cluster = (FIXTURE / "cluster.yml").read_text(encoding="utf-8")
        start = cluster.index("- name: Wait for the first two control planes")
        end = cluster.index("- name: Join worker-03 directly", start)
        readiness = cluster[start:end]

        readyz_offset = readiness.index("--raw=/readyz")
        node_wait_offset = readiness.index("wait, node/ha-cp-02")
        self.assertLess(readyz_offset, node_wait_offset)
        self.assertIn("register: ha_cp02_api_readyz", readiness)
        self.assertIn("until: ha_cp02_api_readyz.rc == 0", readiness)
        self.assertIn("retries: 12", readiness)
        self.assertIn("delay: 5", readiness)
        self.assertIn("register: ha_cp02_node_ready", readiness)
        self.assertIn("until: ha_cp02_node_ready.rc == 0", readiness)
        self.assertIn("retries: 8", readiness)
        self.assertEqual(2, readiness.count("delay: 5"))
        self.assertIn("wait, node/ha-cp-02", readiness)
        self.assertNotIn("failed_when: false", readiness)

        for diagnostic in ("rc=", "stdout=", "stderr=", "attempts="):
            with self.subTest(diagnostic=diagnostic):
                self.assertIn(diagnostic, readiness)
        for classification in (
            "tls-handshake-timeout-exhausted",
            "kubeconfig-invalid-or-missing",
            "authentication-or-certificate-error",
            "api-connection-refused",
            "api-not-ready",
            "node-not-registered",
            "node-not-ready",
        ):
            with self.subTest(classification=classification):
                self.assertIn(classification, readiness)

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
