"""Mutation tests for the local VirtualBox/RKE2 isolation probes."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "platform/ansible/tests/mgmt_offline_vm"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, FIXTURE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RKE2 = load("rke2_probe")
VIRTUALBOX = load("virtualbox_probe")
TAMPER = load("tamper_artifact")
RESTAGE = load("restage_cleanup")


class MgmtOfflineVmMutationTests(unittest.TestCase):
    def nft_document(self, output_policy="drop", forward_policy="drop"):
        return {"nftables": [
            {"chain": {"family": "inet", "table": RKE2.EGRESS_TABLE,
                       "name": "output", "hook": "output", "policy": output_policy}},
            {"chain": {"family": "inet", "table": RKE2.EGRESS_TABLE,
                       "name": "forward", "hook": "forward", "policy": forward_policy}},
        ]}

    def machine(self):
        values = {
            "name": "ecommerce-mgmt-test-review",
            "VMState": "running",
            "ioapic": "on",
            "nic1": "hostonly",
            "hostonlyadapter1": "VirtualBox Host-Only Ethernet Adapter",
            "macaddress1": "02EECC009801",
            "cpus": "4",
            "memory": "4096",
        }
        values.update({f"nic{index}": "none" for index in range(2, 9)})
        return values

    def test_canonical_nftables_boundary_accepts_exact_drop_chains(self):
        self.assertEqual(
            RKE2.require_default_deny(self.nft_document()),
            {"output": "drop", "forward": "drop"},
        )

    def test_nftables_mutations_fail_closed(self):
        for document in (
            {"nftables": []},
            self.nft_document(output_policy="accept"),
            self.nft_document(forward_policy="accept"),
            {"nftables": self.nft_document()["nftables"] * 2},
        ):
            with self.subTest(document=document), self.assertRaises(ValueError):
                RKE2.require_default_deny(document)

    def test_virtualbox_rejects_nat_on_every_secondary_adapter(self):
        for index in range(2, 9):
            values = self.machine()
            values[f"nic{index}"] = "nat"
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, f"adapter {index}"):
                VIRTUALBOX.require_isolated(
                    values, name=values["name"], nic1="hostonly",
                    adapter=values["hostonlyadapter1"], mac=values["macaddress1"],
                    cpus=4, memory=4096, running=True,
                )

    def test_virtualbox_accepts_exact_owned_isolated_machine(self):
        values = self.machine()
        VIRTUALBOX.require_isolated(
            values, name=values["name"], nic1="hostonly",
            adapter=values["hostonlyadapter1"], mac=values["macaddress1"],
            cpus=4, memory=4096, running=True,
        )

    def test_tamper_probe_changes_exactly_the_requested_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "rke2.linux-amd64"
            artifact.write_bytes(b"approved bytes")
            before = TAMPER.sha256(artifact)
            result = TAMPER.mutate(artifact, root)
            self.assertNotEqual(TAMPER.sha256(artifact), before)
            self.assertEqual(result["before_sha256"], before)
            self.assertEqual(result["after_sha256"], TAMPER.sha256(artifact))

    def test_server_writes_strict_json_without_literal_escape_suffix(self):
        server = (FIXTURE / "server.yml").read_text()
        self.assertIn('content: \'{{ "{{ rke2_probe.stdout }}" }}\'', server)
        self.assertNotIn(r"rke2_probe.stdout }}\n", server)

    def test_create_uses_canonical_bounded_native_ansible_ssh_readiness(self):
        contract = (FIXTURE / "contract.yml").read_text()
        create = (FIXTURE / "create.yml").read_text()

        for value in (
            "connect_timeout_seconds: 3",
            "connection_attempts: 1",
            "readiness_timeout_seconds: 300",
            "readiness_sleep_seconds: 3",
        ):
            self.assertIn(value, contract)

        self.assertIn(
            "ConnectTimeout {{ mgmt_local_vm_contract.transport.ssh.connect_timeout_seconds }}",
            create,
        )
        self.assertIn(
            "ConnectionAttempts {{ mgmt_local_vm_contract.transport.ssh.connection_attempts }}",
            create,
        )
        self.assertIn(
            'timeout: "{{ mgmt_local_vm_contract.transport.ssh.readiness_timeout_seconds }}"',
            create,
        )
        self.assertIn(
            'connect_timeout: "{{ mgmt_local_vm_contract.transport.ssh.connect_timeout_seconds }}"',
            create,
        )
        self.assertIn(
            'sleep: "{{ mgmt_local_vm_contract.transport.ssh.readiness_sleep_seconds }}"',
            create,
        )
        self.assertNotIn("ConnectTimeout 3", create)
        self.assertNotIn("ConnectionAttempts 1", create)
        self.assertNotIn("timeout: 300", create)
        self.assertIn(
            "Register isolated guest for native Ansible connection checks",
            create,
        )
        self.assertIn("ansible.builtin.wait_for_connection:", create)
        self.assertIn("Gather real guest facts after SSH is available", create)
        self.assertIn("ansible.builtin.setup:", create)
        self.assertIn("Require a real enforcing non-container guest kernel", create)
        self.assertIn(
            "vm_guest_facts.ansible_facts.ansible_virtualization_type != 'docker'",
            create,
        )
        self.assertIn(
            "vm_guest_facts.ansible_facts.ansible_selinux.mode == 'enforcing'",
            create,
        )
        self.assertNotIn("Wait for SSH and require real enforcing guest kernel", create)

    def test_windows_proxy_uses_canonical_ssh_timeout_and_role_has_live_log(self):
        contract = (FIXTURE / "contract.yml").read_text()
        main = (FIXTURE / "main.yml").read_text()
        transport = (FIXTURE / "transport.py").read_text()
        role_test = (FIXTURE / "test.yml").read_text()

        self.assertIn("connect_timeout_seconds: 3", contract)
        self.assertIn("'ssh_connect_timeout_seconds':", main)
        self.assertIn(
            "mgmt_local_vm_contract.transport.ssh.connect_timeout_seconds | int",
            main,
        )
        self.assertIn(
            'request["connect_timeout_milliseconds"] = connect_timeout_seconds * 1000',
            transport,
        )
        self.assertIn(
            "$connecting.Wait([int]$r.connect_timeout_milliseconds)",
            transport,
        )
        self.assertNotIn("$connecting.Wait(10000)", transport)
        self.assertIn(
            "log_path = {{ vm_state }}/actual-role-live.log",
            role_test,
        )
        self.assertIn(
            "Execute exact repository offline-artifact role through native Ansible SSH",
            role_test,
        )

    def test_restage_cleanup_refuses_state_outside_explicit_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            images = root / "images"
            containerd = root / "containerd"
            unrelated = root / "server"
            for path in (containerd, images, unrelated):
                path.mkdir()
            self.assertEqual(
                RESTAGE.clean((images,), allowed=(images,)),
                [str(images)],
            )
            self.assertTrue(containerd.is_dir())
            self.assertTrue(unrelated.is_dir())
            with self.assertRaisesRegex(ValueError, "non-reconstructible"):
                RESTAGE.clean((unrelated,), allowed=(images,))

    def test_restage_cleanup_refuses_symlinked_allowed_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "runtime"
            target.mkdir()
            sentinel = target / "etcd-state"
            sentinel.write_text("must survive")
            images = root / "images"
            images.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                RESTAGE.clean((images,), allowed=(images,))
            self.assertEqual(sentinel.read_text(), "must survive")


if __name__ == "__main__":
    unittest.main()
