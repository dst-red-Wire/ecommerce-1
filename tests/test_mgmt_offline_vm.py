"""Mutation tests for the local VirtualBox/RKE2 isolation probes."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml

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
TRANSPORT = load("transport")
CLEANUP = load("cleanup_seed")
GUEST = load("guest_probe")
PRIVATE_INTERFACE = load("private_interface")


class MgmtOfflineVmMutationTests(unittest.TestCase):
    def test_bundle_rpm_postcondition_accepts_only_newer_image_baseline(self):
        artifacts = [
            {"category": "rpm", "package": "rke2-selinux", "nevra": "rke2-selinux-0:0.23-1.el10.noarch"},
            {"category": "rpm", "package": "libxml2", "nevra": "libxml2-0:2.12.5-10.el10_2.3.x86_64"},
        ]
        installed = [
            "rke2-selinux\t0\t0.23\t1.el10\tnoarch",
            "libxml2\t0\t2.12.5\t10.el10_2.4\tx86_64",
        ]
        compare = lambda actual, expected: (actual > expected) - (actual < expected)
        exact, newer = GUEST.verify_bundle_rpms(artifacts, installed, compare)
        self.assertEqual(exact, 1)
        self.assertEqual(newer, [{
            "expected_nevra": "libxml2-0:2.12.5-10.el10_2.3.x86_64",
            "installed_nevra": "libxml2-0:2.12.5-10.el10_2.4.x86_64",
        }])
        with self.assertRaisesRegex(AssertionError, "absent without a newer"):
            GUEST.verify_bundle_rpms(artifacts, installed[:-1], compare)
        with self.assertRaisesRegex(AssertionError, "absent without a newer"):
            GUEST.verify_bundle_rpms(
                artifacts, installed[:1] + ["libxml2\t0\t2.12.5\t10.el10_2.2\tx86_64"], compare
            )

    def test_active_fixture_requires_verified_local_rocky_10_box(self):
        contract = (FIXTURE / "contract.yml").read_text(encoding="utf-8")
        main = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        vagrant = (FIXTURE / "Vagrantfile").read_text(encoding="utf-8")
        self.assertIn("active-rocky-10.2-exact-local-box", contract)
        self.assertIn("scripts/rocky_box_catalog.py#find_matching_box", contract)
        self.assertNotIn("rocky-9", (contract + main + vagrant).lower())
        self.assertNotIn("ecommerce/rocky-9.8", (contract + main + vagrant).lower())
        self.assertNotIn("https://", contract)
        self.assertIn("^file:///", main)

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

    def test_rke2_probe_rejects_pending_system_pod(self):
        answers = {
            "nodes": {"items": [{"metadata": {"name": "fixture"},
                                  "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]},
            "daemonsets": {"items": [{"metadata": {"name": "cilium"},
                                       "status": {"desiredNumberScheduled": 1, "numberReady": 1}}]},
            "deployments": {"items": [{"metadata": {"name": "rke2-coredns-rke2-coredns"},
                                        "spec": {"replicas": 1},
                                        "status": {"availableReplicas": 1}}]},
            "pods": {"items": [{"metadata": {"namespace": "kube-system", "name": "pending-system"},
                                 "status": {"phase": "Pending"}}]},
        }
        with mock.patch.object(RKE2, "output", return_value=json.dumps(self.nft_document())):
            with mock.patch.object(RKE2, "kubectl", side_effect=lambda _, kind, *rest: answers[kind]):
                with self.assertRaisesRegex(SystemExit, "pending pods: kube-system/pending-system"):
                    RKE2.main()

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

    def test_bootstrap_vm_requires_disconnected_cable_and_exact_seed(self):
        values = self.machine()
        values.update({
            "UUID": "25653b1f-5ca9-41d3-a4d0-b47c9f341522",
            "cableconnected1": "off",
            "IDE-1-0": r"C:\fixture\seed.iso",
        })
        expected = dict(
            name=values["name"], nic1="hostonly", cable="off",
            adapter=values["hostonlyadapter1"], mac=values["macaddress1"],
            uuid=values["UUID"], seed_iso=values["IDE-1-0"], running=True,
        )
        VIRTUALBOX.require_isolated(values, **expected)
        for key, mutation in (
            ("cableconnected1", "on"),
            ("UUID", "00000000-0000-0000-0000-000000000000"),
            ("IDE-1-0", r"C:\fixture\other.iso"),
        ):
            changed = dict(values, **{key: mutation})
            with self.subTest(key=key), self.assertRaises(ValueError):
                VIRTUALBOX.require_isolated(changed, **expected)

    def test_machine_value_parser_preserves_iso_storage_key(self):
        machine = VIRTUALBOX.machine_values(
            'UUID="25653b1f-5ca9-41d3-a4d0-b47c9f341522"\n'
            '"IDE-1-0"="C:\\\\fixture\\\\seed.iso"\n'
        )
        self.assertEqual(machine["IDE-1-0"], r"C:\fixture\seed.iso")

    def test_serial_marker_requires_exact_nonce_and_fresh_file(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            serial = state / "bootstrap-serial.log"
            nonce = "a" * 32
            marker = f"MGMT_BOOTSTRAP_READY:{nonce} MGMT_HOST_KEY:ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ\n"
            serial.write_text("stale line\n" + marker, encoding="utf-8")
            older_than_file = serial.stat().st_mtime_ns - 1
            self.assertEqual(
                TRANSPORT.wait_for_bootstrap_marker(
                    state, nonce=nonce, minimum_mtime_ns=older_than_file,
                    offset=len("stale line\n"), timeout_seconds=1,
                ),
                marker.rstrip(),
            )
            with self.assertRaisesRegex(ValueError, "marker missing"):
                TRANSPORT.wait_for_bootstrap_marker(
                    state, nonce="b" * 32, minimum_mtime_ns=older_than_file,
                    offset=0, timeout_seconds=0.01,
                )
            with self.assertRaisesRegex(ValueError, "marker missing"):
                TRANSPORT.wait_for_bootstrap_marker(
                    state, nonce=nonce, minimum_mtime_ns=time.time_ns() + 1_000_000_000,
                    offset=0, timeout_seconds=0.01,
                )

    def test_serial_failure_reports_exact_nonce_and_bounded_guest_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            nonce = "c" * 32
            serial = state / "bootstrap-serial.log"
            serial.write_text(
                f"MGMT_BOOTSTRAP_FAIL:{nonce} stage=guest_access rc=10\n"
                "MGMT_BOOTSTRAP_LOG:Error: invalid nmcli field\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "guest_access.*invalid nmcli field"):
                TRANSPORT.wait_for_bootstrap_marker(
                    state, nonce=nonce, minimum_mtime_ns=serial.stat().st_mtime_ns - 1,
                    offset=0, timeout_seconds=1,
                )
            with self.assertRaisesRegex(ValueError, "marker missing"):
                TRANSPORT.wait_for_bootstrap_marker(
                    state, nonce="d" * 32, minimum_mtime_ns=serial.stat().st_mtime_ns - 1,
                    offset=0, timeout_seconds=0.01,
                )

    @unittest.skipUnless(Path(TRANSPORT.POWERSHELL).is_file(), "requires Windows PowerShell through WSL")
    def test_fresh_vagrant_boot_rejects_cached_box_without_deleting_it(self):
        windows_temp = subprocess.check_output(
            [TRANSPORT.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
             "[IO.Path]::GetTempPath()"], text=True,
        ).strip()
        linux_temp = subprocess.check_output(["wslpath", "-u", windows_temp], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="ecommerce-rke2-cache-test-", dir=linux_temp) as directory:
            state = Path(directory)
            cached = state / "vagrant-home/boxes/rocky-10.2-rke2-virtualbox/sentinel"
            cached.parent.mkdir(parents=True)
            cached.write_text("preserve", encoding="utf-8")
            bridge = state / "ipc-transport.ps1"
            bridge.write_text(TRANSPORT.PS, encoding="utf-8")
            request = state / "request.json"
            request.write_text(json.dumps({
                "mode": "vagrant", "directory": TRANSPORT.windows_path(state),
                "executable": "C:\\Windows\\System32\\cmd.exe",
                "arguments": ["/c", "exit", "0"], "fresh_box": True,
            }), encoding="utf-8")
            result = subprocess.run(
                [TRANSPORT.POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", TRANSPORT.windows_path(bridge), "-Request", TRANSPORT.windows_path(request)],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Fresh VM creation requires an empty isolated Vagrant box cache",
                          result.stdout + result.stderr)
            self.assertEqual(cached.read_text(encoding="utf-8"), "preserve")

    def test_fresh_box_cache_is_checked_before_vagrant_validation_and_boot(self):
        main = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        create = (FIXTURE / "create.yml").read_text(encoding="utf-8")
        self.assertIn("['--fresh-box'] if vm_action in ['validate', 'create', 'qualify']", main)
        self.assertIn("['--fresh-box'] if not vm_resume_owned_creation | bool", create)

    def test_server_uses_observed_nic_and_rechecks_exact_sources(self):
        tasks = yaml.safe_load((FIXTURE / "server.yml").read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        fingerprint = names.index("Record exact Git and source identities used by this server invocation")
        derive = names.index("Derive the actual private interface from the owned VM MAC")
        execute = names.index("Execute canonical RKE2 server role through native Ansible SSH")
        recheck = names.index("Require server sources unchanged through the nested role invocation")
        self.assertLess(fingerprint, derive)
        self.assertLess(derive, execute)
        self.assertLess(execute, recheck)
        self.assertIn("server-source.sha256", str(tasks[recheck]["ansible.builtin.command"]["argv"]))
        self.assertIn("mgmt_private_interface: {{ vm_server_interface.stdout | trim | to_json }}",
                      (FIXTURE / "server.yml").read_text(encoding="utf-8"))
        command_task = tasks[derive]["ansible.builtin.command"]
        arguments = command_task["argv"]
        self.assertEqual(arguments[-3:], ["python3", "-", "{{ vm_mac }}"])
        self.assertIn("private_interface.py", command_task["stdin"])
        self.assertEqual(PRIVATE_INTERFACE.interface_for_mac("02EECC009801", [
            {"ifname": "enp0s3", "address": "02:ee:cc:00:98:01"},
        ]), "enp0s3")
        with self.assertRaisesRegex(ValueError, "absent or ambiguous"):
            PRIVATE_INTERFACE.interface_for_mac("02EECC009801", [
                {"ifname": "enp0s3", "address": "02:ee:cc:00:98:01"},
                {"ifname": "eth0", "address": "02:ee:cc:00:98:01"},
            ])
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "ip"
            command.write_text(
                "#!/usr/bin/env python3\nimport json\nprint(json.dumps(" + repr([
                    {"ifname": "lo", "address": "00:00:00:00:00:00"},
                    {"ifname": "enp0s3", "address": "02:ee:cc:00:98:01"},
                ]) + "))\n", encoding="utf-8",
            )
            command.chmod(0o755)
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ.get("PATH", ""))
            source = (FIXTURE / "private_interface.py").read_text(encoding="utf-8")
            actual = subprocess.run([sys.executable, "-", "02EECC009801"], input=source,
                                    capture_output=True, text=True, env=environment, check=False)
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertEqual(actual.stdout.strip(), "enp0s3")
            foreign = subprocess.run([sys.executable, "-", "02EECC009802"], input=source,
                                     capture_output=True, text=True, env=environment, check=False)
            self.assertNotEqual(foreign.returncode, 0)

    def test_fixture_uses_key_only_packer_account_consistently(self):
        create = (FIXTURE / "create.yml").read_text(encoding="utf-8")
        diagnostics = (FIXTURE / "diagnostics.yml").read_text(encoding="utf-8")
        server = (FIXTURE / "server.yml").read_text(encoding="utf-8")
        trial = (FIXTURE / "test.yml").read_text(encoding="utf-8")
        self.assertIn("User packer", create)
        self.assertIn("/home/packer/.ssh/authorized_keys", create)
        self.assertIn("/home/packer/.cache", diagnostics)
        self.assertIn("'ansible_user': 'packer'", server)
        self.assertIn("'ansible_user': 'packer'", trial)
        for contents in (create, diagnostics, server, trial):
            self.assertNotIn("/home/vagrant", contents)
            self.assertNotIn("'ansible_user': 'vagrant'", contents)

    def test_diagnostics_cannot_preinstall_an_offline_bundle_rpm(self):
        tasks = yaml.safe_load((FIXTURE / "diagnostics.yml").read_text(encoding="utf-8"))
        diagnostic_files = {
            item["file"] for item in tasks[0]["ansible.builtin.set_fact"]["vm_diagnostic_rpms"]
        }
        lock = json.loads((ROOT / "config/artifacts/mgmt-rke2-offline-v1.37.0-rke2r1.lock.json")
                          .read_text(encoding="utf-8"))
        bundle_rpms = {
            item["file"]: item for item in lock["rpms"]
        }
        self.assertEqual(set(), diagnostic_files & bundle_rpms.keys())
        self.assertIn("fio-3.36-5.el10.x86_64.rpm", diagnostic_files)
        self.assertIn("iperf3-3.17.1-6.el10_2.1.x86_64.rpm", diagnostic_files)

        numactl = next(item for item in bundle_rpms.values() if item["package"] == "numactl-libs")
        dependency_index = next(index for index, task in enumerate(tasks)
                                if task["name"].startswith("Require the exact bundle-owned fio dependency"))
        install_index = next(index for index, task in enumerate(tasks)
                             if task["name"] == "Install diagnostics with every remote repository disabled")
        self.assertLess(dependency_index, install_index)
        dependency_probe = tasks[dependency_index]
        self.assertIn("numactl-libs", dependency_probe["ansible.builtin.command"]["argv"])
        self.assertIn(numactl["nevra"], dependency_probe["failed_when"])

    def test_guest_dhcp_reconciliation_uses_nmcli_list_field(self):
        create = (FIXTURE / "create.yml").read_text(encoding="utf-8")
        self.assertIn("nmcli -g UUID connection show", create)
        self.assertNotIn("nmcli -g connection.uuid connection show |", create)

    def test_owned_seed_cleanup_archives_failure_then_removes_only_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "ecommerce-mgmt-test-review"
            state = root / "Temp/ecommerce/.context" / name
            state.mkdir(parents=True)
            (state / "runtime.json").write_text(json.dumps({"name": name}))
            (state / "Vagrantfile").write_text("preserve")
            seed = state / "seed"
            seed.mkdir()
            for filename in CLEANUP.SEED_FILES:
                (seed / filename).write_text(filename)
            iso = state / "seed.iso"
            iso.write_bytes(b"fixture iso")
            (state / "seed-result.json").write_text(json.dumps({
                "vm_name": name, "sha256": hashlib.sha256(iso.read_bytes()).hexdigest()
            }))
            (state / "bootstrap-serial.log").write_text("MGMT_BOOTSTRAP_FAIL:fixture stage=guest_access rc=1\n")
            vm_state = root / "repo/.context/mgmt-offline-vm" / name
            vm_state.mkdir(parents=True)
            outcome = CLEANUP.cleanup(state, name, "", root / "repo")
            self.assertTrue(outcome["archived"])
            archive = json.loads(Path(outcome["archive"]).read_text())
            self.assertIn("MGMT_BOOTSTRAP_FAIL", archive["serial_tail"])
            self.assertFalse(seed.exists())
            self.assertFalse(iso.exists())
            self.assertFalse((state / "bootstrap-serial.log").exists())
            self.assertEqual((state / "Vagrantfile").read_text(), "preserve")
            self.assertFalse(CLEANUP.cleanup(state, name, "", root / "repo")["archived"])

    def test_owned_seed_cleanup_refuses_registered_vm_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "ecommerce-mgmt-test-review"
            state = root / "Temp/ecommerce/.context" / name
            state.mkdir(parents=True)
            (state / "runtime.json").write_text(json.dumps({"name": name}))
            (root / "repo/.context/mgmt-offline-vm" / name).mkdir(parents=True)
            sentinel = root / "sentinel"
            sentinel.write_text("must remain")
            (state / "seed.iso").symlink_to(sentinel)
            registered = f'"{name}" {{25653b1f-5ca9-41d3-a4d0-b47c9f341522}}\n'
            with self.assertRaisesRegex(ValueError, "still-registered"):
                CLEANUP.cleanup(state, name, registered, root / "repo")
            renamed = '"renamed-fixture" {25653b1f-5ca9-41d3-a4d0-b47c9f341522}\n'
            with self.assertRaisesRegex(ValueError, "still-registered owned VM UUID"):
                CLEANUP.cleanup(state, name, renamed, root / "repo",
                                "25653b1f-5ca9-41d3-a4d0-b47c9f341522")
            with self.assertRaisesRegex(ValueError, "redirected"):
                CLEANUP.cleanup(state, name, "", root / "repo")
            self.assertEqual(sentinel.read_text(), "must remain")

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
