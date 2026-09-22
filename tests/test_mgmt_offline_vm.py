"""Mutation tests for the local VirtualBox/RKE2 isolation probes."""

from __future__ import annotations

import importlib.util
import json
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
PRIVILEGE = load("privilege_probe")
ROLE_TIMING = load("role_timing")
GUEST_ADDITIONS = load("guest_additions_bundle")


class MgmtOfflineVmMutationTests(unittest.TestCase):
    def role_log(self):
        events = (
            ("2026-09-22 10:00:00,000", "Validate controller bundle before transfer"),
            ("2026-09-22 10:00:05,000", "Create digest-specific node artifact directory"),
            ("2026-09-22 10:00:06,000", "Transfer approved bundle over existing SSH access"),
            ("2026-09-22 10:00:16,000", "Create local validator directory"),
            ("2026-09-22 10:00:17,000", "Verify transferred bytes before package installation"),
            ("2026-09-22 10:00:21,000", "Verify every local RPM signature against isolated approved keys"),
            ("2026-09-22 10:00:27,000", "Import only manifest-approved offline RPM signing keys"),
            ("2026-09-22 10:00:29,000", "Install complete local RPM set with all repositories disabled"),
            ("2026-09-22 10:00:37,000", "Require SELinux enforcement and installed RKE2 policy"),
            ("2026-09-22 10:00:38,000", "Record verified offline artifacts for subsequent RKE2 plays"),
        )
        lines = [
            f"{timestamp} p=123 u=dev n=ansible INFO| "
            f"TASK [mgmt_offline_artifacts : {name}] *****"
            for timestamp, name in events
        ]
        lines.append(
            "2026-09-22 10:00:40,000 p=123 u=dev n=ansible INFO| "
            "PLAY RECAP *****"
        )
        return "\n".join(lines) + "\n"

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

    def test_guest_additions_are_centrally_pinned_preflighted_and_provisioned(self):
        contract = (FIXTURE / "contract.yml").read_text(encoding="utf-8")
        main = (FIXTURE / "main.yml").read_text(encoding="utf-8")
        preflight = (FIXTURE / "preflight.yml").read_text(encoding="utf-8")
        create = (FIXTURE / "create.yml").read_text(encoding="utf-8")
        install = (FIXTURE / "guest_additions.yml").read_text(encoding="utf-8")
        vagrant = (FIXTURE / "Vagrantfile").read_text(encoding="utf-8")
        lock = json.loads((ROOT / "config/artifacts/virtualbox-guest-additions-7.2.18-rocky-9.8.lock.json").read_text())

        self.assertEqual("7.2.18r175117", lock["virtualbox_version"])
        self.assertEqual("7.2.18", lock["guest_additions"]["version"])
        self.assertEqual(175117, lock["guest_additions"]["revision"])
        self.assertEqual(
            "346ea2b9ed47bb954464af83835b14bd8afa5fc1864f34e2561ed923fb74981c",
            lock["guest_additions"]["iso"]["sha256"],
        )
        self.assertEqual("5.14.0-687.10.1.el9_8.0.1.x86_64", lock["target"]["kernel_release"])
        self.assertEqual(78, len(lock["rpms"]))
        self.assertIn("windows_executable: 'C:\\Program Files\\Vagrant\\bin\\vagrant.exe'", contract)
        self.assertIn("wsl_executable: /mnt/c/Program Files/Vagrant/bin/vagrant.exe", contract)
        self.assertIn("guest_additions_lock:", contract)
        self.assertNotIn("version: 7.2.18", contract)
        self.assertIn("Verify exact Windows Vagrant version before any VM mutation", preflight)
        self.assertIn("'Vagrant ' ~ vm_vagrant_version", preflight)
        self.assertIn("include_tasks: preflight.yml", main)
        self.assertNotIn("vm_vagrant_windows: C:\\Program Files", main)
        self.assertIn("when: vm_action != 'destroy'", main)
        self.assertLess(main.index("include_tasks: preflight.yml"), main.index("Run native Vagrant validation"))
        self.assertIn("guest_additions_iso_windows", main)
        self.assertIn("runtime.fetch(\"guest_additions_iso_windows\")", vagrant)
        self.assertIn("SATA Controller", vagrant)
        self.assertIn("include_tasks: guest_additions.yml", create)
        self.assertIn("disablerepo: '*'", install)
        self.assertIn("--rpm-signature-check", install)
        self.assertIn("rcvboxadd", install)
        self.assertIn("Guest/RAM/Usage/Total", install)
        self.assertIn("Guest/RAM/Usage/Free", install)
        self.assertIn("guest-additions.json", install)
        self.assertNotRegex(preflight + install, r"\bcurl\b|\bwget\b")

    def test_guest_additions_bundle_validation_rejects_missing_or_mutated_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "fixture-1.0-1.el9.noarch.rpm"
            key = root / "rocky.asc"
            artifact.write_bytes(b"rpm")
            key.write_bytes(b"key")
            lock = {
                "schema_version": 1,
                "virtualbox_version": "7.2.18r175117",
                "target": {
                    "architecture": "x86_64",
                    "os": "rocky-9.8",
                    "kernel_release": "5.14.0-fixture.x86_64",
                },
                "guest_additions": {
                    "version": "7.2.18",
                    "revision": 175117,
                    "iso": {
                        "file": "VBoxGuestAdditions_7.2.18.iso",
                        "sha256": "a" * 64,
                        "url": "https://download.virtualbox.org/virtualbox/7.2.18/VBoxGuestAdditions_7.2.18.iso",
                        "windows_path": r"C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso",
                        "wsl_path": "/mnt/c/Program Files/Oracle/VirtualBox/VBoxGuestAdditions.iso",
                    },
                },
                "rocky_repositories": {
                    "AppStream": "https://dl.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/Packages"
                },
                "rpm_signing_key": {
                    "file": "rocky.asc",
                    "fingerprint": "21CB256AE16FC54C6E652949702D426D350D275D",
                    "sha256": GUEST_ADDITIONS.digest(key),
                    "url": "https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9",
                },
                "required_packages": ["fixture"],
                "rpms": [{
                    "file": artifact.name,
                    "repository": "AppStream",
                    "sha256": GUEST_ADDITIONS.digest(artifact),
                }],
            }
            manifest = GUEST_ADDITIONS.manifest_from_lock(lock)
            manifest_path = root / "manifest.json"
            GUEST_ADDITIONS.write_json(manifest_path, manifest)
            lock["approved_manifest_sha256"] = GUEST_ADDITIONS.digest(manifest_path)
            checked = GUEST_ADDITIONS.checked_lock(lock)
            self.assertEqual(1, GUEST_ADDITIONS.validate_bundle(root, checked)["rpm_count"])
            artifact.write_bytes(b"mutated")
            with self.assertRaisesRegex(ValueError, "integrity"):
                GUEST_ADDITIONS.validate_bundle(root, checked)
            artifact.unlink()
            with self.assertRaisesRegex(ValueError, "member"):
                GUEST_ADDITIONS.validate_bundle(root, checked)

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

    def test_root_uid_proof_accepts_only_exact_direct_root_output(self):
        for stdout in ("0", "0\n"):
            with self.subTest(stdout=stdout):
                self.assertTrue(
                    PRIVILEGE.root_uid_proof(stdout, ansible_callback=False)
                )
        for stdout in ("1000\n", "uid=0", "foo 0", "0 foo", ""):
            with self.subTest(stdout=stdout):
                self.assertFalse(
                    PRIVILEGE.root_uid_proof(stdout, ansible_callback=False)
                )

    def test_root_uid_proof_accepts_exact_ansible_callback_output(self):
        observed = (
            "ecommerce-mgmt-test-rke2-4g | CHANGED | rc=0 | (stdout) 0"
        )
        self.assertTrue(
            PRIVILEGE.root_uid_proof(observed, ansible_callback=True)
        )
        self.assertTrue(
            PRIVILEGE.root_uid_proof(
                "host | SUCCESS | rc=0 | (stdout) 0\n",
                ansible_callback=True,
            )
        )
        for stdout in (
            "host | CHANGED | rc=0 | (stdout) 1000",
            "host | FAILED | rc=1 | (stdout) 0",
            "foo 0",
        ):
            with self.subTest(stdout=stdout):
                self.assertFalse(
                    PRIVILEGE.root_uid_proof(stdout, ansible_callback=True)
                )

    def test_root_proofs_require_zero_sample_rc(self):
        samples = {
            "sudo_n_id": [{"rc": 0, "stdout": "0\n"}],
            "ansible_become_id": [
                {"rc": 1, "stdout": "host | SUCCESS | rc=0 | (stdout) 0"}
            ],
        }
        self.assertFalse(PRIVILEGE.root_proofs_pass(samples))

    def test_root_proofs_reject_missing_samples(self):
        self.assertFalse(
            PRIVILEGE.root_proofs_pass(
                {"sudo_n_id": [], "ansible_become_id": []}
            )
        )

    def test_role_timing_extracts_exact_phase_and_total_durations(self):
        timing = ROLE_TIMING.parse_role_timing(self.role_log())
        self.assertEqual(40.0, timing["role_total_seconds"])
        self.assertEqual(
            {
                "controller_validation_seconds": 5.0,
                "transfer_seconds": 10.0,
                "post_transfer_validation_seconds": 4.0,
                "rpm_signature_validation_seconds": 6.0,
                "rpm_key_import_seconds": 2.0,
                "dnf_install_seconds": 8.0,
            },
            timing["phases"],
        )

    def test_role_timing_distinguishes_absent_task_from_zero_duration(self):
        log = self.role_log().replace(
            "2026-09-22 10:00:06,000 p=123 u=dev n=ansible INFO| "
            "TASK [mgmt_offline_artifacts : Transfer approved bundle over existing SSH access] *****\n",
            "",
        )
        timing = ROLE_TIMING.parse_role_timing(log)
        self.assertIsNone(timing["phases"]["transfer_seconds"])

        zero_log = self.role_log().replace(
            "2026-09-22 10:00:16,000 p=123 u=dev n=ansible INFO| "
            "TASK [mgmt_offline_artifacts : Create local validator directory] *****",
            "2026-09-22 10:00:06,000 p=123 u=dev n=ansible INFO| "
            "TASK [mgmt_offline_artifacts : Create local validator directory] *****",
        )
        zero_timing = ROLE_TIMING.parse_role_timing(zero_log)
        self.assertEqual(0.0, zero_timing["phases"]["transfer_seconds"])

    def test_role_timing_rejects_ambiguous_target_task(self):
        duplicate = self.role_log().replace(
            "2026-09-22 10:00:40,000 p=123 u=dev n=ansible INFO| PLAY RECAP *****",
            "2026-09-22 10:00:39,000 p=123 u=dev n=ansible INFO| "
            "TASK [mgmt_offline_artifacts : Transfer approved bundle over existing SSH access] *****\n"
            "2026-09-22 10:00:40,000 p=123 u=dev n=ansible INFO| PLAY RECAP *****",
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            ROLE_TIMING.parse_role_timing(duplicate)

    def test_role_timing_requires_log_and_rejects_bundle_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                ROLE_TIMING.parse_log(root / "missing.log")
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "payload").write_bytes(b"approved")
            (bundle / "link").symlink_to(bundle / "payload")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                ROLE_TIMING.bundle_inventory(bundle)

    def test_transport_metrics_use_real_log_path_and_canonical_runtime_source(self):
        contract = (FIXTURE / "contract.yml").read_text(encoding="utf-8")
        role_test = (FIXTURE / "test.yml").read_text(encoding="utf-8")
        self.assertIn(
            "platform/ansible/tests/mgmt_offline_vm/role_timing.py",
            contract,
        )
        self.assertIn("role_timing.py", role_test)
        self.assertIn("actual-role-live.log", role_test)
        self.assertIn("transport-metrics.json", role_test)
        self.assertIn("transport-metrics-replay.json", role_test)
        self.assertIn("test-attempt.json", role_test)
        self.assertIn(".cold_trial", role_test)
        self.assertNotIn("mgmt_offline_transport_metrics is defined", role_test)

    def test_transport_measurement_preserves_offline_cryptographic_gates(self):
        role = (
            ROOT / "platform/ansible/roles/mgmt_offline_artifacts/tasks/main.yml"
        ).read_text(encoding="utf-8")
        for task_name in ROLE_TIMING.PHASE_TASKS.values():
            self.assertIn(task_name, role)
        self.assertIn("Transfer approved bundle over existing SSH access", role)
        self.assertLess(
            role.index("Transfer approved bundle over existing SSH access"),
            role.index("Verify transferred bytes before package installation"),
        )
        self.assertIn("--manifest-sha256", role)
        self.assertIn("--rpm-metadata-check", role)
        self.assertIn("--rpm-signature-check", role)
        self.assertIn("disablerepo: '*'", role)
        self.assertIn("disable_gpg_check: false", role)

    def test_role_timing_metrics_are_bounded_and_dependency_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "one").write_bytes(b"123")
            nested = bundle / "nested"
            nested.mkdir()
            (nested / "two").write_bytes(b"4567")
            metrics = ROLE_TIMING.build_metrics(self.role_log(), bundle)
        self.assertEqual(1, metrics["schema_version"])
        self.assertEqual({"file_count": 2, "bytes": 7}, metrics["bundle"])
        self.assertAlmostEqual(
            round(7 / (1024 * 1024) / 10, 6),
            metrics["transfer_mib_per_second"],
        )
        self.assertEqual(25.0, metrics["transfer_share_percent"])
        self.assertEqual(
            {
                "schema_version",
                "role_total_seconds",
                "bundle",
                "phases",
                "transfer_mib_per_second",
                "transfer_share_percent",
            },
            set(json.loads(json.dumps(metrics))),
        )


if __name__ == "__main__":
    unittest.main()
