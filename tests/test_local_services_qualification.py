import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/contracts/local-services-qualification.yaml"
RPM_LOCK = ROOT / "config/artifacts/local-services-rocky-10.2-packages.lock.json"
FIXTURE = ROOT / "platform/ansible/tests/local_services_vm"


class LocalServicesQualificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
        cls.rpm_lock = json.loads(RPM_LOCK.read_text(encoding="utf-8"))
        cls.orchestrator = (ROOT / "scripts/local_services_qualification.py").read_text(encoding="utf-8")
        cls.materializer = (ROOT / "scripts/materialize_local_service_assets.py").read_text(encoding="utf-8")
        cls.gitea = (ROOT / "platform/ansible/roles/local_gitea/tasks/main.yml").read_text(encoding="utf-8")
        cls.harbor = (ROOT / "platform/ansible/roles/local_harbor/tasks/main.yml").read_text(encoding="utf-8")

    def test_contract_is_local_subordinate_and_exact(self):
        self.assertEqual("exact-local-runtime-qualification", self.contract["status"])
        self.assertEqual("architecture.lock.yaml", self.contract["architecture_authority"])
        self.assertEqual("forbidden", self.contract["production_authority"])
        self.assertEqual("ansible", self.contract["runtime"]["owner"])
        self.assertEqual("virtualbox-linux", self.contract["runtime"]["controller"])
        self.assertFalse(self.contract["runtime"]["native_controller"]["wsl2_required_during_runtime"])
        self.assertRegex(self.contract["runtime"]["native_controller"]["oras_binary_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual("native-vtx", self.contract["runtime"]["required_virtualbox_backend"])
        self.assertEqual("BLOCKED_RUNTIME", self.contract["runtime"]["unavailable_classification"])
        self.assertEqual(1, self.contract["machine_image"]["sizing"]["simultaneous_active_service_vms"])
        self.assertEqual("destroy-after-qualification", self.contract["runtime"]["persistent_disks"])

    def test_active_hypervisor_blocks_service_vms_before_start(self):
        spec = importlib.util.spec_from_file_location("local_services_qualification", ROOT / "scripts/local_services_qualification.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        observed = json.dumps({"hypervisor_present": True, "firmware_virtualization_enabled": False})
        with patch.object(module.platform, "system", return_value="Linux"), patch.object(module.platform, "release", return_value="5.15-microsoft-standard-WSL2"), patch.object(module.Path, "is_file", return_value=True), patch.object(module.shutil, "which", return_value="/usr/bin/ssh"), patch.object(module, "run", return_value=type("Result", (), {"stdout": observed})()):
            result = module.runtime_capabilities()
        self.assertEqual("BLOCKED_RUNTIME", result["status"])
        self.assertEqual("NATIVE_VTX_UNAVAILABLE", result["virtualbox_backend"])
        self.assertTrue(result["hypervisor_present"])

    def test_native_controller_accepts_only_observed_exact_sha_without_nem(self):
        spec = importlib.util.spec_from_file_location("local_services_qualification", ROOT / "scripts/local_services_qualification.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        head = "a" * 40
        document = {
            "source_sha": head,
            "campaign_id": "b" * 32,
            "controller": "virtualbox-linux",
            "target_ip": self.contract["runtime"]["native_controller"]["host_only_service_ipv4"],
            "service_virtualbox_log_sha256": "d" * 64,
            "runtime": {
                "hypervisor_present": False,
                "hardware_virtualization": True,
                "virtualbox_backend": "NATIVE_VTX",
                "nem_detected": False,
                "virtualbox_log_sha256": "c" * 64,
            },
        }
        with patch.object(module.platform, "system", return_value="Linux"), patch.object(module.platform, "release", return_value="6.12.0-rocky"), patch.object(module, "is_virtualbox_guest", return_value=True):
            self.assertEqual(document["runtime"], module.validate_native_controller_input(document, head))
            for mutation in (
                {"controller": "wsl2"},
                {"source_sha": "d" * 40},
                {"runtime": {**document["runtime"], "nem_detected": True}},
                {"runtime": {**document["runtime"], "virtualbox_backend": "UNKNOWN"}},
                {"runtime": {**document["runtime"], "hypervisor_present": True}},
                {"runtime": {**document["runtime"], "virtualbox_log_sha256": None}},
            ):
                with self.subTest(mutation=mutation), self.assertRaises(module.RuntimeBlocked):
                    module.validate_native_controller_input({**document, **mutation}, head)
        with patch.object(module.platform, "system", return_value="Linux"), patch.object(module.platform, "release", return_value="5.15-microsoft-WSL2"):
            with self.assertRaises(module.RuntimeBlocked):
                module.validate_native_controller_input(document, head)
        with patch.object(module.platform, "system", return_value="Linux"), patch.object(module.platform, "release", return_value="6.12.0-rocky"), patch.object(module, "is_virtualbox_guest", return_value=False):
            with self.assertRaises(module.RuntimeBlocked):
                module.validate_native_controller_input(document, head)

    def test_gitea_harbor_and_oras_versions_are_exact(self):
        self.assertEqual("1.24.6", self.contract["gitea"]["version"])
        self.assertEqual("2.13.2", self.contract["harbor"]["version"])
        self.assertEqual("1.3.3", self.contract["oras"]["version"])
        self.assertEqual("digest-only", self.contract["oras"]["reference"])
        self.assertEqual("forbidden", self.contract["oras"]["mutable_pull"])
        text = CONTRACT.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)(?:^|:)latest(?:$|\s)")

    def test_all_external_assets_are_https_and_sha256_locked(self):
        assets = [self.contract["gitea"], self.contract["harbor"]]
        docker = self.contract["harbor"]["container_runtime"]
        assets.extend(docker["rpms"])
        assets.append(docker["signing_key"])
        for asset in assets:
            with self.subTest(asset=asset["filename"]):
                self.assertTrue((asset.get("source") or asset.get("url")).startswith("https://"))
                self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")

    def test_harbor_offline_images_have_registry_and_archive_identities(self):
        images = self.contract["harbor"]["images"]
        self.assertEqual(12, len(images))
        self.assertEqual(12, len({item["name"] for item in images}))
        for image in images:
            self.assertRegex(image["manifest_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(image["offline_config_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertIn("actual != expected", self.materializer)
        self.assertIn("Harbor offline image identities differ", self.materializer)

    def test_gitea_rpm_projection_is_complete_and_self_hashed(self):
        self.assertEqual("complete-minus-base-image", self.rpm_lock["dependency_closure"])
        self.assertEqual(["git"], self.rpm_lock["gitea"]["roots"])
        files = [item["file"] for item in self.rpm_lock["gitea"]["packages"]]
        self.assertEqual(len(files), len(set(files)))
        body = dict(self.rpm_lock["gitea"])
        approved = body.pop("approved_manifest_sha256")
        self.assertEqual(
            approved,
            hashlib.sha256((json.dumps(body, indent=2, sort_keys=True) + "\n").encode()).hexdigest(),
        )
        document = dict(self.rpm_lock)
        approved = document.pop("approved_manifest_sha256")
        self.assertEqual(
            approved,
            hashlib.sha256((json.dumps(document, indent=2, sort_keys=True) + "\n").encode()).hexdigest(),
        )

    def test_first_boot_access_has_no_shared_private_key(self):
        access = self.contract["machine_image"]["access"]
        self.assertEqual("NoCloud-Net", access["datasource"])
        self.assertEqual("runtime-generated-ephemeral", access["ssh_key"])
        self.assertEqual("forbidden", access["password_authentication"])
        self.assertEqual("forbidden", access["shared_private_key"])
        vagrant = (FIXTURE / "Vagrantfile").read_text(encoding="utf-8")
        self.assertIn("ds=nocloud-net;s=http://10.0.2.2:", vagrant)
        self.assertIn('host_ip: "127.0.0.1"', vagrant)
        self.assertIn('config.vm.communicator = "none"', vagrant)
        self.assertIn('"--nat-localhostreachable1", "on"', vagrant)
        self.assertIn('"--vrde", "off"', vagrant)

    def test_services_are_ansible_owned_and_default_deny(self):
        isolation = (ROOT / "platform/ansible/roles/local_service_isolation/templates/ecommerce-local-service.nft.j2").read_text(encoding="utf-8")
        self.assertIn("chain output", isolation)
        self.assertIn("chain forward", isolation)
        self.assertGreaterEqual(isolation.count("policy drop"), 3)
        self.assertNotIn('iifname "br-*" accept', isolation)
        self.assertIn('iifname "br-*" oifname "br-*" accept', isolation)
        self.assertIn("localpkg_gpgcheck=1", self.gitea)
        self.assertIn("localpkg_gpgcheck=1", self.harbor)
        self.assertIn("Verify exact Gitea runtime version", self.gitea)
        self.assertIn("no_log: true", self.gitea)
        self.assertIn("no_log: true", self.harbor)
        self.assertNotIn("validate_certs: false", self.harbor)

    def test_second_ansible_apply_requires_zero_reported_changes(self):
        spec = importlib.util.spec_from_file_location(
            "local_services_qualification", ROOT / "scripts/local_services_qualification.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            executable = runtime / ".venv/qualification/bin/ansible-playbook"
            executable.parent.mkdir(parents=True)
            executable.touch()
            recap = "PLAY RECAP\nlocal_service : ok=42 changed=0 unreachable=0 failed=0 skipped=3\n"
            completed = subprocess.CompletedProcess([], 0, recap, "")
            with patch.object(module, "ROOT", runtime), patch.object(module, "run", return_value=completed):
                self.assertEqual(
                    0, module.prove_second_apply(
                        ROOT / "platform/ansible/tests/local_services_vm/gitea.yml",
                        runtime / "inventory.json", {}, runtime,
                    ),
                )
                completed.stdout = recap.replace("changed=0", "changed=1")
                with self.assertRaisesRegex(module.QualificationError, "second Ansible apply changed 1"):
                    module.prove_second_apply(
                        ROOT / "platform/ansible/tests/local_services_vm/gitea.yml",
                        runtime / "inventory.json", {}, runtime,
                    )
                completed.stdout = "PLAY RECAP\n"
                with self.assertRaisesRegex(module.QualificationError, "recap is absent"):
                    module.prove_second_apply(
                        ROOT / "platform/ansible/tests/local_services_vm/gitea.yml",
                        runtime / "inventory.json", {}, runtime,
                    )

    def test_ansible_roles_can_converge_without_reapplying_firewall_or_post(self):
        isolation = (ROOT / "platform/ansible/roles/local_service_isolation/tasks/main.yml").read_text()
        self.assertIn("local_service_isolation_active.rc != 0", isolation)
        self.assertIn("local_service_isolation_template.changed", isolation)
        self.assertIn("local_gitea_repository_create.status == 201", self.gitea)
        self.assertIn("local_gitea_git_key_create.status == 201", self.gitea)
        self.assertIn("local_harbor_project_create.status == 201", self.harbor)

    def test_functional_proof_and_cleanup_are_explicit(self):
        for marker in (
            "repository_create", "push", "clone", "fetch", "sha_integrity",
            "pull_by_digest", "sha_match", "tamper_rejection",
            "STOPPED_DISK_PRESERVED",
        ):
            self.assertIn(marker, self.orchestrator)
        self.assertIn('"f" * 64', self.orchestrator)
        self.assertIn('vagrant(states["gitea"], "halt"', self.orchestrator)
        self.assertIn('vagrant(states["harbor"], "halt"', self.orchestrator)

    def test_windows_transport_is_owned_bounded_and_race_safe(self):
        transport = (FIXTURE / "transport.py").read_text(encoding="utf-8")
        self.assertIn('Path("/mnt/c/Users").resolve()', transport)
        self.assertIn('r"C:\\Program Files\\Vagrant\\bin\\vagrant.exe"', transport)
        self.assertIn('f"ipc-transport-{suffix}.ps1"', transport)
        self.assertIn("request_path.unlink(missing_ok=True)", transport)
        self.assertIn("bridge.unlink(missing_ok=True)", transport)
        self.assertIn('if ($r.mode -eq "backend")', transport)
        self.assertIn("Get-Content -Raw -LiteralPath (Join-Path $Matches.path 'VBox.log')", transport)

    def test_seed_server_is_hidden_bounded_and_noninteractive(self):
        seed = (ROOT / "scripts/windows/local-services-seed-server.ps1").read_text(encoding="utf-8")
        self.assertIn("-WindowStyle Hidden", seed)
        self.assertIn("-NonInteractive", seed)
        self.assertIn("[Net.IPAddress]::Loopback", seed)
        self.assertIn("Timed", seed.replace("timed", "Timed"))
        self.assertNotIn("read -r -p", seed)
        self.assertNotIn("Press Enter", seed)

    def test_canonical_entrypoints_exist(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        for target in ("local-services-assets", "local-services-qualify", "local-services-recover"):
            self.assertIn(f"{target}:", makefile)
            self.assertIn(f'args.cmd == "{target}"', repoctl)
        self.assertIn("image-rocky-linux-static-validate:", makefile)
        self.assertIn('linux_image_pipeline("static-validate")', repoctl)

    def test_no_tracked_shell_automation_was_added(self):
        self.assertEqual([], list(FIXTURE.rglob("*.sh")))
        for path in (
            ROOT / "scripts/local_services_qualification.py",
            ROOT / "scripts/materialize_local_service_assets.py",
            ROOT / "platform/ansible/tests/local_services_vm/transport.py",
        ):
            raw = path.read_bytes()
            self.assertEqual(raw, raw.decode("utf-8").encode("utf-8"))
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))


if __name__ == "__main__":
    unittest.main()
