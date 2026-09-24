import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "architecture.lock.yaml"
MACHINE_LOCK = ROOT / "config/contracts/machine-image-lock.yaml"
TOOLCHAIN_LOCK = ROOT / "config/contracts/toolchain-lock.json"
CAPABILITIES = ROOT / "config/toolchain/capabilities.json"
PACKER = ROOT / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"
VAGRANTFILE = ROOT / "platform/vagrant/rocky-image-smoke/Vagrantfile"
WINDOWS = ROOT / "scripts/windows"


class WindowsPackerPipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.architecture = yaml.safe_load(ARCHITECTURE.read_text(encoding="utf-8"))
        cls.machine = yaml.safe_load(MACHINE_LOCK.read_text(encoding="utf-8"))
        cls.toolchain = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
        cls.capabilities = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
        cls.packer = PACKER.read_text(encoding="utf-8")
        cls.vagrant = VAGRANTFILE.read_text(encoding="utf-8")
        cls.preflight = (WINDOWS / "packer-preflight.ps1").read_text(encoding="utf-8")
        cls.build = (WINDOWS / "build-rocky-image.ps1").read_text(encoding="utf-8")
        cls.qualify = (WINDOWS / "qualify-rocky-image.ps1").read_text(encoding="utf-8")
        cls.release = (WINDOWS / "release-rocky-image.ps1").read_text(encoding="utf-8")
        cls.module = (WINDOWS / "RockyImagePipeline.psm1").read_text(encoding="utf-8")

    def test_one_responsibility_has_one_canonical_authority(self):
        pipeline = self.architecture["tooling"]["local_vm_image_pipeline"]
        profile = pipeline["profiles"]["windows"]
        self.assertEqual("one-responsibility-one-authority", pipeline["principle"])
        self.assertEqual("packer", profile["image_builder"]["authority"])
        self.assertEqual("virtualbox", profile["hypervisor"]["authority"])
        self.assertEqual("vagrant", profile["vm_lifecycle_and_smoke_test"]["authority"])
        self.assertEqual("ansible", pipeline["guest_configuration"]["authority"])
        self.assertEqual("powershell", profile["host_orchestration"]["authority"])
        self.assertEqual("make", pipeline["repository_entrypoint"]["authority"])
        self.assertEqual("wsl2", profile["developer_environment"])
        self.assertEqual("forbidden", pipeline["rules"]["duplicate_authority"])
        self.assertEqual("forbidden", pipeline["rules"]["packer_in_wsl2"])

    def test_windows_host_tools_are_exact_and_checksum_locked(self):
        expected = {
            "packer": (
                "1.16.1",
                "48e9b25ecf807959a1dcb9aa9b074e6fcd08c7b7ed89803538647c5873dbc95b",
            ),
            "virtualbox": (
                "7.2.18",
                "aae27200546a21b9b7dc11cfc42bd04802329a29f69ae0ada55682715a389d8d",
            ),
            "vagrant": (
                "2.4.9",
                "3bdd967927705872a70c7c98e0576afd5acd9dd73b527695f4d9dd75dd26cbe3",
            ),
        }
        for name, (version, checksum) in expected.items():
            lifecycle = self.toolchain["tool_lifecycle"]["active"][name]
            tool = self.toolchain["tools"][name]
            self.assertEqual("windows-host", lifecycle["provision"]["type"])
            self.assertEqual(["windows/amd64"], tool["platforms"])
            self.assertFalse(tool["install"]["automatic"])
            self.assertEqual(version, self.toolchain["versions"][tool["version_ref"]])
            self.assertEqual(checksum, self.toolchain["versions"][tool["sha256_ref"]])
            self.assertRegex(checksum, r"^[0-9a-f]{64}$")
            self.assertNotRegex(
                tool["artifact"]["url"], r"/(latest|main|master|rolling)/"
            )

    def test_packer_is_not_a_second_wsl_toolchain(self):
        names = {item["name"] for item in self.capabilities["capabilities"]}
        self.assertNotIn("packer", names)
        self.assertNotIn("packer", self.capabilities["provision_owners"])
        lifecycle = self.toolchain["tool_lifecycle"]["active"]["packer"]
        self.assertNotEqual("ansible", lifecycle["provision"]["type"])
        ansible = (
            ROOT / "platform/ansible/roles/developer_toolchain/tasks/main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("Remove superseded WSL Packer installation", ansible)
        self.assertIn("local_bin }}/packer", ansible)

    def test_packer_source_and_plugins_are_exact(self):
        source = self.machine["packer_image"]["source"]
        self.assertEqual("10.2", self.machine["packer_image"]["os"]["version"])
        self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn('iso_checksum  = "sha256:${var.iso_checksum}"', self.packer)
        for plugin, version in {
            "virtualbox": "1.1.5",
            "qemu": "1.1.6",
            "vagrant": "1.1.7",
        }.items():
            block = re.search(
                rf"{plugin}\s*=\s*\{{(?P<body>.*?)\n\s*\}}", self.packer, re.DOTALL
            )
            self.assertIsNotNone(block)
            self.assertIn(f'version = "= {version}"', block.group("body"))
        self.assertIn("artifact_dir", self.packer)
        self.assertIn("ecommerce-rocky-10-2-build-${var.image_profile}", self.packer)

    def test_build_qualification_and_release_are_separate(self):
        self.assertNotIn("qualify-rocky-image.ps1", self.build)
        self.assertNotIn("build-rocky-image.ps1", self.qualify)
        self.assertNotIn("packer build", self.release)
        self.assertIn("qualification.json", self.release)
        self.assertIn("release.json", self.release)
        self.assertIn("remote_publication = 'NOT_PERFORMED'", self.release)
        stages = self.machine["packer_image"]["local_pipeline"]["stages"]
        self.assertEqual(["preflight", "build", "qualification", "release"], stages)

    def test_make_delegates_explicit_windows_targets_to_repoctl_bridge(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        repoctl = (ROOT / "scripts/repoctl.py").read_text(encoding="utf-8")
        for target in (
            "image-rocky-windows-preflight",
            "image-rocky-windows-build",
            "image-rocky-windows-qualify",
            "image-rocky-windows-release",
        ):
            self.assertIn(f"{target}:", makefile)
            self.assertIn(f"scripts/repoctl.py {target}", makefile)
        self.assertIn("image-rocky-preflight: image-rocky-windows-preflight", makefile)
        self.assertIn('["wslpath", "-w", str(ROOT)]', repoctl)
        self.assertIn("windows_image_pipeline", repoctl)
        self.assertIn("WindowsPowerShell/v1.0/powershell.exe", repoctl)
        primitives = {
            entry["command"] for entry in self.capabilities["platform_primitives"]
        }
        self.assertIn("wslpath", primitives)
        self.assertIn(
            "wslpath", self.capabilities["gate_requirements"]["image-windows"]
        )

    def test_preflight_is_read_only_and_fails_closed(self):
        for executable in ("packer.exe", "VBoxManage.exe", "vagrant.exe"):
            self.assertIn(executable, self.preflight)
        self.assertIn("version mismatch", self.preflight)
        self.assertIn("exit 1", self.preflight)
        self.assertNotIn("packer build", self.preflight)
        self.assertNotIn("vagrant up", self.preflight)
        self.assertNotIn("startvm", self.preflight.lower())
        self.assertIn("competing Packer executable exists in WSL2", self.preflight)

    def test_all_external_processes_and_retries_are_bounded(self):
        self.assertIn("TimeoutSeconds", self.module)
        self.assertIn("WaitForExit($TimeoutSeconds * 1000)", self.module)
        self.assertIn("-TimeoutSeconds 60", self.module)
        self.assertIn(") -TimeoutSeconds 300", self.build)
        self.assertIn("taskkill.exe", self.module)
        self.assertIn("$attempt -le 12", self.qualify)
        self.assertIn("Start-Sleep -Seconds 5", self.qualify)
        self.assertNotRegex(
            self.build + self.qualify,
            r"while\s*\(\s*\$true\s*\)|for\s*\(\s*;;",
        )

    def test_build_wsl_process_calls_only_use_supported_parameters(self):
        calls = re.findall(
            r"Invoke-WslProcess\b.*?(?=\n\s*Assert-ProcessSuccess)",
            self.build,
            re.DOTALL,
        )
        self.assertEqual(2, len(calls))
        for call in calls:
            self.assertNotIn("-WorkingDirectory", call)

    def test_vagrant_only_owns_lifecycle_and_smoke_transport(self):
        self.assertIn("config.vm.box", self.vagrant)
        self.assertIn('config.ssh.username = "packer"', self.vagrant)
        self.assertIn('vm.customize ["modifyvm"', self.vagrant)
        self.assertNotIn("config.vm.provision", self.vagrant)
        self.assertNotIn("ansible", self.vagrant.lower())
        self.assertIn("vagrant", self.qualify.lower())
        self.assertIn("destroy", self.qualify.lower())
        self.assertIn("box', 'remove'", self.qualify)

    def test_cleanup_is_owned_and_ephemeral_key_is_destroyed(self):
        self.assertIn("Remove-OwnedVirtualMachine", self.build)
        self.assertIn("Remove-OwnedVirtualMachine", self.qualify)
        self.assertIn("InitialMachines", self.module)
        self.assertIn(
            "Refusing cleanup of VM that existed before this run", self.module
        )
        self.assertIn("Remove-SafeTree", self.build)
        self.assertIn("Remove-SafeTree", self.qualify)
        self.assertIn("ReparsePoint", self.module)
        self.assertIn("key_cleanup = 'NOT_EXECUTED'", self.qualify)
        self.assertIn("ephemeral_key_absent", self.release)

    def test_json_and_powershell_sources_are_utf8_safe(self):
        for path in sorted(WINDOWS.glob("*.ps*")):
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            self.assertNotIn("\ufeff", text)
            self.assertFalse(
                any(0xD800 <= ord(character) <= 0xDFFF for character in text)
            )
        self.assertIn("UTF8Encoding($false)", self.module)
        self.assertIn("ConvertTo-Json", self.module)
        self.assertIn("Set-PipelineUtf8", self.preflight)

    def test_pipeline_introduces_no_node_or_shell_automation(self):
        pipeline_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [PACKER, VAGRANTFILE, *sorted(WINDOWS.glob("*.ps*"))]
        ).lower()
        self.assertNotIn("node.exe", pipeline_text)
        self.assertNotIn("npm ", pipeline_text)
        self.assertNotIn("pnpm ", pipeline_text)
        self.assertEqual([], list((ROOT / "platform/packer/rocky-10.2").rglob("*.sh")))

    def test_runtime_evidence_cannot_be_predeclared_pass(self):
        for source in (self.build, self.qualify, self.release):
            self.assertIn("status = 'FAIL'", source)
            self.assertIn("NOT_EXECUTED", source)
        workflow = yaml.safe_load(
            (ROOT / "config/contracts/qualification-execution-policy.yaml").read_text(
                encoding="utf-8"
            )
        )["workflows"]["rocky_image_virtualbox"]
        self.assertEqual("make image-rocky-windows-release", workflow["entrypoint"])
        self.assertFalse(workflow["merge_authoritative"])


if __name__ == "__main__":
    unittest.main()
