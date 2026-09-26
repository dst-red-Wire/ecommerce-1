import json
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "architecture.lock.yaml"
MACHINE_LOCK = ROOT / "config/contracts/machine-image-lock.yaml"
TOOLCHAIN_LOCK = ROOT / "config/contracts/toolchain-lock.json"
CAPABILITIES = ROOT / "config/toolchain/capabilities.json"
PACKER = ROOT / "platform/packer/rocky-10.2/rocky-10.2.pkr.hcl"
PACKER_VARIABLES = ROOT / "platform/packer/rocky-10.2/variables.pkr.hcl"
VAGRANTFILE = ROOT / "platform/vagrant/rocky-image-smoke/Vagrantfile"
WINDOWS = ROOT / "scripts/windows"
VALIDATOR_PATH = ROOT / "scripts/validate_guest_smoke_commands.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_guest_smoke_commands", VALIDATOR_PATH)
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


class WindowsPackerPipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.architecture = yaml.safe_load(ARCHITECTURE.read_text(encoding="utf-8"))
        cls.machine = yaml.safe_load(MACHINE_LOCK.read_text(encoding="utf-8"))
        cls.toolchain = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
        cls.capabilities = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
        cls.packer = PACKER.read_text(encoding="utf-8") + "\n" + PACKER_VARIABLES.read_text(
            encoding="utf-8"
        )
        cls.vagrant = VAGRANTFILE.read_text(encoding="utf-8")
        cls.preflight = (WINDOWS / "packer-preflight.ps1").read_text(encoding="utf-8")
        cls.build = (WINDOWS / "build-rocky-image.ps1").read_text(encoding="utf-8")
        cls.qualify = (WINDOWS / "qualify-rocky-image.ps1").read_text(encoding="utf-8")
        cls.release = (WINDOWS / "release-rocky-image.ps1").read_text(encoding="utf-8")
        cls.native = (WINDOWS / "native-vtx-cycle.ps1").read_text(encoding="utf-8")
        cls.native_launcher = (WINDOWS / "native-cycle-launch.ps1").read_text(encoding="utf-8")
        cls.startup_resume = (WINDOWS / "native-startup-resume.ps1").read_text(encoding="utf-8")
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

    def test_preparation_defers_firmware_probe_until_native_boot(self):
        self.assertIn(
            "-not $firmwareVirtualizationEnabled -and -not $PreparationOnly.IsPresent",
            self.preflight,
        )
        self.assertIn(
            "DEFERRED_TO_NATIVE_BOOT_RUNTIME_PROBE", self.preflight
        )
        self.assertIn("Get-VirtualBoxBackendFromLog", self.native)
        self.assertIn("NATIVE_VTX", self.native)
        self.assertIn("NEM", self.native)

    def test_native_boot_mutation_fails_early_without_administrator_token(self):
        self.assertIn("if ($Action -in @('Preflight', 'Prepare', 'Reboot', 'Recover', 'Cycle', 'Resume', 'Import', 'ProbeS4U', 'ProbeSystem') -and -not (Test-Administrator))", self.native)
        self.assertIn("BLOCKED_PRIVILEGE", self.native)
        self.assertNotIn("Invoke-ElevatedSelf", self.native)

    def test_system_startup_dry_run_has_bounded_state_and_no_mutation_path(self):
        source = self.startup_resume
        for phase in (
            "PREPARED", "BOOT_RESUME_ARMED", "NATIVE_BOOT_PENDING", "NATIVE_BOOTED",
            "CONTROLLER_START", "QUALIFICATION_RUNNING", "QUALIFICATION_COMPLETE",
            "RESTORE_PENDING", "RESTORED", "COMPLETE", "FAILED",
        ):
            self.assertIn(f"'{phase}'", source)
        for guard in (
            "New-ScheduledTaskTrigger -AtStartup", "-UserId 'SYSTEM'",
            "-LogonType ServiceAccount -RunLevel Highest", "Start-ScheduledTask -TaskName $TaskName",
            "Start-ScheduledTask -TaskName $PrerequisiteTaskName", "[IO.FileShare]::None",
            "Get-ScheduledTaskInfo", "LastTaskResult", "source_sha", "idempotent",
            "7.2.18r175117", "Get-HostMutationSnapshot", "bcd_mutated=$false",
        ):
            self.assertIn(guard, source)
        self.assertNotIn("/set hypervisorlaunchtype", source.lower())
        self.assertNotIn("Restart-Computer", source)
        self.assertNotIn("startvm", source.lower())
        self.assertNotIn("vagrant up", source.lower())

    def test_real_native_cycle_requires_proven_passwordless_startup_resume(self):
        source = self.native
        for guard in (
            "Assert-StartupDryRunProof", "Assert-S4UResumeProof",
            "Invoke-SystemRuntimeProbeTask", "PACKER_PLUGIN_PATH",
            "New-ScheduledTaskTrigger -AtStartup",
            "-UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest",
            "-LogonType S4U -RunLevel Highest",
            "repo_manifest_accessible", "[IO.FileShare]::None",
            "NATIVE_BOOT_PENDING", "QUALIFICATION_RUNNING", "RESTORE_PENDING",
            "Move-NativePhase -SourceSha $sourceSha",
            "Native startup state is inconsistent",
            "Normal-boot import failed closed",
            "Register-NativeWatchdogTask", "Invoke-NativeWatchdog",
            "Native task exceeded the 270-minute watchdog deadline",
            "Set-OneShotBootSequence -BootId $normalId",
        ):
            self.assertIn(guard, source)
        self.assertNotIn("BOOT_RESUME_ARCHITECTURE_NOT_READY", source)
        self.assertNotIn("-AtLogOn", source)
        self.assertNotIn("-LogonType Password", source)

        launcher = self.native_launcher
        self.assertIn("BLOCKED_PRIVILEGE", launcher)
        self.assertIn("GitHub PR #148 HEAD differs", launcher)
        self.assertLess(launcher.index("-Action PrepareDryRun"), launcher.index("-Action Cycle"))
        self.assertIn("BCD remains unchanged", launcher)

    def test_native_probe_reads_live_virtualbox_log_with_bounded_retry(self):
        self.assertIn("[IO.FileShare]::ReadWrite", self.native)
        self.assertIn("Read-SharedUtf8Text -Path $log", self.native)
        self.assertIn("$attempt -le 20", self.native)
        self.assertIn("shared VirtualBox log read self-test failed", self.native)

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
        self.assertIn("'variables.pkr.hcl'", self.build)

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
        self.assertIn("_windows_powershell_environment()", repoctl)
        self.assertIn(r"C:\Windows\system32\WindowsPowerShell\v1.0\Modules", repoctl)
        self.assertNotIn(r"C:\Program Files\PowerShell\7\Modules", repoctl)
        self.assertIn('environment["WSLENV"]', repoctl)
        primitives = {
            entry["command"] for entry in self.capabilities["platform_primitives"]
        }
        self.assertIn("wslpath", primitives)
        self.assertIn(
            "wslpath", self.capabilities["gate_requirements"]["image-windows"]
        )
        for target in (
            "image-rocky-windows-native-prepare",
            "image-rocky-windows-native-reboot",
            "image-rocky-windows-native-import",
            "image-rocky-windows-native-recover",
            "image-rocky-windows-native-self-test",
        ):
            self.assertIn(f"{target}:", makefile)
            self.assertIn(f'sub.add_parser("{target}")', repoctl)

    def test_native_vtx_cycle_is_one_shot_fail_closed_and_recoverable(self):
        cycle = self.machine["packer_image"]["local_pipeline"][
            "windows_native_vtx_cycle"
        ]
        self.assertEqual("C:/ecommerce-lab", cycle["lab_root"])
        self.assertEqual(1, cycle["max_native_boot_attempts"])
        self.assertEqual("native-vtx", cycle["native_boot"]["required_backend"])
        self.assertEqual("nem", cycle["native_boot"]["forbidden_backend"])
        for marker in (
            "bcdedit.exe",
            "'/export'",
            "'/copy'",
            "'/bootsequence'",
            "hypervisorlaunchtype",
            "vsmlaunchtype",
            "MAX_NATIVE_BOOT_ATTEMPTS=1",
            "FAIL_ALREADY_ATTEMPTED",
            "NATIVE_VTX",
            "Remove-NativeTask",
            "Set-OneShotBootSequence -BootId ([string]$prepared.normal_boot_id)",
            "Assert-ResultBinding",
            "Test-StagingManifest",
            "Invoke-EmergencyNativeReturn",
            "ExpectedManifestSha256",
            "transcript_sha256",
            "qualification_private_key_sha256",
        ):
            self.assertIn(marker, self.native)
        self.assertNotIn("/default", self.native.lower())
        self.assertIn("'/delete', $nativeId, '/f'", self.native)
        self.assertIn("Assert-NormalHostRestored", self.native)
        self.assertIn("Register-NormalResumeTask", self.native)
        self.assertIn("Restart-Computer -Force", self.native)
        self.assertLess(
            self.native.index("Set-OneShotBootSequence -BootId ([string]$prepared.normal_boot_id)"),
            self.native.rindex("Restart-Computer -Force"),
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
        self.assertIn("Win32_ComputerSystem", self.preflight)
        self.assertIn("Win32_Processor", self.preflight)
        self.assertIn("Native VT-x is unavailable", self.preflight)
        self.assertIn("NEM is forbidden by contract", self.preflight)

    def test_all_external_processes_and_retries_are_bounded(self):
        self.assertIn("TimeoutSeconds", self.module)
        self.assertIn("WaitForExit($TimeoutSeconds * 1000)", self.module)
        self.assertIn("-TimeoutSeconds 60", self.module)
        self.assertIn(") -TimeoutSeconds 300", self.build)
        self.assertIn("taskkill.exe", self.module)
        self.assertIn("$attempt -le 12", self.module)
        self.assertIn("while it is locked|VBOX_E_INVALID_OBJECT_STATE", self.module)
        self.assertIn("$remaining[$Name] -ne $current[$Name]", self.module)
        self.assertIn("Start-Sleep -Seconds 5", self.module)
        self.assertIn("$attempt -le 12", self.qualify)
        self.assertIn("Start-Sleep -Seconds 5", self.qualify)
        self.assertNotRegex(
            self.build + self.qualify,
            r"while\s*\(\s*\$true\s*\)|for\s*\(\s*;;",
        )

    def test_vagrant_ssh_timeout_remains_a_bounded_readiness_retry(self):
        for source in (self.native, self.qualify):
            self.assertIn("$attempt -le 12", source)
            self.assertIn("@('ssh', '-c', 'true') -TimeoutSeconds 60", source)
            self.assertIn('if ($_.Exception.Message -ne "Timed out after 60s: $vagrant") { throw }', source)
            self.assertIn('if ($attempt -lt 12)', source)

    def test_vagrant_guest_probe_timeout_is_named_and_retried_only_once(self):
        for source in (self.native, self.qualify):
            self.assertIn('$attempt -le 2', source)
            self.assertIn('timed out after 2 bounded attempts', source)
            self.assertIn('Start-Sleep -Seconds 5', source)
        self.assertIn('if ($_.Exception.Message -ne "Timed out after 120s: $Vagrant") { throw }', self.native)
        self.assertIn('if ($_.Exception.Message -ne "Timed out after ${TimeoutSeconds}s: $script:vagrant") { throw }', self.qualify)

    def test_disk_smoke_cannot_report_success_after_failed_size_check(self):
        self.assertIn('test "$size" -ge {0} && printf', self.native)
        self.assertIn('test "$available" -ge 1024 && printf', self.qualify)

    def test_guest_smoke_commands_are_literal_and_shell_syntax_valid(self):
        self.assertGreaterEqual(VALIDATOR.validate_guest_smoke_commands(), 36)

    def test_guest_smoke_preflight_rejects_host_interpolation_and_invalid_bash(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "native-vtx-cycle.ps1"
            with mock.patch.object(VALIDATOR, "WINDOWS_SOURCES", ((candidate, "Invoke-VagrantSmokeCommand", 1),)):
                candidate.write_text('Invoke-VagrantSmokeCommand -Command "test `$(uname -m)"\n', encoding="utf-8")
                with self.assertRaisesRegex(VALIDATOR.GuestSmokePreflightError, "PowerShell literal"):
                    VALIDATOR.validate_guest_smoke_commands()
                candidate.write_text("Invoke-VagrantSmokeCommand -Command 'if true; then'\n", encoding="utf-8")
                with self.assertRaisesRegex(VALIDATOR.GuestSmokePreflightError, "invalid guest shell syntax"):
                    VALIDATOR.validate_guest_smoke_commands()

    def test_native_prepare_runs_guest_command_preflight_before_staging(self):
        self.assertIn('scripts/validate_guest_smoke_commands.py', self.native)
        self.assertIn('scripts/validate_guest_smoke_commands.py', self.preflight)
        self.assertIn("$evidence.guest_smoke_commands = 'PASS'", self.preflight)
        self.assertIn("guest_smoke_commands = 'PASS'", self.native)
        self.assertLess(
            self.native.index("Assert-ProcessSuccess -Result $guestSmokePreflight"),
            self.native.index("foreach ($directory in @('bcd', 'staging'"),
        )
        linux = (ROOT / "scripts/linux_image_pipeline.py").read_text(encoding="utf-8")
        local_services = (ROOT / "scripts/local_services_qualification.py").read_text(encoding="utf-8")
        self.assertLess(linux.index("validate_guest_smoke_commands()", linux.index("def main()")), linux.index('if args.action == "preflight"'))
        self.assertLess(local_services.index("validate_guest_smoke_commands()", local_services.index("def main()")), local_services.index('if args.action == "assets"'))

    def test_process_failure_evidence_preserves_bounded_head_and_tail(self):
        self.assertIn("if ($detail.Length -gt 8000)", self.module)
        self.assertIn("$head = $detail.Substring(0, 2000)", self.module)
        self.assertIn(
            "$tail = $detail.Substring($detail.Length - 6000)", self.module
        )
        self.assertIn("bounded process output omitted", self.module)

    def test_build_records_complete_runtime_milestone_telemetry(self):
        for index in range(14):
            self.assertRegex(self.build, rf"T{index}_[A-Z_]+")
        self.assertIn("virtualbox-serial.log", self.build)
        self.assertIn("PACKER_LOG_PATH", self.build)
        self.assertIn("Packer telemetry is incomplete", self.build)
        self.assertIn("-OnPoll $observeProgress", self.build)
        self.assertIn("'controlvm'", self.module)
        self.assertIn("'poweroff'", self.module)

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
        self.assertIn('runtime.fetch("nic_type")', self.vagrant)
        self.assertNotIn("config.vm.provision", self.vagrant)
        self.assertNotIn("ansible", self.vagrant.lower())
        self.assertIn("vagrant", self.qualify.lower())
        self.assertIn("destroy", self.qualify.lower())
        self.assertIn("box', 'remove'", self.qualify)
        self.assertIn("$buildEvidence.resources.vcpus", self.qualify)
        self.assertIn("$buildEvidence.resources.memory_mib", self.qualify)
        self.assertNotIn("cpus = 2", self.qualify)

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

    def test_reviewed_security_and_release_evidence_are_fail_closed(self):
        for source in (self.qualify, self.native):
            self.assertIn('sudo -n test ! -e /root/.config/gh/hosts.yml', source)
            self.assertIn('sudo -n test ! -e /etc/rancher/rke2/config.yaml', source)
            self.assertIn('New-ImageSupplyChainEvidence', source)
        self.assertIn('Assert-ImageSupplyChainEvidence', self.release)
        self.assertIn('Assert-ImageSupplyChainEvidence', self.native)
        self.assertIn('package_manifest', self.release)
        self.assertIn('profile_inventory', self.release)
        self.assertIn('sbom', self.release)
        self.assertIn('$promotionStarted', self.build)
        self.assertIn('qualification key rollback failed', self.build)

    def test_image_entrypoints_share_governed_host_user_lock(self):
        policy = yaml.safe_load((ROOT / 'config/contracts/qualification-execution-policy.yaml').read_text(encoding='utf-8'))
        capability = policy['runtime_orchestration']['capabilities']['local-virtualization-serialization']
        self.assertTrue(capability['global_lock'])
        self.assertEqual('local-virtualization', capability['mutation_class'])
        controller = (ROOT / 'scripts/repoctl.py').read_text(encoding='utf-8')
        self.assertIn('workflow_capabilities=["local-virtualization-serialization"]', controller)
        self.assertIn('return image_phase_with_runtime(args.cmd', controller)

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
