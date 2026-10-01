"""Read-only checks for the native smoke UAC bootstrap boundary."""

import base64
import gzip
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import exact_pr_binding
import repoctl


CAMPAIGN = "20260929T163821Z-9da62296f3d5"
SHA = "a" * 40
BASE_SHA = "b" * 40
VM_ID = "e80d60f3-a12e-4734-a654-0cd24dce0fa1"
REPO_WINDOWS = "\\\\wsl.localhost\\Ubuntu-24.04\\home\\dev\\ecommerce-1"
GH_PIN = (
    "/home/dev/.local/share/ecommerce-1/tools/gh-2.101.0/bin/gh",
    "2.101.0",
    "e" * 64,
)


class NativeBootBootstrapTests(unittest.TestCase):
    def _source(self, action="Prepare"):
        binding = exact_pr_binding.ExactPRBinding(
            "dst-red-Wire/ecommerce-1", 170, "main", BASE_SHA,
            "fix/vm-lifecycle-runtime-proof", SHA)
        reviewed = action != "Recover"
        return repoctl._native_bootstrap_script(
            action, CAMPAIGN, SHA, "Ubuntu-24.04", REPO_WINDOWS,
            VM_ID if reviewed else "", binding if reviewed else None,
            GH_PIN if reviewed else None,
            runner_digests={name: "f" * 64 for name in repoctl._NATIVE_UAC_RUNNER_NAMES},
            trusted_root="/home/dev/ecommerce-1", qualification_witness="d" * 64)

    def test_credential_boundary_and_command_length(self):
        source = self._source()
        command = repoctl._native_boot_elevation_command(
            Path("powershell.exe"), source)
        self.assertEqual(command[-2], "-EncodedCommand")
        self.assertLess(len(" ".join(command)), 32767)
        loader = base64.b64decode(command[-1]).decode("utf-16-le")
        self.assertIn("[ScriptBlock]::Create", loader)
        packed = re.search(r"FromBase64String\('([^']+)'\)", loader)
        self.assertIsNotNone(packed)
        self.assertEqual(gzip.decompress(base64.b64decode(packed.group(1))).decode("utf-8"),
                         source)
        self.assertIn("Start-Process -FilePath $powershell -Verb RunAs", source)
        self.assertIn("exit $child.ExitCode", source)
        self.assertIn("[IO.File]::Create($target,4096", source)
        self.assertIn("Get-GitBlobSha1", source)
        self.assertIn("Assert-PublishedHead", source)
        self.assertIn("Get-FileHash -LiteralPath $target -Algorithm SHA256", source)
        for name in repoctl._NATIVE_UAC_RUNNER_NAMES:
            self.assertIn(f"'{name}'", source)
        self.assertLess(source.index("protected runner SHA-256 manifest differs"),
                        source.index("& $runner -Action SelfTest"))
        self.assertIn("$prNumber = '170'", source)
        self.assertIn("$prBaseSha = '" + BASE_SHA + "'", source)
        self.assertIn("$pr.head.ref -cne $prBranch", source)
        self.assertIn("$pr.base.sha -cne $prBaseSha", source)
        self.assertNotIn("'pr','view'", source)
        self.assertIn("'/usr/bin/git'", source)
        self.assertNotIn("'/usr/bin/gh'", source)
        self.assertIn("$g = '" + GH_PIN[0] + "'", source)
        self.assertIn("$v = '2.101.0'", source)
        self.assertIn("$d = '" + GH_PIN[2] + "'", source)
        self.assertIn("'/usr/bin/sha256sum',$g", source)
        self.assertIn("-PinnedGhPath $g", source)
        self.assertIn("-PinnedGhVersion $v", source)
        self.assertIn("-PinnedGhSha256 $d", source)
        self.assertIn("-PrNumber $prNumber", source)
        self.assertIn("-PrBaseSha $prBaseSha", source)
        self.assertLess(source.index("Get-GitBlobSha1 -Bytes"),
                        source.index("& $runner -Action Prepare"))
        self.assertLess(source.index("Assert-PublishedHead\nAssert-CurrentAuthority\n$runner"),
                        source.index("& $runner -Action Prepare"))
        reviewed = source.split("if ($action -in @('Prepare','SelfTest')) {", 1)[1]
        self.assertLess(reviewed.index("Assert-CurrentAuthority\n$bootstrap"),
                        reviewed.index("[IO.File]::ReadAllBytes($source)"))
        self.assertIn("'--qualification-sha256',$qualificationWitness", source)
        self.assertIn("'--action','Verify'", source)
        self.assertLess(source.index("& $runner -Action SelfTest"),
                        source.index("& $runner -Action Prepare"))
        self.assertIn("-ExpectedVmId $expectedVmId", source)

    def test_reboot_and_recover_use_protected_runner_without_network(self):
        for action in ("Reboot", "Recover"):
            with self.subTest(action=action):
                source = self._source(action)
                branch = source.split("else {\nAssert-Protected -Path $shadow", 1)[1]
                self.assertIn("Assert-Protected -Path $runner -Directory $false", branch)
                self.assertIn("& $runner -Action $action", branch)
                self.assertNotIn("Assert-PublishedHead", branch)
                if action == "Reboot":
                    self.assertEqual(branch.count("Assert-CurrentAuthority"), 2)
                    self.assertLess(branch.rindex("Assert-CurrentAuthority"),
                                    branch.index("& $runner -Action $action"))
                else:
                    self.assertIn("if ($action -eq 'Reboot') { Assert-CurrentAuthority }", branch)
                self.assertLess(branch.index("Assert-ShadowRunnerBytes -RunnerRoot"),
                                branch.index("& $runner -Action $action"))

    def test_shadow_manifest_property_count_on_windows_powershell(self):
        exe = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        if not Path(exe).exists():
            self.skipTest("Windows PowerShell 5.1 is unavailable")
        lines = [line.strip() for line in self._source("Reboot").splitlines()
                 if "runner_files.PSObject.Properties" in line and "-ne 7" in line]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith(") {"))
        condition = lines[0][:-3]
        seven = json.dumps({"runner_files": {f"file{i}": "digest" for i in range(7)}})
        six = json.dumps({"runner_files": {f"file{i}": "digest" for i in range(6)}})
        eight = json.dumps({"runner_files": {f"file{i}": "digest" for i in range(8)}})
        script = (
            "$stored=ConvertFrom-Json -InputObject '" + seven + "';"
            "if (" + condition + ") { exit 1 };"
            "$stored=ConvertFrom-Json -InputObject '" + six + "';"
            "if (-not (" + condition + ")) { exit 2 };"
            "$stored=ConvertFrom-Json -InputObject '" + eight + "';"
            "if (-not (" + condition + ")) { exit 3 }; exit 0"
        )
        result = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", script],
            text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_self_test_uses_attested_uac_bootstrap(self):
        source = self._source("SelfTest")
        self.assertIn("Assert-PublishedHead", source)
        self.assertIn("& $runner -Action SelfTest", source)
        self.assertIn("if ($action -eq 'Prepare') {", source)
        command = repoctl._native_boot_elevation_command(Path("powershell.exe"), source)
        self.assertLess(len(subprocess.list2cmdline(command)), 32767)

    def test_prepare_rejects_missing_or_mismatched_binding(self):
        for binding in (
            None,
            exact_pr_binding.ExactPRBinding(
                "dst-red-Wire/ecommerce-1", 170, "main", BASE_SHA,
                "fix/vm-lifecycle-runtime-proof", "c" * 40),
        ):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                repoctl._native_bootstrap_script(
                    "Prepare", CAMPAIGN, SHA, "Ubuntu-24.04", REPO_WINDOWS,
                    VM_ID, binding, GH_PIN)

    def test_prepare_rejects_missing_or_invalid_managed_gh(self):
        binding = exact_pr_binding.ExactPRBinding(
            "dst-red-Wire/ecommerce-1", 170, "main", BASE_SHA,
            "fix/vm-lifecycle-runtime-proof", SHA)
        for pin in (None, ("/usr/bin/gh", "2.45.0", "e" * 64),
                    (GH_PIN[0], "bad-version", GH_PIN[2]),
                    (GH_PIN[0], GH_PIN[1], "bad-digest")):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                repoctl._native_bootstrap_script(
                    "Prepare", CAMPAIGN, SHA, "Ubuntu-24.04", REPO_WINDOWS,
                    VM_ID, binding, pin)

    def test_bootstrap_parses_in_windows_powershell(self):
        parser = (
            "$tokens=$null;$errors=$null;"
            "$null=[System.Management.Automation.Language.Parser]::ParseInput("
            "[Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors);"
            "if($errors.Count -gt 0){$errors|ForEach-Object{Write-Error $_.Message};exit 1};exit 0"
        )
        for exe in ("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                    "/mnt/c/Program Files/PowerShell/7/pwsh.exe"):
            if not Path(exe).exists():
                continue
            for action in ("Prepare", "Reboot", "Recover", "SelfTest"):
                with self.subTest(exe=exe, action=action):
                    result = subprocess.run(
                        [exe, "-NoProfile", "-NonInteractive", "-Command", parser],
                        input=self._source(action), text=True, capture_output=True,
                        timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_encoded_loader_runs_only_its_embedded_source(self):
        exe = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        if not Path(exe).exists():
            self.skipTest("Windows PowerShell is unavailable")
        payload = "[Console]::WriteLine('NATIVE-BOOT-LOADER-PASS')"
        command = repoctl._native_boot_elevation_command(Path(exe), payload)
        result = subprocess.run(command, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NATIVE-BOOT-LOADER-PASS", result.stdout)

    def test_program_files_parent_check_accepts_the_real_host_read_only(self):
        source = self._source()
        sid_values = source[source.index("$adminSid ="):source.index("$principal =")]
        functions = source[source.index("function Assert-Regular {"):
                           source.index("function Invoke-WslBounded {")]
        script = (
            "$env:PSModulePath='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules'\n"
            + sid_values + functions + "\nAssert-ProgramFiles\n")
        exe = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command",
             "Invoke-Expression ([Console]::In.ReadToEnd())"],
            input=script, text=True, errors="replace", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bootstrap_git_blob_normalization_matches_exact_object(self):
        source = self._source()
        function = source[source.index("function Get-GitBlobSha1 {"):
                          source.index("function Assert-PublishedHead {")]
        script = (
            function
            + "\n$bytes=[Text.Encoding]::UTF8.GetBytes(('hello'+[char]13+[char]10));"
            + "if ((Get-GitBlobSha1 -Bytes $bytes) -ne "
            + "'ce013625030ba8dba906f756967f9e9ca394464a') { exit 1 };"
            + "try { [void](Get-GitBlobSha1 -Bytes "
            + "([Text.Encoding]::UTF8.GetBytes(('hello'+[char]13)))); exit 2 }"
            + "catch { exit 0 }"
        )
        exe = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command",
             "Invoke-Expression ([Console]::In.ReadToEnd())"],
            input=script, text=True, errors="replace", capture_output=True,
            timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prepare_cli_requires_explicit_vm_id(self):
        result = subprocess.run(
            [sys.executable, str(repoctl.ROOT / "scripts/repoctl.py"),
             "lab-network-native-boot-prepare", "--campaign-id", CAMPAIGN],
            text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--expected-vm-id", result.stderr)
        with mock.patch.object(repoctl, "git") as git:
            git.return_value = ""
            self.assertNotEqual(repoctl.lab_network_native_boot(
                "Prepare", CAMPAIGN, "1111"), 0)

    def test_recover_uses_unique_persisted_source_sha(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shadow = root / f"{CAMPAIGN}-{SHA}"
            shadow.mkdir()
            (shadow / "native-boot.json").write_text(json.dumps({
                "source_sha": SHA, "campaign_id": CAMPAIGN,
                "shadow_root": repoctl._native_shadow_windows_path(shadow),
                "phase": "PREPARED", "vm_id": VM_ID, "expected_vm_id": VM_ID,
            }), encoding="utf-8")
            with mock.patch.object(repoctl, "NATIVE_SHADOW_BASE", root):
                self.assertEqual(
                    repoctl._native_boot_shadow_source_sha(CAMPAIGN, "Recover"), SHA)
                self.assertEqual(
                    repoctl._native_boot_shadow_source_sha(CAMPAIGN, "Reboot"), SHA)
                (shadow / "native-boot.json").write_text(json.dumps({
                    "source_sha": SHA, "campaign_id": CAMPAIGN,
                    "shadow_root": repoctl._native_shadow_windows_path(shadow),
                    "phase": "PREPARED", "vm_id": VM_ID,
                    "expected_vm_id": "11111111-1111-1111-1111-111111111111",
                }), encoding="utf-8")
                with self.assertRaises(ValueError):
                    repoctl._native_boot_shadow_source_sha(CAMPAIGN, "Recover")


if __name__ == "__main__":
    unittest.main()
