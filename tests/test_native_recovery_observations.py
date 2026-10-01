"""Prospective native recovery observations; host commands are mocked."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/windows/LabNativeBoot.ps1").read_text(encoding="utf-8")
PS51 = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
PS7 = Path("/mnt/c/Program Files/PowerShell/7/pwsh.exe")


def function_source(name: str) -> str:
    start = SOURCE.index("function " + name + " {")
    end = SOURCE.find("\nfunction ", start + 1)
    return SOURCE[start:end if end >= 0 else len(SOURCE)]


def ps_run(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(PS51), "-NoProfile", "-NonInteractive", "-Command",
         "Invoke-Expression ([Console]::In.ReadToEnd())"],
        input="Set-StrictMode -Version Latest\n$ErrorActionPreference='Stop'\n" + source,
        text=True, errors="replace", capture_output=True, timeout=30,
    )


class NativeRecoveryObservationTests(unittest.TestCase):
    def test_full_runner_parses_in_both_windows_engines(self) -> None:
        command = (
            "$tokens=$null;$errors=$null;"
            "$null=[System.Management.Automation.Language.Parser]::ParseInput("
            "[Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors);"
            "if($errors.Count){$errors|ForEach-Object{Write-Error $_.Message};exit 1};exit 0"
        )
        for engine in (PS51, PS7):
            with self.subTest(engine=str(engine)):
                result = subprocess.run(
                    [str(engine), "-NoProfile", "-NonInteractive", "-Command", command],
                    input=SOURCE, text=True, errors="replace", capture_output=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def snapshot(self, *, fail_bcd: bool = False, fail_tasks: bool = False,
                 key_present: bool = False) -> subprocess.CompletedProcess[str]:
        source = r"""
$env:SystemRoot='C:\Windows'
$ResumeTaskName='Ecommerce-Network-Smoke-Native-Resume'
$WatchdogTaskName='Ecommerce-Network-Smoke-Native-Watchdog'
$ProbeTaskName='Ecommerce-Network-Smoke-Native-S4U-Probe'
$script:Calls=@()
function Invoke-BoundedProcess {
    param($FilePath,$Arguments,$TimeoutSeconds,$WorkingDirectory)
    $command=$Arguments -join ' '
    if ($command -notin @('/enum {current} /v','/enum {bootmgr} /v','/enum all /v','showvminfo retained-uuid --machinereadable')) {
        throw ('Unexpected or mutating command: '+$command)
    }
    $script:Calls+=@($command)
    return [pscustomobject]@{ ExitCode=@@EXIT@@; StdOut=$command; StdErr='' }
}
function Assert-ProcessSuccess {
    param($Result,$Operation)
    if ($Result.ExitCode -ne 0) { throw 'observer command failed' }
}
function Get-ScheduledTask {
    param($TaskPath,$ErrorAction)
    if ($ErrorAction -ne 'Stop') { throw 'Task enumeration must fail closed' }
    @@TASK_FAILURE@@
    return @(
        [pscustomobject]@{TaskName=$ProbeTaskName},
        [pscustomobject]@{TaskName='unrelated-task'},
        [pscustomobject]@{TaskName=$ResumeTaskName}
    )
}
function Get-NativeShadowRoot { param($Id,$Sha); return 'C:\audit-shadow' }
function Get-OptionalShadowItem {
    param($Path)
    if ($Path -cne 'C:\audit-shadow\identity\id_ed25519') { throw 'wrong identity observed' }
    @@KEY_RESULT@@
}
function Assert-RegularLabPath { param($Path,$Directory); if ($Directory) { throw 'wrong key type' } }
@@FUNCTION@@
try {
    $snapshot=Get-NativeRecoverySnapshot -Id 'campaign' -Sha 'sha' -VmId 'retained-uuid'
    @{ snapshot=$snapshot; calls=$script:Calls } | ConvertTo-Json -Depth 8 -Compress
}
catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
"""
        return ps_run(source.replace("@@FUNCTION@@", function_source("Get-NativeRecoverySnapshot"))
                      .replace("@@EXIT@@", "1" if fail_bcd else "0")
                      .replace("@@TASK_FAILURE@@", "throw 'task access denied'" if fail_tasks else "")
                      .replace("@@KEY_RESULT@@", "return [pscustomobject]@{FullName=$Path}" if key_present else "return $null"))

    def test_snapshot_observes_all_three_bcd_views_tasks_and_retained_vm(self) -> None:
        result = self.snapshot(key_present=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        snapshot = body["snapshot"]
        self.assertEqual(len(body["calls"]), 4)
        self.assertEqual(snapshot["bcd"]["bootmgr_stdout"], "/enum {bootmgr} /v")
        self.assertEqual(snapshot["native_tasks"], [
            "Ecommerce-Network-Smoke-Native-Resume",
            "Ecommerce-Network-Smoke-Native-S4U-Probe",
        ])
        self.assertIs(snapshot["private_key_present"], True)
        self.assertLessEqual(snapshot["observed_at"], snapshot["completed_at"])

    def test_snapshot_records_key_absence_without_reading_contents(self) -> None:
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIs(json.loads(result.stdout)["snapshot"]["private_key_present"], False)
        self.assertNotIn("ReadAll", function_source("Get-NativeRecoverySnapshot"))

    def test_observation_failure_never_becomes_absence(self) -> None:
        for kwargs, message in (({"fail_bcd": True}, "observer command failed"),
                                ({"fail_tasks": True}, "task access denied")):
            with self.subTest(kwargs=kwargs):
                result = self.snapshot(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_receipts_are_write_once(self) -> None:
        source = r"""
$script:SmokeRoot='C:\audit-shadow'
function Assert-ShadowBoundary {}
function Ensure-ShadowDirectory { param($Path) }
function Get-OptionalShadowItem { param($Path); return [pscustomobject]@{FullName=$Path} }
function Write-ProtectedNativeJson { throw 'must not overwrite an existing receipt' }
@@FUNCTION@@
try { Write-NativeRecoveryRecord -Name capture -Record @{}; exit 2 }
catch {
    if ($_.Exception.Message -notlike '*write-once*') { throw }
}
"""
        result = ps_run(source.replace("@@FUNCTION@@", function_source("Write-NativeRecoveryRecord")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_capture_is_not_backfilled(self) -> None:
        source = r"""
function Assert-RegularLabPath { throw 'legacy path must not be read or created' }
@@FUNCTION@@
if ($null -ne (Get-NativeRecoveryCapture -State ([pscustomobject]@{phase='RECOVERED'}))) { exit 2 }
"""
        result = ps_run(source.replace("@@FUNCTION@@", function_source("Get-NativeRecoveryCapture")))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_new_state_rejects_missing_or_tampered_capture(self) -> None:
        source = r"""
$script:SmokeRoot='C:\audit-shadow'
function Assert-RegularLabPath { param($Path,$Directory); @@MISSING@@ }
function Get-Acl { param($LiteralPath); return @{} }
function Assert-ProtectedLabAcl { param($Acl,$Directory,$Path) }
function Get-FileSha256 { param($Path); return ('0'*64) }
function Read-JsonFile { throw 'digest mismatch must stop before JSON is consumed' }
@@FUNCTION@@
try {
    Get-NativeRecoveryCapture -State ([pscustomobject]@{recovery_capture_sha256=('f'*64)})
    exit 2
}
catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
"""
        for missing, message in (("throw 'capture is missing'", "capture is missing"),
                                 ("", "capture differs")):
            with self.subTest(missing=bool(missing)):
                result = ps_run(source.replace("@@MISSING@@", missing).replace(
                    "@@FUNCTION@@", function_source("Get-NativeRecoveryCapture")))
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)

    def test_prepare_captures_before_initialization_and_seals_before_tasks(self) -> None:
        source = function_source("Invoke-Prepare")
        operations = [
            "$baseline = Get-NativeRecoverySnapshot",
            "$shadowInitializationStarted =",
            "Initialize-NativeShadow -Id",
            "Invoke-Bcd -Arguments @('/export'",
            "Write-NativeRecoveryRecord -Name 'capture'",
            "$mutationStarted =",
            "Invoke-S4UProbeTask",
            "Invoke-Bcd -Arguments @('/copy'",
        ]
        indices = [source.index(operation) for operation in operations]
        self.assertEqual(indices, sorted(indices))
        self.assertIn("recovery_capture_sha256=$captureDigest", source)

    def test_already_recovered_checks_probe_and_cannot_backfill_receipts(self) -> None:
        recovered = function_source("Invoke-Recover").split("if ($state.phase -notin", 1)[0]
        self.assertIn("-TaskName $ProbeTaskName", recovered)
        self.assertNotIn("Write-NativeRecoveryRecord", recovered)
        self.assertNotIn("Get-NativeRecoverySnapshot", recovered)

    def mock_recover(self, failure: str = "") -> subprocess.CompletedProcess[str]:
        source = r"""
$script:Failure='@@FAILURE@@'
$script:SmokeRoot='C:\audit-shadow'
$script:StatePath='C:\audit-shadow\native-boot.json'
$CampaignId='campaign'
$ResumeTaskName='resume'
$WatchdogTaskName='watchdog'
$ProbeTaskName='probe'
$script:Events=@()
$script:Records=@{}
$script:TasksRemoved=$false
$script:BootCalls=0
$script:OwnedCalls=0
$script:SnapshotCalls=0
$script:State=[pscustomobject]@{
    phase='RETURN_PENDING'; campaign_id='campaign'; source_sha=('a'*40)
    source_tree_sha=('b'*40); vm_id='uuid'; vm_name='vm'; box_sha256=('c'*64)
    runner_manifest_sha256=('d'*64); normal_boot_id='normal'; native_boot_id='native'
    recovery_capture_sha256=('e'*64); bcd_backup='backup'; bcd_backup_sha256=('f'*64)
    owner_sid='owner'; run_status='PASS'
}
function Read-JsonFile { param($Path); return $script:State }
function Assert-RecoveryCampaign { param($State,$Requested) }
function Assert-StateBinding { param($State,$ExpectedPhase) }
function Get-NativeRecoveryCapture {
    param($State)
    if ($script:Failure -eq 'capture') { throw 'capture observer unavailable' }
    return [pscustomobject]@{phase='capture'}
}
function Get-OptionalShadowItem {
    param($Path)
    if ($script:Failure -eq 'existing-receipt') { return [pscustomobject]@{FullName=$Path} }
    return $null
}
function Get-NativeShadowRoot { param($Id,$Sha); return 'C:\audit-shadow' }
function Get-FileSha256 { param($Path); return ('f'*64) }
function Get-NativeRecoverySnapshot {
    param($Id,$Sha,$VmId)
    $script:SnapshotCalls++
    $script:Events+=('snapshot'+$script:SnapshotCalls)
    if (($script:Failure -eq 'before-snapshot' -and $script:SnapshotCalls -eq 1) -or
        ($script:Failure -eq 'after-snapshot' -and $script:SnapshotCalls -eq 2)) { throw 'host observer unavailable' }
    return [ordered]@{ observed_at='2026-10-01T00:00:00Z'; native_tasks=@(); private_key_present=($script:SnapshotCalls -eq 1) }
}
function Get-BootContext {
    $script:BootCalls++
    return [pscustomobject]@{ current='normal'; default='normal'; sequence=$(if($script:BootCalls -eq 1){'native'}else{''}) }
}
function Get-OwnedEntries {
    $script:OwnedCalls++
    if($script:OwnedCalls -eq 1){return [pscustomobject]@{id='native'}}
    return @()
}
function Get-ScheduledTask {
    param($TaskPath,$TaskName,$ErrorAction)
    if (!$script:TasksRemoved -and $TaskName -in @('resume','watchdog')) { return [pscustomobject]@{TaskName=$TaskName} }
    return $null
}
function Assert-NativeTaskIdentity { param($Task,$Name,$Runner,$Mode,$Id,$Sha,$Sid,$LogonType) }
function Assert-NativeTaskSecurity { param($Name); if($script:Failure -eq 'task-security'){throw 'owned task security differs'} }
function Invoke-Bcd { param($Arguments); $script:Events+=($Arguments -join ' '); return '' }
function Remove-NativeTasks { param($State); $script:TasksRemoved=$true; $script:Events+='tasks_removed' }
function Assert-NativeRecoveredProof { param($State) }
function Remove-NativeShadowPrivateKey { param($Id,$Sha); $script:Events+='key_removed'; return $true }
function Write-NativeRecoveryRecord {
    param($Name,$Record)
    if ($script:Failure -eq ('write-'+$Name)) { throw 'protected receipt write failed' }
    $script:Records[$Name]=$Record
    $script:Events+=('receipt_'+$Name)
    return ('f'*64)
}
function Write-NativeBootState { param($State); $script:Events+='state_'+$State.phase }
@@NEW_RECORD@@
@@RECOVER@@
Invoke-Recover | Out-Null
@{ events=$script:Events; records=$script:Records; state=$script:State } | ConvertTo-Json -Depth 12 -Compress
"""
        return ps_run(source.replace("@@NEW_RECORD@@", function_source("New-NativeRecoveryRecord"))
                      .replace("@@RECOVER@@", function_source("Invoke-Recover"))
                      .replace("@@FAILURE@@", failure))

    def test_restore_observation_follows_cleanup_and_finalized_state(self) -> None:
        result = self.mock_recover()
        self.assertEqual(result.returncode, 0, result.stderr)
        # Recover emits its public log via Console; the final line is our mock receipt.
        body = json.loads(result.stdout.strip().splitlines()[-1])
        events = body["events"]
        self.assertLess(events.index("snapshot1"), events.index("tasks_removed"))
        self.assertLess(events.index("key_removed"), events.index("receipt_restore"))
        self.assertLess(events.index("receipt_restore"), events.index("state_RECOVERED"))
        self.assertLess(events.index("state_RECOVERED"), events.index("snapshot2"))
        self.assertLess(events.index("snapshot2"), events.index("receipt_verification"))
        self.assertEqual(body["records"]["restore"]["operations"], {
            "bootsequence_removed": True, "native_loader_removed": True,
            "tasks_removed": ["resume", "watchdog"], "private_key_removed": True,
        })
        self.assertNotIn("status", body["records"]["verification"])


    def test_unavailable_observers_do_not_prevent_original_safe_cleanup(self) -> None:
        for failure in ("capture", "existing-receipt", "before-snapshot",
                        "write-restore", "after-snapshot", "write-verification"):
            with self.subTest(failure=failure):
                result = self.mock_recover(failure)
                self.assertEqual(result.returncode, 0, result.stderr)
                body = json.loads(result.stdout.strip().splitlines()[-1])
                self.assertEqual(body["state"]["phase"], "RECOVERED")
                self.assertTrue(body["state"]["recovery_evidence_error"])
                self.assertIn("/deletevalue {bootmgr} bootsequence", body["events"])
                self.assertIn("/delete native /f", body["events"])
                self.assertIn("tasks_removed", body["events"])
                self.assertIn("key_removed", body["events"])
                self.assertNotIn("verification", body["records"])
                if failure in ("capture", "existing-receipt", "before-snapshot", "write-restore"):
                    self.assertEqual(body["records"], {})

    def test_original_task_security_failure_still_stops_cleanup(self) -> None:
        result = self.mock_recover("task-security")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owned task security differs", result.stderr)


if __name__ == "__main__":
    unittest.main()
