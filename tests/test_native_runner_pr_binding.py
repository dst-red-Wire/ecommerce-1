"""PowerShell proof that the protected native runner checks one pinned PR binding."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/windows/LabNativeBoot.ps1").read_text(encoding="utf-8")
POWERSHELL = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
SHA = "a" * 40
BASE_SHA = "b" * 40
TREE = "c" * 40
DIGEST = "d" * 64
GH_PATH = "/home/dev/.local/share/ecommerce-1/tools/gh-2.101.0/bin/gh"
BRANCH = "fix/vm-lifecycle-runtime-proof"
REPO = "dst-red-Wire/ecommerce-1"


def function_source(name: str, next_name: str) -> str:
    return "function " + name + SOURCE.split("function " + name, 1)[1].split(
        "function " + next_name, 1)[0]


def ps_run(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
         "Invoke-Expression ([Console]::In.ReadToEnd())"],
        input=source, text=True, errors="replace", capture_output=True, timeout=30)


class NativeRunnerPrBindingTests(unittest.TestCase):
    def test_runner_parses_in_windows_powershell(self) -> None:
        parser = (
            "$tokens=$null;$errors=$null;"
            "$null=[System.Management.Automation.Language.Parser]::ParseInput("
            "[Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors);"
            "if($errors.Count -gt 0){$errors|ForEach-Object{Write-Error $_.Message};exit 1};exit 0"
        )
        result = subprocess.run(
            [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", parser],
            input=SOURCE, text=True, errors="replace", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_head_check(self, *, pr_change: dict | None = None,
                       base_change: dict | None = None, digest: str = DIGEST,
                       version: str = "2.101.0") -> subprocess.CompletedProcess[str]:
        pr = {
            "number": 170, "state": "open", "draft": False, "merged_at": None,
            "head": {"ref": BRANCH, "sha": SHA, "repo": {"full_name": REPO}},
            "base": {"ref": "main", "sha": BASE_SHA, "repo": {"full_name": REPO}},
        }
        base = {"name": "main", "commit": {"sha": BASE_SHA}}
        if pr_change:
            for path, value in pr_change.items():
                current = pr
                keys = path.split(".")
                for key in keys[:-1]:
                    current = current[key]
                current[keys[-1]] = value
        if base_change:
            for path, value in base_change.items():
                current = base
                keys = path.split(".")
                for key in keys[:-1]:
                    current = current[key]
                current[keys[-1]] = value
        script = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:SystemRoot = 'C:\Windows'
$WslDistribution = 'Ubuntu-24.04'
$WslRepoRoot = '/home/dev/ecommerce-1'
$PrNumber = 170
$PrRepository = 'dst-red-Wire/ecommerce-1'
$PrBase = 'main'
$PrBaseSha = '@@BASE_SHA@@'
$PrBranch = 'fix/vm-lifecycle-runtime-proof'
$PinnedGhPath = '@@GH_PATH@@'
$PinnedGhVersion = '2.101.0'
$PinnedGhSha256 = '@@DIGEST@@'
$script:ActualDigest = '@@ACTUAL_DIGEST@@'
$script:ActualVersion = '@@ACTUAL_VERSION@@'
$script:PrPayload = '@@PR_JSON@@'
$script:BasePayload = '@@BASE_JSON@@'
$script:Calls = 0
function Invoke-BoundedProcess {
    param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds,
          [string]$WorkingDirectory)
    $script:Calls++
    $command = $Arguments -join ' '
    if ($command.Contains('/usr/bin/gh')) { throw 'Unpinned system gh was used' }
    if ($command.Contains('/usr/bin/sha256sum')) {
        $body = $script:ActualDigest + '  ' + $PinnedGhPath
    }
    elseif ($command.EndsWith($PinnedGhPath + ' --version')) {
        $body = 'gh version ' + $script:ActualVersion + ' (2026-09-15)'
    }
    elseif ($command.EndsWith('/usr/bin/git rev-parse HEAD')) { $body = '@@SHA@@' }
    elseif ($command.Contains('/usr/bin/git status')) { $body = '' }
    elseif ($command.EndsWith('/usr/bin/git symbolic-ref --quiet --short HEAD')) {
        $body = 'fix/vm-lifecycle-runtime-proof'
    }
    elseif ($command.EndsWith($PinnedGhPath + ' api repos/dst-red-Wire/ecommerce-1/pulls/170')) {
        $body = $script:PrPayload
    }
    elseif ($command.EndsWith($PinnedGhPath + ' api repos/dst-red-Wire/ecommerce-1/branches/main')) {
        $body = $script:BasePayload
    }
    elseif ($command.EndsWith('/usr/bin/git rev-parse HEAD^{tree}')) { $body = '@@TREE@@' }
    else { throw ('Unexpected WSL command: ' + $command) }
    return [pscustomobject]@{ ExitCode=0; StdOut=$body; StdErr='' }
}
function Assert-ProcessSuccess {
    param($Result, [string]$Operation)
    if ($Result.ExitCode -ne 0) { throw $Operation }
}
@@FUNCTION@@
try {
    $tree = Assert-WslHead -Expected '@@SHA@@'
    if ($tree -cne '@@TREE@@' -or $script:Calls -ne 8) {
        throw ('Exact PR revalidation omitted a check; calls=' + $script:Calls)
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
        values = {
            "@@BASE_SHA@@": BASE_SHA, "@@GH_PATH@@": GH_PATH,
            "@@DIGEST@@": DIGEST, "@@ACTUAL_DIGEST@@": digest,
            "@@ACTUAL_VERSION@@": version, "@@PR_JSON@@": json.dumps(pr, separators=(",", ":")),
            "@@BASE_JSON@@": json.dumps(base, separators=(",", ":")),
            "@@SHA@@": SHA, "@@TREE@@": TREE,
            "@@FUNCTION@@": function_source("Assert-WslHead", "Get-NativeGitBlobSha1"),
        }
        for key, value in values.items():
            script = script.replace(key, value)
        return ps_run(script)

    def test_exact_pr_and_managed_gh_pass(self) -> None:
        result = self.run_head_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pr_drift_and_unpinned_gh_fail_closed(self) -> None:
        cases = (
            ({"number": 169}, None, DIGEST, "2.101.0", "Exact PR number"),
            ({"draft": True}, None, DIGEST, "2.101.0", "Exact PR number"),
            ({"base.sha": "e" * 40}, None, DIGEST, "2.101.0", "Exact PR number"),
            ({"head.repo.full_name": "fork/repo"}, None, DIGEST, "2.101.0", "Exact PR number"),
            ({"head.sha": "e" * 40}, None, DIGEST, "2.101.0", "Exact PR number"),
            (None, {"commit.sha": "e" * 40}, DIGEST, "2.101.0", "PR base moved"),
            (None, None, "e" * 64, "2.101.0", "Managed GitHub CLI bytes"),
            (None, None, DIGEST, "2.45.0", "Managed GitHub CLI version"),
        )
        for pr, base, digest, version, message in cases:
            with self.subTest(pr=pr, base=base, digest=digest, version=version):
                result = self.run_head_check(
                    pr_change=pr, base_change=base, digest=digest, version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_reboot_imports_protected_binding_before_pr_check_and_recover_stays_local(self) -> None:
        reboot = SOURCE.split("function Invoke-Reboot {", 1)[1].split(
            "function Invoke-Recover {", 1)[0]
        self.assertLess(reboot.index("Import-ProtectedPrBinding -State $state"),
                        reboot.index("Assert-ExistingCampaign -Id $Id -Sha $Sha"))
        self.assertNotIn("Assert-ExistingCampaign -Id $Id -Sha $Sha -LocalOnly", reboot)
        recover = SOURCE.split("function Invoke-Recover {", 1)[1].split(
            "function Assert-RecoveryCampaign {", 1)[0] if (
                "function Assert-RecoveryCampaign {" in SOURCE.split("function Invoke-Recover {", 1)[1]
            ) else SOURCE.split("function Invoke-Recover {", 1)[1]
        self.assertNotIn("Assert-WslHead", recover)
        self.assertNotIn("Import-ProtectedPrBinding", recover)
        self.assertIn("pr_number=$PrNumber", SOURCE)
        self.assertIn("pinned_gh_sha256=$PinnedGhSha256", SOURCE)

    def test_protected_state_binding_is_required_and_restored_for_reboot(self) -> None:
        state = {
            "pr_number": 170, "pr_repository": REPO, "pr_base": "main",
            "pr_base_sha": BASE_SHA, "pr_branch": BRANCH,
            "pinned_gh_path": GH_PATH, "pinned_gh_version": "2.101.0",
            "pinned_gh_sha256": DIGEST,
        }
        script = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
@@FUNCTION@@
$state = ConvertFrom-Json -InputObject '@@STATE@@'
Import-ProtectedPrBinding -State $state
if ($PrNumber -ne 170 -or $PrBaseSha -cne '@@BASE@@' -or
    $PinnedGhPath -cne '@@GH@@' -or $PinnedGhSha256 -cne '@@DIGEST@@') {
    throw 'Protected PR binding was not restored'
}
$state.PSObject.Properties.Remove('pr_number')
$rejected = $false
try { Import-ProtectedPrBinding -State $state }
catch {
    if ($_.Exception.Message -like 'Prepared native PR binding is incomplete*') {
        $rejected = $true
    }
    else { throw }
}
if (-not $rejected) { throw 'Missing protected PR field was accepted' }
"""
        for before, after in {
            "@@FUNCTION@@": function_source("Import-ProtectedPrBinding", "Assert-OwnedBcdEntry"),
            "@@STATE@@": json.dumps(state, separators=(",", ":")),
            "@@BASE@@": BASE_SHA, "@@GH@@": GH_PATH, "@@DIGEST@@": DIGEST,
        }.items():
            script = script.replace(before, after)
        result = ps_run(script)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
