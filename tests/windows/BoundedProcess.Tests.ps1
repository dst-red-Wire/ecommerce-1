$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repo 'scripts/windows/RockyImagePipeline.psm1') -Force
class StubbornProcess {
    [int] $ObservedTimeout = 0
    [bool] WaitForExit([int] $timeout) {
        $this.ObservedTimeout = $timeout
        return $false
    }
}
$fake = [StubbornProcess]::new()
$failed = $false
try { Assert-BoundedProcessTermination -Process $fake -FilePath 'stubborn.exe' -TimeoutSeconds 1 }
catch { $failed = $_.Exception.Message.Contains('remained alive 10s after taskkill') }
if (-not $failed -or $fake.ObservedTimeout -ne 10000) { throw 'Post-taskkill bounded wait did not fail closed' }
$pwsh = (Get-Process -Id $PID).Path
$started = [DateTime]::UtcNow
$failed = $false
try {
    [void](Invoke-BoundedProcess -FilePath $pwsh -Arguments @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 4') -TimeoutSeconds 1 -WorkingDirectory $env:SystemRoot)
}
catch { $failed = $_.Exception.Message.Contains('Timed out after 1s') }
if (-not $failed -or ([DateTime]::UtcNow - $started).TotalSeconds -gt 20) { throw 'Live timeout was not bounded' }
Write-Output 'PASS Windows process timeout fixtures'
