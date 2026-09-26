[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSourceSha,
    [string]$RepoRoot = '\\wsl.localhost\Ubuntu-24.04\home\dev\ecommerce-1',
    [string]$WslDistribution = 'Ubuntu-24.04',
    [string]$WslRepoRoot = '/home/dev/ecommerce-1',
    [string]$LabRoot = 'C:\ecommerce-lab'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'BLOCKED_PRIVILEGE: launch requires elevated administrator PowerShell'
}
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
foreach ($executable in @($powershell, $wsl)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "Required executable is absent: $executable" }
}
$head = (& $wsl -d $WslDistribution --cd $WslRepoRoot -- git rev-parse HEAD 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $ExpectedSourceSha) { throw 'Local Git HEAD differs from the exact expected source SHA' }
$published = (& $wsl -d $WslDistribution --cd $WslRepoRoot -- gh pr view 148 --repo dst-red-Wire/ecommerce-1 --json headRefOid -q .headRefOid 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $published -ne $ExpectedSourceSha) { throw 'GitHub PR #148 HEAD differs from the exact expected source SHA' }
$payload = Join-Path $RepoRoot ".context\cache\native-controller-payload\$ExpectedSourceSha"
$manifest = Join-Path $payload 'payload.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Exact-SHA payload is absent: $manifest" }
$dryRunScript = Join-Path $RepoRoot 'scripts\windows\native-startup-resume.ps1'
$cycleScript = Join-Path $RepoRoot 'scripts\windows\native-vtx-cycle.ps1'
$summaryPath = Join-Path $LabRoot "startup-dry-run\$ExpectedSourceSha\evidence\summary.json"
if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $dryRunScript -Action PrepareDryRun -LabRoot $LabRoot -SourceSha $ExpectedSourceSha -PayloadRoot $payload
    if ($LASTEXITCODE -ne 0) { throw 'SYSTEM AtStartup dry-run failed; BCD remains unchanged' }
}
$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
if ($summary.status -ne 'PASS' -or $summary.source_sha -ne $ExpectedSourceSha -or
    $summary.bcd_mutated -ne $false -or $summary.reboot_occurred -ne $false) {
    throw 'Exact-SHA startup dry-run is not PASS; BCD remains unchanged'
}
foreach ($name in @('Ecommerce-System-WSL-Probe','Ecommerce-S4U-WSL-Probe')) {
    if ($null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}
$published = (& $wsl -d $WslDistribution --cd $WslRepoRoot -- gh pr view 148 --repo dst-red-Wire/ecommerce-1 --json headRefOid -q .headRefOid 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $published -ne $ExpectedSourceSha) { throw 'PR head advanced after startup dry-run; BCD remains unchanged' }
& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cycleScript -Action Cycle -RepoRoot $RepoRoot -WslDistribution $WslDistribution -WslRepoRoot $WslRepoRoot -LabRoot $LabRoot -Offline
if ($LASTEXITCODE -ne 0) { throw 'Native cycle preparation failed; inspect persistent Windows evidence and host state' }
