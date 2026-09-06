[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$RepoWindowsPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Required command missing: $Name" }
}

Assert-Command winget.exe
Assert-Command wsl.exe

# Keep the already validated project networking decision: WSL2 NAT, firewall and DNS tunneling enabled.
$wslConfig = Join-Path $HOME '.wslconfig'
$desired = [ordered]@{
  networkingMode = 'nat'
  firewall = 'true'
  dnsTunneling = 'true'
  autoProxy = 'true'
}
$lines = [System.Collections.Generic.List[string]]::new()
if (Test-Path $wslConfig) {
  foreach ($line in Get-Content -Path $wslConfig) {
    [void]$lines.Add([string]$line)
  }
}
$sectionStart = -1
for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim().ToLowerInvariant() -eq '[wsl2]') { $sectionStart = $i; break } }
if ($sectionStart -lt 0) { if ($lines.Count -gt 0 -and $lines[$lines.Count-1] -ne '') { $lines.Add('') }; $lines.Add('[wsl2]'); $sectionStart = $lines.Count-1 }
$sectionEnd = $lines.Count
for ($i=$sectionStart+1; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim().StartsWith('[')) { $sectionEnd = $i; break } }
foreach ($entry in $desired.GetEnumerator()) {
  $found = $false
  for ($i=$sectionStart+1; $i -lt $sectionEnd; $i++) {
    if ($lines[$i] -match ('^\s*' + [regex]::Escape($entry.Key) + '\s*=')) { $lines[$i] = "$($entry.Key)=$($entry.Value)"; $found = $true; break }
  }
  if (-not $found) { $lines.Insert($sectionEnd, "$($entry.Key)=$($entry.Value)"); $sectionEnd++ }
}
Set-Content -Path $wslConfig -Value $lines -Encoding utf8

wsl.exe --update
wsl.exe --set-default-version 2

$cfg = Join-Path $RepoWindowsPath '.config\configuration.winget'
# WinGet Configuration prompts for trust/third-party acknowledgement even during
# `configure test`. The repository-owned configuration has already been reviewed,
# so every state-inspecting or state-applying call is explicitly non-interactive.
$configureCommon = @('--accept-configuration-agreements', '--disable-interactivity')
winget.exe configure validate -f $cfg --disable-interactivity
winget.exe configure test -f $cfg @configureCommon | Out-Host
winget.exe configure -f $cfg @configureCommon

# Docker Desktop is controlled through its supported CLI when available.
$docker = Get-Command docker.exe -ErrorAction SilentlyContinue
if ($docker) {
  try {
    $status = (& docker.exe desktop status 2>$null | Out-String).Trim()
    if ($status -notmatch 'running') { & docker.exe desktop start | Out-Host }
  } catch {
    Write-Host 'SKIP Docker Desktop CLI control: desktop subcommand unavailable; WSL-side validation will decide readiness.'
  }
}
Write-Host 'PASS Windows/WSL desired state reconciled. WSL networking changes take effect on the next WSL restart.'
