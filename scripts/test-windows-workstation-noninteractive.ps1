$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptPath = Join-Path $PSScriptRoot 'windows-workstation.ps1'
$content = Get-Content -Raw -Path $scriptPath

# Single-quoted regex patterns are intentional: PowerShell must not interpolate
# the literal "$cfg" token while this regression test is running under StrictMode.
if ($content -notmatch 'configure test -f \$cfg @configureCommon') {
  throw 'WinGet configure test must use the shared non-interactive arguments'
}
if ($content -notmatch 'configure -f \$cfg @configureCommon') {
  throw 'WinGet configure apply must use the shared non-interactive arguments'
}
if ($content -notmatch 'accept-configuration-agreements') {
  throw 'WinGet configuration agreements must be accepted explicitly'
}
if ($content -notmatch 'disable-interactivity') {
  throw 'WinGet configuration must disable interactive prompts'
}

Write-Host 'PASS WinGet configuration non-interactive regression'
