$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in @('[wsl2]', 'networkingMode=nat')) { [void]$lines.Add([string]$line) }
$lines.Insert(1, 'firewall=true')
if ($lines.Count -ne 3 -or $lines[1] -ne 'firewall=true') { throw 'Mutable WSL config collection regression' }
Write-Host 'PASS mutable WSL config collection'
