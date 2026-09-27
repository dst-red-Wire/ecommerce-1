$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $repo 'scripts/windows/RockyImagePipeline.psm1') -Force
. (Join-Path $repo 'scripts/windows/NativeStorageGc.ps1')
function Test-StagingManifest { param([string]$Root) return $false }
function Assert-Equal { param($Actual, $Expected, [string]$What) if ($Actual -ne $Expected) { throw "$What expected=$Expected actual=$Actual" } }
$base = Join-Path $env:TEMP ("ecommerce-storage-gc-test-" + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $base)
try {
    foreach ($dir in @('artifacts','staging','evidence/current')) { [void](New-Item -ItemType Directory -Path (Join-Path $base $dir) -Force) }
    $sha = 'a' * 40
    $boxName = 'rocky-10.2-rke2-virtualbox.box'
    $paths = @()
    for ($i=1; $i -le 4; $i++) {
        $path = Join-Path $base ("artifacts/g$i")
        [void](New-Item -ItemType Directory -Path $path)
        [IO.File]::WriteAllText((Join-Path $path $boxName), "box-$i")
        [IO.File]::WriteAllText((Join-Path $path 'packer.log'), "log-$i")
        $box = Join-Path $path $boxName
        Write-Utf8Json -Path (Join-Path $path 'manifest.json') -InputObject @{
            schema=1; source_sha=$sha; box_sha256=(Get-FileSha256 -Path $box)
            box_filename=$boxName; box_size_bytes=(Get-Item -LiteralPath $box).Length
            packer_log_sha256=(Get-FileSha256 -Path (Join-Path $path 'packer.log'))
        }
        Write-Utf8Json -Path (Join-Path $path 'storage-generation.json') -InputObject @{
            schema=1; owner='ecommerce-1/native-vtx'; kind='artifacts'; generation="g$i"
            source_sha=$sha; status='successful'; completed_at="2026-01-0$i"+'T00:00:00Z'
        }
        $paths += $path
    }
    $foreign = Join-Path $base 'artifacts/foreign'
    [void](New-Item -ItemType Directory -Path $foreign)
    $current = Join-Path $base 'artifacts/current'
    [void](New-Item -ItemType Directory -Path $current)
    Assert-Equal (Test-NativeStorageGenerationOwned -LabRoot $base -Path $foreign) $false 'foreign ownership'
    Assert-Equal (Test-NativeStorageGenerationOwned -LabRoot $base -Path $current) $false 'current ownership'
    Assert-Equal (Test-NativeStorageGenerationOwned -LabRoot $base -Path $env:TEMP) $false 'outside ownership'
    $reuse = Join-Path $paths[0] $boxName
    Assert-Equal (Test-NativeStorageGenerationProtected -LabRoot $base -Path $paths[0] -ReuseBoxPath $reuse) $true 'reuse protection'
    Write-Utf8Json -Path (Join-Path $base 'prepared.json') -InputObject @{stage_root=$paths[1]}
    Assert-Equal (Test-NativeStorageGenerationProtected -LabRoot $base -Path $paths[1]) $true 'prepared protection'
    Remove-Item -LiteralPath (Join-Path $base 'prepared.json') -Force
    [void](New-Item -ItemType Directory -Path (Join-Path $base 'startup-real') -Force)
    Write-Utf8Json -Path (Join-Path $base 'startup-real/state.json') -InputObject @{stage_root=$paths[2]}
    Assert-Equal (Test-NativeStorageGenerationProtected -LabRoot $base -Path $paths[2]) $true 'recovery protection'
    Remove-Item -LiteralPath (Join-Path $base 'startup-real/state.json') -Force
    $probe = { 27GB + (4 - @(Get-ChildItem -LiteralPath (Join-Path $base 'artifacts') -Directory | Where-Object Name -match '^g[0-9]$').Count) * 15GB }.GetNewClosure()
    $notRequired = Invoke-NativeStorageGc -LabRoot $base -RequiredFreeGiB 40 -TargetFreeGiB 48 -MeasureFreeBytes { 50GB }
    Assert-Equal $notRequired.status 'NOT_REQUIRED' 'sufficient space'
    Assert-Equal $notRequired.deleted.Count 0 'sufficient space deletion'
    $result = Invoke-NativeStorageGc -LabRoot $base -RequiredFreeGiB 40 -TargetFreeGiB 48 -MeasureFreeBytes $probe
    Assert-Equal $result.status 'PASS' 'GC status'
    Assert-Equal $result.deleted.Count 2 'stop at target'
    Assert-Equal $result.deleted[0].generation 'g1' 'oldest first'
    Assert-Equal $result.deleted[1].generation 'g2' 'oldest second'
    Assert-Equal (Test-Path -LiteralPath $paths[2]) $true 'unneeded generation retained'
    Assert-Equal (Test-Path -LiteralPath $paths[3]) $true 'last successful retained'
    Assert-Equal (Test-Path -LiteralPath $current) $true 'current retained'
    Assert-Equal (Test-Path -LiteralPath $foreign) $true 'foreign retained'
    $again = Invoke-NativeStorageGc -LabRoot $base -RequiredFreeGiB 40 -TargetFreeGiB 48 -MeasureFreeBytes $probe
    Assert-Equal $again.status 'NOT_REQUIRED' 'idempotent'
    Assert-Equal $again.deleted.Count 0 'idempotent deletion'
    $evidence = Read-JsonFile (Join-Path $base 'evidence/current/storage-gc.json')
    Assert-Equal $evidence.status 'NOT_REQUIRED' 'evidence'
    $blocked = $false
    try {
        [void](Invoke-NativeStorageGc -LabRoot $base -RequiredFreeGiB 40 -TargetFreeGiB 48 -ReuseBoxPath (Join-Path $paths[2] $boxName) -MeasureFreeBytes { 1GB })
    }
    catch { $blocked = $_.Exception.Message.Contains('BLOCKED_RUNTIME') }
    Assert-Equal $blocked $true 'eligible exhausted'
    $blockedEvidence = Read-JsonFile (Join-Path $base 'evidence/current/storage-gc.json')
    Assert-Equal $blockedEvidence.status 'BLOCKED_RUNTIME' 'blocked evidence'
    Assert-Equal $blockedEvidence.bytes_reclaimed 0 'no artificial reclaimed bytes'
    $retention = Select-NativeStorageRetention -Eligible @(
        [pscustomobject]@{path='success-old';status='successful';completed_at='2026-01-01T00:00:00Z'},
        [pscustomobject]@{path='success-new';status='successful';completed_at='2026-01-02T00:00:00Z'},
        [pscustomobject]@{path='failed-old';status='failed';completed_at='2026-01-01T00:00:00Z'},
        [pscustomobject]@{path='failed-new';status='failed';completed_at='2026-01-03T00:00:00Z'}
    )
    Assert-Equal ($retention.protected -contains 'success-new') $true 'last successful retention'
    Assert-Equal ($retention.protected -contains 'failed-new') $true 'last failed retention'
    Assert-Equal $retention.eligible.Count 2 'older generations eligible'
    function Get-Item {
        param([string]$LiteralPath, [switch]$Force)
        if ($LiteralPath -eq $paths[3]) {
            return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint}
        }
        return Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
    }
    $reparseRefused = $false
    try { [void](Assert-NativeGcPath -LabRoot $base -Path $paths[3]) }
    catch { $reparseRefused = $_.Exception.Message.Contains('reparse') }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath Function:\Get-Item
    Assert-Equal $reparseRefused $true 'reparse point refusal'
    Write-Output 'PASS native storage GC fixtures'
}
finally {
    Remove-Item -LiteralPath $base -Recurse -Force
}
