Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-NativeStorageTimestampUtc {
    param([Parameter(Mandatory = $true)]$Value)
    if ($Value -is [DateTimeOffset]) {
        $timestamp = $Value
    }
    elseif ($Value -is [DateTime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            throw 'Storage generation timestamp has no timezone'
        }
        $timestamp = [DateTimeOffset]::new($Value)
    }
    elseif ($Value -is [string] -and
        $Value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$') {
        $timestamp = [DateTimeOffset]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    else { throw 'Storage generation timestamp is not an ISO-8601 value with timezone' }
    return $timestamp.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function Assert-NativeGcPath {
    param([string]$LabRoot, [string]$Path)
    $root = [IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $relative = $target.Substring($root.Length).TrimStart('\')
    $parts = $relative.Split('\')
    if (-not $target.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $parts.Count -ne 2 -or $parts[0] -notin @('staging','artifacts') -or
        $parts[1] -eq 'current' -or $parts[1] -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$') {
        throw "Refusing storage GC outside an owned generation: $target"
    }
    foreach ($ancestor in @($root, (Join-Path $root $parts[0]), $target)) {
        if (-not (Test-Path -LiteralPath $ancestor -PathType Container) -or
            ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing missing or reparse storage GC path: $ancestor"
        }
    }
    $reparse = Get-ChildItem -LiteralPath $target -Force -Recurse | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint
    } | Select-Object -First 1
    if ($null -ne $reparse) { throw "Refusing storage GC reparse descendant: $($reparse.FullName)" }
    return $target
}

function Test-NativeStorageGenerationOwned {
    param([string]$LabRoot, [string]$Path)
    try {
        $target = Assert-NativeGcPath -LabRoot $LabRoot -Path $Path
        $manifestPath = Join-Path $target 'storage-generation.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return $false }
        $manifest = Read-JsonFile $manifestPath
        $kind = Split-Path -Leaf (Split-Path -Parent $target)
        $name = Split-Path -Leaf $target
        if ($manifest.schema -ne 1 -or $manifest.owner -ne 'ecommerce-1/native-vtx' -or
            $manifest.kind -ne $kind -or $manifest.generation -ne $name -or
            $manifest.source_sha -notmatch '^[0-9a-f]{40}$' -or
            $manifest.status -notin @('successful','failed') -or
            [string]::IsNullOrWhiteSpace([string]$manifest.completed_at)) { return $false }
        [void](Convert-NativeStorageTimestampUtc -Value $manifest.completed_at)
        if ($kind -eq 'artifacts') {
            $boxManifest = Read-JsonFile (Join-Path $target 'manifest.json')
            if ($boxManifest.schema -ne 1 -or $boxManifest.source_sha -ne $manifest.source_sha -or
                $boxManifest.box_sha256 -notmatch '^[0-9a-f]{64}$' -or
                $boxManifest.box_filename -ne 'rocky-10.2-rke2-virtualbox.box') { return $false }
            $box = Join-Path $target $boxManifest.box_filename
            if (-not (Test-Path -LiteralPath $box -PathType Leaf) -or
                (Get-Item -LiteralPath $box).Length -ne $boxManifest.box_size_bytes -or
                (Get-FileSha256 -Path $box) -ne $boxManifest.box_sha256 -or
                (Get-FileSha256 -Path (Join-Path $target 'packer.log')) -ne $boxManifest.packer_log_sha256) { return $false }
        }
        else {
            $prepared = Read-JsonFile (Join-Path $target '.prepared.json')
            if ($prepared.schema -ne 1 -or $prepared.source_git_sha -ne $manifest.source_sha -or
                -not (Test-StagingManifest -Root $target)) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Get-NativeStorageGeneration {
    param([string]$LabRoot)
    $rows = @()
    foreach ($kind in @('staging','artifacts')) {
        $base = Join-Path $LabRoot $kind
        if (-not (Test-Path -LiteralPath $base -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $base -Directory -Force)) {
            if ($item.Name -eq 'current') { continue }
            $owned = Test-NativeStorageGenerationOwned -LabRoot $LabRoot -Path $item.FullName
            $manifest = if ($owned) { Read-JsonFile (Join-Path $item.FullName 'storage-generation.json') } else { $null }
            $rows += [pscustomobject]@{
                path = $item.FullName; generation = $item.Name; kind = $kind
                owned = $owned; status = if ($owned) { [string]$manifest.status } else { '' }
                completed_at = if ($owned) { Convert-NativeStorageTimestampUtc -Value $manifest.completed_at } else { '' }
            }
        }
    }
    return @($rows)
}

function Test-NativeStorageGenerationProtected {
    param([string]$LabRoot, [string]$Path, [string]$ReuseBoxPath = '')
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ((Split-Path -Leaf $target) -eq 'current') { return $true }
    $resetPath = Join-Path $LabRoot 'failed-cycle-reset.json'
    if (Test-Path -LiteralPath $resetPath -PathType Leaf) {
        $reset = Read-JsonFile $resetPath
        if ($reset.status -notin @('RESETTING', 'FAILED_ARCHIVED') -or
            $reset.source_sha -notmatch '^[0-9a-f]{40}$' -or
            $reset.staging_manifest_sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'FAILED reset marker has an invalid storage protection identity'
        }
        $expected = [IO.Path]::GetFullPath((Join-Path $LabRoot (
            "staging\failed-$($reset.source_sha.Substring(0, 20))-$($reset.staging_manifest_sha256.Substring(0, 16))"
        ))).TrimEnd('\')
        $archive = [IO.Path]::GetFullPath([string]$reset.archive_root).TrimEnd('\')
        if ($archive -ine $expected) { throw 'FAILED reset marker references a different storage generation' }
        if ($archive -ieq $target) { return $true }
    }
    if ($ReuseBoxPath) {
        $reuse = [IO.Path]::GetFullPath($ReuseBoxPath)
        if ($reuse.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $preparedPath = Join-Path $LabRoot 'prepared.json'
    if (Test-Path -LiteralPath $preparedPath) {
        $prepared = Read-JsonFile $preparedPath
        if ($prepared.stage_root -and ([IO.Path]::GetFullPath([string]$prepared.stage_root).TrimEnd('\') -ieq $target)) { return $true }
        if ($prepared.reuse_box -and $prepared.reuse_box.path -and
            ([IO.Path]::GetFullPath([string]$prepared.reuse_box.path)).StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($file in @((Join-Path $LabRoot 'startup-real\state.json'), (Join-Path $LabRoot 'evidence\current\recovery.json'))) {
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            $body = [IO.File]::ReadAllText($file)
            if ($body.IndexOf($target, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $body.IndexOf((Split-Path -Leaf $target), [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }
    return $false
}

function Remove-NativeStorageGeneration {
    param([string]$LabRoot, [string]$Path, [string]$ReuseBoxPath = '', [scriptblock]$RuntimeClearProbe = $null)
    if ([IO.Path]::GetFullPath($LabRoot).TrimEnd('\') -ieq 'C:\ecommerce-lab') {
        if ($env:ECOMMERCE_RUNTIME_ORCHESTRATED -ne '1' -or
            $null -eq $RuntimeClearProbe -or -not (& $RuntimeClearProbe)) {
            throw 'BLOCKED_RUNTIME storage deletion requires the global lock, normal boot and no active VM or task'
        }
    }
    $target = Assert-NativeGcPath -LabRoot $LabRoot -Path $Path
    if (-not (Test-NativeStorageGenerationOwned -LabRoot $LabRoot -Path $target) -or
        (Test-NativeStorageGenerationProtected -LabRoot $LabRoot -Path $target -ReuseBoxPath $ReuseBoxPath)) {
        throw "Storage generation is not owned or is protected: $target"
    }
    Remove-SafeTree -BasePath $LabRoot -CandidatePath $target
    if (Test-Path -LiteralPath $target) { throw "Storage generation remains after deletion: $target" }
}

function Get-NativeGcBytes {
    param([string]$LabRoot)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($LabRoot)))
    if (-not $drive.IsReady) { throw 'BLOCKED_RUNTIME storage GC drive unavailable' }
    return [int64]$drive.AvailableFreeSpace
}

function Test-NativeCurrentArtifactSuccessful {
    param([string]$LabRoot)
    $current = Join-Path $LabRoot 'artifacts\current'
    try {
        foreach ($path in @($LabRoot, (Join-Path $LabRoot 'artifacts'), $current)) {
            if (-not (Test-Path -LiteralPath $path -PathType Container) -or
                ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
        }
        if ($null -ne (Get-ChildItem -LiteralPath $current -Force -Recurse | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        } | Select-Object -First 1)) { return $false }
        $generation = Read-JsonFile (Join-Path $current 'storage-generation.json')
        $manifest = Read-JsonFile (Join-Path $current 'manifest.json')
        if ($generation.schema -ne 1 -or $generation.owner -ne 'ecommerce-1/native-vtx' -or
            $generation.kind -ne 'artifacts' -or $generation.generation -ne 'current' -or
            $generation.status -ne 'successful' -or $generation.source_sha -notmatch '^[0-9a-f]{40}$' -or
            $manifest.schema -ne 1 -or $manifest.source_sha -ne $generation.source_sha -or
            $manifest.box_filename -ne 'rocky-10.2-rke2-virtualbox.box' -or
            $manifest.box_sha256 -notmatch '^[0-9a-f]{64}$') { return $false }
        $box = Join-Path $current $manifest.box_filename
        return (Get-Item -LiteralPath $box).Length -eq $manifest.box_size_bytes -and
            (Get-FileSha256 -Path $box) -eq $manifest.box_sha256 -and
            (Get-FileSha256 -Path (Join-Path $current 'packer.log')) -eq $manifest.packer_log_sha256
    }
    catch { return $false }
}

function Select-NativeStorageRetention {
    param([array]$Eligible, [bool]$CurrentSuccessful = $false)
    $remaining = @($Eligible)
    $protected = @()
    foreach ($status in @('successful','failed')) {
        if ($status -eq 'successful' -and $CurrentSuccessful) { continue }
        $retained = @($remaining | Where-Object status -eq $status |
            Sort-Object completed_at, path -Descending | Select-Object -First 1)
        foreach ($item in $retained) {
            $protected += $item.path
            $remaining = @($remaining | Where-Object path -ne $item.path)
        }
    }
    return [pscustomobject]@{ eligible=$remaining; protected=$protected }
}

function Invoke-NativeStorageGc {
    param(
        [string]$LabRoot, [int]$RequiredFreeGiB, [int]$TargetFreeGiB,
        [string]$ReuseBoxPath = '', [scriptblock]$MeasureFreeBytes = $null,
        [scriptblock]$RuntimeClearProbe = $null
    )
    $root = [IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
    $production = $root -ieq 'C:\ecommerce-lab'
    if (-not $production -and $null -eq $MeasureFreeBytes) { throw 'Fixture storage GC requires an explicit free-space probe' }
    if ($RequiredFreeGiB -le 0 -or $TargetFreeGiB -le $RequiredFreeGiB) { throw 'Invalid storage GC thresholds' }
    if ($null -eq $MeasureFreeBytes) { $MeasureFreeBytes = { Get-NativeGcBytes -LabRoot $root }.GetNewClosure() }
    $evidencePath = Join-Path $root 'evidence\current\storage-gc.json'
    $before = [int64](& $MeasureFreeBytes)
    $after = $before
    $evidence = [ordered]@{
        schema=1; status='BLOCKED_RUNTIME'; trigger='insufficient-free-space'
        required_free_gib=$RequiredFreeGiB; target_free_gib=$TargetFreeGiB
        before_free_bytes=$before; before_free_gib=[math]::Round($before / 1GB, 2)
        after_free_bytes=$after; after_free_gib=[math]::Round($after / 1GB, 2)
        bytes_reclaimed=0; deleted=@(); protected=@(); rejected=@(); error=$null; completed_at=$null
    }
    try {
        if ($before -ge ([int64]$RequiredFreeGiB * 1GB)) {
            $evidence.status = 'NOT_REQUIRED'; $evidence.trigger = 'sufficient-free-space'
            return $evidence
        }
        if ($production -and $env:ECOMMERCE_RUNTIME_ORCHESTRATED -ne '1') {
            throw 'BLOCKED_RUNTIME storage GC requires local-virtualization-serialization'
        }
        if ($production -and ($null -eq $RuntimeClearProbe -or -not (& $RuntimeClearProbe))) { throw 'BLOCKED_RUNTIME native runtime is not clear for storage GC' }
        $generations = @(Get-NativeStorageGeneration -LabRoot $root)
        $eligible = @()
        foreach ($generation in $generations) {
            if (-not $generation.owned) { $evidence.rejected += $generation.path; continue }
            if (Test-NativeStorageGenerationProtected -LabRoot $root -Path $generation.path -ReuseBoxPath $ReuseBoxPath) {
                $evidence.protected += $generation.path; continue
            }
            $eligible += $generation
        }
        $retention = Select-NativeStorageRetention -Eligible $eligible -CurrentSuccessful (Test-NativeCurrentArtifactSuccessful -LabRoot $root)
        $evidence.protected += $retention.protected
        $eligible = @($retention.eligible)
        foreach ($item in @($eligible | Sort-Object completed_at, path)) {
            if ($after -ge ([int64]$TargetFreeGiB * 1GB)) { break }
            if ($production -and -not (& $RuntimeClearProbe)) {
                throw 'BLOCKED_RUNTIME native runtime became active during storage GC'
            }
            $currentManifest = Read-JsonFile (Join-Path $item.path 'storage-generation.json')
            if ($currentManifest.status -ne $item.status -or
                (Convert-NativeStorageTimestampUtc -Value $currentManifest.completed_at) -ne $item.completed_at) {
                throw "BLOCKED_RUNTIME storage generation changed after inventory: $($item.path)"
            }
            if (-not (Test-NativeStorageGenerationOwned -LabRoot $root -Path $item.path) -or
                (Test-NativeStorageGenerationProtected -LabRoot $root -Path $item.path -ReuseBoxPath $ReuseBoxPath)) {
                throw "BLOCKED_RUNTIME storage generation changed before deletion: $($item.path)"
            }
            $bytes = [int64](Get-ChildItem -LiteralPath $item.path -File -Recurse -Force | Measure-Object -Property Length -Sum).Sum
            Remove-NativeStorageGeneration -LabRoot $root -Path $item.path -ReuseBoxPath $ReuseBoxPath -RuntimeClearProbe $RuntimeClearProbe
            $after = [int64](& $MeasureFreeBytes)
            $evidence.deleted += [ordered]@{generation=$item.generation;path=$item.path;ownership='VERIFIED';reason='oldest-eligible-generation';bytes_before=$bytes;free_bytes_after=$after}
            $evidence.after_free_bytes = $after
            $evidence.after_free_gib = [math]::Round($after / 1GB, 2)
            $evidence.bytes_reclaimed = [math]::Max([long]0, [long]($after - $before))
        }
        if ($after -lt ([int64]$RequiredFreeGiB * 1GB)) {
            throw "BLOCKED_RUNTIME storage GC eligible exhausted: free=$([math]::Round($after/1GB,2)) required=$RequiredFreeGiB target=$TargetFreeGiB reclaimed=$($evidence.bytes_reclaimed) protected=$($evidence.protected.Count)"
        }
        $evidence.status = 'PASS'
        return $evidence
    }
    catch {
        $evidence.error = $_.Exception.Message
        throw
    }
    finally {
        $evidence.completed_at = [DateTime]::UtcNow.ToString('o')
        Write-Utf8Json -InputObject $evidence -Path $evidencePath
    }
}
