Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-PipelineUtf8 {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [Console]::OutputEncoding = $utf8
    $script:OutputEncoding = $utf8
}

function ConvertTo-NativeArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -match '^[A-Za-z0-9._/:=+-]+$') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [hashtable]$Environment = @{},
        [scriptblock]$OnPoll = $null,
        [ValidateRange(1, 60)][int]$PollIntervalSeconds = 5
    )

    if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        throw "Process working directory does not exist: $WorkingDirectory"
    }
    if ($WorkingDirectory.StartsWith('\\')) {
        throw "Windows programs must not use a UNC working directory: $WorkingDirectory"
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ')
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) {
        $startInfo.EnvironmentVariables[[string]$key] = [string]$Environment[$key]
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start process: $FilePath"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = $false
    if ($null -eq $OnPoll) {
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    }
    else {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $process.WaitForExit($PollIntervalSeconds * 1000)) {
            & $OnPoll
            if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                $timedOut = $true
                break
            }
        }
        if (-not $timedOut) {
            & $OnPoll
        }
    }
    if ($timedOut) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F *> $null
        $process.WaitForExit()
        throw "Timed out after ${TimeoutSeconds}s: $FilePath"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        StdOut = $stdout
        StdErr = $stderr
    }
}

function Assert-ProcessSuccess {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Operation
    )
    if ($Result.ExitCode -ne 0) {
        $detail = ($Result.StdErr + "`n" + $Result.StdOut).Trim()
        if ($detail.Length -gt 8000) {
            $head = $detail.Substring(0, 2000)
            $tail = $detail.Substring($detail.Length - 6000)
            $detail = $head + "`n... bounded process output omitted ...`n" + $tail
        }
        throw "$Operation failed with exit code $($Result.ExitCode): $detail"
    }
}

function Write-Utf8Json {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent -Force)
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $json = $InputObject | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required JSON file is missing: $Path"
    }
    return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
}

function Get-RepositoryRoot {
    param([string]$RequestedRoot = '')
    $candidate = $RequestedRoot
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $candidate = Join-Path $PSScriptRoot '..\..'
    }
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($candidate)
    foreach ($required in @('architecture.lock.yaml', 'config\contracts\machine-image-lock.yaml', 'config\contracts\toolchain-lock.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolved $required) -PathType Leaf)) {
            throw "Repository root is missing $required`: $resolved"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $resolved '.git'))) {
        throw "Repository root has no Git worktree marker: $resolved"
    }
    return $resolved
}

function Get-ToolchainLock {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    return Read-JsonFile (Join-Path $RepoRoot 'config\contracts\toolchain-lock.json')
}

function Resolve-WindowsTool {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$FallbackPaths = @()
    )
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        return $command.Source
    }
    foreach ($path in $FallbackPaths) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            return (Resolve-Path -LiteralPath $path).Path
        }
    }
    throw "Required Windows executable is missing: $Name"
}

function Get-LocalPipelineRoot {
    $local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($local) -or $local.StartsWith('\\')) {
        throw 'LOCALAPPDATA must resolve to a local Windows path'
    }
    return [System.IO.Path]::GetFullPath((Join-Path $local 'ecommerce-1\packer\rocky-10.2'))
}

function Assert-SafeChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$CandidatePath
    )
    $base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\')
    $candidate = [System.IO.Path]::GetFullPath($CandidatePath)
    if (-not $candidate.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside governed Windows pipeline root: $candidate"
    }
    return $candidate
}

function Remove-SafeTree {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$CandidatePath
    )
    $safe = Assert-SafeChildPath -BasePath $BasePath -CandidatePath $CandidatePath
    if (Test-Path -LiteralPath $safe) {
        $baseItem = Get-Item -LiteralPath $BasePath -Force
        $targetItem = Get-Item -LiteralPath $safe -Force
        if (($baseItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or ($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing cleanup through a Windows reparse point: $safe"
        }
        $nestedReparsePoint = Get-ChildItem -LiteralPath $safe -Force -Recurse | Where-Object {
            $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint
        } | Select-Object -First 1
        if ($null -ne $nestedReparsePoint) {
            throw "Refusing cleanup tree containing a Windows reparse point: $($nestedReparsePoint.FullName)"
        }
        Remove-Item -LiteralPath $safe -Recurse -Force
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot hash missing file: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-ToWslPath {
    param(
        [Parameter(Mandatory = $true)][string]$WindowsPath,
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $result = Invoke-BoundedProcess -FilePath 'wsl.exe' -Arguments @('-d', $Distribution, '--', 'wslpath', '-u', $WindowsPath) -TimeoutSeconds $TimeoutSeconds -WorkingDirectory "$env:SystemRoot"
    Assert-ProcessSuccess -Result $result -Operation 'wslpath Windows-to-WSL conversion'
    $path = $result.StdOut.Trim()
    if (-not $path.StartsWith('/') -or $path -match "[\r\n]") {
        throw "wslpath returned an invalid WSL path"
    }
    return $path
}

function Invoke-WslProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][string]$WslWorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $wslArguments = @('-d', $Distribution, '--cd', $WslWorkingDirectory, '--', $Command) + $Arguments
    return Invoke-BoundedProcess -FilePath 'wsl.exe' -Arguments $wslArguments -TimeoutSeconds $TimeoutSeconds -WorkingDirectory "$env:SystemRoot"
}

function Get-GitState {
    param(
        [Parameter(Mandatory = $true)][string]$Distribution,
        [Parameter(Mandatory = $true)][string]$WslRepoRoot
    )
    $head = Invoke-WslProcess -Distribution $Distribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('rev-parse', 'HEAD') -TimeoutSeconds 60
    Assert-ProcessSuccess -Result $head -Operation 'Git HEAD resolution'
    $status = Invoke-WslProcess -Distribution $Distribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -TimeoutSeconds 60
    Assert-ProcessSuccess -Result $status -Operation 'Git worktree inspection'
    return [pscustomobject]@{
        Head = $head.StdOut.Trim()
        Clean = [string]::IsNullOrWhiteSpace($status.StdOut)
    }
}

function Get-VBoxMachines {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $result = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('list', 'vms') -TimeoutSeconds 15 -WorkingDirectory $WorkingDirectory
    Assert-ProcessSuccess -Result $result -Operation 'VirtualBox machine inventory'
    $machines = @{}
    foreach ($line in ($result.StdOut -split "`r?`n")) {
        if ($line -match '^"(?<name>[^"]+)"\s+\{(?<uuid>[0-9a-fA-F-]{36})\}$') {
            $machines[$Matches.name] = $Matches.uuid.ToLowerInvariant()
        }
    }
    return $machines
}

function Remove-OwnedVirtualMachine {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$InitialMachines,
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    if ($Name -notmatch '^ecommerce-rocky-10-2-(?:build|smoke|native-probe)-[a-z0-9-]+$') {
        throw "Refusing cleanup of unowned VM name: $Name"
    }
    $current = Get-VBoxMachines -VBoxManage $VBoxManage -WorkingDirectory $WorkingDirectory
    if (-not $current.ContainsKey($Name)) {
        return 'NOT_NEEDED'
    }
    if ($InitialMachines.ContainsKey($Name)) {
        throw "Refusing cleanup of VM that existed before this run: $Name"
    }
    $running = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('list', 'runningvms') -TimeoutSeconds 15 -WorkingDirectory $WorkingDirectory
    Assert-ProcessSuccess -Result $running -Operation 'VirtualBox running machine inventory'
    if ($running.StdOut -match [regex]::Escape("{$($current[$Name])}")) {
        $poweroff = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('controlvm', $current[$Name], 'poweroff') -TimeoutSeconds 60 -WorkingDirectory $WorkingDirectory
        Assert-ProcessSuccess -Result $poweroff -Operation "VirtualBox poweroff for $Name"
    }
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $result = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('unregistervm', $current[$Name], '--delete') -TimeoutSeconds 30 -WorkingDirectory $WorkingDirectory
        if ($result.ExitCode -eq 0) { return 'PASS' }
        if (($result.StdOut + $result.StdErr) -notmatch 'while it is locked|VBOX_E_INVALID_OBJECT_STATE') {
            Assert-ProcessSuccess -Result $result -Operation "VirtualBox cleanup for $Name"
        }
        $remaining = Get-VBoxMachines -VBoxManage $VBoxManage -WorkingDirectory $WorkingDirectory
        if (-not $remaining.ContainsKey($Name)) { return 'PASS' }
        if ($remaining[$Name] -ne $current[$Name]) {
            throw "VirtualBox cleanup target changed identity while waiting: $Name"
        }
        if ($attempt -eq 12) {
            Assert-ProcessSuccess -Result $result -Operation "VirtualBox cleanup for $Name after bounded lock retries"
        }
        Start-Sleep -Seconds 5
    }
}

function New-ImageSupplyChainEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ArtifactSha256,
        [Parameter(Mandatory = $true)][string]$RpmInventory,
        [Parameter(Mandatory = $true)][string[]]$RequiredPackages
    )
    if ($ArtifactSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid supply-chain artifact digest' }
    $packages = @($RpmInventory -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($packages.Count -lt 50 -or @($packages | Sort-Object -Unique).Count -ne $packages.Count) {
        throw 'RPM package manifest is empty, incomplete or duplicated'
    }
    $components = @()
    foreach ($line in $packages) {
        if ($line -cnotmatch '^([A-Za-z0-9+_.-]+)\|([^\s|]+)$') { throw 'Invalid RPM package manifest entry' }
        $components += [ordered]@{ type = 'library'; name = $Matches[1]; version = $Matches[2] }
    }
    $required = @($RequiredPackages | Sort-Object -Unique)
    if ($required.Count -eq 0 -or @($required | Where-Object { $_ -cnotmatch '^[A-Za-z0-9+_.-]+$' }).Count -gt 0) {
        throw 'Required image profile package list is invalid'
    }
    $installed = @($components | ForEach-Object { $_.name })
    foreach ($name in $required) {
        if ($installed -cnotcontains $name) { throw "Required image profile package is absent: $name" }
    }
    return [ordered]@{
        artifact_sha256 = $ArtifactSha256
        package_manifest = [ordered]@{ format = 'rpm-nevra-v1'; packages = $packages }
        profile_inventory = [ordered]@{ profile = 'rke2'; required_packages = $required }
        sbom = [ordered]@{
            bomFormat = 'CycloneDX'; specVersion = '1.5'; version = 1
            metadata = [ordered]@{ component = [ordered]@{ type = 'file'; name = 'rocky-10.2-rke2-virtualbox.box'; hashes = @([ordered]@{ alg = 'SHA-256'; content = $ArtifactSha256 }) } }
            components = $components
        }
    }
}

function Assert-ImageSupplyChainEvidence {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$ArtifactSha256,
        [Parameter(Mandatory = $true)][string[]]$RequiredPackages
    )
    if ($null -eq $Evidence -or [string]$Evidence.artifact_sha256 -cne $ArtifactSha256 -or
        [string]$Evidence.sbom.bomFormat -cne 'CycloneDX' -or
        [string]$Evidence.sbom.specVersion -cne '1.5' -or
        [string]$Evidence.sbom.metadata.component.hashes[0].content -cne $ArtifactSha256 -or
        [string]$Evidence.sbom.metadata.component.hashes[0].alg -cne 'SHA-256' -or
        [string]$Evidence.package_manifest.format -cne 'rpm-nevra-v1' -or
        [string]$Evidence.profile_inventory.profile -cne 'rke2') {
        throw 'Supply-chain evidence is absent or not bound to the exact artifact'
    }
    if ((@($Evidence.profile_inventory.required_packages) -join "`n") -cne ((@($RequiredPackages | Sort-Object -Unique)) -join "`n")) {
        throw 'Supply-chain profile inventory differs from the contracted package roots'
    }
    $expected = New-ImageSupplyChainEvidence -ArtifactSha256 $ArtifactSha256 -RpmInventory (($Evidence.package_manifest.packages) -join "`n") -RequiredPackages @($Evidence.profile_inventory.required_packages)
    if (@($Evidence.sbom.components).Count -ne @($expected.sbom.components).Count) {
        throw 'SBOM components differ from the package manifest'
    }
    for ($index = 0; $index -lt $expected.sbom.components.Count; $index++) {
        if ([string]$Evidence.sbom.components[$index].name -cne [string]$expected.sbom.components[$index].name -or
            [string]$Evidence.sbom.components[$index].version -cne [string]$expected.sbom.components[$index].version) {
            throw 'SBOM components differ from the package manifest'
        }
    }
}

Export-ModuleMember -Function Set-PipelineUtf8, ConvertTo-NativeArgument, Invoke-BoundedProcess, Assert-ProcessSuccess, Write-Utf8Json, Read-JsonFile, Get-RepositoryRoot, Get-ToolchainLock, Resolve-WindowsTool, Get-LocalPipelineRoot, Assert-SafeChildPath, Remove-SafeTree, Get-FileSha256, Convert-ToWslPath, Invoke-WslProcess, Get-GitState, Get-VBoxMachines, Remove-OwnedVirtualMachine, New-ImageSupplyChainEvidence, Assert-ImageSupplyChainEvidence
