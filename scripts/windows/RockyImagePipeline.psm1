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
        [hashtable]$Environment = @{}
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
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
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
        if ($detail.Length -gt 2000) {
            $detail = $detail.Substring(0, 2000)
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
    $head = Invoke-WslProcess -Distribution $Distribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('rev-parse', 'HEAD') -TimeoutSeconds 15
    Assert-ProcessSuccess -Result $head -Operation 'Git HEAD resolution'
    $status = Invoke-WslProcess -Distribution $Distribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('status', '--porcelain=v1', '--untracked-files=all') -TimeoutSeconds 15
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
    if ($Name -notmatch '^ecommerce-rocky-10-2-(?:build|smoke)-[a-z0-9-]+$') {
        throw "Refusing cleanup of unowned VM name: $Name"
    }
    $current = Get-VBoxMachines -VBoxManage $VBoxManage -WorkingDirectory $WorkingDirectory
    if (-not $current.ContainsKey($Name)) {
        return 'NOT_NEEDED'
    }
    if ($InitialMachines.ContainsKey($Name)) {
        throw "Refusing cleanup of VM that existed before this run: $Name"
    }
    $result = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('unregistervm', $current[$Name], '--delete') -TimeoutSeconds 300 -WorkingDirectory $WorkingDirectory
    Assert-ProcessSuccess -Result $result -Operation "VirtualBox cleanup for $Name"
    return 'PASS'
}

Export-ModuleMember -Function Set-PipelineUtf8, Invoke-BoundedProcess, Assert-ProcessSuccess, Write-Utf8Json, Read-JsonFile, Get-RepositoryRoot, Get-ToolchainLock, Resolve-WindowsTool, Get-LocalPipelineRoot, Assert-SafeChildPath, Remove-SafeTree, Get-FileSha256, Convert-ToWslPath, Invoke-WslProcess, Get-GitState, Get-VBoxMachines, Remove-OwnedVirtualMachine
