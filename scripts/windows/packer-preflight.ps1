[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$WslDistribution = '',
    [string]$WslRepoRoot = '',
    [string]$EvidencePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$startedAt = [DateTime]::UtcNow.ToString('o')
$evidence = [ordered]@{
    schema = 1
    check = 'windows-packer-preflight'
    status = 'FAIL'
    started_at = $startedAt
    completed_at = $null
    tools = [ordered]@{}
    wsl2_duplicate_packer = 'NOT_CHECKED'
    error = $null
}

try {
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    $lock = Get-ToolchainLock -RepoRoot $root
    if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
        $EvidencePath = Join-Path $root '.context\evidence\rocky-image\rocky-10.2\windows\preflight.json'
    }

    $definitions = @(
        [pscustomobject]@{
            Name = 'packer'
            Executable = 'packer.exe'
            Fallbacks = @((Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'Microsoft\WinGet\Links\packer.exe'))
            Arguments = @('version')
            VersionRef = 'PACKER_VERSION'
            Pattern = '^Packer v(?<version>[0-9]+\.[0-9]+\.[0-9]+)'
        },
        [pscustomobject]@{
            Name = 'virtualbox'
            Executable = 'VBoxManage.exe'
            Fallbacks = @((Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'))
            Arguments = @('--version')
            VersionRef = 'VIRTUALBOX_VERSION'
            Pattern = '^(?<version>[0-9]+\.[0-9]+\.[0-9]+)r[0-9]+'
        },
        [pscustomobject]@{
            Name = 'vagrant'
            Executable = 'vagrant.exe'
            Fallbacks = @((Join-Path $env:ProgramFiles 'Vagrant\bin\vagrant.exe'))
            Arguments = @('--version')
            VersionRef = 'VAGRANT_VERSION'
            Pattern = '^Vagrant (?<version>[0-9]+\.[0-9]+\.[0-9]+)$'
        }
    )

    foreach ($definition in $definitions) {
        $lifecycle = $lock.tool_lifecycle.active.($definition.Name)
        $tool = $lock.tools.($definition.Name)
        if ($lifecycle.provision.type -ne 'windows-host') {
            throw "$($definition.Name) is not governed as a Windows-host tool"
        }
        if (@($tool.platforms) -notcontains 'windows/amd64') {
            throw "$($definition.Name) has no Windows amd64 toolchain artifact"
        }
        $expected = [string]$lock.versions.($definition.VersionRef)
        $path = Resolve-WindowsTool -Name $definition.Executable -FallbackPaths $definition.Fallbacks
        $result = Invoke-BoundedProcess -FilePath $path -Arguments $definition.Arguments -TimeoutSeconds 15 -WorkingDirectory $env:SystemRoot
        Assert-ProcessSuccess -Result $result -Operation "$($definition.Name) version probe"
        $output = ($result.StdOut + $result.StdErr).Trim()
        if ($output -notmatch $definition.Pattern) {
            throw "$($definition.Name) returned an unrecognized version"
        }
        $actual = $Matches.version
        if ($actual -ne $expected) {
            throw "$($definition.Name) version mismatch: expected $expected, got $actual"
        }
        $evidence.tools[$definition.Name] = [ordered]@{
            status = 'PASS'
            expected_version = $expected
            actual_version = $actual
            executable = $path
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($WslDistribution) -or -not [string]::IsNullOrWhiteSpace($WslRepoRoot)) {
        if ([string]::IsNullOrWhiteSpace($WslDistribution) -or [string]::IsNullOrWhiteSpace($WslRepoRoot)) {
            throw 'WslDistribution and WslRepoRoot must be provided together'
        }
        if ($WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or -not $WslRepoRoot.StartsWith('/')) {
            throw 'Invalid WSL distribution or repository path'
        }
        $probe = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments @('-c', 'import pathlib,shutil,sys; candidates=[shutil.which("packer"), str(pathlib.Path.home()/".local/bin/packer") if (pathlib.Path.home()/".local/bin/packer").exists() else None]; found=next((p for p in candidates if p), ""); print(found); sys.exit(1 if found else 0)') -TimeoutSeconds 60
        if ($probe.ExitCode -ne 0) {
            throw "A competing Packer executable exists in WSL2: $($probe.StdOut.Trim())"
        }
        $evidence.wsl2_duplicate_packer = 'ABSENT'
    }

    $evidence.status = 'PASS'
    $evidence.completed_at = [DateTime]::UtcNow.ToString('o')
    Write-Utf8Json -InputObject $evidence -Path $EvidencePath
    [Console]::WriteLine(($evidence | ConvertTo-Json -Depth 10 -Compress))
    [Console]::WriteLine('PASS windows-packer-preflight')
    exit 0
}
catch {
    $evidence.error = $_.Exception.Message
    $evidence.completed_at = [DateTime]::UtcNow.ToString('o')
    if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
        try { Write-Utf8Json -InputObject $evidence -Path $EvidencePath } catch { }
    }
    [Console]::Error.WriteLine("FAIL windows-packer-preflight: $($_.Exception.Message)")
    exit 1
}
