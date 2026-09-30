[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Reboot', 'Recover', 'ProbeUser', 'RunNative', 'Watchdog', 'SelfTest')]
    [string]$Action,
    [string]$CampaignId = '',
    [string]$SourceSha = '',
    [string]$LabRoot = 'C:\ecommerce-lab',
    [string]$WslDistribution = 'Ubuntu-24.04',
    [string]$WslRepoRoot = '/home/dev/ecommerce-1',
    [string]$ExpectedVmId = '',
    [string]$ExpectedOwnerSid = '',
    [int]$PrNumber = 0,
    [string]$PrRepository = '',
    [string]$PrBase = '',
    [string]$PrBaseSha = '',
    [string]$PrBranch = '',
    [string]$PinnedGhPath = '',
    [string]$PinnedGhVersion = '',
    [string]$PinnedGhSha256 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if (-not $windowsDirectory -or -not [IO.Directory]::Exists($windowsDirectory)) {
    throw 'Native smoke cannot resolve the trusted Windows system directory'
}
$env:SystemRoot = $windowsDirectory
$env:PATH = (@(
    (Join-Path $windowsDirectory 'System32'), $windowsDirectory,
    (Join-Path $windowsDirectory 'System32\Wbem'),
    (Join-Path $windowsDirectory 'System32\WindowsPowerShell\v1.0'),
    (Join-Path $windowsDirectory 'System32\OpenSSH'),
    'C:\Program Files\Oracle\VirtualBox'
) -join ';')
$env:PSModulePath = Join-Path $windowsDirectory 'System32\WindowsPowerShell\v1.0\Modules'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$EntryName = 'Windows - Ecommerce Network Smoke Native VT-x'
$StateName = 'native-boot.json'
$ResumeTaskName = 'Ecommerce-Network-Smoke-Native-Resume'
$WatchdogTaskName = 'Ecommerce-Network-Smoke-Native-Watchdog'
$ProbeTaskName = 'Ecommerce-Network-Smoke-Native-S4U-Probe'
$ProtectedTaskSddl = 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)'
$AdminSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$SystemSid = [Security.Principal.SecurityIdentifier]'S-1-5-18'
$UsersSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
$AuthenticatedUsersSid = [Security.Principal.SecurityIdentifier]'S-1-5-11'
$OwnerRightsSid = [Security.Principal.SecurityIdentifier]'S-1-3-4'
$script:SmokeRoot = ''
$script:PrivateShadowRoot = ''
$GuidPattern = '^\{[0-9a-fA-F-]{36}\}$'
$CampaignPattern = '^\d{8}T\d{6}Z-[0-9a-f]{12}$'
$VmPattern = '^ecommerce-rocky-10-2-smoke-[0-9a-f]{12}$'
$RunnerNames = @(
    'LabNativeBoot.ps1', 'LabNetworkSmoke.ps1', 'RockyImagePipeline.psm1', 'NativeVagrantSshSmoke.ps1',
    'LabNetworkSeed.ps1', 'LabSshIdentity.ps1', 'local-services-seed-server.ps1'
)

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class NativeSmokeDeleteGuard {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    public static SafeFileHandle OpenDirectory(string path) {
        // READ_ATTRIBUTES, SHARE_READ|SHARE_WRITE, OPEN_EXISTING,
        // BACKUP_SEMANTICS|OPEN_REPARSE_POINT. Denying SHARE_DELETE pins the path.
        SafeFileHandle handle = CreateFileW(path, 0x80, 0x3, IntPtr.Zero, 3,
            0x02000000 | 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Cannot pin native smoke directory against replacement");
        }
        return handle;
    }

    public static SafeFileHandle OpenRegularFile(string path) {
        // READ_DATA|READ_ATTRIBUTES; no FILE_SHARE_DELETE; inspect the link itself.
        SafeFileHandle handle = CreateFileW(path, 0x81, 0x3, IntPtr.Zero, 3,
            0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Cannot pin native smoke source file");
        }
        return handle;
    }
}
'@

function Open-LabDeleteGuard {
    param([string]$Path)
    $guard = [NativeSmokeDeleteGuard]::OpenDirectory($Path)
    try {
        [void](Assert-RegularLabPath -Path $Path -Directory $true)
        return $guard
    }
    catch {
        $guard.Dispose()
        throw
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'BLOCKED_PRIVILEGE: native boot BCD changes require an elevated administrator PowerShell token'
    }
}

function Assert-LabRoot {
    param([string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($resolved -ine 'C:\ecommerce-lab' -or -not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw 'Native boot requires the governed C:\ecommerce-lab root'
    }
    foreach ($candidate in @($resolved, (Join-Path $resolved 'network-smoke'))) {
        $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Native boot path is a reparse point: $candidate"
        }
    }
    return $resolved
}

function Assert-Guid {
    param([string]$Value, [string]$Forbidden = '')
    if ($Value -notmatch $GuidPattern -or ($Forbidden -and $Value -ieq $Forbidden)) {
        throw "Invalid or forbidden Windows loader identifier: $Value"
    }
    return $Value.ToLowerInvariant()
}

function Invoke-Bcd {
    param([string[]]$Arguments)
    $tool = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
    $result = Invoke-BoundedProcess -FilePath $tool -Arguments $Arguments -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $result -Operation "bcdedit $($Arguments -join ' ')"
    return ($result.StdOut + "`n" + $result.StdErr)
}

function Get-BcdEntries {
    param([string]$Text)
    $entries = @()
    foreach ($block in ($Text -split '(?:\r?\n){2,}')) {
        $match = [regex]::Match($block, '\{[0-9a-fA-F-]{36}\}')
        if ($match.Success) {
            $entries += [pscustomobject]@{ id=$match.Value.ToLowerInvariant(); text=$block }
        }
    }
    return @($entries)
}

function Get-BootManagerBinding {
    param([string]$Text)
    $default = @([regex]::Matches($Text, '(?im)^[ \t]*(?:default|d[eé]faut|par d[eé]faut)[ \t]+(?<value>[^\r\n]*)\r?$'))
    $sequence = @([regex]::Matches($Text, '(?im)^[ \t]*(?:bootsequence|s[eé]quence de d[eé]marrage)[ \t]+(?<value>[^\r\n]*)\r?$'))
    if ($default.Count -ne 1 -or $sequence.Count -gt 1 -or
        $default[0].Groups['value'].Value.Trim() -notmatch $GuidPattern) {
        throw 'BCD boot manager default or one-shot sequence is ambiguous'
    }
    $sequenceId = ''
    if ($sequence.Count -eq 1) {
        $value = $sequence[0].Groups['value'].Value.Trim()
        $following = $Text.Substring($sequence[0].Index + $sequence[0].Length)
        if ($value -notmatch $GuidPattern -or $following -match '^\r?\n[ \t]+\S') {
            throw 'BCD boot manager has an ambiguous or multi-entry bootsequence'
        }
        $sequenceId = Assert-Guid -Value $value
    }
    return [pscustomobject]@{
        default = (Assert-Guid -Value $default[0].Groups['value'].Value.Trim())
        sequence = $sequenceId
    }
}

function Get-BootContext {
    $currentText = Invoke-Bcd -Arguments @('/enum', '{current}', '/v')
    $current = @(Get-BcdEntries -Text $currentText)
    if ($current.Count -ne 1 -or $current[0].text -notmatch '(?i)winload\.(efi|exe)') {
        throw 'Current BCD entry is not one unambiguous Windows loader'
    }
    $manager = Get-BootManagerBinding -Text (Invoke-Bcd -Arguments @('/enum', '{bootmgr}', '/v'))
    return [pscustomobject]@{
        current = (Assert-Guid -Value $current[0].id)
        default = $manager.default
        sequence = $manager.sequence
        current_text = $currentText
    }
}

function Get-OwnedEntries {
    $entries = @(Get-BcdEntries -Text (Invoke-Bcd -Arguments @('/enum', 'all', '/v')))
    return @($entries | Where-Object {
        $_.text -match '(?i)winload\.(efi|exe)' -and
        $_.text -match ('(?m)^.*' + [regex]::Escape($EntryName) + '\s*$')
    })
}

function Assert-NoImageCycle {
    foreach ($name in @(
        'Ecommerce-VirtualBox-Native-Qualification',
        'Ecommerce-VirtualBox-Native-Watchdog',
        'Ecommerce-VirtualBox-Native-Import'
    )) {
        if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue)) {
            throw "Image native cycle is active: $name"
        }
    }
    $imageState = Join-Path $script:LabRootResolved 'prepared.json'
    if (Test-Path -LiteralPath $imageState -PathType Leaf) {
        $prepared = Read-JsonFile $imageState
        if ([string]$prepared.status -ne 'COMPLETE') {
            $startup = Read-JsonFile (Join-Path $script:LabRootResolved 'startup-real\state.json')
            $recovery = Read-JsonFile (Join-Path $script:LabRootResolved 'evidence\current\recovery.json')
            if ($prepared.schema -ne 1 -or $prepared.status -ne 'PREPARED' -or
                $startup.schema -ne 1 -or $startup.mode -ne 'REAL' -or $startup.phase -ne 'FAILED' -or
                $startup.source_sha -ne $prepared.source_git_sha -or
                $startup.staging_manifest_sha256 -ne $prepared.staging_manifest_sha256 -or
                $startup.normal_boot_id -ne $prepared.normal_boot_id -or
                $startup.native_boot_id -ne $prepared.native_boot_id -or
                $recovery.schema -ne 1 -or $recovery.status -ne 'PASS' -or
                $recovery.next_boot -ne $prepared.normal_boot_id -or
                $recovery.scheduled_task_removed -ne $true -or
                $recovery.native_entry_removed -ne $true) {
                throw 'Image native cycle is active or lacks verified failed-cycle recovery'
            }
        }
    }
    $imageEntries = @(Get-BcdEntries -Text (Invoke-Bcd -Arguments @('/enum','all','/v')) |
        Where-Object { $_.text -match '(?i)winload\.(efi|exe)' -and
            $_.text -match '(?m)^.*Windows - VirtualBox VT-x native\s*$' })
    if ($imageEntries.Count -ne 0) { throw 'Image native BCD entry still exists' }
}

function Assert-WslHead {
    param([string]$Expected)
    if ($Expected -notmatch '^[0-9a-f]{40}$' -or $WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or
        $WslRepoRoot -notmatch '^/[A-Za-z0-9._/-]+$' -or $WslRepoRoot.Contains('..') -or
        $PrNumber -lt 1 -or $PrRepository -cne 'dst-red-Wire/ecommerce-1' -or
        $PrBase -cne 'main' -or $PrBaseSha -notmatch '^[0-9a-f]{40}$' -or
        $PrBranch -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or $PrBranch.Contains('..') -or
        $PinnedGhVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
        $PinnedGhSha256 -notmatch '^[0-9a-f]{64}$' -or
        $PinnedGhPath -notmatch '^/[A-Za-z0-9._/-]+$' -or $PinnedGhPath.Contains('..') -or
        $PinnedGhPath -notmatch ('/tools/gh-' + [regex]::Escape($PinnedGhVersion) + '/bin/gh$')) {
        throw 'Exact SHA, PR, managed gh or WSL binding is invalid'
    }
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    $ghHash = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/sha256sum',$PinnedGhPath) -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $ghHash -Operation 'managed GitHub CLI SHA256'
    $hashMatch = [regex]::Match($ghHash.StdOut.Trim(), '^([0-9a-f]{64})  /\S+$')
    if (-not $hashMatch.Success -or $hashMatch.Groups[1].Value -cne $PinnedGhSha256) {
        throw 'Managed GitHub CLI bytes differ from pinned archive'
    }
    $ghVersion = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--',$PinnedGhPath,'--version') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $ghVersion -Operation 'managed GitHub CLI version'
    $versionLine = ($ghVersion.StdOut -split "[`r`n]")[0]
    $versionMatch = [regex]::Match($versionLine, '^gh version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)')
    if (-not $versionMatch.Success -or $versionMatch.Groups[1].Value -cne $PinnedGhVersion) {
        throw 'Managed GitHub CLI version differs from pin'
    }
    $head = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/git','rev-parse','HEAD') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $head -Operation 'exact WSL repository HEAD'
    if ($head.StdOut.Trim() -ne $Expected) { throw 'Local WSL Git HEAD differs from the exact runner source SHA' }
    $status = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/git','status','--porcelain=v1','--untracked-files=all') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $status -Operation 'exact WSL worktree status'
    if (-not [string]::IsNullOrWhiteSpace($status.StdOut)) { throw 'Exact-SHA native boot requires a clean WSL worktree' }
    $branch = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/git','symbolic-ref','--quiet','--short','HEAD') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $branch -Operation 'exact WSL branch'
    if ($branch.StdOut.Trim() -cne $PrBranch) { throw 'Local WSL branch differs from exact PR binding' }
    $prEndpoint = "repos/$PrRepository/pulls/$PrNumber"
    $published = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--',$PinnedGhPath,'api',$prEndpoint) -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $published -Operation 'exact published PR'
    $pr = ConvertFrom-Json -InputObject $published.StdOut -ErrorAction Stop
    if ([string]$pr.number -cne [string]$PrNumber -or $pr.state -cne 'open' -or
        $pr.draft -ne $false -or $null -ne $pr.merged_at -or
        $pr.head.ref -cne $PrBranch -or $pr.head.sha -cne $Expected -or
        $pr.head.repo.full_name -cne $PrRepository -or
        $pr.base.ref -cne $PrBase -or $pr.base.sha -cne $PrBaseSha -or
        $pr.base.repo.full_name -cne $PrRepository) {
        throw 'Exact PR number, HEAD, base or repository changed during native preparation'
    }
    $baseEndpoint = "repos/$PrRepository/branches/$PrBase"
    $currentBase = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--',$PinnedGhPath,'api',$baseEndpoint) -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $currentBase -Operation 'exact PR base'
    $base = ConvertFrom-Json -InputObject $currentBase.StdOut -ErrorAction Stop
    if ($base.name -cne $PrBase -or $base.commit.sha -cne $PrBaseSha) {
        throw 'PR base moved during native preparation'
    }
    $tree = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/git','rev-parse','HEAD^{tree}') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $tree -Operation 'exact WSL repository tree'
    return $tree.StdOut.Trim()
}

function Get-NativeGitBlobSha1 {
    param([byte[]]$Bytes)
    $utf8 = [Text.UTF8Encoding]::new($false,$true)
    $text = $utf8.GetString($Bytes).Replace("`r`n","`n")
    if ($text.Contains("`r")) { throw 'Protected native Git input has an unsupported newline' }
    $content = $utf8.GetBytes($text)
    $prefix = [Text.Encoding]::ASCII.GetBytes("blob $($content.Length)`0")
    $blob = New-Object byte[] ($prefix.Length + $content.Length)
    [Buffer]::BlockCopy($prefix,0,$blob,0,$prefix.Length)
    [Buffer]::BlockCopy($content,0,$blob,$prefix.Length,$content.Length)
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try { return -join ($sha1.ComputeHash($blob) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha1.Dispose() }
}

function Assert-ShadowGitObjects {
    param([string]$Id, [string]$Sha)
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    $converted = Invoke-BoundedProcess -FilePath $wsl -Arguments @(
        '-d',$WslDistribution,'--','/usr/bin/wslpath','-u',$script:SmokeRoot
    ) -TimeoutSeconds 30 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $converted -Operation 'protected native shadow WSL path'
    $wslShadow = $converted.StdOut.Trim().TrimEnd('/')
    if (-not $wslShadow.StartsWith('/mnt/c/Program Files/EcommerceNativeSmoke/',[StringComparison]::Ordinal)) {
        throw 'Protected native shadow is not mounted at its governed Windows path'
    }
    $bindings = @()
    foreach ($name in $RunnerNames) {
        $relative = "scripts/windows/$name"
        $bindings += [pscustomobject]@{ source=$relative; shadow="runner-$Sha/$relative" }
    }
    $bindings += [pscustomobject]@{
        source='platform/vagrant/rocky-image-smoke/Vagrantfile'
        shadow="$Id/platform/vagrant/rocky-image-smoke/Vagrantfile"
    }
    $bindings += [pscustomobject]@{
        source='platform/vagrant/rocky-image-smoke/Vagrantfile'
        shadow="$Id/smoke-run/Vagrantfile"
    }
    $bindings += [pscustomobject]@{
        source='config/artifacts/rocky-10.2-base-packages.lock.json'
        shadow="$Id/config/artifacts/rocky-10.2-base-packages.lock.json"
    }
    foreach ($binding in $bindings) {
        $expected = Invoke-BoundedProcess -FilePath $wsl -Arguments @(
            '-d',$WslDistribution,'--cd',$WslRepoRoot,'--','/usr/bin/git','rev-parse',"${Sha}:$($binding.source)"
        ) -TimeoutSeconds 30 -WorkingDirectory $env:SystemRoot
        Assert-ProcessSuccess -Result $expected -Operation "exact native Git object $($binding.source)"
        $actual = Get-NativeGitBlobSha1 -Bytes ([IO.File]::ReadAllBytes(
            (Join-Path $script:SmokeRoot $binding.shadow.Replace('/','\'))))
        if ($expected.StdOut.Trim() -notmatch '^[0-9a-f]{40}$' -or
            $actual -ne $expected.StdOut.Trim()) {
            throw "Protected native input differs from the immutable Git object: $($binding.shadow)"
        }
    }
}

function Assert-StagedCampaignManifest {
    param([string]$Stage)
    $manifest = Join-Path $Stage 'SHA256SUMS'
    $seen = @{}
    foreach ($line in [IO.File]::ReadAllLines($manifest, [Text.Encoding]::UTF8)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$') {
            throw 'Retained campaign staging manifest is malformed'
        }
        $expected = $Matches[1]
        $relative = $Matches[2]
        if ($relative -match '(^|/)\.\.(/|$)' -or $relative -match '(^|/)\.(/|$)') {
            throw 'Retained campaign staging manifest has an unsafe path'
        }
        if ($seen.ContainsKey($relative)) { throw 'Retained campaign staging manifest repeats a path' }
        $seen[$relative] = $true
        $candidate = [IO.Path]::GetFullPath((Join-Path $Stage $relative.Replace('/','\')))
        if (-not $candidate.StartsWith($Stage.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
            ((Get-Item -LiteralPath $candidate).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileSha256 -Path $candidate) -ne $expected) {
            throw "Retained campaign staged input differs: $relative"
        }
    }
    if ($seen.Count -lt 3 -or -not $seen.ContainsKey('platform/vagrant/rocky-image-smoke/Vagrantfile')) {
        throw 'Retained campaign staging manifest is incomplete'
    }
}

function Assert-RunnerIdentity {
    param($Manifest, [string]$Id, [string]$Sha, [string]$Tree)
    if ($Manifest.campaign_id -ne $Id -or $Manifest.source_sha -ne $Sha -or
        $Manifest.source_tree_sha -ne $Tree -or $Tree -notmatch '^[0-9a-f]{40}$') {
        throw 'Exact-SHA runner campaign, source SHA or tree binding differs'
    }
}

function Assert-ExistingCampaign {
    param([string]$Id, [string]$Sha, [switch]$LocalOnly)
    if ($Id -notmatch $CampaignPattern) { throw 'Network smoke campaign ID is invalid' }
    if ($Sha -notmatch '^[0-9a-f]{40}$') { throw 'Exact native smoke runner SHA is invalid' }
    $stage = Join-Path $script:SmokeRoot $Id
    $runner = Join-Path $script:SmokeRoot "runner-$Sha"
    foreach ($path in @($stage,$runner)) {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Campaign or runner directory is invalid: $path"
        }
    }
    Assert-StagedCampaignManifest -Stage $stage
    $prepared = Read-JsonFile (Join-Path $stage 'prepared.json')
    $result = Read-JsonFile (Join-Path (Join-Path $script:EvidenceBase $Id) 'result.json')
    $runnerManifest = Read-JsonFile (Join-Path $runner 'runner.json')
    if ($prepared.schema -ne 1 -or $prepared.status -ne 'PREPARED' -or $prepared.campaign_id -ne $Id -or
        $prepared.retain_vm -ne $true -or $result.schema -ne 1 -or $result.campaign_id -ne $Id -or
        $result.source_git_sha -ne $prepared.source_sha -or $result.cleanup.vm_preserved -ne $true -or
        $result.vm_name -notmatch $VmPattern -or $result.cleanup.vm_name -ne $result.vm_name -or
        [string]$result.cleanup.vm_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        [string]$runnerManifest.source_tree_sha -notmatch '^[0-9a-f]{40}$') {
        throw 'Retained campaign, VM or exact-SHA runner binding is invalid'
    }
    $tree = if ($LocalOnly) { [string]$runnerManifest.source_tree_sha } else { Assert-WslHead -Expected $Sha }
    Assert-RunnerIdentity -Manifest $runnerManifest -Id $Id -Sha $Sha -Tree $tree
    $runnerFiles = @($runnerManifest.runner_files.PSObject.Properties.Name)
    if ($runnerFiles.Count -ne $RunnerNames.Count) { throw 'Exact runner file set is incomplete' }
    if (-not $LocalOnly) {
        $sourceRoot = "\\wsl.localhost\$WslDistribution$($WslRepoRoot.Replace('/', '\'))"
    }
    foreach ($name in $RunnerNames) {
        if ($name -notin $runnerFiles -or [string]$runnerManifest.runner_files.$name -notmatch '^[0-9a-f]{64}$' -or
            (Get-FileSha256 -Path (Join-Path $runner "scripts\windows\$name")) -ne [string]$runnerManifest.runner_files.$name -or
            (-not $LocalOnly -and (Get-FileSha256 -Path (Join-Path $sourceRoot "scripts\windows\$name")) -ne [string]$runnerManifest.runner_files.$name)) {
            throw "Staged exact-SHA runner differs: $name"
        }
    }
    $packageRelative = 'config\artifacts\rocky-10.2-base-packages.lock.json'
    $packageDigest = [string]$runnerManifest.package_lock_sha256
    if ($packageDigest -notmatch '^[0-9a-f]{64}$' -or
        ($script:PrivateShadowRoot -and (Get-FileSha256 -Path (Join-Path $stage $packageRelative)) -ne $packageDigest) -or
        (-not $LocalOnly -and (Get-FileSha256 -Path (Join-Path $sourceRoot $packageRelative)) -ne $packageDigest)) {
        throw 'Staged native image qualification package lock differs from the exact runner source'
    }
    $stagedVagrantfile = Join-Path $stage 'platform\vagrant\rocky-image-smoke\Vagrantfile'
    $runtimeVagrantfile = Join-Path $stage 'smoke-run\Vagrantfile'
    $globalVagrantfile = Join-Path $stage 'smoke-run\vagrant-home\Vagrantfile'
    if (Test-Path -LiteralPath $globalVagrantfile) {
        throw 'Retained Vagrant home contains a global Vagrantfile executable under S4U'
    }
    $vagrantfileDigest = [string]$runnerManifest.vagrantfile_sha256
    if ($vagrantfileDigest -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $stagedVagrantfile) -ne $vagrantfileDigest -or
        (Get-FileSha256 -Path $runtimeVagrantfile) -ne $vagrantfileDigest -or
        (-not $LocalOnly -and (Get-FileSha256 -Path (Join-Path $sourceRoot 'platform\vagrant\rocky-image-smoke\Vagrantfile')) -ne $vagrantfileDigest)) {
        throw 'Retained VM Vagrantfile differs from the exact runner contract'
    }
    $box = [IO.Path]::GetFullPath([string]$prepared.box_path)
    if ($box -notlike "$($script:LabRootResolved)\artifacts\*" -or
        [string]$prepared.box_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$prepared.box_manifest_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Retained campaign box path or digest provenance is invalid'
    }
    $boxToVerify = if ($script:PrivateShadowRoot) { Join-Path $script:SmokeRoot 'box\source.box' } else { $box }
    $manifestToVerify = if ($script:PrivateShadowRoot) { Join-Path $script:SmokeRoot 'box\manifest.json' }
                        else { Join-Path (Split-Path -Parent $box) 'manifest.json' }
    if ((Get-FileSha256 -Path $boxToVerify) -ne [string]$prepared.box_sha256 -or
        (Get-FileSha256 -Path $manifestToVerify) -ne [string]$prepared.box_manifest_sha256 -or
        $result.box_digest -ne $prepared.box_sha256) {
        throw 'Retained campaign box digest or provenance differs'
    }
    $vbox = Resolve-WindowsTool -Name 'VBoxManage.exe' -FallbackPaths @('C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory (Join-Path $stage 'smoke-run')
    $vagrantId = Join-Path $stage 'smoke-run\.vagrant\machines\default\virtualbox\id'
    if (-not $machines.ContainsKey([string]$result.vm_name) -or
        ([string]$machines[[string]$result.vm_name]).Trim('{}') -ine [string]$result.cleanup.vm_id -or
        -not (Test-Path -LiteralPath $vagrantId -PathType Leaf) -or
        [IO.File]::ReadAllText($vagrantId).Trim().Trim('{}') -ine [string]$result.cleanup.vm_id) {
        throw 'Retained VirtualBox VM UUID differs from the campaign checkpoint'
    }
    return [pscustomobject]@{
        stage=$stage; runner=$runner; vm_name=[string]$result.vm_name; source_tree_sha=$tree
        vm_id=[string]$result.cleanup.vm_id; box_sha256=[string]$prepared.box_sha256
        runner_manifest_sha256=(Get-FileSha256 -Path (Join-Path $runner 'runner.json'))
    }
}

function Assert-NormalBoot {
    $boot = Get-BootContext
    if ($boot.current -ne $boot.default -or $boot.sequence -ne '' -or
        $boot.current_text -match '(?im)^\s*hypervisorlaunchtype\s+off\s*$' -or
        -not (Get-CimInstance Win32_ComputerSystem).HypervisorPresent) {
        throw 'Native boot preparation requires the normal default Windows loader with no pending bootsequence'
    }
    return $boot
}

function Assert-StateBinding {
    param($State, [string]$ExpectedPhase)
    if ($State.schema -ne 1 -or $State.mode -ne 'NETWORK_SMOKE_NATIVE' -or
        $State.phase -ne $ExpectedPhase -or $State.campaign_id -notmatch $CampaignPattern -or
        $State.source_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$State.shadow_root -ine (Get-NativeShadowRoot -Id ([string]$State.campaign_id) -Sha ([string]$State.source_sha)) -or
        $State.normal_boot_id -notmatch $GuidPattern -or $State.native_boot_id -notmatch $GuidPattern -or
        $State.normal_boot_id -ieq $State.native_boot_id -or
        $State.entry_name -ne $EntryName -or [string]$State.vm_name -notmatch $VmPattern -or
        $State.vm_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        [string]$State.expected_vm_id -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -or
        [string]$State.expected_vm_id -ine [string]$State.vm_id -or
        $State.owner_sid -notmatch '^S-\d+(?:-\d+)+$' -or
        $State.source_tree_sha -notmatch '^[0-9a-f]{40}$' -or
        $State.runner_manifest_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $State.s4u_probe_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $State.vsmlaunchtype -notin @('PASS','UNSUPPORTED') -or
        $State.bcd_backup_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Persistent owned native boot state is invalid'
    }
}

function Import-ProtectedPrBinding {
    param($State)
    $required = @(
        'pr_number','pr_repository','pr_base','pr_base_sha','pr_branch',
        'pinned_gh_path','pinned_gh_version','pinned_gh_sha256'
    )
    foreach ($name in $required) {
        if ($State.PSObject.Properties.Name -notcontains $name) {
            throw "Prepared native PR binding is incomplete: $name"
        }
    }
    $script:PrNumber = [int]$State.pr_number
    $script:PrRepository = [string]$State.pr_repository
    $script:PrBase = [string]$State.pr_base
    $script:PrBaseSha = [string]$State.pr_base_sha
    $script:PrBranch = [string]$State.pr_branch
    $script:PinnedGhPath = [string]$State.pinned_gh_path
    $script:PinnedGhVersion = [string]$State.pinned_gh_version
    $script:PinnedGhSha256 = [string]$State.pinned_gh_sha256
}

function Assert-OwnedBcdEntry {
    param($State)
    $entries = @(Get-OwnedEntries)
    if ($entries.Count -ne 1 -or $entries[0].id -ne [string]$State.native_boot_id -or
        $entries[0].text -notmatch '(?im)^\s*hypervisorlaunchtype\s+off\s*$') {
        throw 'Owned native BCD entry is absent, ambiguous or no longer has hypervisorlaunchtype off'
    }
    if ($State.vsmlaunchtype -eq 'PASS' -and
        $entries[0].text -notmatch '(?im)^\s*vsmlaunchtype\s+off\s*$') {
        throw 'Owned native BCD entry no longer has vsmlaunchtype off'
    }
}

function Get-TaskPrincipalSid {
    param($Task)
    $userId = [string]$Task.Principal.UserId
    if ($userId -match '^S-\d+(?:-\d+)+$') { return $userId }
    return [Security.Principal.NTAccount]::new($userId).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-NativeTaskArguments {
    param([string]$Runner, [string]$Mode, [string]$Id, [string]$Sha)
    $parts = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Runner,
        '-Action',$Mode,'-CampaignId',$Id,'-SourceSha',$Sha,'-LabRoot',$script:LabRootResolved)
    return (($parts | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ')
}

function Assert-NativeTaskIdentity {
    param($Task, [string]$Name, [string]$Runner, [string]$Mode, [string]$Id, [string]$Sha,
        [string]$Sid, [string]$LogonType)
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($Task.TaskName -ne $Name -or $Task.TaskPath -ne '\' -or @(($Task.Actions)).Count -ne 1 -or
        (Get-TaskPrincipalSid -Task $Task) -ne $Sid -or
        [string]$Task.Principal.LogonType -ne $LogonType -or
        [string]$Task.Principal.RunLevel -ne 'Highest' -or
        [string]$Task.Actions[0].Execute -ine $powershell -or
        [string]$Task.Actions[0].Arguments -ne (Get-NativeTaskArguments -Runner $Runner -Mode $Mode -Id $Id -Sha $Sha) -or
        @(($Task.Triggers)).Count -ne 1 -or
        [string]$Task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {
        throw "Native smoke scheduled task identity differs: $Name"
    }
}

function Assert-RegularLabPath {
    param([string]$Path, [bool]$Directory)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Native smoke security path is absent, has the wrong type or is a reparse point: $Path"
    }
    return $item
}

function Assert-NoNonAdminDeleteChild {
    param($Acl, [string]$Path)
    foreach ($rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -eq 0) {
            continue
        }
        if ($rule.IdentityReference.Value -notin @($AdminSid.Value,$SystemSid.Value)) {
            throw "Native smoke parent grants unprivileged DeleteChild: $Path"
        }
    }
}

function Assert-LabParentBoundary {
    param([string]$Path, [bool]$WindowsRoot = $false)
    [void](Assert-RegularLabPath -Path $Path -Directory $true)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    Assert-NoNonAdminDeleteChild -Acl $acl -Path $Path
    if ($WindowsRoot) {
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notmatch '^S-1-5-80-' -and $owner -notin @($AdminSid.Value,$SystemSid.Value)) {
            throw 'Native smoke Windows volume root is not owned by a privileged identity'
        }
        return
    }
    Assert-ProtectedLabAcl -Acl $acl -Directory $true -Path $Path
}

function Protect-LabParentBoundary {
    param([string]$Path)
    Protect-LabPath -Path $Path -Directory $true
    Assert-LabParentBoundary -Path $Path
}

function New-ProtectedLabAcl {
    param([bool]$Directory)
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity }
           else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($AdminSid)
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($entry in @(
        @($AdminSid,[Security.AccessControl.FileSystemRights]::FullControl),
        @($SystemSid,[Security.AccessControl.FileSystemRights]::FullControl),
        @($UsersSid,[Security.AccessControl.FileSystemRights]::ReadAndExecute),
        @($OwnerRightsSid,[Security.AccessControl.FileSystemRights]::ReadAndExecute)
    )) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $entry[0],$entry[1],$inherit,[Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Get-NativeTaskFolder {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    return $service.GetFolder('\')
}

function Assert-NativeTaskSecurity {
    param([string]$Name)
    $registered = (Get-NativeTaskFolder).GetTask($Name)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new(
        [string]$registered.GetSecurityDescriptor(7))
    if ($raw.Owner.Value -ne $AdminSid.Value -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or
        $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 2) {
        throw "Native smoke task ACL owner or protection differs: $Name"
    }
    $seen = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
            $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
            $ace.AccessMask -ne 0x10000000 -or
            $ace.SecurityIdentifier.Value -notin @($AdminSid.Value,$SystemSid.Value) -or
            $seen.ContainsKey($ace.SecurityIdentifier.Value)) {
            throw "Native smoke task ACL grants an unexpected principal: $Name"
        }
        $seen[$ace.SecurityIdentifier.Value] = $true
    }
    if (-not $seen.ContainsKey($AdminSid.Value) -or -not $seen.ContainsKey($SystemSid.Value)) {
        throw "Native smoke task ACL lacks privileged principals: $Name"
    }
}

function Register-ProtectedNativeTask {
    param([string]$Name, $Action, $Trigger, $Principal, $Settings,
        [string]$UserId, [int]$LogonType)
    $definition = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
    $xml = Export-ScheduledTask -InputObject $definition
    # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE: apply the privileged-only
    # DACL atomically, before the creator's standard token can edit the action.
    [void](Get-NativeTaskFolder).RegisterTask($Name,$xml,0x12,$UserId,$null,$LogonType,$ProtectedTaskSddl)
    Assert-NativeTaskSecurity -Name $Name
}

function New-PrivateShadowAcl {
    param([bool]$Directory)
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity }
           else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($AdminSid)
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($AdminSid,$SystemSid)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)))
    }
    return $acl
}

function Assert-PrivateShadowAcl {
    param($Acl, [bool]$Directory, [string]$Path)
    if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $AdminSid.Value -or
        -not $Acl.AreAccessRulesProtected) {
        throw "Native smoke private ACL owner or inheritance differs: $Path"
    }
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    $rules = @($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "Native smoke private ACL rule count differs: $Path" }
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin @($AdminSid.Value,$SystemSid.Value) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inherit -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Native smoke private ACL grants unexpected rights: $Path"
        }
    }
}

function Test-PrivateShadowPath {
    param([string]$Path)
    if (-not $script:PrivateShadowRoot) { return $false }
    return ($Path -ieq $script:PrivateShadowRoot -or
        $Path.StartsWith($script:PrivateShadowRoot + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Assert-ProtectedLabAcl {
    param($Acl, [bool]$Directory, [string]$Path)
    if ($Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $AdminSid.Value -or
        -not $Acl.AreAccessRulesProtected) {
        throw "Native smoke ACL owner or inheritance differs: $Path"
    }
    $expected = @{
        $AdminSid.Value=[Security.AccessControl.FileSystemRights]::FullControl
        $SystemSid.Value=[Security.AccessControl.FileSystemRights]::FullControl
        $UsersSid.Value=([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize)
        $OwnerRightsSid.Value=([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize)
    }
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    $rules = @($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expected.Count) { throw "Native smoke ACL rule set differs: $Path" }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne $expected[$sid] -or
            $rule.InheritanceFlags -ne $inherit -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Native smoke ACL grants unexpected rights: $Path"
        }
    }
}

function Protect-LabPath {
    param([string]$Path, [bool]$Directory)
    [void](Assert-RegularLabPath -Path $Path -Directory $Directory)
    if (Test-PrivateShadowPath -Path $Path) {
        Set-Acl -LiteralPath $Path -AclObject (New-PrivateShadowAcl -Directory $Directory) -ErrorAction Stop
        Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $Directory -Path $Path
    }
    else {
        Set-Acl -LiteralPath $Path -AclObject (New-ProtectedLabAcl -Directory $Directory) -ErrorAction Stop
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $Directory -Path $Path
    }
}

function Write-ProtectedNativeJson {
    param($InputObject, [string]$Path, [string]$GovernedRoot)
    $path = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($GovernedRoot).TrimEnd('\')
    if (-not $path.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Protected native JSON destination differs from its governed directory'
    }
    [void](Assert-RegularLabPath -Path $root -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $root) -Directory $true -Path $root
    $parent = Split-Path -Parent $path
    [void](Assert-RegularLabPath -Path $parent -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $parent) -Directory $true -Path $parent
    $temporary = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        (($InputObject | ConvertTo-Json -Depth 20) + "`n"))
    $stream = $null
    try {
        $stream = [IO.File]::Create($temporary,4096,[IO.FileOptions]::None,
            (New-ProtectedLabAcl -Directory $false))
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [void](Assert-RegularLabPath -Path $temporary -Directory $false)
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $temporary) -Directory $false -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $path -Force
        [void](Assert-RegularLabPath -Path $path -Directory $false)
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $path) -Directory $false -Path $path
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Write-NativeBootState {
    param($State)
    if ([IO.Path]::GetFullPath($script:StatePath) -ine (Join-Path $script:SmokeRoot $StateName)) {
        throw 'Native boot state destination differs from the protected shadow'
    }
    Assert-ShadowBoundary
    Write-ProtectedNativeJson -InputObject $State -Path $script:StatePath -GovernedRoot $script:SmokeRoot
}

function Visit-LabTree {
    param([string]$Root, [bool]$Seal, [switch]$Preflight)
    [void](Assert-RegularLabPath -Path $Root -Directory $true)
    if ($Seal) { Protect-LabPath -Path $Root -Directory $true }
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $path = [string]$item.FullName
            [void](Assert-RegularLabPath -Path $path -Directory ([bool]$item.PSIsContainer))
            if ($Seal) { Protect-LabPath -Path $path -Directory ([bool]$item.PSIsContainer) }
            elseif (-not $Preflight) {
                if (Test-PrivateShadowPath -Path $path) {
                    Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $path) -Directory ([bool]$item.PSIsContainer) -Path $path
                }
                else { Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $path) -Directory ([bool]$item.PSIsContainer) -Path $path }
            }
            if ($item.PSIsContainer) { $stack.Push($path) }
        }
    }
    if (-not $Preflight) { Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $Root) -Directory $true -Path $Root }
}

function Assert-ShadowProgramFiles {
    Assert-LabParentBoundary -Path 'C:\' -WindowsRoot $true
    $rootAcl = Get-Acl -LiteralPath 'C:\' -ErrorAction Stop
    foreach ($rule in $rootAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0 -or
            $rule.IdentityReference.Value -in @($AdminSid.Value,$SystemSid.Value) -or
            $rule.IdentityReference.Value -match '^S-1-5-80-') { continue }
        $rootMutation = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [Security.AccessControl.FileSystemRights]::Delete
        if (($rule.FileSystemRights -band $rootMutation) -ne 0) {
            throw 'Native shadow volume root grants unprivileged ACL or deletion rights'
        }
    }
    $path = 'C:\Program Files'
    [void](Assert-RegularLabPath -Path $path -Directory $true)
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notmatch '^S-1-5-80-' -and $owner -notin @($AdminSid.Value,$SystemSid.Value)) {
        throw 'Native shadow parent has an unprivileged owner'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
            continue
        }
        $sid = $rule.IdentityReference.Value
        if ($sid -eq $AdminSid.Value -or $sid -eq $SystemSid.Value -or $sid -match '^S-1-5-80-') { continue }
        $mutationRights = [Security.AccessControl.FileSystemRights]::Write -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        if (($rule.FileSystemRights -band $mutationRights) -ne 0) {
            throw 'Native shadow parent grants unprivileged mutation rights'
        }
    }
}

function Assert-ShadowBoundary {
    Assert-ShadowProgramFiles
    $parent = 'C:\Program Files\EcommerceNativeSmoke'
    [void](Assert-RegularLabPath -Path $parent -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $parent) -Directory $true -Path $parent
    [void](Assert-RegularLabPath -Path $script:SmokeRoot -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $script:SmokeRoot) -Directory $true -Path $script:SmokeRoot
}

function Protect-NativeInputs {
    param([string]$Id)
    if ($Id -notmatch $CampaignPattern) { throw 'Native smoke protected campaign ID is invalid' }
    Assert-ShadowBoundary
    Visit-LabTree -Root $script:SmokeRoot -Seal $false -Preflight
    Visit-LabTree -Root $script:SmokeRoot -Seal $true
}

function Assert-ProtectedNativeInputs {
    param([string]$Id)
    if ($Id -notmatch $CampaignPattern) { throw 'Native smoke protected campaign ID is invalid' }
    Assert-ShadowBoundary
    Visit-LabTree -Root $script:SmokeRoot -Seal $false
}

function Assert-ProtectedNativeControlPlane {
    param([string]$Sha)
    Assert-ShadowBoundary
    [void](Assert-RegularLabPath -Path $script:StatePath -Directory $false)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $script:StatePath) -Directory $false -Path $script:StatePath
    Visit-LabTree -Root (Join-Path $script:SmokeRoot "runner-$Sha") -Seal $false
}

function Assert-NativeRecoveredProof {
    param($State)
    Assert-ProtectedNativeInputs -Id ([string]$State.campaign_id)
    if ($State.PSObject.Properties.Name -notcontains 'run_status' -or $State.run_status -ne 'PASS') { return }
    $resultPath = Join-Path (Join-Path $script:EvidenceBase ([string]$State.campaign_id)) 'result.json'
    if ([string]$State.result_sha256 -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $resultPath) -ne [string]$State.result_sha256 -or
        (Get-FileSha256 -Path (Join-Path $script:SmokeRoot "runner-$($State.source_sha)\runner.json")) -ne
            [string]$State.runner_manifest_sha256 -or
        (Get-FileSha256 -Path (Join-Path $script:SmokeRoot 'box\source.box')) -ne [string]$State.box_sha256) {
        throw 'Recovered native smoke result, runner or box digest differs'
    }
    $result = Read-JsonFile $resultPath
    $relative = [string]$result.image_qualification.virtualbox_log_relative
    $logPath = Join-Path (Join-Path $script:SmokeRoot ([string]$State.campaign_id)) $relative.Replace('/','\')
    if ($relative -notmatch '^logs/ssh-resume-[0-9]{8}T[0-9]{6}Z/VBox\.log$' -or
        [string]$result.image_qualification.virtualbox_log_sha256 -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $logPath) -ne [string]$result.image_qualification.virtualbox_log_sha256) {
        throw 'Recovered native VT-x log digest differs from its protected result'
    }
}

function Get-NativeShadowRoot {
    param([string]$Id, [string]$Sha)
    if ($Id -notmatch $CampaignPattern -or $Sha -notmatch '^[0-9a-f]{40}$') {
        throw 'Native shadow requires an exact campaign and source SHA'
    }
    return Join-Path 'C:\Program Files\EcommerceNativeSmoke' "$Id-$Sha"
}

function Set-NativeShadowContext {
    param([string]$Id, [string]$Sha)
    $script:SmokeRoot = Get-NativeShadowRoot -Id $Id -Sha $Sha
    $script:EvidenceBase = Join-Path $script:SmokeRoot 'evidence\network-smoke'
    $script:PrivateShadowRoot = Join-Path $script:SmokeRoot 'identity'
    $script:StatePath = Join-Path $script:SmokeRoot $StateName
    $script:RuntimeLockPath = Join-Path $script:SmokeRoot '.runtime.lock'
}

function New-ShadowDirectory {
    param([string]$Path, [switch]$Private)
    if (Test-Path -LiteralPath $Path) { throw "Native shadow destination already exists: $Path" }
    $acl = if ($Private) { New-PrivateShadowAcl -Directory $true }
           else { New-ProtectedLabAcl -Directory $true }
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    [void](Assert-RegularLabPath -Path $Path -Directory $true)
    if ($Private) { Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $true -Path $Path }
    else { Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $true -Path $Path }
}

function Ensure-ShadowDirectory {
    param([string]$Path, [switch]$Private)
    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $resolved.StartsWith($script:SmokeRoot + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native shadow directory is outside the protected campaign root'
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        $parent = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $parent)) { Ensure-ShadowDirectory -Path $parent }
        New-ShadowDirectory -Path $Path -Private:$Private
        return
    }
    [void](Assert-RegularLabPath -Path $Path -Directory $true)
    if ($Private) { Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $true -Path $Path }
    else { Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $Path) -Directory $true -Path $Path }
}

function Copy-PinnedSourceFile {
    param([string]$Source, [string]$Destination, [switch]$Private,
        [string]$AllowedRoot = $script:LabRootResolved)
    $sourcePath = [IO.Path]::GetFullPath($Source)
    $labPrefix = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\') + '\'
    if (-not $sourcePath.StartsWith($labPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $Destination)) {
        throw 'Native shadow source or destination path is not unique and governed'
    }
    $directoryPath = Split-Path -Parent $sourcePath
    $parents = New-Object 'System.Collections.Generic.List[string]'
    while ($directoryPath.StartsWith($labPrefix,[StringComparison]::OrdinalIgnoreCase)) {
        $parents.Add($directoryPath)
        $directoryPath = Split-Path -Parent $directoryPath
    }
    if ($directoryPath -ine $AllowedRoot) { throw 'Native shadow source ancestry differs from laboratory root' }
    $guards = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    $sourceStream = $null
    $destinationStream = $null
    try {
        for ($index = $parents.Count - 1; $index -ge 0; $index--) {
            $guards.Add((Open-LabDeleteGuard -Path $parents[$index]))
        }
        $handle = [NativeSmokeDeleteGuard]::OpenRegularFile($sourcePath)
        try { [void](Assert-RegularLabPath -Path $sourcePath -Directory $false) }
        catch { $handle.Dispose(); throw }
        $sourceStream = [IO.FileStream]::new($handle,[IO.FileAccess]::Read)
        $acl = if ($Private) { New-PrivateShadowAcl -Directory $false }
               else { New-ProtectedLabAcl -Directory $false }
        $destinationStream = [IO.File]::Create($Destination,1048576,[IO.FileOptions]::None,$acl)
        $sourceStream.CopyTo($destinationStream,1048576)
        $destinationStream.Flush($true)
    }
    finally {
        if ($null -ne $destinationStream) { $destinationStream.Dispose() }
        if ($null -ne $sourceStream) { $sourceStream.Dispose() }
        foreach ($guard in $guards) { $guard.Dispose() }
    }
    [void](Assert-RegularLabPath -Path $Destination -Directory $false)
    if ($Private) { Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $Destination) -Directory $false -Path $Destination }
    else { Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $Destination) -Directory $false -Path $Destination }
}

function Copy-ShadowRelativeFile {
    param([string]$SourceRoot, [string]$DestinationRoot, [string]$Relative)
    if ($Relative -notmatch '^[A-Za-z0-9._/-]+$' -or $Relative.Contains('..')) {
        throw 'Native shadow relative source path is invalid'
    }
    $windowsRelative = $Relative.Replace('/','\')
    $destination = Join-Path $DestinationRoot $windowsRelative
    $resolved = [IO.Path]::GetFullPath($destination)
    if (-not $resolved.StartsWith($DestinationRoot.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native shadow destination escapes its campaign directory'
    }
    Ensure-ShadowDirectory -Path (Split-Path -Parent $resolved)
    Copy-PinnedSourceFile -Source (Join-Path $SourceRoot $windowsRelative) -Destination $resolved
}

function Get-OptionalShadowItem {
    param([string]$Path)
    try { return Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
    catch [System.IO.FileNotFoundException] { return $null }
}

function Remove-VerifiedShadowPrivateKey {
    param([string]$ShadowRoot, [scriptblock]$RuntimeClearProbe)
    if ($null -eq $RuntimeClearProbe) { throw 'Shadow key removal requires an explicit idle runtime probe' }
    $root = [IO.Path]::GetFullPath($ShadowRoot).TrimEnd('\')
    $identity = Join-Path $root 'identity'
    $key = Join-Path $identity 'id_ed25519'
    if ($null -eq (Get-OptionalShadowItem -Path $root)) { return $false }
    [void](Assert-RegularLabPath -Path $root -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $root) -Directory $true -Path $root
    if ($null -eq (Get-OptionalShadowItem -Path $identity)) { return $false }
    [void](Assert-RegularLabPath -Path $identity -Directory $true)
    Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $identity) -Directory $true -Path $identity
    if ($null -eq (Get-OptionalShadowItem -Path $key)) { return $false }
    [void](Assert-RegularLabPath -Path $key -Directory $false)
    Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $key) -Directory $false -Path $key
    if (-not (& $RuntimeClearProbe)) {
        throw 'Native shadow key removal requires normal boot and no owned task or BCD entry'
    }
    Remove-Item -LiteralPath $key -Force -ErrorAction Stop
    if ($null -ne (Get-OptionalShadowItem -Path $key)) {
        throw 'Native shadow private key remains after bounded removal'
    }
    return $true
}

function Remove-NativeShadowPrivateKey {
    param([string]$Id, [string]$Sha)
    $root = Get-NativeShadowRoot -Id $Id -Sha $Sha
    $identity = Join-Path $root 'identity'
    if ($script:SmokeRoot -ine $root -or $script:PrivateShadowRoot -ine $identity) {
        throw 'Native shadow key cleanup differs from the exact campaign and source root'
    }
    Assert-ShadowProgramFiles
    $parent = 'C:\Program Files\EcommerceNativeSmoke'
    if ($null -eq (Get-OptionalShadowItem -Path $parent)) { return $false }
    [void](Assert-RegularLabPath -Path $parent -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $parent) -Directory $true -Path $parent
    if ($null -eq (Get-OptionalShadowItem -Path $root)) { return $false }
    Assert-ShadowBoundary
    $runtimeClear = {
        $boot = Get-BootContext
        if ($boot.current -ne $boot.default -or $boot.sequence -ne '' -or
            @(Get-OwnedEntries).Count -ne 0) { return $false }
        foreach ($name in @($ResumeTaskName,$WatchdogTaskName,$ProbeTaskName)) {
            if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue)) {
                return $false
            }
        }
        return $true
    }
    return Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe $runtimeClear
}

function Initialize-NativeShadow {
    param([string]$Id, [string]$Sha, $OriginalCampaign)
    Assert-ShadowProgramFiles
    $originalSmokeRoot = $script:SmokeRoot
    $originalEvidenceBase = $script:EvidenceBase
    $parent = 'C:\Program Files\EcommerceNativeSmoke'
    if (-not (Test-Path -LiteralPath $parent)) {
        [void][IO.Directory]::CreateDirectory($parent,(New-ProtectedLabAcl -Directory $true))
    }
    [void](Assert-RegularLabPath -Path $parent -Directory $true)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $parent) -Directory $true -Path $parent
    Set-NativeShadowContext -Id $Id -Sha $Sha
    New-ShadowDirectory -Path $script:SmokeRoot
    $script:PrepareShadowCreated = $true
    $shadowLock = [IO.File]::Create($script:RuntimeLockPath,4096,[IO.FileOptions]::None,
        (New-ProtectedLabAcl -Directory $false))
    $shadowLock.Dispose()
    [void](Assert-RegularLabPath -Path $script:RuntimeLockPath -Directory $false)
    Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $script:RuntimeLockPath) -Directory $false -Path $script:RuntimeLockPath
    $stage = Join-Path $script:SmokeRoot $Id
    $runner = Join-Path $script:SmokeRoot "runner-$Sha"
    New-ShadowDirectory -Path $stage
    New-ShadowDirectory -Path $runner
    Ensure-ShadowDirectory -Path (Join-Path $runner 'scripts\windows')
    $originalRunner = Join-Path $originalSmokeRoot "runner-$Sha"
    Copy-PinnedSourceFile -Source (Join-Path $originalRunner 'runner.json') -Destination (Join-Path $runner 'runner.json')
    foreach ($name in $RunnerNames) {
        Copy-PinnedSourceFile -Source (Join-Path $originalRunner "scripts\windows\$name") -Destination (Join-Path $runner "scripts\windows\$name")
    }
    $originalStage = Join-Path $originalSmokeRoot $Id
    Copy-PinnedSourceFile -Source (Join-Path $originalStage 'SHA256SUMS') -Destination (Join-Path $stage 'SHA256SUMS')
    $stagedFiles = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $stage 'SHA256SUMS'),[Text.Encoding]::UTF8)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$') {
            throw 'Native shadow source campaign manifest is malformed'
        }
        if ($stagedFiles.ContainsKey($Matches[2])) { throw 'Native shadow source campaign manifest repeats a path' }
        $stagedFiles[$Matches[2]] = $Matches[1]
        Copy-ShadowRelativeFile -SourceRoot $originalStage -DestinationRoot $stage -Relative $Matches[2]
    }
    $packageRelative = 'config/artifacts/rocky-10.2-base-packages.lock.json'
    $packageDigest = [string](Read-JsonFile (Join-Path $runner 'runner.json')).package_lock_sha256
    if ($packageDigest -notmatch '^[0-9a-f]{64}$') {
        throw 'Native shadow runner lacks an exact source package lock digest'
    }
    $shadowPackage = Join-Path $stage $packageRelative.Replace('/','\')
    if ($stagedFiles.ContainsKey($packageRelative)) {
        if ($stagedFiles[$packageRelative] -ne $packageDigest) {
            throw 'Retained campaign package lock differs from the exact current runner'
        }
    }
    else {
        Ensure-ShadowDirectory -Path (Split-Path -Parent $shadowPackage)
        $runnerPackage = Join-Path $originalRunner $packageRelative.Replace('/','\')
        Copy-PinnedSourceFile -Source $runnerPackage -Destination $shadowPackage
        if ((Get-FileSha256 -Path $shadowPackage) -ne $packageDigest) {
            throw 'Copied native image qualification package lock differs from the exact runner'
        }
        $manifestPath = Join-Path $stage 'SHA256SUMS'
        $lines = @([IO.File]::ReadAllLines($manifestPath,[Text.Encoding]::UTF8)) + "$packageDigest  $packageRelative"
        [IO.File]::WriteAllText($manifestPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        Protect-LabPath -Path $manifestPath -Directory $false
    }
    foreach ($relative in @(
        'smoke-run/Vagrantfile', 'smoke-run/runtime.json', 'smoke-run/ssh_known_hosts',
        'smoke-run/.vagrant/machines/default/virtualbox/id'
    )) {
        Copy-ShadowRelativeFile -SourceRoot $originalStage -DestinationRoot $stage -Relative $relative
    }
    $smokeRun = Join-Path $stage 'smoke-run'
    Ensure-ShadowDirectory -Path (Join-Path $smokeRun 'logs')
    Ensure-ShadowDirectory -Path (Join-Path $smokeRun 'vagrant-home')
    $shadowIdentity = $script:PrivateShadowRoot
    New-ShadowDirectory -Path $shadowIdentity -Private
    Copy-PinnedSourceFile -Source (Join-Path $script:LabRootResolved 'identity\id_ed25519') -Destination (Join-Path $shadowIdentity 'id_ed25519') -Private
    Copy-PinnedSourceFile -Source (Join-Path $script:LabRootResolved 'identity\id_ed25519.pub') -Destination (Join-Path $shadowIdentity 'id_ed25519.pub') -Private
    $runtimePath = Join-Path $smokeRun 'runtime.json'
    $runtime = Read-JsonFile $runtimePath
    if ($null -eq $runtime -or $runtime.PSObject.Properties.Name -notcontains 'private_key' -or
        [string]$runtime.box_name -notmatch '^ecommerce/rocky-10\.2-rke2-[0-9a-f]{12}$' -or
        [string]$runtime.name -ne [string]$OriginalCampaign.vm_name) {
        throw 'Native shadow runtime lacks a valid VM, box or SSH identity binding'
    }
    $runtime.private_key = Join-Path $shadowIdentity 'id_ed25519'
    Write-ProtectedNativeJson -InputObject $runtime -Path $runtimePath -GovernedRoot $script:SmokeRoot
    $evidenceDir = Join-Path $script:EvidenceBase $Id
    Ensure-ShadowDirectory -Path $evidenceDir
    Copy-PinnedSourceFile -Source (Join-Path (Join-Path $originalEvidenceBase $Id) 'result.json') -Destination (Join-Path $evidenceDir 'result.json')
    $prepared = Read-JsonFile (Join-Path $stage 'prepared.json')
    $boxDir = Join-Path $script:SmokeRoot 'box'
    New-ShadowDirectory -Path $boxDir
    $box = Join-Path $boxDir 'source.box'
    Copy-PinnedSourceFile -Source ([string]$prepared.box_path) -Destination $box
    $originalBoxDir = Split-Path -Parent ([IO.Path]::GetFullPath([string]$prepared.box_path))
    Copy-PinnedSourceFile -Source (Join-Path $originalBoxDir 'manifest.json') -Destination (Join-Path $boxDir 'manifest.json')
    Copy-PinnedSourceFile -Source (Join-Path $originalBoxDir 'packer.log') -Destination (Join-Path $boxDir 'packer.log')
    $boxManifest = Read-JsonFile (Join-Path $boxDir 'manifest.json')
    if ((Get-FileSha256 -Path $box) -ne [string]$prepared.box_sha256 -or
        $prepared.box_sha256 -ne $OriginalCampaign.box_sha256 -or
        [string]$boxManifest.box_sha256 -ne [string]$prepared.box_sha256 -or
        [string]$boxManifest.inputs_digest -ne [string]$prepared.inputs_digest -or
        [string]$boxManifest.packer_log_sha256 -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path (Join-Path $boxDir 'packer.log')) -ne [string]$boxManifest.packer_log_sha256) {
        throw 'Native shadow box archive differs from the exact retained artifact'
    }
    $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
    if ($campaign.vm_id -ine $OriginalCampaign.vm_id -or
        $campaign.runner_manifest_sha256 -ne $OriginalCampaign.runner_manifest_sha256) {
        throw 'Native shadow retained VM UUID or exact runner differs after fresh copying'
    }
    Assert-ShadowGitObjects -Id $Id -Sha $Sha
    . (Join-Path $runner 'scripts\windows\LabNetworkSeed.ps1')
    $publicKey = [IO.File]::ReadAllText((Join-Path $shadowIdentity 'id_ed25519.pub'),[Text.Encoding]::UTF8).Trim()
    [void](Write-LabSeed -Root $smokeRun -Campaign $Id -PublicKey $publicKey)
    . (Join-Path $runner 'scripts\windows\NativeVagrantSshSmoke.ps1')
    Set-NativeSmokeProcessEnvironment -VagrantHome (Join-Path $smokeRun 'vagrant-home')
    $vagrant = Resolve-WindowsTool -Name 'vagrant.exe' -FallbackPaths @('C:\Program Files\Vagrant\bin\vagrant.exe')
    $vbox = Resolve-WindowsTool -Name 'VBoxManage.exe' -FallbackPaths @('C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
    $environment = @{
        VAGRANT_HOME=(Join-Path $smokeRun 'vagrant-home'); VAGRANT_NO_PLUGINS='1'
        VAGRANT_CHECKPOINT_DISABLE='1'; VAGRANT_DEFAULT_PROVIDER='virtualbox'
    }
    $boxAdd = Invoke-BoundedProcess -FilePath $vagrant -Arguments @(
        'box','add','--name',[string]$runtime.box_name,'--provider','virtualbox',
        '--checksum-type','sha256','--checksum',[string]$prepared.box_sha256,$box
    ) -TimeoutSeconds 900 -WorkingDirectory $smokeRun -Environment $environment
    Assert-ProcessSuccess -Result $boxAdd -Operation 'protected native shadow box installation'
    if (Test-Path -LiteralPath (Join-Path $smokeRun 'vagrant-home\Vagrantfile')) {
        throw 'Native shadow Vagrant home unexpectedly contains a global Vagrantfile'
    }
    $status = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('status','--machine-readable') -TimeoutSeconds 90 -WorkingDirectory $smokeRun -Environment $environment
    Assert-ProcessSuccess -Result $status -Operation 'protected retained VM Vagrant status'
    if ($status.StdOut -notmatch '(?m)^\d+,default,state,poweroff\s*$') {
        throw 'Protected Vagrant state did not observe the retained VM powered off'
    }
    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRun
    if (-not $machines.ContainsKey($campaign.vm_name) -or
        ([string]$machines[$campaign.vm_name]).Trim('{}') -ine [string]$campaign.vm_id -or
        [IO.File]::ReadAllText((Join-Path $smokeRun '.vagrant\machines\default\virtualbox\id')).Trim().Trim('{}') -ine $campaign.vm_id) {
        throw 'Protected Vagrant project changed or lost the retained VirtualBox VM UUID'
    }
    Protect-NativeInputs -Id $Id
    Assert-ProtectedNativeInputs -Id $Id
    $verified = Assert-ExistingCampaign -Id $Id -Sha $Sha
    if ($verified.vm_id -ine $OriginalCampaign.vm_id -or
        $verified.runner_manifest_sha256 -ne $OriginalCampaign.runner_manifest_sha256) {
        throw 'Protected native shadow differs after Vagrant bootstrap'
    }
    return $verified
}

function Assert-NativeTaskBinding {
    param($Task, [string]$Name, [string]$Runner, [string]$Mode, [string]$Id, [string]$Sha,
        [string]$Sid, [string]$LogonType)
    Assert-NativeTaskIdentity -Task $Task -Name $Name -Runner $Runner -Mode $Mode -Id $Id -Sha $Sha -Sid $Sid -LogonType $LogonType
    $limitMinutes = if ($Mode -eq 'RunNative') { 45 } elseif ($Mode -eq 'Watchdog') { 60 } else { throw 'Unknown native smoke task mode' }
    $actualLimit = [System.Xml.XmlConvert]::ToTimeSpan([string]$Task.Settings.ExecutionTimeLimit)
    if (
        $Task.Triggers[0].Enabled -ne $true -or $Task.Settings.Enabled -ne $true -or
        [string]$Task.State -eq 'Disabled' -or
        $Task.Settings.StartWhenAvailable -ne $true -or
        [string]$Task.Settings.MultipleInstances -ne 'IgnoreNew' -or
        $Task.Settings.DisallowStartIfOnBatteries -ne $false -or
        $Task.Settings.StopIfGoingOnBatteries -ne $false -or
        $Task.Settings.RunOnlyIfNetworkAvailable -ne $false -or
        $actualLimit -ne [TimeSpan]::FromMinutes($limitMinutes)) {
        throw "Native smoke scheduled task binding differs: $Name"
    }
}

function Assert-NativeTask {
    param([string]$Name, [string]$Runner, [string]$Mode, [string]$Id, [string]$Sha,
        [string]$Sid, [string]$LogonType)
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $Name -ErrorAction Stop
    Assert-NativeTaskBinding -Task $task -Name $Name -Runner $Runner -Mode $Mode -Id $Id -Sha $Sha -Sid $Sid -LogonType $LogonType
    Assert-NativeTaskSecurity -Name $Name
}

function Assert-NativeTasks {
    param($State)
    $runner = Join-Path (Join-Path $script:SmokeRoot "runner-$($State.source_sha)") 'scripts\windows\LabNativeBoot.ps1'
    Assert-NativeTask -Name $ResumeTaskName -Runner $runner -Mode 'RunNative' -Id $State.campaign_id -Sha $State.source_sha -Sid $State.owner_sid -LogonType 'S4U'
    Assert-NativeTask -Name $WatchdogTaskName -Runner $runner -Mode 'Watchdog' -Id $State.campaign_id -Sha $State.source_sha -Sid 'S-1-5-18' -LogonType 'ServiceAccount'
}

function Remove-NativeTasks {
    param($State, [string[]]$Names = @($ResumeTaskName,$WatchdogTaskName))
    $runner = Join-Path (Join-Path $script:SmokeRoot "runner-$($State.source_sha)") 'scripts\windows\LabNativeBoot.ps1'
    foreach ($name in $Names) {
        $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $task) { continue }
        if ($name -eq $ResumeTaskName) {
            Assert-NativeTaskIdentity -Task $task -Name $name -Runner $runner -Mode 'RunNative' -Id $State.campaign_id -Sha $State.source_sha -Sid $State.owner_sid -LogonType 'S4U'
        }
        elseif ($name -eq $WatchdogTaskName) {
            Assert-NativeTaskIdentity -Task $task -Name $name -Runner $runner -Mode 'Watchdog' -Id $State.campaign_id -Sha $State.source_sha -Sid 'S-1-5-18' -LogonType 'ServiceAccount'
        }
        else { throw "Refusing to remove an unrelated task: $name" }
        Assert-NativeTaskSecurity -Name $name
    }
    foreach ($name in $Names) {
        $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $task) { continue }
        if ($name -eq $ResumeTaskName) {
            Assert-NativeTaskIdentity -Task $task -Name $name -Runner $runner -Mode 'RunNative' -Id $State.campaign_id -Sha $State.source_sha -Sid $State.owner_sid -LogonType 'S4U'
        }
        else {
            Assert-NativeTaskIdentity -Task $task -Name $name -Runner $runner -Mode 'Watchdog' -Id $State.campaign_id -Sha $State.source_sha -Sid 'S-1-5-18' -LogonType 'ServiceAccount'
        }
        Assert-NativeTaskSecurity -Name $name
        Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false
    }
}

function Invoke-ProbeUser {
    param([string]$Id, [string]$Sha, [string]$VmId, [string]$OwnerSid)
    $proofPath = Join-Path $script:SmokeRoot "s4u-probe-$Id-$Sha.json"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($VmId -notmatch '^[0-9a-fA-F-]{36}$' -or $OwnerSid -notmatch '^S-\d+(?:-\d+)+$' -or
            $identity.User.Value -ne $OwnerSid) {
            throw 'S4U probe owner SID or retained VM UUID differs'
        }
        Assert-ProtectedNativeInputs -Id $Id
        . (Join-Path $PSScriptRoot 'NativeVagrantSshSmoke.ps1')
        Set-NativeSmokeProcessEnvironment -VagrantHome (Join-Path $script:SmokeRoot "$Id\smoke-run\vagrant-home")
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        $appData = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
        $temp = [IO.Path]::GetTempPath()
        foreach ($path in @($profile,$appData,$temp)) {
            if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Container)) {
                throw 'S4U probe lacks the retained VM owner profile, AppData or Temp directory'
            }
        }
        $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha -LocalOnly
        if ($campaign.vm_id -ine $VmId) { throw 'S4U probe cannot see the retained VirtualBox VM UUID' }
        Write-ProtectedNativeJson -InputObject ([ordered]@{
            schema=1; status='PASS'; campaign_id=$Id; source_sha=$Sha; owner_sid=$OwnerSid
            vm_id=$campaign.vm_id; runner_manifest_sha256=$campaign.runner_manifest_sha256
            profile_path=$profile; app_data_path=$appData; temp_path=$temp
            administrator=$true; completed_at=[DateTime]::UtcNow.ToString('o')
        }) -Path $proofPath -GovernedRoot $script:SmokeRoot
    }
    catch {
        Write-ProtectedNativeJson -InputObject ([ordered]@{
            schema=1; status='FAIL'; campaign_id=$Id; source_sha=$Sha; owner_sid=$identity.User.Value
            vm_id=$VmId; error=$_.Exception.Message; completed_at=[DateTime]::UtcNow.ToString('o')
        }) -Path $proofPath -GovernedRoot $script:SmokeRoot
        throw
    }
    [Console]::WriteLine("PASS lab-native-boot-s4u-probe vm=$VmId sid=$OwnerSid")
}

function Invoke-S4UProbeTask {
    param($Campaign, [string]$Id, [string]$Sha, [string]$OwnerSid)
    if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName -ErrorAction SilentlyContinue)) {
        throw 'Existing native network smoke S4U probe task requires inspection'
    }
    $proofPath = Join-Path $script:SmokeRoot "s4u-probe-$Id-$Sha.json"
    if (Test-Path -LiteralPath $proofPath) { Remove-Item -LiteralPath $proofPath -Force }
    $runner = Join-Path $Campaign.runner 'scripts\windows\LabNativeBoot.ps1'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $parts = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$runner,
        '-Action','ProbeUser','-CampaignId',$Id,'-SourceSha',$Sha,'-LabRoot',$script:LabRootResolved,
        '-ExpectedVmId',$Campaign.vm_id,'-ExpectedOwnerSid',$OwnerSid)
    $arguments = ($parts | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' '
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    try {
        Register-ProtectedNativeTask -Name $ProbeTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType 2
        $registered = Get-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName -ErrorAction Stop
        if ($registered.TaskPath -ne '\' -or
            (Get-TaskPrincipalSid -Task $registered) -ne $OwnerSid -or
            [string]$registered.Principal.LogonType -ne 'S4U' -or
            [string]$registered.Principal.RunLevel -ne 'Highest' -or
            [string]$registered.Actions[0].Arguments -ne $arguments -or
            [string]$registered.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {
            throw 'Native smoke S4U probe task binding differs'
        }
        $started = [DateTime]::UtcNow
        Start-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName
        $deadline = $started.AddMinutes(2)
        while (-not (Test-Path -LiteralPath $proofPath -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 1
        }
        if (-not (Test-Path -LiteralPath $proofPath -PathType Leaf)) { throw 'S4U retained-VM probe timed out' }
        $proof = Read-JsonFile $proofPath
        while ((Get-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName).State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $ProbeTaskName
        if ($info.LastTaskResult -ne 0 -or $info.LastRunTime.ToUniversalTime() -lt $started.AddSeconds(-2) -or
            $proof.schema -ne 1 -or $proof.status -ne 'PASS' -or $proof.campaign_id -ne $Id -or
            $proof.source_sha -ne $Sha -or $proof.owner_sid -ne $OwnerSid -or
            $proof.vm_id -ine $Campaign.vm_id -or $proof.administrator -ne $true -or
            $proof.profile_path -ine [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile) -or
            -not $proof.app_data_path -or -not $proof.temp_path -or
            $proof.runner_manifest_sha256 -ne $Campaign.runner_manifest_sha256) {
            throw "S4U retained-VM probe failed: $($proof.error)"
        }
    }
    finally {
        $remaining = Get-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName -ErrorAction SilentlyContinue
        if ($null -ne $remaining) {
            if ($remaining.TaskPath -ne '\' -or
                (Get-TaskPrincipalSid -Task $remaining) -ne $OwnerSid -or
                [string]$remaining.Principal.LogonType -ne 'S4U' -or
                [string]$remaining.Principal.RunLevel -ne 'Highest' -or
                [string]$remaining.Actions[0].Execute -ine $powershell -or
                [string]$remaining.Actions[0].Arguments -ne $arguments -or
                [string]$remaining.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') {
                throw 'S4U probe task was not safely owned for cleanup; inspect it manually'
            }
            Assert-NativeTaskSecurity -Name $ProbeTaskName
            Unregister-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName -Confirm:$false
            if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $ProbeTaskName -ErrorAction SilentlyContinue)) {
                throw 'S4U probe task remained after cleanup'
            }
        }
    }
}

function Register-NativeTasks {
    param($State, $Campaign)
    $runner = Join-Path $Campaign.runner 'scripts\windows\LabNativeBoot.ps1'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $resumeAction = New-ScheduledTaskAction -Execute $powershell -Argument (Get-NativeTaskArguments -Runner $runner -Mode 'RunNative' -Id $State.campaign_id -Sha $State.source_sha)
    $resumePrincipal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $resumeSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 45) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $script:RegisteredNativeTasks += $ResumeTaskName
    Register-ProtectedNativeTask -Name $ResumeTaskName -Action $resumeAction -Trigger $trigger -Principal $resumePrincipal -Settings $resumeSettings -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType 2
    $watchdogAction = New-ScheduledTaskAction -Execute $powershell -Argument (Get-NativeTaskArguments -Runner $runner -Mode 'Watchdog' -Id $State.campaign_id -Sha $State.source_sha)
    $watchdogPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $watchdogSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $script:RegisteredNativeTasks += $WatchdogTaskName
    Register-ProtectedNativeTask -Name $WatchdogTaskName -Action $watchdogAction -Trigger $trigger -Principal $watchdogPrincipal -Settings $watchdogSettings -UserId 'SYSTEM' -LogonType 5
    Assert-NativeTasks -State $State
}

function Invoke-WatchdogProbeTask {
    $started = [DateTime]::UtcNow
    Start-ScheduledTask -TaskPath '\' -TaskName $WatchdogTaskName
    $deadline = $started.AddMinutes(2)
    while ((Get-ScheduledTask -TaskPath '\' -TaskName $WatchdogTaskName).State -eq 'Running' -and
        [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $WatchdogTaskName
    if ($info.LastTaskResult -ne 0 -or $info.LastRunTime.ToUniversalTime() -lt $started.AddSeconds(-2)) {
        throw 'SYSTEM native smoke watchdog failed its normal-boot no-op probe'
    }
}

function Open-NativeRuntimeLock {
    param([ValidateRange(0, 180)][int]$WaitSeconds = 0)
    $path = $script:RuntimeLockPath
    $mode = if ($script:PrivateShadowRoot) {
        [void](Assert-RegularLabPath -Path $path -Directory $false)
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $path) -Directory $false -Path $path
        [IO.FileMode]::Open
    } else { [IO.FileMode]::OpenOrCreate }
    $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
    while ($true) {
        try { return [IO.File]::Open($path, $mode, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'BLOCKED_RUNTIME another network smoke action holds the runtime lock'
            }
            Start-Sleep -Seconds 1
        }
    }
}

function Assert-NativeBootForRun {
    param($State, [switch]$AllowNormalSequence)
    $boot = Assert-OwnedBootForReturn -State $State -AllowNormalSequence:$AllowNormalSequence
    if ((Get-CimInstance Win32_ComputerSystem).HypervisorPresent) {
        throw 'Native smoke task requires a hypervisor-free Windows boot'
    }
    Assert-OwnedBcdEntry -State $State
    return $boot
}

function Assert-OwnedBootForReturn {
    param($State, [switch]$AllowNormalSequence)
    $boot = Get-BootContext
    $allowedSequence = if ($AllowNormalSequence) { @('',[string]$State.native_boot_id,[string]$State.normal_boot_id) } else { @('',[string]$State.native_boot_id) }
    if ($boot.current -ne [string]$State.native_boot_id -or
        $boot.default -ne [string]$State.normal_boot_id -or
        $boot.sequence -notin $allowedSequence) {
        throw 'Native smoke return requires the owned Windows loader and unchanged default'
    }
    $entries = @(Get-OwnedEntries)
    if ($entries.Count -ne 1 -or $entries[0].id -ne [string]$State.native_boot_id) {
        throw 'Native smoke return BCD entry identity differs'
    }
    return $boot
}

function Request-NormalReturn {
    param([string]$Id, [string]$Sha, [string]$RunStatus, [string]$ErrorText = '', [string]$ResultDigest = '')
    $lock = Open-NativeRuntimeLock -WaitSeconds 120
    try {
        $state = Read-JsonFile $script:StatePath
        if ($state.phase -notin @('PREPARED','BOOT_PENDING','RUNNING','RETURN_PENDING','FAILED')) {
            throw 'Native smoke return state is not recoverable'
        }
        Assert-StateBinding -State $state -ExpectedPhase ([string]$state.phase)
        if ($state.campaign_id -ne $Id -or $state.source_sha -ne $Sha -or
            $RunStatus -notin @('PASS','FAIL') -or
            ($ResultDigest -and $ResultDigest -notmatch '^[0-9a-f]{64}$')) {
            throw 'Native smoke return campaign, runner or result binding differs'
        }
        [void](Assert-OwnedBootForReturn -State $state -AllowNormalSequence)
        $state.phase = 'RETURN_PENDING'
        $state | Add-Member -NotePropertyName run_status -NotePropertyValue $RunStatus -Force
        $state | Add-Member -NotePropertyName run_error -NotePropertyValue $ErrorText -Force
        $state | Add-Member -NotePropertyName result_sha256 -NotePropertyValue $ResultDigest -Force
        $state | Add-Member -NotePropertyName normal_return_requested_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        Write-NativeBootState -State $state
        [void](Invoke-Bcd -Arguments @('/bootsequence',[string]$state.normal_boot_id))
        $after = Get-BootContext
        if ($after.current -ne [string]$state.native_boot_id -or
            $after.default -ne [string]$state.normal_boot_id -or
            $after.sequence -ne [string]$state.normal_boot_id) {
            throw 'Normal Windows one-shot bootsequence failed verification'
        }
    }
    finally { $lock.Dispose() }
    [Console]::WriteLine("PASS lab-native-boot-return campaign=$Id run=$RunStatus next=normal")
    Restart-Computer -Force
}

function Invoke-RunNative {
    param([string]$Id, [string]$Sha)
    $runStatus = 'FAIL'
    $runError = ''
    $resultDigest = ''
    $normalBoot = $false
    try {
        $lock = Open-NativeRuntimeLock -WaitSeconds 120
        try {
            $state = Read-JsonFile $script:StatePath
            Assert-StateBinding -State $state -ExpectedPhase ([string]$state.phase)
            if ($state.campaign_id -ne $Id -or $state.source_sha -ne $Sha -or
                [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne [string]$state.owner_sid) {
                throw 'Native smoke task owner, campaign or source SHA differs'
            }
            $boot = Get-BootContext
            if ($boot.current -eq [string]$state.normal_boot_id -and
                $boot.default -eq [string]$state.normal_boot_id -and
                $state.phase -in @('RETURN_PENDING','FAILED','RECOVERED')) {
                $normalBoot = $true
            }
            else {
                if ($state.phase -ne 'BOOT_PENDING' -or [int]$state.boot_attempts -ne 1) {
                    throw 'Native smoke task was not armed for a single native boot'
                }
                Assert-ProtectedNativeInputs -Id $Id
                . (Join-Path $PSScriptRoot 'NativeVagrantSshSmoke.ps1')
                Set-NativeSmokeProcessEnvironment -VagrantHome (Join-Path $script:SmokeRoot "$Id\smoke-run\vagrant-home")
                [void](Assert-NativeBootForRun -State $state)
                Assert-NativeTasks -State $state
                $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha -LocalOnly
                if ($campaign.vm_id -ine [string]$state.vm_id -or
                    $campaign.box_sha256 -ne [string]$state.box_sha256 -or
                    $campaign.source_tree_sha -ne [string]$state.source_tree_sha -or
                    $campaign.runner_manifest_sha256 -ne [string]$state.runner_manifest_sha256 -or
                    (Get-FileSha256 -Path (Join-Path $script:SmokeRoot "s4u-probe-$Id-$Sha.json")) -ne [string]$state.s4u_probe_sha256 -or
                    (Get-FileSha256 -Path ([string]$state.bcd_backup)) -ne [string]$state.bcd_backup_sha256) {
                    throw 'Native smoke task retained VM, runner or backup differs'
                }
                $state.phase = 'RUNNING'
                $state | Add-Member -NotePropertyName run_started_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
                Write-NativeBootState -State $state
            }
        }
        finally { $lock.Dispose() }
        if ($normalBoot) {
            [Console]::WriteLine("PASS lab-native-boot-run campaign=$Id normal-boot-noop=true")
            return
        }
        $started = [DateTime]::UtcNow
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $runner = Join-Path (Join-Path $script:SmokeRoot "runner-$Sha") 'scripts\windows\LabNetworkSmoke.ps1'
        $stage = Join-Path $script:SmokeRoot $Id
        $resume = Invoke-BoundedProcess -FilePath $powershell -Arguments @(
            '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$runner,
            '-Action','Resume','-StageRoot',$stage,'-RunnerSourceSha',$Sha,
            '-ShadowRoot',$script:SmokeRoot
        ) -TimeoutSeconds 2100 -WorkingDirectory $stage
        if ($resume.ExitCode -ne 0) { throw "Native network SSH Resume exited $($resume.ExitCode)" }
        Protect-NativeInputs -Id $Id
        Assert-ProtectedNativeInputs -Id $Id
        $resultPath = Join-Path (Join-Path $script:EvidenceBase $Id) 'result.json'
        $result = Read-JsonFile $resultPath
        $prepared = Read-JsonFile (Join-Path $stage 'prepared.json')
        $completed = [DateTimeOffset]::Parse([string]$result.completed_at).UtcDateTime
        $image = if ($result.PSObject.Properties.Name -contains 'image_qualification') { $result.image_qualification } else { $null }
        $imageChecks = if ($image -is [pscustomobject] -and $image.PSObject.Properties.Name -contains 'checks') { $image.checks } else { $null }
        $imagePass = $image -is [pscustomobject] -and $imageChecks -is [pscustomobject] -and
            $image.status -eq 'PASS' -and $image.source_sha -eq $Sha -and
            $image.source_tree_sha -eq [string]$state.source_tree_sha -and
            $image.box_sha256 -eq [string]$state.box_sha256 -and
            [string]$image.vm_id -ieq [string]$state.vm_id -and
            $image.virtualbox_backend -eq 'NATIVE_VTX'
        foreach ($check in @(
            'rocky_release','kernel','architecture_cpu','memory','disk','xfs','lvm_absent',
            'swap_absent','rpm_profile','systemd','network','fundamental_tools',
            'rke2_prerequisites','security','package_inventory','supply_chain'
        )) {
            if ($null -eq $imageChecks -or $imageChecks.PSObject.Properties.Name -notcontains $check -or
                $imageChecks.$check -ne 'PASS') { $imagePass = $false }
        }
        if ($completed -lt $started.AddSeconds(-2) -or $result.campaign_id -ne $Id -or
            $result.resume_runner_source_sha -ne $Sha -or $result.status -ne 'PASS' -or
            $result.guest_security -ne 'PASS' -or $result.virtualbox_backend -ne 'NATIVE_VTX' -or
            $result.box_digest_verified -ne 'PASS' -or
            $result.box_digest -ne [string]$state.box_sha256 -or
            $result.packer.status -ne 'REUSED' -or $result.packer.build -ne 'NOT_EXECUTED' -or
            $result.packer.inputs_digest -ne [string]$prepared.inputs_digest -or
            $result.vm_recreate -ne 'NOT_REQUIRED' -or
            $result.vm_restart -notin @('NOT_REQUIRED','EXECUTED_EXISTING_VM') -or
            $result.resume_seed_server -notin @('PASS','NOT_REQUIRED') -or
            ($result.vm_restart -eq 'EXECUTED_EXISTING_VM' -and $result.resume_seed_server -ne 'PASS') -or
            -not $imagePass -or
            $result.vm_name -ne [string]$state.vm_name -or
            $result.cleanup.status -ne 'PASS' -or
            $result.cleanup.seed_server -ne 'PASS' -or
            $result.cleanup.lock -ne 'PASS' -or
            $result.cleanup.vm_preserved -ne $true -or
            $result.cleanup.vm_name -ne [string]$state.vm_name -or
            [string]$result.cleanup.vm_id -ine [string]$state.vm_id -or
            $result.checkpoints.'03-vm-smoke' -ne 'PASS' -or
            $result.checkpoints.'04-network-ssh' -ne 'PASS' -or
            $result.checkpoints.'05-rocky-runtime' -ne 'PASS' -or
            $result.checkpoints.'06-image-qualification' -ne 'PASS' -or
            $result.resume_from -ne 'downstream-qualification') {
            throw 'Native Resume result is stale, failed or lacks guest, image and native VT-x proof'
        }
        $resultDigest = Get-FileSha256 -Path $resultPath
        $runStatus = 'PASS'
    }
    catch { $runError = $_.Exception.Message }
    if ($normalBoot) { return }
    Request-NormalReturn -Id $Id -Sha $Sha -RunStatus $runStatus -ErrorText $runError -ResultDigest $resultDigest
}

function Invoke-Watchdog {
    param([string]$Id, [string]$Sha)
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        throw 'Native smoke watchdog requires the SYSTEM service account'
    }
    Assert-ProtectedNativeControlPlane -Sha $Sha
    $state = Read-JsonFile $script:StatePath
    Assert-StateBinding -State $state -ExpectedPhase ([string]$state.phase)
    if ($state.campaign_id -ne $Id -or $state.source_sha -ne $Sha) {
        throw 'Native smoke watchdog campaign or source SHA differs'
    }
    $boot = Get-BootContext
    if ($boot.current -eq [string]$state.normal_boot_id -and $boot.default -eq [string]$state.normal_boot_id) {
        if ($state.phase -ne 'PREPARED' -and $state.phase -ne 'RECOVERED') {
            $lock = Open-NativeRuntimeLock -WaitSeconds 120
            try { Invoke-Recover }
            finally { $lock.Dispose() }
        }
        return
    }
    [void](Assert-OwnedBootForReturn -State $state -AllowNormalSequence)
    $deadline = [DateTime]::UtcNow.AddMinutes(50)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 15
        $state = Read-JsonFile $script:StatePath
        if ($state.campaign_id -ne $Id -or $state.source_sha -ne $Sha) {
            throw 'Native smoke watchdog state binding changed during the run'
        }
        $boot = Get-BootContext
        if ($boot.current -ne [string]$state.native_boot_id) { return }
    }
    Request-NormalReturn -Id $Id -Sha $Sha -RunStatus 'FAIL' -ErrorText 'Native Resume exceeded the watchdog deadline'
}

function Invoke-Prepare {
    param([string]$Id, [string]$Sha)
    if ($ExpectedVmId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw 'Native preparation requires the independently observed retained VM UUID'
    }
    if (Test-Path -LiteralPath $script:StatePath -PathType Leaf) {
        $prior = Read-JsonFile $script:StatePath
        if ($prior.phase -ne 'RECOVERED') { throw 'Existing native smoke boot requires explicit Recover before another Prepare' }
    }
    Assert-NoImageCycle
    $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
    if ($campaign.vm_id -ine $ExpectedVmId) {
        throw 'Retained VM UUID differs from the independently observed operator value'
    }
    $boot = Assert-NormalBoot
    if (@(Get-OwnedEntries).Count -ne 0) { throw 'An unowned or stale native smoke BCD entry already exists' }
    foreach ($name in @($ResumeTaskName,$WatchdogTaskName,$ProbeTaskName)) {
        if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue)) {
            throw "An existing native smoke task requires inspection: $name"
        }
    }
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:PrepareShadowCreated = $false
    try {
        # Create fresh inodes under a historically protected Windows parent. Old
        # write handles on the diagnostic stage cannot mutate these task inputs.
        $campaign = Initialize-NativeShadow -Id $Id -Sha $Sha -OriginalCampaign $campaign
        Invoke-S4UProbeTask -Campaign $campaign -Id $Id -Sha $Sha -OwnerSid $ownerSid
        Protect-NativeInputs -Id $Id
        Assert-ProtectedNativeInputs -Id $Id
        $sealedCampaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
        if ($sealedCampaign.vm_id -ine $campaign.vm_id -or
            $sealedCampaign.runner_manifest_sha256 -ne $campaign.runner_manifest_sha256 -or
            $sealedCampaign.box_sha256 -ne $campaign.box_sha256) {
            throw 'Retained VM, runner or box changed after the S4U probe'
        }
        $probeDigest = Get-FileSha256 -Path (Join-Path $script:SmokeRoot "s4u-probe-$Id-$Sha.json")
        $backupDir = Join-Path $script:SmokeRoot 'bcd'
        New-ShadowDirectory -Path $backupDir
        $backup = Join-Path $backupDir "before-$Id-$Sha-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).bak"
        if (Test-Path -LiteralPath $backup) { throw 'Campaign BCD backup already exists' }
    }
    catch {
        $failure = $_.Exception.Message
        if ($script:PrepareShadowCreated) {
            try { [void](Remove-NativeShadowPrivateKey -Id $Id -Sha $Sha) }
            catch { $failure += "; shadow key cleanup: $($_.Exception.Message)" }
        }
        throw "Native smoke preparation failed before BCD mutation: $failure"
    }
    $script:RegisteredNativeTasks = @()
    $state = $null
    $nativeId = ''
    $vsmStatus = 'UNSUPPORTED'
    try {
        [void](Invoke-Bcd -Arguments @('/export',$backup))
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or (Get-Item -LiteralPath $backup).Length -lt 1024) {
            throw 'BCD backup is absent or unexpectedly small'
        }
        $backupDigest = Get-FileSha256 -Path $backup
        $copy = Invoke-Bcd -Arguments @('/copy',$boot.current,'/d',$EntryName)
        $match = [regex]::Match($copy, '\{[0-9a-fA-F-]{36}\}')
        if (-not $match.Success) { throw 'Cannot parse copied native BCD entry ID' }
        $nativeId = Assert-Guid -Value $match.Value -Forbidden $boot.current
        [void](Invoke-Bcd -Arguments @('/set',$nativeId,'hypervisorlaunchtype','off'))
        $vsm = Invoke-BoundedProcess -FilePath (Join-Path $env:SystemRoot 'System32\bcdedit.exe') -Arguments @('/set',$nativeId,'vsmlaunchtype','off') -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
        $vsmStatus = if ($vsm.ExitCode -eq 0) { 'PASS' } else { 'UNSUPPORTED' }
        $entries = @(Get-OwnedEntries)
        if ($entries.Count -ne 1 -or $entries[0].id -ne $nativeId -or
            $entries[0].text -notmatch '(?im)^\s*hypervisorlaunchtype\s+off\s*$' -or
            ($vsmStatus -eq 'PASS' -and $entries[0].text -notmatch '(?im)^\s*vsmlaunchtype\s+off\s*$')) {
            throw 'Copied native BCD entry failed postcondition'
        }
        $after = Get-BootContext
        if ($after.current -ne $boot.current -or $after.default -ne $boot.default -or $after.sequence -ne '') {
            throw 'BCD normal loader or default changed during native preparation'
        }
        $state = [ordered]@{
            schema=1; mode='NETWORK_SMOKE_NATIVE'; phase='PREPARED'
            campaign_id=$Id; source_sha=$Sha; shadow_root=$script:SmokeRoot; source_tree_sha=$campaign.source_tree_sha
            pr_number=$PrNumber; pr_repository=$PrRepository; pr_base=$PrBase
            pr_base_sha=$PrBaseSha; pr_branch=$PrBranch
            pinned_gh_path=$PinnedGhPath; pinned_gh_version=$PinnedGhVersion
            pinned_gh_sha256=$PinnedGhSha256
            owner_sid=$ownerSid; s4u_probe_sha256=$probeDigest; normal_boot_id=$boot.current
            native_boot_id=$nativeId; entry_name=$EntryName; vm_name=$campaign.vm_name
            vm_id=$campaign.vm_id; expected_vm_id=$ExpectedVmId; box_sha256=$campaign.box_sha256
            runner_manifest_sha256=$campaign.runner_manifest_sha256
            vsmlaunchtype=$vsmStatus
            bcd_backup=$backup; bcd_backup_sha256=$backupDigest
            boot_attempts=0; prepared_at=[DateTime]::UtcNow.ToString('o')
        }
        Write-NativeBootState -State $state
        Protect-NativeInputs -Id $Id
        Assert-ProtectedNativeInputs -Id $Id
        $sealedCampaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
        if ($sealedCampaign.vm_id -ine $campaign.vm_id -or
            $sealedCampaign.runner_manifest_sha256 -ne $campaign.runner_manifest_sha256 -or
            $sealedCampaign.box_sha256 -ne $campaign.box_sha256) {
            throw 'Retained VM, runner or box changed before startup task registration'
        }
        Register-NativeTasks -State $state -Campaign $campaign
        Invoke-WatchdogProbeTask
        [Console]::WriteLine("PASS lab-native-boot-prepare campaign=$Id sha=$Sha vm=$($campaign.vm_id) reboot=EXPLICITLY_REQUIRED")
    }
    catch {
        $failure = $_.Exception.Message
        try {
            if ($script:RegisteredNativeTasks.Count -gt 0) {
                Remove-NativeTasks -State $state -Names $script:RegisteredNativeTasks
            }
        }
        catch { $failure += "; task cleanup: $($_.Exception.Message)" }
        try {
            if ($nativeId -ne '' -and (Get-BootContext).current -eq $boot.current) {
                $ownedEntries = @(Get-OwnedEntries)
                if ($ownedEntries.Count -ne 1 -or $ownedEntries[0].id -ne $nativeId) {
                    throw 'Copied native BCD entry identity is ambiguous; manual inspection required'
                }
                [void](Invoke-Bcd -Arguments @('/delete',$nativeId,'/f'))
            }
            if ($nativeId -eq '') { $failure += '; copied BCD identifier was not observed; inspect the BCD backup and entries manually' }
        }
        catch { $failure += "; BCD cleanup: $($_.Exception.Message)" }
        try {
            if ($nativeId -ne '') {
                Write-NativeBootState -State ([ordered]@{
                    schema=1; mode='NETWORK_SMOKE_NATIVE'; phase='FAILED'; campaign_id=$Id; source_sha=$Sha
                    shadow_root=$script:SmokeRoot
                    source_tree_sha=$campaign.source_tree_sha; owner_sid=$ownerSid; s4u_probe_sha256=$probeDigest
                    pr_number=$PrNumber; pr_repository=$PrRepository; pr_base=$PrBase
                    pr_base_sha=$PrBaseSha; pr_branch=$PrBranch
                    pinned_gh_path=$PinnedGhPath; pinned_gh_version=$PinnedGhVersion
                    pinned_gh_sha256=$PinnedGhSha256
                    normal_boot_id=$boot.current; native_boot_id=$nativeId; entry_name=$EntryName
                    vm_name=$campaign.vm_name; vm_id=$campaign.vm_id; expected_vm_id=$ExpectedVmId
                    box_sha256=$campaign.box_sha256
                    runner_manifest_sha256=$campaign.runner_manifest_sha256
                    vsmlaunchtype=if ($vsmStatus) { $vsmStatus } else { 'UNSUPPORTED' }
                    bcd_backup=$backup; bcd_backup_sha256=if (Test-Path -LiteralPath $backup) { Get-FileSha256 -Path $backup } else { '' }
                    boot_attempts=0; error=$failure; failed_at=[DateTime]::UtcNow.ToString('o')
                })
            }
        }
        catch { $failure += "; failure state: $($_.Exception.Message)" }
        if ($script:PrepareShadowCreated) {
            try { [void](Remove-NativeShadowPrivateKey -Id $Id -Sha $Sha) }
            catch { $failure += "; shadow key cleanup: $($_.Exception.Message)" }
        }
        throw "Native smoke preparation failed closed: $failure"
    }
}

function Invoke-Reboot {
    param([string]$Id, [string]$Sha)
    $state = Read-JsonFile $script:StatePath
    Assert-StateBinding -State $state -ExpectedPhase 'PREPARED'
    if ($state.campaign_id -ne $Id -or $state.source_sha -ne $Sha -or [int]$state.boot_attempts -ne 0) {
        throw 'Native smoke reboot differs from prepared exact campaign or was already attempted'
    }
    Import-ProtectedPrBinding -State $state
    Assert-NoImageCycle
    $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
    Assert-ProtectedNativeInputs -Id $Id
    if ($campaign.vm_id -ine [string]$state.vm_id -or $campaign.box_sha256 -ne $state.box_sha256 -or
        $campaign.runner_manifest_sha256 -ne $state.runner_manifest_sha256 -or
        $campaign.source_tree_sha -ne $state.source_tree_sha -or
        (Get-FileSha256 -Path (Join-Path $script:SmokeRoot "s4u-probe-$Id-$Sha.json")) -ne [string]$state.s4u_probe_sha256 -or
        (Get-FileSha256 -Path ([string]$state.bcd_backup)) -ne [string]$state.bcd_backup_sha256) {
        throw 'Retained VM, box, runner or BCD backup differs before reboot'
    }
    $boot = Assert-NormalBoot
    if ($boot.current -ne [string]$state.normal_boot_id) { throw 'Normal Windows loader differs from prepared loader' }
    Assert-OwnedBcdEntry -State $state
    Assert-NativeTasks -State $state
    $state.boot_attempts = 1
    $state.phase = 'BOOT_PENDING'
    $state | Add-Member -NotePropertyName reboot_requested_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-NativeBootState -State $state
    try {
        [void](Invoke-Bcd -Arguments @('/bootsequence',[string]$state.native_boot_id))
        $after = Get-BootContext
        if ($after.current -ne $boot.current -or $after.default -ne $boot.default -or
            $after.sequence -ne [string]$state.native_boot_id) {
            throw 'One-shot BCD bootsequence failed verification'
        }
        [Console]::WriteLine("PASS lab-native-boot-reboot campaign=$Id next=$($state.native_boot_id)")
        Restart-Computer -Force
    }
    catch {
        $failure = $_.Exception.Message
        try {
            $after = Get-BootContext
            if ($after.sequence -eq [string]$state.native_boot_id) {
                [void](Invoke-Bcd -Arguments @('/deletevalue','{bootmgr}','bootsequence'))
            }
        }
        catch { $failure += "; bootsequence cleanup: $($_.Exception.Message)" }
        $state.phase = 'FAILED'
        $state | Add-Member -NotePropertyName error -NotePropertyValue $failure -Force
        $state | Add-Member -NotePropertyName failed_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        Write-NativeBootState -State $state
        throw "Native smoke reboot failed closed: $failure"
    }
}

function Invoke-Recover {
    $state = Read-JsonFile $script:StatePath
    Assert-RecoveryCampaign -State $state -Requested $CampaignId
    if ($state.phase -eq 'RECOVERED') {
        Assert-StateBinding -State $state -ExpectedPhase 'RECOVERED'
        $already = Get-BootContext
        if ($already.current -ne [string]$state.normal_boot_id -or
            $already.default -ne [string]$state.normal_boot_id -or $already.sequence -ne '' -or
            @(Get-OwnedEntries).Count -ne 0 -or
            $null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $ResumeTaskName -ErrorAction SilentlyContinue) -or
            $null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $WatchdogTaskName -ErrorAction SilentlyContinue)) {
            throw 'Previously recovered native smoke boot no longer has a clean normal BCD state'
        }
        Assert-NativeRecoveredProof -State $state
        [void](Remove-NativeShadowPrivateKey -Id ([string]$state.campaign_id) -Sha ([string]$state.source_sha))
        [Console]::WriteLine("PASS lab-native-boot-recover campaign=$($state.campaign_id) already-recovered=true")
        return
    }
    if ($state.phase -notin @('PREPARED','BOOT_PENDING','RUNNING','RETURN_PENDING','FAILED')) {
        throw 'Native smoke boot state is not recoverable'
    }
    $expectedPhase = [string]$state.phase
    Assert-StateBinding -State $state -ExpectedPhase $expectedPhase
    if ((Get-FileSha256 -Path ([string]$state.bcd_backup)) -ne [string]$state.bcd_backup_sha256) {
        throw 'Owned BCD backup digest differs; recovery requires manual inspection'
    }
    $boot = Get-BootContext
    if ($boot.current -ne [string]$state.normal_boot_id -or $boot.default -ne [string]$state.normal_boot_id) {
        throw 'Recovery requires the original normal Windows loader and unchanged default'
    }
    if ($boot.sequence -ne '' -and $boot.sequence -notin @([string]$state.normal_boot_id,[string]$state.native_boot_id)) {
        throw 'Another one-shot bootsequence is pending; refusing to change it'
    }
    $entries = @(Get-OwnedEntries)
    if ($entries.Count -gt 1 -or ($entries.Count -eq 1 -and $entries[0].id -ne [string]$state.native_boot_id)) {
        throw 'Recovery found a different or ambiguous native smoke BCD entry'
    }
    $resumeTask = Get-ScheduledTask -TaskPath '\' -TaskName $ResumeTaskName -ErrorAction SilentlyContinue
    $watchdogTask = Get-ScheduledTask -TaskPath '\' -TaskName $WatchdogTaskName -ErrorAction SilentlyContinue
    if ($null -ne $resumeTask) {
        $runner = Join-Path (Join-Path $script:SmokeRoot "runner-$($state.source_sha)") 'scripts\windows\LabNativeBoot.ps1'
        Assert-NativeTaskIdentity -Task $resumeTask -Name $ResumeTaskName -Runner $runner -Mode 'RunNative' -Id $state.campaign_id -Sha $state.source_sha -Sid $state.owner_sid -LogonType 'S4U'
        Assert-NativeTaskSecurity -Name $ResumeTaskName
    }
    if ($null -ne $watchdogTask) {
        $runner = Join-Path (Join-Path $script:SmokeRoot "runner-$($state.source_sha)") 'scripts\windows\LabNativeBoot.ps1'
        Assert-NativeTaskIdentity -Task $watchdogTask -Name $WatchdogTaskName -Runner $runner -Mode 'Watchdog' -Id $state.campaign_id -Sha $state.source_sha -Sid 'S-1-5-18' -LogonType 'ServiceAccount'
        Assert-NativeTaskSecurity -Name $WatchdogTaskName
    }
    if ($boot.sequence -ne '') {
        [void](Invoke-Bcd -Arguments @('/deletevalue','{bootmgr}','bootsequence'))
    }
    if ($entries.Count -eq 1) { [void](Invoke-Bcd -Arguments @('/delete',[string]$state.native_boot_id,'/f')) }
    $after = Get-BootContext
    if ($after.current -ne [string]$state.normal_boot_id -or $after.default -ne [string]$state.normal_boot_id -or
        $after.sequence -ne '' -or @(Get-OwnedEntries).Count -ne 0) {
        throw 'Native smoke recovery BCD postcondition failed'
    }
    Remove-NativeTasks -State $state
    if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $ResumeTaskName -ErrorAction SilentlyContinue) -or
        $null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $WatchdogTaskName -ErrorAction SilentlyContinue)) {
        throw 'Native smoke recovery did not remove the owned startup tasks'
    }
    try { Assert-NativeRecoveredProof -State $state }
    catch {
        $state | Add-Member -NotePropertyName run_status -NotePropertyValue 'FAIL' -Force
        $state | Add-Member -NotePropertyName run_error -NotePropertyValue ("Protected native proof failed recovery validation: $($_.Exception.Message)") -Force
        $state | Add-Member -NotePropertyName result_sha256 -NotePropertyValue '' -Force
    }
    [void](Remove-NativeShadowPrivateKey -Id ([string]$state.campaign_id) -Sha ([string]$state.source_sha))
    $state.phase = 'RECOVERED'
    $state | Add-Member -NotePropertyName recovered_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-NativeBootState -State $state
    [Console]::WriteLine("PASS lab-native-boot-recover campaign=$($state.campaign_id) native-entry-removed=true")
}

function Assert-RecoveryCampaign {
    param($State, [string]$Requested)
    if ($Requested -and $Requested -ne [string]$State.campaign_id) {
        throw 'Recovery campaign ID differs from the persisted owned boot state'
    }
}

function Invoke-NativeAclDiskSelfTest {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $ancestor = $tempRoot
    while ($ancestor) {
        [void](Assert-RegularLabPath -Path $ancestor -Directory $true)
        $parent = Split-Path -Parent $ancestor
        if (-not $parent -or $parent -eq $ancestor) { break }
        $ancestor = $parent
    }
    $leaf = 'native-smoke-acl-' + [Guid]::NewGuid().ToString('N')
    $root = [IO.Path]::GetFullPath((Join-Path $tempRoot $leaf))
    $guard = $null
    try {
        [void](New-Item -ItemType Directory -Path $root -ErrorAction Stop)
        $guard = Open-LabDeleteGuard -Path $root
        Protect-LabPath -Path $root -Directory $true
        $stateFixture = Join-Path $root 'state.json'
        Write-ProtectedNativeJson -InputObject @{ phase='FIRST' } -Path $stateFixture -GovernedRoot $root
        Write-ProtectedNativeJson -InputObject @{ phase='SECOND' } -Path $stateFixture -GovernedRoot $root
        if ((Read-JsonFile $stateFixture).phase -ne 'SECOND') {
            throw 'Protected native JSON replacement did not preserve the final state'
        }
        $fresh = Join-Path $root 'fresh'
        New-ShadowDirectory -Path $fresh
        $private = Join-Path $root 'private'
        New-ShadowDirectory -Path $private -Private
        $atomicFile = Join-Path $fresh 'atomic.txt'
        $atomicStream = [IO.File]::Create($atomicFile,4096,[IO.FileOptions]::None,(New-ProtectedLabAcl -Directory $false))
        $atomicStream.Dispose()
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $atomicFile) -Directory $false -Path $atomicFile
        $privateFile = Join-Path $private 'secret.txt'
        $privateStream = [IO.File]::Create($privateFile,4096,[IO.FileOptions]::None,(New-PrivateShadowAcl -Directory $false))
        $privateStream.Dispose()
        Assert-PrivateShadowAcl -Acl (Get-Acl -LiteralPath $privateFile) -Directory $false -Path $privateFile
        $file = Join-Path $root 'child.txt'
        [IO.File]::WriteAllText($file, 'native smoke ACL fixture', [Text.Encoding]::UTF8)
        $inheritedAcl = Get-Acl -LiteralPath $file
        $ownerRights = @($inheritedAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $OwnerRightsSid.Value })
        $readRights = (New-Object Security.AccessControl.FileSystemAccessRule(
            $OwnerRightsSid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [Security.AccessControl.AccessControlType]::Allow)).FileSystemRights
        if ($ownerRights.Count -ne 1 -or -not $ownerRights[0].IsInherited -or
            $ownerRights[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $ownerRights[0].FileSystemRights -ne $readRights) {
            throw 'New elevated child file lacks inherited OWNER RIGHTS read-only protection'
        }
        Protect-LabPath -Path $file -Directory $false
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $root) -Directory $true -Path $root
        Assert-ProtectedLabAcl -Acl (Get-Acl -LiteralPath $file) -Directory $false -Path $file
        $copiedFile = Join-Path $fresh 'copied.txt'
        Copy-PinnedSourceFile -Source $file -Destination $copiedFile -AllowedRoot $root
        if ([IO.File]::ReadAllText($copiedFile,[Text.Encoding]::UTF8) -ne 'native smoke ACL fixture') {
            throw 'Native shadow pinned file copy changed its bytes'
        }
        $privateCopy = Join-Path $private 'copied-secret.txt'
        Copy-PinnedSourceFile -Source $file -Destination $privateCopy -AllowedRoot $root -Private
        $keyDirectory = Join-Path $root 'identity'
        New-ShadowDirectory -Path $keyDirectory -Private
        $key = Join-Path $keyDirectory 'id_ed25519'
        $publicKey = Join-Path $keyDirectory 'id_ed25519.pub'
        Copy-PinnedSourceFile -Source $file -Destination $key -AllowedRoot $root -Private
        Copy-PinnedSourceFile -Source $file -Destination $publicKey -AllowedRoot $root -Private
        $publicDigest = Get-FileSha256 -Path $publicKey
        $siblingDigest = Get-FileSha256 -Path $privateCopy
        $rejected = $false
        try { [void](Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe { $false }) }
        catch { $rejected = $true }
        if (-not $rejected -or -not (Test-Path -LiteralPath $key -PathType Leaf)) {
            throw 'Native shadow key removal ignored an active runtime probe'
        }
        Set-Acl -LiteralPath $key -AclObject (New-ProtectedLabAcl -Directory $false)
        $rejected = $false
        try { [void](Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe { $true }) }
        catch { $rejected = $true }
        if (-not $rejected -or -not (Test-Path -LiteralPath $key -PathType Leaf)) {
            throw 'Native shadow key removal accepted a widened private key ACL'
        }
        Set-Acl -LiteralPath $key -AclObject (New-PrivateShadowAcl -Directory $false)
        if (-not (Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe { $true }) -or
            (Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe { $true })) {
            throw 'Native shadow key removal was not exact and idempotent'
        }
        [void](New-Item -ItemType SymbolicLink -Path $key -Target $publicKey -ErrorAction Stop)
        try {
            $rejected = $false
            try { [void](Remove-VerifiedShadowPrivateKey -ShadowRoot $root -RuntimeClearProbe { $true }) }
            catch { $rejected = $true }
            if (-not $rejected) { throw 'Native shadow key removal accepted a symbolic link' }
        }
        finally { [IO.File]::Delete($key) }
        if ((Get-FileSha256 -Path $publicKey) -ne $publicDigest -or
            (Get-FileSha256 -Path $privateCopy) -ne $siblingDigest) {
            throw 'Native shadow key removal changed unrelated files'
        }
        $lockPath = Join-Path $root '.runtime.lock'
        $lockStream = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { Protect-LabPath -Path $lockPath -Directory $false }
        finally { $lockStream.Dispose() }
    }
    finally {
        if ($null -ne $guard) { $guard.Dispose() }
        if (Test-Path -LiteralPath $root) {
            $resolved = [IO.Path]::GetFullPath($root).TrimEnd('\')
            if ($leaf -notmatch '^native-smoke-acl-[0-9a-f]{32}$' -or
                $resolved -ine (Join-Path $tempRoot $leaf) -or
                -not $resolved.StartsWith($tempRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Native smoke ACL fixture cleanup target is outside the validated Temp directory'
            }
            [void](Assert-RegularLabPath -Path $resolved -Directory $true)
            Visit-LabTree -Root $resolved -Seal $false -Preflight
            Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop
        }
    }
}

function Invoke-NativeTaskAclDiskSelfTest {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    $execute = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $action = New-ScheduledTaskAction -Execute $execute -Argument '/c exit 0'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    foreach ($case in @(
        [pscustomobject]@{ user=$identity.Name; sid=$identity.User.Value; logon='S4U'; logon_value=2 },
        [pscustomobject]@{ user='SYSTEM'; sid=$SystemSid.Value; logon='ServiceAccount'; logon_value=5 }
    )) {
        $name = 'Ecommerce-NativeSmoke-SelfTest-' + [Guid]::NewGuid().ToString('N')
        try {
            $runAs = New-ScheduledTaskPrincipal -UserId $case.user -LogonType $case.logon -RunLevel Highest
            Register-ProtectedNativeTask -Name $name -Action $action -Trigger $trigger -Principal $runAs -Settings $settings -UserId $case.user -LogonType $case.logon_value
            $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
            if ($task.TaskPath -ne '\' -or (Get-TaskPrincipalSid -Task $task) -ne $case.sid -or
                [string]$task.Principal.LogonType -ne $case.logon) {
                throw 'Native task ACL fixture has the wrong principal'
            }
        }
        finally {
            $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
            if ($null -ne $task) {
                if ($task.TaskPath -ne '\' -or [string]$task.Actions[0].Execute -ine $execute -or
                    [string]$task.Actions[0].Arguments -ne '/c exit 0' -or
                    (Get-TaskPrincipalSid -Task $task) -ne $case.sid) {
                    throw "Temporary native task is not safely owned for cleanup: $name"
                }
                Assert-NativeTaskSecurity -Name $name
                Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false
            }
            if ($null -ne (Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue)) {
                throw "Temporary native task remained after ACL self-test: $name"
            }
        }
    }
}

function Invoke-SelfTest {
    Assert-LabParentBoundary -Path 'C:\' -WindowsRoot $true
    Assert-ShadowProgramFiles
    $normal = '{11111111-1111-1111-1111-111111111111}'
    $native = '{22222222-2222-2222-2222-222222222222}'
    $fixture = "Windows Boot Manager`r`nidentifier $normal`r`ndefault $normal`r`nbootsequence $native"
    $binding = Get-BootManagerBinding -Text $fixture
    if ($binding.default -ne $normal -or $binding.sequence -ne $native) { throw 'BCD manager fixture parser failed' }
    $entryFixture = "Windows Boot Loader`r`nidentifier $native`r`ndescription $EntryName`r`npath \Windows\system32\winload.efi`r`nhypervisorlaunchtype off"
    $entries = @(Get-BcdEntries -Text $entryFixture)
    if ($entries.Count -ne 1 -or $entries[0].id -ne $native -or $entries[0].text -notmatch '(?im)^\s*hypervisorlaunchtype\s+off\s*$') {
        throw 'Native BCD entry fixture parser failed'
    }
    $invalid = $false
    try { [void](Get-BootManagerBinding -Text ($fixture + "`r`ndefault $native")) } catch { $invalid = $true }
    if (-not $invalid) { throw 'Ambiguous BCD default was accepted' }
    foreach ($malformed in @(
        ($fixture + "`r`n                        $normal"),
        $fixture.Replace("bootsequence $native", "bootsequence $native $normal")
    )) {
        $invalid = $false
        try { [void](Get-BootManagerBinding -Text $malformed) } catch { $invalid = $true }
        if (-not $invalid) { throw 'Multi-entry BCD bootsequence was accepted' }
    }
    $campaign = '20260929T163821Z-9da62296f3d5'
    if ((Get-NativeGitBlobSha1 -Bytes ([Text.Encoding]::UTF8.GetBytes("hello`r`n"))) -ne
        'ce013625030ba8dba906f756967f9e9ca394464a') {
        throw 'Protected native Git blob computation failed CRLF normalization'
    }
    $invalid = $false
    try { [void](Get-NativeGitBlobSha1 -Bytes ([Text.Encoding]::UTF8.GetBytes("hello`r"))) }
    catch { $invalid = $true }
    if (-not $invalid) { throw 'Protected native Git blob computation accepted a bare carriage return' }
    $sha = 'a' * 40
    $tree = 'b' * 40
    $manifest = [pscustomobject]@{ campaign_id=$campaign; source_sha=$sha; source_tree_sha=$tree }
    Assert-RunnerIdentity -Manifest $manifest -Id $campaign -Sha $sha -Tree $tree
    foreach ($changed in @(
        [pscustomobject]@{ id='20260929T163821Z-000000000000'; sha=$sha; tree=$tree },
        [pscustomobject]@{ id=$campaign; sha=('c' * 40); tree=$tree },
        [pscustomobject]@{ id=$campaign; sha=$sha; tree=('d' * 40) }
    )) {
        $rejected = $false
        try { Assert-RunnerIdentity -Manifest $manifest -Id $changed.id -Sha $changed.sha -Tree $changed.tree }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Mismatched exact runner identity was accepted' }
    }
    $state = [pscustomobject]@{
        schema=1; mode='NETWORK_SMOKE_NATIVE'; phase='PREPARED'; campaign_id=$campaign
        shadow_root=(Get-NativeShadowRoot -Id $campaign -Sha $sha)
        source_sha=$sha; source_tree_sha=$tree; owner_sid='S-1-5-21-111-222-333-1001'
        s4u_probe_sha256=('a' * 64)
        normal_boot_id=$normal; native_boot_id=$native; entry_name=$EntryName
        vm_name='ecommerce-rocky-10-2-smoke-4e935faff986'
        vm_id='e80d60f3-a12e-4734-a654-0cd24dce0fa1'
        expected_vm_id='e80d60f3-a12e-4734-a654-0cd24dce0fa1'
        runner_manifest_sha256=('e' * 64); bcd_backup_sha256=('f' * 64)
        vsmlaunchtype='PASS'
    }
    Assert-StateBinding -State $state -ExpectedPhase 'PREPARED'
    $state.expected_vm_id = '11111111-1111-1111-1111-111111111111'
    $rejected = $false
    try { Assert-StateBinding -State $state -ExpectedPhase 'PREPARED' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Different operator VM UUID was accepted in persistent native state' }
    $state.expected_vm_id = $state.vm_id
    $state.source_sha = 'bad'
    $rejected = $false
    try { Assert-StateBinding -State $state -ExpectedPhase 'PREPARED' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid persistent native source SHA was accepted' }
    $state.source_sha = $sha
    $state.owner_sid = 'bad'
    $rejected = $false
    try { Assert-StateBinding -State $state -ExpectedPhase 'PREPARED' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid S4U owner SID was accepted' }
    $state.owner_sid = 'S-1-5-21-111-222-333-1001'
    $script:LabRootResolved = 'C:\ecommerce-lab'
    $taskArguments = Get-NativeTaskArguments -Runner 'C:\ecommerce-lab\network-smoke\runner-a\scripts\windows\LabNativeBoot.ps1' -Mode 'RunNative' -Id $campaign -Sha $sha
    if ($taskArguments -notmatch 'RunNative' -or $taskArguments -notmatch [regex]::Escape($campaign) -or
        $taskArguments -notmatch [regex]::Escape($sha)) {
        throw 'Native S4U task arguments lack the campaign and exact runner SHA'
    }
    foreach ($directory in @($true,$false)) {
        $acl = New-ProtectedLabAcl -Directory $directory
        Assert-ProtectedLabAcl -Acl $acl -Directory $directory -Path 'fixture'
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $AuthenticatedUsersSid,[Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow)))
        $rejected = $false
        try { Assert-ProtectedLabAcl -Acl $acl -Directory $directory -Path 'fixture' }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Native boot accepted a writable unprivileged ACL' }
    }
    $runner = 'C:\ecommerce-lab\network-smoke\runner-a\scripts\windows\LabNativeBoot.ps1'
    $task = [pscustomobject]@{
        TaskName=$ResumeTaskName; TaskPath='\'
        Actions=@([pscustomobject]@{
            Execute=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
            Arguments=(Get-NativeTaskArguments -Runner $runner -Mode 'RunNative' -Id $campaign -Sha $sha)
        })
        Principal=[pscustomobject]@{ UserId=$state.owner_sid; LogonType='S4U'; RunLevel='Highest' }
        Triggers=@([pscustomobject]@{ CimClass=[pscustomobject]@{ CimClassName='MSFT_TaskBootTrigger' }; Enabled=$true })
        Settings=[pscustomobject]@{
            Enabled=$true; StartWhenAvailable=$true; MultipleInstances='IgnoreNew'
            DisallowStartIfOnBatteries=$false; StopIfGoingOnBatteries=$false
            RunOnlyIfNetworkAvailable=$false; ExecutionTimeLimit='PT45M'
        }
        State='Ready'
    }
    Assert-NativeTaskBinding -Task $task -Name $ResumeTaskName -Runner $runner -Mode 'RunNative' -Id $campaign -Sha $sha -Sid $state.owner_sid -LogonType 'S4U'
    foreach ($case in @('DisabledTask','DisabledTrigger','ShortLimit','NetworkRequired')) {
        switch ($case) {
            DisabledTask { $task.Settings.Enabled = $false }
            DisabledTrigger { $task.Triggers[0].Enabled = $false }
            ShortLimit { $task.Settings.ExecutionTimeLimit = 'PT3M' }
            NetworkRequired { $task.Settings.RunOnlyIfNetworkAvailable = $true }
        }
        $rejected = $false
        try { Assert-NativeTaskBinding -Task $task -Name $ResumeTaskName -Runner $runner -Mode 'RunNative' -Id $campaign -Sha $sha -Sid $state.owner_sid -LogonType 'S4U' }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Unsafe scheduled task binding was accepted: $case" }
        $task.Settings.Enabled = $true
        $task.Triggers[0].Enabled = $true
        $task.Settings.ExecutionTimeLimit = 'PT45M'
        $task.Settings.RunOnlyIfNetworkAvailable = $false
    }
    $rejected = $false
    try { Assert-RecoveryCampaign -State $state -Requested '20260929T163821Z-000000000000' }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Wrong recovery campaign was accepted' }
    Invoke-NativeAclDiskSelfTest
    Invoke-NativeTaskAclDiskSelfTest
    [Console]::WriteLine('PASS lab-native-boot-self-test')
}

if ($Action -eq 'SelfTest') { Invoke-SelfTest; exit 0 }
Assert-Administrator
$script:LabRootResolved = [IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
if ($script:LabRootResolved -ine 'C:\ecommerce-lab') { throw 'Native boot requires the governed C:\ecommerce-lab root' }
$script:OriginalSmokeRoot = Join-Path $script:LabRootResolved 'network-smoke'
$script:OriginalEvidenceBase = Join-Path $script:LabRootResolved 'evidence\network-smoke'
$rootGuard = $null
$smokeGuard = $null
if ($Action -eq 'Prepare') {
    $script:LabRootResolved = Assert-LabRoot -Path $LabRoot
    $rootGuard = Open-LabDeleteGuard -Path $script:LabRootResolved
    try { $smokeGuard = Open-LabDeleteGuard -Path $script:OriginalSmokeRoot }
    catch { $rootGuard.Dispose(); throw }
    $script:SmokeRoot = $script:OriginalSmokeRoot
    $script:EvidenceBase = $script:OriginalEvidenceBase
    $script:StatePath = Join-Path $script:SmokeRoot $StateName
    $script:RuntimeLockPath = Join-Path $script:SmokeRoot '.runtime.lock'
}
else {
    Set-NativeShadowContext -Id $CampaignId -Sha $SourceSha
    Assert-ShadowBoundary
}
try {
    if ($Action -eq 'ProbeUser') {
        Invoke-ProbeUser -Id $CampaignId -Sha $SourceSha -VmId $ExpectedVmId -OwnerSid $ExpectedOwnerSid
        exit 0
    }
    if ($Action -eq 'RunNative') { Invoke-RunNative -Id $CampaignId -Sha $SourceSha; exit 0 }
    if ($Action -eq 'Watchdog') { Invoke-Watchdog -Id $CampaignId -Sha $SourceSha; exit 0 }
    $lock = Open-NativeRuntimeLock
    try {
        switch ($Action) {
            Prepare { Invoke-Prepare -Id $CampaignId -Sha $SourceSha }
            Reboot { Invoke-Reboot -Id $CampaignId -Sha $SourceSha }
            Recover { Invoke-Recover }
        }
    }
    finally { $lock.Dispose() }
}
finally {
    if ($null -ne $smokeGuard) { $smokeGuard.Dispose() }
    if ($null -ne $rootGuard) { $rootGuard.Dispose() }
}
