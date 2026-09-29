[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Reboot', 'Recover', 'SelfTest')]
    [string]$Action,
    [string]$CampaignId = '',
    [string]$SourceSha = '',
    [string]$LabRoot = 'C:\ecommerce-lab',
    [string]$WslDistribution = 'Ubuntu-24.04',
    [string]$WslRepoRoot = '/home/dev/ecommerce-1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$EntryName = 'Windows - Ecommerce Network Smoke Native VT-x'
$StateName = 'native-boot.json'
$GuidPattern = '^\{[0-9a-fA-F-]{36}\}$'
$CampaignPattern = '^\d{8}T\d{6}Z-[0-9a-f]{12}$'
$VmPattern = '^ecommerce-rocky-10-2-smoke-[0-9a-f]{12}$'
$RunnerNames = @(
    'LabNetworkSmoke.ps1', 'RockyImagePipeline.psm1', 'NativeVagrantSshSmoke.ps1',
    'LabNetworkSeed.ps1', 'LabSshIdentity.ps1', 'local-services-seed-server.ps1'
)

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
        if ($null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
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
        $WslRepoRoot -notmatch '^/[A-Za-z0-9._/-]+$' -or $WslRepoRoot.Contains('..')) {
        throw 'Exact SHA or WSL repository binding is invalid'
    }
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    $head = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','git','rev-parse','HEAD') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $head -Operation 'exact WSL repository HEAD'
    if ($head.StdOut.Trim() -ne $Expected) { throw 'Local WSL Git HEAD differs from the exact runner source SHA' }
    $status = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','git','status','--porcelain=v1','--untracked-files=all') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $status -Operation 'exact WSL worktree status'
    if (-not [string]::IsNullOrWhiteSpace($status.StdOut)) { throw 'Exact-SHA native boot requires a clean WSL worktree' }
    $branch = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','git','branch','--show-current') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $branch -Operation 'exact WSL branch'
    $branchName = $branch.StdOut.Trim()
    if ($branchName -notmatch '^[A-Za-z0-9/_-]+$') { throw 'Exact-SHA native boot requires a named branch' }
    $published = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','gh','pr','view',$branchName,'--repo','dst-red-Wire/ecommerce-1','--json','headRefOid','-q','.headRefOid') -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $published -Operation 'published PR head'
    if ($published.StdOut.Trim() -ne $Expected) { throw 'Published PR HEAD differs from the exact runner source SHA' }
    $tree = Invoke-BoundedProcess -FilePath $wsl -Arguments @('-d',$WslDistribution,'--cd',$WslRepoRoot,'--','git','rev-parse','HEAD^{tree}') -TimeoutSeconds 45 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $tree -Operation 'exact WSL repository tree'
    return $tree.StdOut.Trim()
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
    param([string]$Id, [string]$Sha)
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
    $result = Read-JsonFile (Join-Path (Join-Path (Join-Path $script:LabRootResolved 'evidence\network-smoke') $Id) 'result.json')
    $runnerManifest = Read-JsonFile (Join-Path $runner 'runner.json')
    if ($prepared.schema -ne 1 -or $prepared.status -ne 'PREPARED' -or $prepared.campaign_id -ne $Id -or
        $prepared.retain_vm -ne $true -or $result.schema -ne 1 -or $result.campaign_id -ne $Id -or
        $result.source_git_sha -ne $prepared.source_sha -or $result.cleanup.vm_preserved -ne $true -or
        $result.vm_name -notmatch $VmPattern -or $result.cleanup.vm_name -ne $result.vm_name -or
        [string]$result.cleanup.vm_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        [string]$runnerManifest.source_tree_sha -notmatch '^[0-9a-f]{40}$') {
        throw 'Retained campaign, VM or exact-SHA runner binding is invalid'
    }
    $tree = Assert-WslHead -Expected $Sha
    Assert-RunnerIdentity -Manifest $runnerManifest -Id $Id -Sha $Sha -Tree $tree
    $runnerFiles = @($runnerManifest.runner_files.PSObject.Properties.Name)
    if ($runnerFiles.Count -ne $RunnerNames.Count) { throw 'Exact runner file set is incomplete' }
    $sourceRoot = "\\wsl.localhost\$WslDistribution$($WslRepoRoot.Replace('/', '\'))"
    foreach ($name in $RunnerNames) {
        if ($name -notin $runnerFiles -or [string]$runnerManifest.runner_files.$name -notmatch '^[0-9a-f]{64}$' -or
            (Get-FileSha256 -Path (Join-Path $runner "scripts\windows\$name")) -ne [string]$runnerManifest.runner_files.$name -or
            (Get-FileSha256 -Path (Join-Path $sourceRoot "scripts\windows\$name")) -ne [string]$runnerManifest.runner_files.$name) {
            throw "Staged exact-SHA runner differs: $name"
        }
    }
    $stagedVagrantfile = Join-Path $stage 'platform\vagrant\rocky-image-smoke\Vagrantfile'
    $runtimeVagrantfile = Join-Path $stage 'smoke-run\Vagrantfile'
    $vagrantfileDigest = [string]$runnerManifest.vagrantfile_sha256
    if ($vagrantfileDigest -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $stagedVagrantfile) -ne $vagrantfileDigest -or
        (Get-FileSha256 -Path $runtimeVagrantfile) -ne $vagrantfileDigest -or
        (Get-FileSha256 -Path (Join-Path $sourceRoot 'platform\vagrant\rocky-image-smoke\Vagrantfile')) -ne $vagrantfileDigest) {
        throw 'Retained VM Vagrantfile differs from the exact runner contract'
    }
    $box = [IO.Path]::GetFullPath([string]$prepared.box_path)
    if ($box -notlike "$($script:LabRootResolved)\artifacts\*" -or
        [string]$prepared.box_sha256 -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $box) -ne [string]$prepared.box_sha256 -or
        (Get-FileSha256 -Path (Join-Path (Split-Path -Parent $box) 'manifest.json')) -ne [string]$prepared.box_manifest_sha256 -or
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
        stage=$stage; runner=$runner; vm_name=[string]$result.vm_name
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
        $State.normal_boot_id -notmatch $GuidPattern -or $State.native_boot_id -notmatch $GuidPattern -or
        $State.normal_boot_id -ieq $State.native_boot_id -or
        $State.entry_name -ne $EntryName -or $State.vm_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        $State.runner_manifest_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $State.vsmlaunchtype -notin @('PASS','UNSUPPORTED') -or
        $State.bcd_backup_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Persistent owned native boot state is invalid'
    }
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

function Invoke-Prepare {
    param([string]$Id, [string]$Sha)
    if (Test-Path -LiteralPath $script:StatePath -PathType Leaf) {
        $prior = Read-JsonFile $script:StatePath
        if ($prior.phase -ne 'RECOVERED') { throw 'Existing native smoke boot requires explicit Recover before another Prepare' }
    }
    Assert-NoImageCycle
    $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
    $boot = Assert-NormalBoot
    if (@(Get-OwnedEntries).Count -ne 0) { throw 'An unowned or stale native smoke BCD entry already exists' }
    $backupDir = Join-Path $script:SmokeRoot 'bcd'
    [void](New-Item -ItemType Directory -Path $backupDir -Force)
    $backup = Join-Path $backupDir "before-$Id-$Sha-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).bak"
    if (Test-Path -LiteralPath $backup) { throw 'Campaign BCD backup already exists' }
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
            campaign_id=$Id; source_sha=$Sha; normal_boot_id=$boot.current
            native_boot_id=$nativeId; entry_name=$EntryName; vm_name=$campaign.vm_name
            vm_id=$campaign.vm_id; box_sha256=$campaign.box_sha256
            runner_manifest_sha256=$campaign.runner_manifest_sha256
            vsmlaunchtype=$vsmStatus
            bcd_backup=$backup; bcd_backup_sha256=$backupDigest
            boot_attempts=0; prepared_at=[DateTime]::UtcNow.ToString('o')
        }
        Write-Utf8Json -InputObject $state -Path $script:StatePath
        [Console]::WriteLine("PASS lab-native-boot-prepare campaign=$Id sha=$Sha vm=$($campaign.vm_id) reboot=EXPLICITLY_REQUIRED")
    }
    catch {
        $failure = $_.Exception.Message
        try {
            if ($nativeId -eq '') {
                $entries = @(Get-OwnedEntries)
                if ($entries.Count -eq 1) { $nativeId = $entries[0].id }
            }
            if ($nativeId -ne '' -and (Get-BootContext).current -eq $boot.current) {
                [void](Invoke-Bcd -Arguments @('/delete',$nativeId,'/f'))
            }
        }
        catch { $failure += "; BCD cleanup: $($_.Exception.Message)" }
        try {
            if ($nativeId -ne '') {
                Write-Utf8Json -InputObject ([ordered]@{
                    schema=1; mode='NETWORK_SMOKE_NATIVE'; phase='FAILED'; campaign_id=$Id; source_sha=$Sha
                    normal_boot_id=$boot.current; native_boot_id=$nativeId; entry_name=$EntryName
                    vm_name=$campaign.vm_name; vm_id=$campaign.vm_id; box_sha256=$campaign.box_sha256
                    runner_manifest_sha256=$campaign.runner_manifest_sha256
                    vsmlaunchtype=if ($vsmStatus) { $vsmStatus } else { 'UNSUPPORTED' }
                    bcd_backup=$backup; bcd_backup_sha256=if (Test-Path -LiteralPath $backup) { Get-FileSha256 -Path $backup } else { '' }
                    boot_attempts=0; error=$failure; failed_at=[DateTime]::UtcNow.ToString('o')
                }) -Path $script:StatePath
            }
        }
        catch { $failure += "; failure state: $($_.Exception.Message)" }
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
    Assert-NoImageCycle
    $campaign = Assert-ExistingCampaign -Id $Id -Sha $Sha
    if ($campaign.vm_id -ine [string]$state.vm_id -or $campaign.box_sha256 -ne $state.box_sha256 -or
        $campaign.runner_manifest_sha256 -ne $state.runner_manifest_sha256 -or
        (Get-FileSha256 -Path ([string]$state.bcd_backup)) -ne [string]$state.bcd_backup_sha256) {
        throw 'Retained VM, box, runner or BCD backup differs before reboot'
    }
    $boot = Assert-NormalBoot
    if ($boot.current -ne [string]$state.normal_boot_id) { throw 'Normal Windows loader differs from prepared loader' }
    Assert-OwnedBcdEntry -State $state
    $state.boot_attempts = 1
    $state.phase = 'BOOT_PENDING'
    $state | Add-Member -NotePropertyName reboot_requested_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-Utf8Json -InputObject $state -Path $script:StatePath
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
        Write-Utf8Json -InputObject $state -Path $script:StatePath
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
            @(Get-OwnedEntries).Count -ne 0) {
            throw 'Previously recovered native smoke boot no longer has a clean normal BCD state'
        }
        [Console]::WriteLine("PASS lab-native-boot-recover campaign=$($state.campaign_id) already-recovered=true")
        return
    }
    if ($state.phase -notin @('PREPARED','BOOT_PENDING','FAILED')) {
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
    if ($boot.sequence -ne '') {
        [void](Invoke-Bcd -Arguments @('/deletevalue','{bootmgr}','bootsequence'))
    }
    if ($entries.Count -eq 1) { [void](Invoke-Bcd -Arguments @('/delete',[string]$state.native_boot_id,'/f')) }
    $after = Get-BootContext
    if ($after.current -ne [string]$state.normal_boot_id -or $after.default -ne [string]$state.normal_boot_id -or
        $after.sequence -ne '' -or @(Get-OwnedEntries).Count -ne 0) {
        throw 'Native smoke recovery BCD postcondition failed'
    }
    $state.phase = 'RECOVERED'
    $state | Add-Member -NotePropertyName recovered_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-Utf8Json -InputObject $state -Path $script:StatePath
    [Console]::WriteLine("PASS lab-native-boot-recover campaign=$($state.campaign_id) native-entry-removed=true")
}

function Assert-RecoveryCampaign {
    param($State, [string]$Requested)
    if ($Requested -and $Requested -ne [string]$State.campaign_id) {
        throw 'Recovery campaign ID differs from the persisted owned boot state'
    }
}

function Invoke-SelfTest {
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
        source_sha=$sha; normal_boot_id=$normal; native_boot_id=$native; entry_name=$EntryName
        vm_id='e80d60f3-a12e-4734-a654-0cd24dce0fa1'
        runner_manifest_sha256=('e' * 64); bcd_backup_sha256=('f' * 64)
        vsmlaunchtype='PASS'
    }
    Assert-StateBinding -State $state -ExpectedPhase 'PREPARED'
    $state.source_sha = 'bad'
    $rejected = $false
    try { Assert-StateBinding -State $state -ExpectedPhase 'PREPARED' } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid persistent native source SHA was accepted' }
    $state.source_sha = $sha
    $rejected = $false
    try { Assert-RecoveryCampaign -State $state -Requested '20260929T163821Z-000000000000' }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Wrong recovery campaign was accepted' }
    [Console]::WriteLine('PASS lab-native-boot-self-test')
}

if ($Action -eq 'SelfTest') { Invoke-SelfTest; exit 0 }
Assert-Administrator
$script:LabRootResolved = Assert-LabRoot -Path $LabRoot
$script:SmokeRoot = Join-Path $script:LabRootResolved 'network-smoke'
$script:StatePath = Join-Path $script:SmokeRoot $StateName
$lockPath = Join-Path $script:SmokeRoot '.runtime.lock'
try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
}
catch [IO.IOException] { throw 'BLOCKED_RUNTIME another network smoke action holds the runtime lock' }
try {
    switch ($Action) {
        Prepare { Invoke-Prepare -Id $CampaignId -Sha $SourceSha }
        Reboot { Invoke-Reboot -Id $CampaignId -Sha $SourceSha }
        Recover { Invoke-Recover }
    }
}
finally { $lock.Dispose() }
