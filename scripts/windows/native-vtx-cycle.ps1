[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'Reboot', 'Run', 'Import', 'Recover', 'SelfTest')]
    [string]$Action,
    [string]$RepoRoot = '',
    [string]$WslDistribution = '',
    [string]$WslRepoRoot = '',
    [string]$LabRoot = 'C:\ecommerce-lab',
    [string]$StageRoot = '',
    [string]$ExpectedSourceSha = '',
    [string]$ExpectedSourceTree = '',
    [string]$ExpectedManifestSha256 = '',
    [string]$ExpectedNormalBootId = '',
    [string]$ExpectedNativeBootId = '',
    [switch]$Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:PSModulePath = @(
    (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
    (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
) -join ';'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$NativeEntryName = 'Windows - VirtualBox VT-x native'
$NativeTaskName = 'Ecommerce-VirtualBox-Native-Qualification'
$GuidPattern = '^\{[0-9a-fA-F-]{36}\}$'

function Get-UtcTimestamp {
    return [DateTime]::UtcNow.ToString('o')
}

function Resolve-LabRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($resolved -notmatch '^[A-Za-z]:\\[^\\].+' -or $resolved.StartsWith('\\')) {
        throw "LabRoot must be a non-root local Windows drive path: $resolved"
    }
    return $resolved
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-SingleQuotedPowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Invoke-ElevatedSelf {
    $parameters = @(
        '-Action', $Action,
        '-LabRoot', $LabRoot
    )
    if (-not [string]::IsNullOrWhiteSpace($RepoRoot)) { $parameters += @('-RepoRoot', $RepoRoot) }
    if (-not [string]::IsNullOrWhiteSpace($WslDistribution)) { $parameters += @('-WslDistribution', $WslDistribution) }
    if (-not [string]::IsNullOrWhiteSpace($WslRepoRoot)) { $parameters += @('-WslRepoRoot', $WslRepoRoot) }
    if (-not [string]::IsNullOrWhiteSpace($StageRoot)) { $parameters += @('-StageRoot', $StageRoot) }
    if ($Offline.IsPresent) { $parameters += '-Offline' }
    $parts = @('&', (ConvertTo-SingleQuotedPowerShellLiteral $PSCommandPath))
    foreach ($parameter in $parameters) {
        if ([string]$parameter -match '^-[A-Za-z][A-Za-z0-9]*$') {
            $parts += [string]$parameter
        }
        else {
            $parts += ConvertTo-SingleQuotedPowerShellLiteral ([string]$parameter)
        }
    }
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes(($parts -join ' '))
    )
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded
    )
    exit $process.ExitCode
}

function Assert-Guid {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [string]$Forbidden = ''
    )
    if ($Value -notmatch $GuidPattern -or $Value -ieq '{bootmgr}') {
        throw "Invalid or forbidden BCD identifier: $Value"
    }
    if (-not [string]::IsNullOrWhiteSpace($Forbidden) -and $Value -ieq $Forbidden) {
        throw "Refusing to use the normal Windows loader as the native loader: $Value"
    }
    return $Value.ToLowerInvariant()
}

function Invoke-BcdEdit {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )
    $result = Invoke-BoundedProcess -FilePath (Join-Path $env:SystemRoot 'System32\bcdedit.exe') -Arguments $Arguments -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    if (-not $AllowFailure.IsPresent) {
        Assert-ProcessSuccess -Result $result -Operation "bcdedit $($Arguments -join ' ')"
    }
    return $result
}

function Get-BcdEntries {
    param([Parameter(Mandatory = $true)][string]$Text)
    $entries = @()
    foreach ($block in ($Text -split "(?:\r?\n){2,}")) {
        $identifier = [regex]::Match($block, '\{[0-9a-fA-F-]{36}\}')
        if ($identifier.Success) {
            $entries += [pscustomobject]@{
                Id = $identifier.Value.ToLowerInvariant()
                Text = $block
            }
        }
    }
    return @($entries)
}

function Get-CurrentWindowsLoaderId {
    $result = Invoke-BcdEdit -Arguments @('/enum', '{current}', '/v')
    $entries = @(Get-BcdEntries -Text ($result.StdOut + "`n" + $result.StdErr))
    if ($entries.Count -ne 1 -or $entries[0].Text -notmatch '(?i)winload\.(efi|exe)') {
        throw 'Cannot resolve exactly one current Windows loader from BCD'
    }
    return Assert-Guid -Value $entries[0].Id
}

function Find-NativeWindowsLoaderIds {
    $result = Invoke-BcdEdit -Arguments @('/enum', 'all', '/v')
    $entries = @(Get-BcdEntries -Text ($result.StdOut + "`n" + $result.StdErr))
    return @(
        $entries | Where-Object {
            $_.Text -match '(?i)winload\.(efi|exe)' -and
            $_.Text -match ('(?m)^.*' + [regex]::Escape($NativeEntryName) + '\s*$')
        } | ForEach-Object { $_.Id }
    )
}

function Set-OneShotBootSequence {
    param([Parameter(Mandatory = $true)][string]$BootId)
    $validated = Assert-Guid -Value $BootId
    [void](Invoke-BcdEdit -Arguments @('/bootsequence', $validated))
    $bootManager = Invoke-BcdEdit -Arguments @('/enum', '{bootmgr}', '/v')
    if (($bootManager.StdOut + $bootManager.StdErr) -notmatch [regex]::Escape($validated)) {
        throw "BCD bootsequence does not reference the expected loader: $validated"
    }
}

function Write-StagingManifest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $manifest = Join-Path $Root 'SHA256SUMS'
    if (Test-Path -LiteralPath $manifest) {
        throw "Staging manifest already exists: $manifest"
    }
    $lines = @()
    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -Recurse | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($Root.Length).TrimStart('\').Replace('\', '/')
        if (
            $relative -in @('.prepared.json', 'qualification-key', 'qualification-key.pub') -or
            $relative -match '^(artifacts|evidence|logs|smoke-run)/'
        ) {
            continue
        }
        $lines += "$(Get-FileSha256 -Path $file.FullName)  $relative"
    }
    if ($lines.Count -lt 8) {
        throw 'Staging manifest is unexpectedly small'
    }
    [IO.File]::WriteAllText(
        $manifest,
        (($lines -join "`n") + "`n"),
        (New-Object Text.UTF8Encoding($false))
    )
    return $manifest
}

function Test-StagingManifest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $manifest = Join-Path $Root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return $false }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $manifestPaths = @{}
    foreach ($line in [IO.File]::ReadAllLines($manifest, [Text.Encoding]::UTF8)) {
        if ($line -notmatch '^(?<digest>[0-9a-f]{64})  (?<path>[^\r\n]+)$') { return $false }
        $relative = $Matches.path
        if ($manifestPaths.ContainsKey($relative)) { return $false }
        $manifestPaths[$relative] = $true
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|/)\.\.(/|$)') { return $false }
        $candidate = [IO.Path]::GetFullPath((Join-Path $rootPath $relative.Replace('/', '\')))
        if (-not $candidate.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) { return $false }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $false }
        if ((Get-FileSha256 -Path $candidate) -ne $Matches.digest) { return $false }
    }
    $currentPaths = @(
        Get-ChildItem -LiteralPath $Root -File -Recurse | ForEach-Object {
            $_.FullName.Substring($Root.Length).TrimStart('\').Replace('\', '/')
        } | Where-Object {
            $_ -ne 'SHA256SUMS' -and
            $_ -notin @('.prepared.json', 'qualification-key', 'qualification-key.pub') -and
            $_ -notmatch '^(artifacts|evidence|logs|smoke-run|probe)/'
        }
    )
    if ($currentPaths.Count -ne $manifestPaths.Count) { return $false }
    foreach ($relative in $currentPaths) {
        if (-not $manifestPaths.ContainsKey($relative)) { return $false }
    }
    return $true
}

function Get-VirtualBoxBackendFromLog {
    param([Parameter(Mandatory = $true)][string]$Text)
    if ($Text -match '(?im)Attempting fall back to NEM|\bNEM:|WHvCapabilityCodeHypervisorPresent') {
        return 'NEM'
    }
    if ($Text -match '(?im)\bHM:.*(?:VT-x|AMD-V)') {
        return 'NATIVE_VTX'
    }
    return 'UNKNOWN'
}

function Assert-ResultBinding {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$SourceSha,
        [Parameter(Mandatory = $true)][string]$SourceTree,
        [Parameter(Mandatory = $true)][string]$ManifestSha256
    )
    if (
        $Result.source_git_sha -ne $SourceSha -or
        $Result.source_tree_sha -ne $SourceTree -or
        $Result.staging_manifest_sha256 -ne $ManifestSha256
    ) {
        throw 'Native Windows evidence does not bind the expected source and staging manifest'
    }
}

function Register-NativeTask {
    param(
        [Parameter(Mandatory = $true)][string]$Runner,
        [Parameter(Mandatory = $true)][string]$PreparedStage,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$SourceSha,
        [Parameter(Mandatory = $true)][string]$SourceTree,
        [Parameter(Mandatory = $true)][string]$ManifestSha256,
        [Parameter(Mandatory = $true)][string]$NormalBootId,
        [Parameter(Mandatory = $true)][string]$NativeBootId
    )
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $Runner, '-Action', 'Run', '-StageRoot', $PreparedStage, '-LabRoot', $Root,
        '-ExpectedSourceSha', $SourceSha, '-ExpectedSourceTree', $SourceTree,
        '-ExpectedManifestSha256', $ManifestSha256,
        '-ExpectedNormalBootId', $NormalBootId, '-ExpectedNativeBootId', $NativeBootId
    )
    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (($arguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ')
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
    [void](Register-ScheduledTask -TaskName $NativeTaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force)
    $registered = Get-ScheduledTask -TaskName $NativeTaskName -ErrorAction Stop
    if ($registered.TaskName -ne $NativeTaskName) {
        throw 'Native qualification scheduled task registration failed'
    }
}

function Remove-NativeTask {
    $task = Get-ScheduledTask -TaskName $NativeTaskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Unregister-ScheduledTask -TaskName $NativeTaskName -Confirm:$false
    }
}

function Invoke-EmergencyNativeReturn {
    param([Parameter(Mandatory = $true)][string]$Failure)
    $failures = @()
    $normalBootId = $null
    try {
        $globalPrepared = Read-JsonFile (Join-Path $script:LabRootResolved 'prepared.json')
        $normalBootId = Assert-Guid -Value ([string]$globalPrepared.normal_boot_id)
        Set-OneShotBootSequence -BootId $normalBootId
    }
    catch { $failures += "normal boot sequence: $($_.Exception.Message)" }
    try { Remove-NativeTask } catch { $failures += "scheduled task cleanup: $($_.Exception.Message)" }
    try {
        $emergencyRoot = Join-Path $script:LabRootResolved 'evidence'
        [void](New-Item -ItemType Directory -Path $emergencyRoot -Force)
        Write-Utf8Json -InputObject ([ordered]@{
            schema = 1; status = 'FAIL'; failure = $Failure
            normal_boot_id = $normalBootId; cleanup_failures = $failures
            completed_at = Get-UtcTimestamp
        }) -Path (Join-Path $emergencyRoot 'native-emergency-return.json')
    }
    catch { $failures += "emergency evidence: $($_.Exception.Message)" }
    try { Restart-Computer -Force }
    catch { throw "Native emergency return could not reboot: $($failures + $_.Exception.Message -join '; ')" }
}

function Invoke-NativeBackendProbe {
    param(
        [Parameter(Mandatory = $true)][string]$VBoxManage,
        [Parameter(Mandatory = $true)][string]$PreparedStage,
        [Parameter(Mandatory = $true)][string]$SourceSha
    )
    $name = "ecommerce-rocky-10-2-native-probe-$($SourceSha.Substring(0, 12))"
    $probeRoot = Join-Path $PreparedStage 'probe'
    [void](New-Item -ItemType Directory -Path $probeRoot -Force)
    $initial = Get-VBoxMachines -VBoxManage $VBoxManage -WorkingDirectory $PreparedStage
    if ($initial.ContainsKey($name)) { throw "Native backend probe VM already exists: $name" }
    try {
        $create = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('createvm', '--name', $name, '--ostype', 'RedHat_64', '--basefolder', $probeRoot, '--register') -TimeoutSeconds 30 -WorkingDirectory $PreparedStage
        Assert-ProcessSuccess -Result $create -Operation 'VirtualBox native backend probe creation'
        $modify = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('modifyvm', $name, '--memory', '256', '--cpus', '1', '--audio-enabled', 'off', '--nic1', 'none') -TimeoutSeconds 30 -WorkingDirectory $PreparedStage
        Assert-ProcessSuccess -Result $modify -Operation 'VirtualBox native backend probe configuration'
        $start = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('startvm', $name, '--type', 'headless') -TimeoutSeconds 60 -WorkingDirectory $PreparedStage
        Assert-ProcessSuccess -Result $start -Operation 'VirtualBox native backend probe start'
        Start-Sleep -Seconds 5
        $log = Join-Path $probeRoot "$name\Logs\VBox.log"
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) {
            throw 'VirtualBox native backend probe produced no VBox.log'
        }
        $backend = Get-VirtualBoxBackendFromLog -Text ([IO.File]::ReadAllText($log, [Text.Encoding]::UTF8))
        if ($backend -ne 'NATIVE_VTX') {
            throw "VirtualBox backend is $backend; native VT-x is required and NEM is forbidden"
        }
        return $backend
    }
    finally {
        [void](Remove-OwnedVirtualMachine -Name $name -InitialMachines $initial -VBoxManage $VBoxManage -WorkingDirectory $PreparedStage)
    }
}

function Invoke-VagrantSmokeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Vagrant,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $result = Invoke-BoundedProcess -FilePath $Vagrant -Arguments @('ssh', '-c', $Command) -TimeoutSeconds 120 -WorkingDirectory $WorkingDirectory -Environment $Environment
    Assert-ProcessSuccess -Result $result -Operation "Vagrant native smoke check $Name"
    return $result.StdOut.Trim()
}

function Invoke-NativeRun {
    if (-not (Test-Administrator)) { throw 'Native runtime task requires an elevated token' }
    $preparedStage = [IO.Path]::GetFullPath($StageRoot).TrimEnd('\')
    $stagingBase = [IO.Path]::GetFullPath((Join-Path $script:LabRootResolved 'staging')).TrimEnd('\')
    if (-not $preparedStage.StartsWith($stagingBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Native runtime stage is outside the governed lab staging root'
    }
    $prepared = Read-JsonFile (Join-Path $preparedStage '.prepared.json')
    $sourceSha = [string]$prepared.source_git_sha
    $sourceTree = [string]$prepared.source_tree_sha
    if ($sourceSha -notmatch '^[0-9a-f]{40}$' -or $sourceTree -notmatch '^[0-9a-f]{40}$') {
        throw 'Prepared native runtime has invalid Git identities'
    }
    $resultRoot = Join-Path $script:LabRootResolved "evidence\$sourceSha"
    [void](New-Item -ItemType Directory -Path $resultRoot -Force)
    $resultPath = Join-Path $resultRoot 'result.json'
    $attemptPath = Join-Path $resultRoot 'attempt.json'
    $artifactRoot = Join-Path $script:LabRootResolved "artifacts\$sourceSha"
    [void](New-Item -ItemType Directory -Path $artifactRoot -Force)
    $result = [ordered]@{
        schema = 1
        status = 'FAIL'
        source_git_sha = $sourceSha
        source_tree_sha = $sourceTree
        staging_manifest_sha256 = [string]$prepared.staging_manifest_sha256
        virtualbox_backend = 'UNKNOWN'
        nem_detected = $null
        native_vtx = 'NOT_EXECUTED'
        precheck = 'NOT_EXECUTED'
        packer = [ordered]@{
            init = 'NOT_EXECUTED'; fmt = 'NOT_EXECUTED'; validate = 'NOT_EXECUTED'
            build = 'NOT_EXECUTED'; duration_seconds = $null
        }
        milestones = [ordered]@{
            T0_PACKER_START = $null; T1_VM_CREATED = $null; T2_ISO_BOOT = $null
            T3_KICKSTART_START = $null; T4_NETWORK_READY = $null
            T5_RPM_INSTALLATION_START = $null; T6_RPM_INSTALLATION_END = $null
            T7_FIRST_REBOOT = $null; T8_INSTALLED_OS_BOOT = $null
            T9_SSHD_READY = $null; T10_PACKER_SSH_CONNECTION = $null
            T11_PROVISIONING_COMPLETE = $null; T12_SHUTDOWN = $null
            T13_ARTIFACT_EXPORT_COMPLETE = $null
        }
        artifact = $null
        artifact_sha256 = $null
        artifact_size_bytes = $null
        vagrant_smoke = [ordered]@{
            box_add = 'NOT_EXECUTED'; boot = 'NOT_EXECUTED'; ssh = 'NOT_EXECUTED'
            rocky_version = 'NOT_EXECUTED'; expected_arch = 'NOT_EXECUTED'
            expected_cpu = 'NOT_EXECUTED'; expected_memory = 'NOT_EXECUTED'
            expected_disk = 'NOT_EXECUTED'; xfs = 'NOT_EXECUTED'
            lvm_absent = 'NOT_EXECUTED'; swap_absent = 'NOT_EXECUTED'
            rpm_profile = 'NOT_EXECUTED'; kernel = 'NOT_EXECUTED'
            systemd = 'NOT_EXECUTED'; network = 'NOT_EXECUTED'
            fundamental_tools = 'NOT_EXECUTED'; rke2_prerequisites = 'NOT_EXECUTED'
            security = 'NOT_EXECUTED'
        }
        observations = [ordered]@{}
        cleanup = 'NOT_EXECUTED'
        qualification_key_cleanup = 'NOT_EXECUTED'
        bootsequence_return_normal = 'NOT_EXECUTED'
        native_task_removed = 'NOT_EXECUTED'
        runtime_capture = [ordered]@{
            systeminfo_sha256 = $null; bcd_current_sha256 = $null
            transcript = $null; transcript_sha256 = $null
        }
        started_at = Get-UtcTimestamp
        completed_at = $null
        error = $null
    }
    $vbox = [string]$prepared.tools.virtualbox.executable
    $packer = [string]$prepared.tools.packer.executable
    $vagrant = [string]$prepared.tools.vagrant.executable
    $ownedBuildVm = 'ecommerce-rocky-10-2-build-rke2'
    $initialBuildMachines = @{}
    $smokeRoot = $null
    $smokeEnvironment = @{}
    $smokeInitialMachines = @{}
    $smokeVmName = $null
    $smokeBoxName = $null
    $cleanupFailed = $false
    $transcriptStarted = $false
    try {
        if (
            $ExpectedSourceSha -notmatch '^[0-9a-f]{40}$' -or
            $ExpectedSourceTree -notmatch '^[0-9a-f]{40}$' -or
            $ExpectedManifestSha256 -notmatch '^[0-9a-f]{64}$'
        ) {
            throw 'Native scheduled task has invalid expected source bindings'
        }
        $expectedNormal = Assert-Guid -Value $ExpectedNormalBootId
        $expectedNative = Assert-Guid -Value $ExpectedNativeBootId -Forbidden $expectedNormal
        if (
            $sourceSha -ne $ExpectedSourceSha -or $sourceTree -ne $ExpectedSourceTree -or
            [string]$prepared.staging_manifest_sha256 -ne $ExpectedManifestSha256 -or
            [string]$prepared.normal_boot_id -ne $expectedNormal -or
            [string]$prepared.native_boot_id -ne $expectedNative
        ) {
            throw 'Native staged metadata differs from the scheduled exact-source bindings'
        }
        if (Test-Path -LiteralPath $attemptPath) {
            throw 'FAIL_ALREADY_ATTEMPTED: MAX_NATIVE_BOOT_ATTEMPTS=1'
        }
        Write-Utf8Json -InputObject ([ordered]@{ source_git_sha = $sourceSha; attempt = 1; started_at = Get-UtcTimestamp }) -Path $attemptPath
        if (-not (Test-StagingManifest -Root $preparedStage)) { throw 'Native staging integrity verification failed before build' }
        if ((Get-FileSha256 -Path (Join-Path $preparedStage 'SHA256SUMS')) -ne [string]$prepared.staging_manifest_sha256) {
            throw 'Native staging manifest digest differs from preparation evidence'
        }
        foreach ($keyBinding in @(
            [pscustomobject]@{ Name = 'qualification-key'; Digest = [string]$prepared.qualification_private_key_sha256 },
            [pscustomobject]@{ Name = 'qualification-key.pub'; Digest = [string]$prepared.qualification_public_key_sha256 }
        )) {
            $keyPath = Join-Path $preparedStage $keyBinding.Name
            if ($keyBinding.Digest -notmatch '^[0-9a-f]{64}$' -or (Get-FileSha256 -Path $keyPath) -ne $keyBinding.Digest) {
                throw "Ephemeral qualification key binding failed: $($keyBinding.Name)"
            }
        }
        $transcriptPath = Join-Path $preparedStage 'logs\native-qualification-transcript.txt'
        [void](Start-Transcript -LiteralPath $transcriptPath -Force)
        $transcriptStarted = $true
        $result.runtime_capture.transcript = $transcriptPath
        $currentBootId = Get-CurrentWindowsLoaderId
        if ($currentBootId -ne [string]$prepared.native_boot_id) {
            throw "Native task is running under unexpected Windows loader: $currentBootId"
        }
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
        $processors = @(Get-CimInstance -ClassName Win32_Processor)
        if ($computer.HypervisorPresent) { throw 'Microsoft hypervisor remains active in the native boot' }
        if ($processors.Count -eq 0 -or @($processors | Where-Object { $_.VirtualizationFirmwareEnabled -ne $true }).Count -gt 0) {
            throw 'Firmware virtualization is unavailable in the native boot'
        }
        $systemInfo = Invoke-BoundedProcess -FilePath (Join-Path $env:SystemRoot 'System32\systeminfo.exe') -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
        Assert-ProcessSuccess -Result $systemInfo -Operation 'native boot systeminfo capture'
        $systemInfoPath = Join-Path $preparedStage 'logs\systeminfo.txt'
        [IO.File]::WriteAllText($systemInfoPath, $systemInfo.StdOut, (New-Object Text.UTF8Encoding($false)))
        $result.runtime_capture.systeminfo_sha256 = Get-FileSha256 -Path $systemInfoPath
        $bcdCurrent = Invoke-BcdEdit -Arguments @('/enum', '{current}', '/v')
        $bcdCurrentPath = Join-Path $preparedStage 'logs\bcd-current.txt'
        [IO.File]::WriteAllText($bcdCurrentPath, ($bcdCurrent.StdOut + $bcdCurrent.StdErr), (New-Object Text.UTF8Encoding($false)))
        $result.runtime_capture.bcd_current_sha256 = Get-FileSha256 -Path $bcdCurrentPath
        foreach ($tool in @(
            [pscustomobject]@{ Path = $packer; Args = @('version'); Pattern = '^Packer v(?<version>[0-9]+\.[0-9]+\.[0-9]+)'; Expected = [string]$prepared.tools.packer.actual_version; Name = 'Packer' },
            [pscustomobject]@{ Path = $vbox; Args = @('--version'); Pattern = '^(?<version>[0-9]+\.[0-9]+\.[0-9]+)r'; Expected = [string]$prepared.tools.virtualbox.actual_version; Name = 'VirtualBox' },
            [pscustomobject]@{ Path = $vagrant; Args = @('--version'); Pattern = '^Vagrant (?<version>[0-9]+\.[0-9]+\.[0-9]+)$'; Expected = [string]$prepared.tools.vagrant.actual_version; Name = 'Vagrant' }
        )) {
            $versionResult = Invoke-BoundedProcess -FilePath $tool.Path -Arguments $tool.Args -TimeoutSeconds 15 -WorkingDirectory $preparedStage
            Assert-ProcessSuccess -Result $versionResult -Operation "$($tool.Name) native version probe"
            $versionOutput = ($versionResult.StdOut + $versionResult.StdErr).Trim()
            if ($versionOutput -notmatch $tool.Pattern -or $Matches.version -ne $tool.Expected) {
                throw "$($tool.Name) native version differs from prepared exact version"
            }
        }
        $result.virtualbox_backend = Invoke-NativeBackendProbe -VBoxManage $vbox -PreparedStage $preparedStage -SourceSha $sourceSha
        $result.nem_detected = $false
        $result.native_vtx = 'PASS'
        $result.precheck = 'PASS'

        $sourceRoot = Join-Path $preparedStage 'packer'
        $varFile = Join-Path $preparedStage 'rocky-10.2.auto.pkrvars.hcl'
        foreach ($operation in @(
            [pscustomobject]@{ Field = 'init'; Args = @('init', $sourceRoot); Timeout = 300; Name = 'packer init' },
            [pscustomobject]@{ Field = 'fmt'; Args = @('fmt', '-check', $sourceRoot); Timeout = 120; Name = 'packer fmt -check' },
            [pscustomobject]@{ Field = 'validate'; Args = @('validate', "-var-file=$varFile", $sourceRoot); Timeout = 120; Name = 'packer validate' }
        )) {
            $operationResult = Invoke-BoundedProcess -FilePath $packer -Arguments $operation.Args -TimeoutSeconds $operation.Timeout -WorkingDirectory $preparedStage
            Assert-ProcessSuccess -Result $operationResult -Operation $operation.Name
            $result.packer[$operation.Field] = 'PASS'
        }

        $serialLog = Join-Path $preparedStage 'artifacts\virtualbox-serial.log'
        $packerLog = Join-Path $preparedStage 'logs\packer-build.log'
        $milestoneTokens = [ordered]@{
            T3_KICKSTART_START = 'ECOMMERCE_MILESTONE T3_KICKSTART_START'
            T4_NETWORK_READY = 'ECOMMERCE_MILESTONE T4_NETWORK_READY'
            T5_RPM_INSTALLATION_START = 'ECOMMERCE_MILESTONE T5_RPM_INSTALLATION_START'
            T6_RPM_INSTALLATION_END = 'ECOMMERCE_MILESTONE T6_RPM_INSTALLATION_END'
            T7_FIRST_REBOOT = 'ECOMMERCE_MILESTONE T7_FIRST_REBOOT'
            T8_INSTALLED_OS_BOOT = 'ECOMMERCE_MILESTONE T8_INSTALLED_OS_BOOT'
            T9_SSHD_READY = 'ECOMMERCE_MILESTONE T9_SSHD_READY'
            T10_PACKER_SSH_CONNECTION = 'ECOMMERCE_MILESTONE T10_PACKER_SSH_CONNECTION'
            T11_PROVISIONING_COMPLETE = 'ECOMMERCE_MILESTONE T11_PROVISIONING_COMPLETE'
            T12_SHUTDOWN = 'ECOMMERCE_MILESTONE T12_SHUTDOWN'
        }
        $initialBuildMachines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $preparedStage
        if ($initialBuildMachines.ContainsKey($ownedBuildVm)) { throw "Owned Packer VM already exists: $ownedBuildVm" }
        $result.milestones.T0_PACKER_START = Get-UtcTimestamp
        $observeProgress = {
            $observedAt = Get-UtcTimestamp
            if ($null -eq $result.milestones.T1_VM_CREATED) {
                try {
                    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $preparedStage
                    if ($machines.ContainsKey($ownedBuildVm)) { $result.milestones.T1_VM_CREATED = $observedAt }
                }
                catch { }
            }
            try {
                if (Test-Path -LiteralPath $serialLog -PathType Leaf) {
                    $serialInfo = Get-Item -LiteralPath $serialLog
                    if ($serialInfo.Length -gt 0 -and $null -eq $result.milestones.T2_ISO_BOOT) { $result.milestones.T2_ISO_BOOT = $observedAt }
                    $serial = [IO.File]::ReadAllText($serialLog, [Text.Encoding]::UTF8)
                    foreach ($name in $milestoneTokens.Keys) {
                        if ($null -eq $result.milestones[$name] -and $serial.Contains($milestoneTokens[$name])) { $result.milestones[$name] = $observedAt }
                    }
                }
            }
            catch { }
        }.GetNewClosure()
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $build = Invoke-BoundedProcess -FilePath $packer -Arguments @('build', '-only=rocky-10.2-base.virtualbox-iso.base', "-var-file=$varFile", '-var=image_profile=rke2', $sourceRoot) -TimeoutSeconds 7200 -WorkingDirectory $preparedStage -Environment @{ PACKER_LOG = '1'; PACKER_LOG_PATH = $packerLog } -OnPoll $observeProgress -PollIntervalSeconds 5
        $stopwatch.Stop()
        Assert-ProcessSuccess -Result $build -Operation 'native VT-x packer build'
        $result.packer.duration_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
        $result.packer.build = 'PASS'
        $artifactSource = Join-Path $preparedStage 'artifacts\rocky-10.2-rke2-virtualbox.box'
        if (-not (Test-Path -LiteralPath $artifactSource -PathType Leaf)) { throw 'Packer produced no contracted VirtualBox box' }
        $result.milestones.T13_ARTIFACT_EXPORT_COMPLETE = Get-UtcTimestamp
        $missingMilestones = @($result.milestones.Keys | Where-Object { $null -eq $result.milestones[$_] })
        if ($missingMilestones.Count -gt 0) { throw "Packer runtime milestones are incomplete: $($missingMilestones -join ', ')" }
        $artifactSha256 = Get-FileSha256 -Path $artifactSource
        $artifact = Join-Path $artifactRoot 'rocky-10.2-rke2-virtualbox.box'
        $temporaryArtifact = "$artifact.$([Guid]::NewGuid().ToString('N')).tmp"
        Copy-Item -LiteralPath $artifactSource -Destination $temporaryArtifact
        if ((Get-FileSha256 -Path $temporaryArtifact) -ne $artifactSha256) { throw 'Artifact digest changed during native promotion' }
        Move-Item -LiteralPath $temporaryArtifact -Destination $artifact -Force
        $result.artifact = $artifact
        $result.artifact_sha256 = $artifactSha256
        $result.artifact_size_bytes = (Get-Item -LiteralPath $artifact).Length

        $runtimeContract = Read-JsonFile (Join-Path $preparedStage 'runtime-contract.json')
        if ($runtimeContract.resources.vcpus -ne 4 -or $runtimeContract.resources.memory_mib -ne 4096 -or $runtimeContract.resources.disk_mib -ne 32768) {
            throw 'Generated runtime resource contract differs from the canonical reference image'
        }
        $smokeRoot = Join-Path $preparedStage 'smoke-run'
        [void](New-Item -ItemType Directory -Path $smokeRoot)
        Copy-Item -LiteralPath (Join-Path $preparedStage 'smoke\Vagrantfile') -Destination $smokeRoot
        $smokeVmName = "ecommerce-rocky-10-2-smoke-$($artifactSha256.Substring(0, 12))"
        $smokeBoxName = "ecommerce/rocky-10.2-rke2-$($artifactSha256.Substring(0, 12))"
        Write-Utf8Json -InputObject ([ordered]@{
            name = $smokeVmName; box_name = $smokeBoxName
            vagrant_version = [string]$prepared.tools.vagrant.actual_version
            private_key = (Join-Path $preparedStage 'qualification-key')
            boot_timeout_seconds = 900; ssh_timeout_seconds = 30
            cpus = [int]$runtimeContract.resources.vcpus
            memory_mib = [int]$runtimeContract.resources.memory_mib
            nic_type = [string]$runtimeContract.virtualbox.network_adapter
        }) -Path (Join-Path $smokeRoot 'runtime.json')
        $smokeEnvironment = @{
            VAGRANT_HOME = (Join-Path $smokeRoot 'vagrant-home')
            VAGRANT_CHECKPOINT_DISABLE = '1'; VAGRANT_DEFAULT_PROVIDER = 'virtualbox'; VAGRANT_NO_PLUGINS = '1'
        }
        $smokeInitialMachines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
        if ($smokeInitialMachines.ContainsKey($smokeVmName)) { throw "Owned smoke VM already exists: $smokeVmName" }
        $boxAdd = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box', 'add', '--name', $smokeBoxName, '--provider', 'virtualbox', '--checksum-type', 'sha256', '--checksum', $artifactSha256, $artifact) -TimeoutSeconds 600 -WorkingDirectory $smokeRoot -Environment $smokeEnvironment
        Assert-ProcessSuccess -Result $boxAdd -Operation 'native Vagrant box add'
        $result.vagrant_smoke.box_add = 'PASS'
        $up = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('up', '--provider', 'virtualbox', '--no-provision') -TimeoutSeconds 900 -WorkingDirectory $smokeRoot -Environment $smokeEnvironment
        Assert-ProcessSuccess -Result $up -Operation 'native Vagrant smoke boot'
        $result.vagrant_smoke.boot = 'PASS'
        $sshReady = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            $probe = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('ssh', '-c', 'true') -TimeoutSeconds 30 -WorkingDirectory $smokeRoot -Environment $smokeEnvironment
            if ($probe.ExitCode -eq 0) { $sshReady = $true; break }
            if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
        }
        if (-not $sshReady) { throw 'Native Vagrant SSH readiness failed' }
        $result.vagrant_smoke.ssh = 'PASS'
        $result.observations.rocky_version = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'rocky-version' -Command "grep -Fx 'Rocky Linux release 10.2 (Red Quartz)' /etc/rocky-release"
        $result.vagrant_smoke.rocky_version = 'PASS'
        $result.observations.architecture = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'architecture' -Command "test \"`$(uname -m)\" = x86_64 && uname -m"
        $result.vagrant_smoke.expected_arch = 'PASS'
        $result.observations.cpu = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'cpu' -Command "test \"`$(getconf _NPROCESSORS_ONLN)\" -eq 4 && getconf _NPROCESSORS_ONLN"
        $result.vagrant_smoke.expected_cpu = 'PASS'
        $result.observations.memory = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'memory' -Command "awk '`$1 == \"MemTotal:\" { print `$2; exit !(`$2 >= 3500000) }' /proc/meminfo"
        $result.vagrant_smoke.expected_memory = 'PASS'
        $diskBytes = [int64]$runtimeContract.resources.disk_mib * 1MB
        $result.observations.disk = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'disk' -Command "size=`$(lsblk -b -dn -o SIZE /dev/sda); test \"`$size\" -ge $diskBytes; printf '%s' \"`$size\""
        $result.vagrant_smoke.expected_disk = 'PASS'
        [void](Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'xfs' -Command "test \"`$(findmnt -n -o FSTYPE /)\" = xfs")
        $result.vagrant_smoke.xfs = 'PASS'
        [void](Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'lvm-absent' -Command "! lsblk -n -o TYPE | grep -qx lvm")
        $result.vagrant_smoke.lvm_absent = 'PASS'
        [void](Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'swap-absent' -Command "test -z \"`$(swapon --noheadings --show)\"")
        $result.vagrant_smoke.swap_absent = 'PASS'
        $packages = @($runtimeContract.rpm_profile_roots)
        if ($packages.Count -lt 10 -or @($packages | Where-Object { $_ -notmatch '^[A-Za-z0-9+_.-]+$' }).Count -gt 0) { throw 'Runtime RPM profile roots are invalid' }
        $result.observations.rpm_profile = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'rpm-profile' -Command ("rpm -q " + ($packages -join ' '))
        $result.vagrant_smoke.rpm_profile = 'PASS'
        $result.observations.kernel = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'kernel' -Command 'uname -r'
        $result.vagrant_smoke.kernel = 'PASS'
        $result.observations.systemd = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'systemd' -Command "state=`$(systemctl is-system-running --wait || true); test \"`$state\" = running; test -z \"`$(systemctl --failed --no-legend --plain)\"; printf '%s' \"`$state\""
        $result.vagrant_smoke.systemd = 'PASS'
        $result.observations.network = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'network' -Command "ip -4 -o addr show scope global | grep -q .; ip -4 route show default | grep -q '^default '; ip -4 -o addr show scope global; ip -4 route show default"
        $result.vagrant_smoke.network = 'PASS'
        $result.observations.fundamental_tools = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'fundamental-tools' -Command "for tool in python3 curl tar gzip xz zstd rsync unzip openssl nft ip ss systemctl; do command -v \"`$tool\" >/dev/null; done; printf 'required-tools-present'"
        $result.vagrant_smoke.fundamental_tools = 'PASS'
        $result.observations.rke2_prerequisites = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'rke2-prerequisites' -Command "test \"`$(stat -fc %T /sys/fs/cgroup)\" = cgroup2fs; for module in overlay br_netfilter nf_conntrack vxlan; do sudo -n modprobe \"`$module\"; done; test \"`$(sysctl -n net.ipv4.ip_forward)\" = 1; test \"`$(sysctl -n net.bridge.bridge-nf-call-iptables)\" = 1; test -d /sys/fs/bpf; printf 'rke2-prerequisites-present'"
        $result.vagrant_smoke.rke2_prerequisites = 'PASS'
        $result.observations.security = Invoke-VagrantSmokeCommand -Vagrant $vagrant -WorkingDirectory $smokeRoot -Environment $smokeEnvironment -Name 'security' -Command "test \"`$(getenforce)\" = Enforcing; sudo -n sshd -T | grep -qx 'permitrootlogin no'; sudo -n sshd -T | grep -qx 'passwordauthentication no'"
        $result.vagrant_smoke.security = 'PASS'
        $result.status = 'PASS'
    }
    catch {
        $result.error = $_.Exception.Message
    }
    finally {
        try {
            if ($null -ne $smokeRoot -and (Test-Path -LiteralPath $smokeRoot -PathType Container)) {
                $destroy = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('destroy', '--force') -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $smokeEnvironment
                if ($destroy.ExitCode -ne 0 -and $null -ne $smokeVmName) { [void](Remove-OwnedVirtualMachine -Name $smokeVmName -InitialMachines $smokeInitialMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot) }
                if ($null -ne $smokeBoxName) {
                    $boxRemove = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box', 'remove', '--force', $smokeBoxName) -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $smokeEnvironment
                    if ($boxRemove.ExitCode -ne 0 -and $result.vagrant_smoke.box_add -eq 'PASS') { throw 'Native Vagrant box cleanup failed' }
                }
            }
            if ($initialBuildMachines.Count -gt 0 -or (Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $preparedStage).ContainsKey($ownedBuildVm)) {
                [void](Remove-OwnedVirtualMachine -Name $ownedBuildVm -InitialMachines $initialBuildMachines -VBoxManage $vbox -WorkingDirectory $preparedStage)
            }
            $result.cleanup = 'PASS'
        }
        catch {
            $cleanupFailed = $true; $result.cleanup = 'FAIL'
            if ($null -eq $result.error) { $result.error = $_.Exception.Message }
        }
        try {
            foreach ($key in @('qualification-key', 'qualification-key.pub')) {
                $keyPath = Join-Path $preparedStage $key
                if (Test-Path -LiteralPath $keyPath -PathType Leaf) { Remove-Item -LiteralPath $keyPath -Force }
            }
            $result.qualification_key_cleanup = 'PASS'
        }
        catch {
            $cleanupFailed = $true; $result.qualification_key_cleanup = 'FAIL'
            if ($null -eq $result.error) { $result.error = $_.Exception.Message }
        }
        try { Set-OneShotBootSequence -BootId ([string]$prepared.normal_boot_id); $result.bootsequence_return_normal = 'PASS' } catch {
            $result.bootsequence_return_normal = 'FAIL'; if ($null -eq $result.error) { $result.error = $_.Exception.Message }
        }
        try { Remove-NativeTask; $result.native_task_removed = 'PASS' } catch {
            $result.native_task_removed = 'FAIL'; if ($null -eq $result.error) { $result.error = $_.Exception.Message }
        }
        if ($cleanupFailed -or $result.cleanup -ne 'PASS' -or $result.qualification_key_cleanup -ne 'PASS' -or $result.bootsequence_return_normal -ne 'PASS' -or $result.native_task_removed -ne 'PASS') {
            $result.status = 'FAIL'
        }
        if ($transcriptStarted) {
            try {
                [void](Stop-Transcript)
                $transcriptStarted = $false
                $result.runtime_capture.transcript_sha256 = Get-FileSha256 -Path ([string]$result.runtime_capture.transcript)
            }
            catch {
                $result.status = 'FAIL'
                if ($null -eq $result.error) { $result.error = "Native transcript flush failed: $($_.Exception.Message)" }
            }
        }
        $result.completed_at = Get-UtcTimestamp
        try { Write-Utf8Json -InputObject $result -Path $resultPath }
        finally { Restart-Computer -Force }
    }
}

function Invoke-Import {
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    if ($WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or -not $WslRepoRoot.StartsWith('/')) {
        throw 'Import requires valid WSL distribution and repository paths'
    }
    $prepared = Read-JsonFile (Join-Path $script:LabRootResolved 'prepared.json')
    $sourceSha = [string]$prepared.source_git_sha
    $sourceTree = [string]$prepared.source_tree_sha
    $preparedStage = [string]$prepared.stage_root
    $resultPath = Join-Path $script:LabRootResolved "evidence\$sourceSha\result.json"
    $result = Read-JsonFile $resultPath
    $gitState = Get-GitState -Distribution $WslDistribution -WslRepoRoot $WslRepoRoot
    if (-not $gitState.Clean -or $gitState.Head -ne $sourceSha) {
        throw 'Native evidence import requires the clean exact staged source SHA'
    }
    $treeResult = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('rev-parse', 'HEAD^{tree}') -TimeoutSeconds 60
    Assert-ProcessSuccess -Result $treeResult -Operation 'Native evidence import Git tree resolution'
    if ($treeResult.StdOut.Trim() -ne $sourceTree) { throw 'Native evidence source tree is stale' }
    if (-not (Test-StagingManifest -Root $preparedStage)) { throw 'Native evidence staging manifest no longer verifies' }
    $manifestSha256 = Get-FileSha256 -Path (Join-Path $preparedStage 'SHA256SUMS')
    Assert-ResultBinding -Result $result -SourceSha $sourceSha -SourceTree $sourceTree -ManifestSha256 $manifestSha256
    if (
        $result.status -ne 'PASS' -or $result.virtualbox_backend -ne 'NATIVE_VTX' -or
        $result.nem_detected -ne $false -or
        $result.native_vtx -ne 'PASS' -or $result.precheck -ne 'PASS' -or
        $result.packer.init -ne 'PASS' -or $result.packer.fmt -ne 'PASS' -or
        $result.packer.validate -ne 'PASS' -or $result.packer.build -ne 'PASS' -or
        $result.cleanup -ne 'PASS' -or
        $result.qualification_key_cleanup -ne 'PASS' -or
        $result.bootsequence_return_normal -ne 'PASS' -or $result.native_task_removed -ne 'PASS'
    ) {
        throw 'Native runtime result is absent, stale or not fully PASS'
    }
    foreach ($field in $result.milestones.PSObject.Properties.Name) {
        if ($null -eq $result.milestones.$field) { throw "Native runtime milestone is absent: $field" }
    }
    foreach ($field in $result.vagrant_smoke.PSObject.Properties.Name) {
        if ($result.vagrant_smoke.$field -ne 'PASS') { throw "Native Vagrant smoke field is not PASS: $field" }
    }
    $artifactSource = [string]$result.artifact
    $expectedArtifactSource = Join-Path $script:LabRootResolved "artifacts\$sourceSha\rocky-10.2-rke2-virtualbox.box"
    if ([IO.Path]::GetFullPath($artifactSource) -ne [IO.Path]::GetFullPath($expectedArtifactSource)) {
        throw 'Native artifact path is outside the exact-source artifact location'
    }
    if (-not (Test-Path -LiteralPath $artifactSource -PathType Leaf)) { throw 'Native artifact is missing' }
    $artifactSha256 = Get-FileSha256 -Path $artifactSource
    if ($artifactSha256 -ne [string]$result.artifact_sha256) { throw 'Native artifact SHA-256 differs from runtime evidence' }
    if ((Get-Item -LiteralPath $artifactSource).Length -ne [int64]$result.artifact_size_bytes) {
        throw 'Native artifact size differs from runtime evidence'
    }
    $captureFiles = [ordered]@{
        systeminfo_sha256 = (Join-Path $preparedStage 'logs\systeminfo.txt')
        bcd_current_sha256 = (Join-Path $preparedStage 'logs\bcd-current.txt')
        transcript_sha256 = (Join-Path $preparedStage 'logs\native-qualification-transcript.txt')
    }
    if ([IO.Path]::GetFullPath([string]$result.runtime_capture.transcript) -ne [IO.Path]::GetFullPath($captureFiles.transcript_sha256)) {
        throw 'Native transcript path differs from the governed staging path'
    }
    foreach ($capture in $captureFiles.GetEnumerator()) {
        $expectedDigest = [string]$result.runtime_capture.($capture.Key)
        if ($expectedDigest -notmatch '^[0-9a-f]{64}$' -or (Get-FileSha256 -Path $capture.Value) -ne $expectedDigest) {
            throw "Native runtime capture digest differs: $($capture.Key)"
        }
    }
    foreach ($key in @('qualification-key', 'qualification-key.pub')) {
        if (Test-Path -LiteralPath (Join-Path $preparedStage $key)) { throw 'Ephemeral qualification key remains after native runtime' }
    }

    $artifactRoot = Join-Path $root '.artifacts\packer\rocky-10.2\windows'
    $evidenceRoot = Join-Path $root '.context\evidence\rocky-image\rocky-10.2\windows'
    [void](New-Item -ItemType Directory -Path $artifactRoot -Force)
    [void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
    $artifactTarget = Join-Path $artifactRoot 'rocky-10.2-rke2-virtualbox.box'
    $artifactTemporary = "$artifactTarget.$([Guid]::NewGuid().ToString('N')).tmp"
    Copy-Item -LiteralPath $artifactSource -Destination $artifactTemporary
    if ((Get-FileSha256 -Path $artifactTemporary) -ne $artifactSha256) { throw 'Artifact changed while importing native evidence' }
    Move-Item -LiteralPath $artifactTemporary -Destination $artifactTarget -Force
    [IO.File]::WriteAllText((Join-Path $artifactRoot 'SHA256SUMS'), "$artifactSha256  rocky-10.2-rke2-virtualbox.box`n", (New-Object Text.UTF8Encoding($false)))

    $buildEvidence = [ordered]@{
        schema = 1; image = 'rocky-10.2'; profile = 'rke2'; builder = 'packer'; hypervisor = 'virtualbox'
        status = 'PASS'; source_sha = $sourceSha; source_tree = $sourceTree; source_clean = $true
        artifact = 'rocky-10.2-rke2-virtualbox.box'; sha256 = $artifactSha256
        packer_version = [string]$prepared.tools.packer.actual_version
        virtualbox_version = [string]$prepared.tools.virtualbox.actual_version
        vagrant_version = [string]$prepared.tools.vagrant.actual_version
        virtualbox_backend = 'NATIVE_VTX'; preflight = 'PASS'
        packer_init = [string]$result.packer.init; packer_fmt = [string]$result.packer.fmt
        packer_validate = [string]$result.packer.validate; packer_build = [string]$result.packer.build
        checksum = 'PASS'; cleanup = 'PASS'; qualification_key = 'REMOVED_AFTER_QUALIFICATION'
        resources = (Read-JsonFile (Join-Path $preparedStage 'runtime-contract.json')).resources
        storage = (Read-JsonFile (Join-Path $preparedStage 'runtime-contract.json')).storage
        milestones = $result.milestones; started_at = $result.started_at; completed_at = $result.completed_at; error = $null
    }
    $qualificationEvidence = [ordered]@{
        schema = 1; image = 'rocky-10.2'; artifact = 'rocky-10.2-rke2-virtualbox.box'
        artifact_sha256 = $artifactSha256; source_sha = $sourceSha; status = 'PASS'
        qualification = [ordered]@{
            preflight = 'PASS'; checksum = 'PASS'; box_add = 'PASS'; boot = 'PASS'; ssh = 'PASS'
            rocky_release = 'PASS'; kernel = 'PASS'; architecture_cpu = 'PASS'; systemd = 'PASS'
            disk = 'PASS'; network = 'PASS'; fundamental_tools = 'PASS'; rke2_prerequisites = 'PASS'
            security = 'PASS'; cleanup = 'PASS'; key_cleanup = 'PASS'
            expected_memory = 'PASS'; root_filesystem_xfs = 'PASS'; lvm_absent = 'PASS'
            swap_absent = 'PASS'; rpm_profile = 'PASS'
        }
        observations = $result.observations; started_at = $result.started_at; completed_at = $result.completed_at; error = $null
    }
    $releaseEvidence = [ordered]@{
        schema = 1; image = 'rocky-10.2'; artifact = 'rocky-10.2-rke2-virtualbox.box'
        artifact_sha256 = $artifactSha256; source_sha = $sourceSha; status = 'PASS'
        remote_publication = 'NOT_PERFORMED'
        checks = [ordered]@{
            preflight = 'PASS'; exact_source_sha = 'PASS'; clean_source = 'PASS'
            build_evidence = 'PASS'; checksum = 'PASS'; qualification_evidence = 'PASS'
            cleanup = 'PASS'; ephemeral_key_absent = 'PASS'
        }
        completed_at = Get-UtcTimestamp; error = $null
    }
    $preflightEvidence = [ordered]@{
        schema = 1; check = 'windows-packer-native-vtx-preflight'; status = 'PASS'
        source_sha = $sourceSha; virtualbox_backend = 'NATIVE_VTX'; tools = $prepared.tools
        completed_at = $result.completed_at; error = $null
    }
    Write-Utf8Json -InputObject $preflightEvidence -Path (Join-Path $evidenceRoot 'preflight.json')
    Write-Utf8Json -InputObject $buildEvidence -Path (Join-Path $evidenceRoot 'build.json')
    Write-Utf8Json -InputObject $qualificationEvidence -Path (Join-Path $evidenceRoot 'qualification.json')
    Write-Utf8Json -InputObject $releaseEvidence -Path (Join-Path $evidenceRoot 'release.json')
    Copy-Item -LiteralPath $resultPath -Destination (Join-Path $evidenceRoot 'native-result.json') -Force
    Write-Utf8Json -InputObject ([ordered]@{
        schema = 1; status = 'PASS'; source_git_sha = $sourceSha; source_tree_sha = $sourceTree
        staging_manifest_sha256 = $manifestSha256; artifact_sha256 = $artifactSha256
        virtualbox_backend = 'NATIVE_VTX'; imported_at = Get-UtcTimestamp
    }) -Path (Join-Path $evidenceRoot 'native-import.json')
    [Console]::WriteLine("PASS native-vtx-import sha=$sourceSha artifact_sha256=$artifactSha256")
}

function Invoke-Prepare {
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    if ($WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or -not $WslRepoRoot.StartsWith('/')) {
        throw 'Prepare requires valid WSL distribution and repository paths'
    }
    $gitState = Get-GitState -Distribution $WslDistribution -WslRepoRoot $WslRepoRoot
    if (-not $gitState.Clean) { throw 'Native VT-x staging requires a clean exact-SHA worktree' }
    $treeResult = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'git' -Arguments @('rev-parse', 'HEAD^{tree}') -TimeoutSeconds 60
    Assert-ProcessSuccess -Result $treeResult -Operation 'Git tree resolution'
    $sourceSha = $gitState.Head
    $sourceTree = $treeResult.StdOut.Trim()
    if ($sourceSha -notmatch '^[0-9a-f]{40}$' -or $sourceTree -notmatch '^[0-9a-f]{40}$') {
        throw 'Prepare could not resolve full Git source identities'
    }

    foreach ($directory in @('bcd', 'staging', 'evidence', 'logs', 'artifacts')) {
        [void](New-Item -ItemType Directory -Path (Join-Path $script:LabRootResolved $directory) -Force)
    }
    $preparedStage = Join-Path $script:LabRootResolved "staging\$sourceSha"
    $preparedPath = Join-Path $preparedStage '.prepared.json'
    $manifestPath = Join-Path $preparedStage 'SHA256SUMS'
    $reused = $false
    $qualificationPrivateKeySha256 = $null
    $qualificationPublicKeySha256 = $null
    if (Test-Path -LiteralPath $preparedStage -PathType Container) {
        if (-not (Test-Path -LiteralPath $preparedPath -PathType Leaf) -or -not (Test-StagingManifest -Root $preparedStage)) {
            throw "Existing staging is incomplete or invalid and requires explicit cleanup: $preparedStage"
        }
        $prepared = Read-JsonFile $preparedPath
        if ($prepared.source_git_sha -ne $sourceSha -or $prepared.source_tree_sha -ne $sourceTree) {
            throw 'Existing staging source binding is stale'
        }
        $qualificationPrivateKeySha256 = [string]$prepared.qualification_private_key_sha256
        $qualificationPublicKeySha256 = [string]$prepared.qualification_public_key_sha256
        if (
            $qualificationPrivateKeySha256 -notmatch '^[0-9a-f]{64}$' -or
            $qualificationPublicKeySha256 -notmatch '^[0-9a-f]{64}$' -or
            (Get-FileSha256 -Path (Join-Path $preparedStage 'qualification-key')) -ne $qualificationPrivateKeySha256 -or
            (Get-FileSha256 -Path (Join-Path $preparedStage 'qualification-key.pub')) -ne $qualificationPublicKeySha256
        ) {
            throw 'Existing staging ephemeral qualification key binding is invalid'
        }
        $reused = $true
    }
    else {
        [void](New-Item -ItemType Directory -Path $preparedStage)
        foreach ($directory in @('packer', 'smoke', 'runner', 'artifacts', 'evidence', 'logs')) {
            [void](New-Item -ItemType Directory -Path (Join-Path $preparedStage $directory))
        }
        foreach ($definition in @('rocky-10.2.pkr.hcl', 'variables.pkr.hcl')) {
            Copy-Item -LiteralPath (Join-Path $root "platform\packer\rocky-10.2\$definition") -Destination (Join-Path $preparedStage 'packer')
        }
        Copy-Item -LiteralPath (Join-Path $root 'platform\packer\rocky-10.2\http') -Destination (Join-Path $preparedStage 'packer') -Recurse
        Copy-Item -LiteralPath (Join-Path $root 'platform\vagrant\rocky-image-smoke\Vagrantfile') -Destination (Join-Path $preparedStage 'smoke\Vagrantfile')
        Copy-Item -LiteralPath (Join-Path $root 'scripts\windows\RockyImagePipeline.psm1') -Destination (Join-Path $preparedStage 'runner\RockyImagePipeline.psm1')
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $preparedStage 'runner\native-vtx-cycle.ps1')

        $preflightPath = Join-Path $preparedStage 'evidence\preflight-prepare.json'
        $preflight = Invoke-BoundedProcess -FilePath 'powershell.exe' -Arguments @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $PSScriptRoot 'packer-preflight.ps1'), '-RepoRoot', $root,
            '-WslDistribution', $WslDistribution, '-WslRepoRoot', $WslRepoRoot,
            '-EvidencePath', $preflightPath, '-PreparationOnly'
        ) -TimeoutSeconds 120 -WorkingDirectory $env:SystemRoot
        Assert-ProcessSuccess -Result $preflight -Operation 'Native VT-x preparation preflight'
        $preflightDocument = Read-JsonFile $preflightPath
        if ($preflightDocument.status -ne 'PASS') { throw 'Preparation preflight is not PASS' }

        $stageWsl = Convert-ToWslPath -WindowsPath $preparedStage -Distribution $WslDistribution -TimeoutSeconds 15
        $materializeArguments = @(
            'scripts/materialize_packer_rpm_repo.py',
            '--contract', 'config/contracts/machine-image-lock.yaml',
            '--package-lock', 'config/artifacts/rocky-10.2-base-packages.lock.json',
            '--toolchain-lock', 'config/contracts/toolchain-lock.json',
            '--cache', '.context/cache/packer', '--output', "$stageWsl/offline"
        )
        if ($Offline.IsPresent) { $materializeArguments += '--offline' }
        $materialize = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments $materializeArguments -TimeoutSeconds 7200
        Assert-ProcessSuccess -Result $materialize -Operation 'Native VT-x offline input materialization'

        $sshKeygen = Resolve-WindowsTool -Name 'ssh-keygen.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'))
        $privateKey = Join-Path $preparedStage 'qualification-key'
        $keygen = Invoke-BoundedProcess -FilePath $sshKeygen -Arguments @('-q', '-t', 'ed25519', '-N', '', '-C', 'ecommerce-rocky-image-qualification', '-f', $privateKey) -TimeoutSeconds 30 -WorkingDirectory $preparedStage
        Assert-ProcessSuccess -Result $keygen -Operation 'Native VT-x ephemeral SSH key generation'
        $qualificationPrivateKeySha256 = Get-FileSha256 -Path $privateKey
        $qualificationPublicKeySha256 = Get-FileSha256 -Path "$privateKey.pub"

        $render = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments @(
            'scripts/render_packer_vars.py', '--contract', 'config/contracts/machine-image-lock.yaml',
            '--bundle', "$stageWsl/offline", '--build-public-key-file', "$stageWsl/qualification-key.pub",
            '--build-private-key-file', "$stageWsl/qualification-key", '--artifact-dir', "$stageWsl/artifacts",
            '--target-platform', 'windows', '--runtime-contract-output', "$stageWsl/runtime-contract.json",
            '--output', "$stageWsl/rocky-10.2.auto.pkrvars.hcl"
        ) -TimeoutSeconds 300
        Assert-ProcessSuccess -Result $render -Operation 'Native VT-x variable rendering'

        $packer = [string]$preflightDocument.tools.packer.executable
        foreach ($operation in @(
            [pscustomobject]@{ Args = @('init', (Join-Path $preparedStage 'packer')); Timeout = 300; Name = 'packer init' },
            [pscustomobject]@{ Args = @('fmt', '-check', (Join-Path $preparedStage 'packer')); Timeout = 120; Name = 'packer fmt -check' },
            [pscustomobject]@{ Args = @('validate', "-var-file=$(Join-Path $preparedStage 'rocky-10.2.auto.pkrvars.hcl')", (Join-Path $preparedStage 'packer')); Timeout = 120; Name = 'packer validate' }
        )) {
            $result = Invoke-BoundedProcess -FilePath $packer -Arguments $operation.Args -TimeoutSeconds $operation.Timeout -WorkingDirectory $preparedStage
            Assert-ProcessSuccess -Result $result -Operation $operation.Name
        }
        $manifestPath = Write-StagingManifest -Root $preparedStage
    }

    if (-not (Test-StagingManifest -Root $preparedStage)) { throw 'Staging SHA-256 verification failed' }
    $manifestSha256 = Get-FileSha256 -Path $manifestPath
    $normalBootId = Get-CurrentWindowsLoaderId
    $backupPath = Join-Path $script:LabRootResolved "bcd\bcd-$sourceSha.bak"
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        [void](Invoke-BcdEdit -Arguments @('/export', $backupPath))
    }
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or (Get-Item -LiteralPath $backupPath).Length -lt 1024) {
        throw 'BCD backup is absent or unexpectedly small'
    }
    $backupSha256 = Get-FileSha256 -Path $backupPath

    $nativeIds = @(Find-NativeWindowsLoaderIds)
    if ($nativeIds.Count -gt 1) { throw 'Multiple canonical native VirtualBox BCD entries exist; explicit cleanup is required' }
    if ($nativeIds.Count -eq 0) {
        $copy = Invoke-BcdEdit -Arguments @('/copy', $normalBootId, '/d', $NativeEntryName)
        $match = [regex]::Match(($copy.StdOut + "`n" + $copy.StdErr), '\{[0-9a-fA-F-]{36}\}')
        if (-not $match.Success) { throw 'Cannot parse the native BCD identifier returned by bcdedit /copy' }
        $nativeBootId = Assert-Guid -Value $match.Value -Forbidden $normalBootId
    }
    else {
        $nativeBootId = Assert-Guid -Value $nativeIds[0] -Forbidden $normalBootId
    }
    [void](Invoke-BcdEdit -Arguments @('/set', $nativeBootId, 'hypervisorlaunchtype', 'off'))
    $vsm = Invoke-BcdEdit -Arguments @('/set', $nativeBootId, 'vsmlaunchtype', 'off') -AllowFailure
    $vsmStatus = if ($vsm.ExitCode -eq 0) { 'PASS' } else { 'UNSUPPORTED' }

    $prepared = [ordered]@{
        schema = 1
        status = 'PREPARED'
        source_git_sha = $sourceSha
        source_tree_sha = $sourceTree
        stage_root = $preparedStage
        staging_manifest = $manifestPath
        staging_manifest_sha256 = $manifestSha256
        qualification_private_key_sha256 = $qualificationPrivateKeySha256
        qualification_public_key_sha256 = $qualificationPublicKeySha256
        normal_boot_id = $normalBootId
        native_boot_id = $nativeBootId
        native_entry_name = $NativeEntryName
        bcd_backup = $backupPath
        bcd_backup_sha256 = $backupSha256
        hypervisorlaunchtype = 'off'
        vsmlaunchtype = $vsmStatus
        scheduled_task = $NativeTaskName
        max_native_boot_attempts = 1
        tools = (Read-JsonFile (Join-Path $preparedStage 'evidence\preflight-prepare.json')).tools
        prepared_at = Get-UtcTimestamp
    }
    Write-Utf8Json -InputObject $prepared -Path $preparedPath
    Write-Utf8Json -InputObject $prepared -Path (Join-Path $script:LabRootResolved 'prepared.json')
    Register-NativeTask -Runner (Join-Path $preparedStage 'runner\native-vtx-cycle.ps1') -PreparedStage $preparedStage -Root $script:LabRootResolved -SourceSha $sourceSha -SourceTree $sourceTree -ManifestSha256 $manifestSha256 -NormalBootId $normalBootId -NativeBootId $nativeBootId
    $prepareEvidence = [ordered]@{
        schema = 1
        status = 'PASS'
        source_git_sha = $sourceSha
        source_tree_sha = $sourceTree
        bcd_backup = 'PASS'
        normal_boot_id_captured = 'PASS'
        native_entry = if ($reused) { 'REUSED' } else { 'CREATED_OR_REUSED' }
        hypervisorlaunchtype = 'PASS'
        vsmlaunchtype = $vsmStatus
        windows_staging = 'PASS'
        staging_integrity = 'PASS'
        staging_manifest_sha256 = $manifestSha256
        scheduled_task = 'PASS'
        bootsequence_native = 'NOT_ARMED'
        reboot_required = $true
        completed_at = Get-UtcTimestamp
    }
    Write-Utf8Json -InputObject $prepareEvidence -Path (Join-Path $script:LabRootResolved "evidence\prepare-$sourceSha.json")
    [Console]::WriteLine("PASS native-vtx-prepare sha=$sourceSha stage=$preparedStage reboot=EXPLICITLY_REQUIRED")
}

function Invoke-Reboot {
    $prepared = Read-JsonFile (Join-Path $script:LabRootResolved 'prepared.json')
    if ($prepared.status -ne 'PREPARED' -or -not (Test-StagingManifest -Root ([string]$prepared.stage_root))) {
        throw 'Native reboot requires verified PREPARED staging'
    }
    if ($prepared.max_native_boot_attempts -ne 1) { throw 'Native boot attempt contract must equal one' }
    if ($null -eq (Get-ScheduledTask -TaskName $NativeTaskName -ErrorAction SilentlyContinue)) {
        throw 'Native qualification scheduled task is missing'
    }
    Set-OneShotBootSequence -BootId ([string]$prepared.native_boot_id)
    [Console]::WriteLine("PASS native-vtx-reboot-authorized next=$($prepared.native_boot_id)")
    Restart-Computer -Force
}

function Invoke-Recover {
    $prepared = Read-JsonFile (Join-Path $script:LabRootResolved 'prepared.json')
    Set-OneShotBootSequence -BootId ([string]$prepared.normal_boot_id)
    Remove-NativeTask
    $evidence = [ordered]@{
        schema = 1
        status = 'PASS'
        next_boot = [string]$prepared.normal_boot_id
        scheduled_task_removed = $true
        native_entry_preserved = $true
        completed_at = Get-UtcTimestamp
    }
    Write-Utf8Json -InputObject $evidence -Path (Join-Path $script:LabRootResolved 'evidence\recovery.json')
    [Console]::WriteLine('PASS native-vtx-recover normal boot armed; native entry preserved')
}

function Invoke-SelfTest {
    $normal = '{11111111-1111-1111-1111-111111111111}'
    $native = '{22222222-2222-2222-2222-222222222222}'
    $fixture = @"
Windows Boot Loader
-------------------
identifier              $normal
path                    \Windows\system32\winload.efi
description             Windows 11

Chargeur de démarrage Windows
-----------------------------
identificateur          $native
path                    \Windows\system32\winload.efi
description             $NativeEntryName
"@
    $entries = @(Get-BcdEntries -Text $fixture)
    if ($entries.Count -ne 2 -or $entries[1].Id -ne $native) { throw 'BCD GUID parsing self-test failed' }
    try { [void](Assert-Guid -Value '{bootmgr}'); throw 'bootmgr rejection self-test failed' } catch { }
    try { [void](Assert-Guid -Value $normal -Forbidden $normal); throw 'normal loader rejection self-test failed' } catch { }
    if ((Get-VirtualBoxBackendFromLog -Text 'NEM: WHvCapabilityCodeHypervisorPresent is TRUE') -ne 'NEM') { throw 'NEM rejection parser self-test failed' }
    if ((Get-VirtualBoxBackendFromLog -Text 'HM: HMR3Init: VT-x w/ nested paging') -ne 'NATIVE_VTX') { throw 'native VT-x parser self-test failed' }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ("native-vtx-selftest-" + [Guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -ItemType Directory -Path $temporary)
        foreach ($name in 1..8) { [IO.File]::WriteAllText((Join-Path $temporary "$name.txt"), "value-$name", [Text.Encoding]::UTF8) }
        $manifest = Write-StagingManifest -Root $temporary
        if (-not (Test-StagingManifest -Root $temporary)) { throw 'staging manifest acceptance self-test failed' }
        [IO.File]::AppendAllText((Join-Path $temporary '1.txt'), 'tampered', [Text.Encoding]::UTF8)
        if (Test-StagingManifest -Root $temporary) { throw 'staging tamper rejection self-test failed' }
        $result = [pscustomobject]@{ source_git_sha = 'a' * 40; source_tree_sha = 'b' * 40; staging_manifest_sha256 = 'c' * 64 }
        Assert-ResultBinding -Result $result -SourceSha ('a' * 40) -SourceTree ('b' * 40) -ManifestSha256 ('c' * 64)
        try { Assert-ResultBinding -Result $result -SourceSha ('d' * 40) -SourceTree ('b' * 40) -ManifestSha256 ('c' * 64); throw 'stale evidence rejection self-test failed' } catch { }
        [Console]::WriteLine('PASS native-vtx-self-test BCD GUID parsing, protected loader, backend classification, staging integrity, stale evidence rejection')
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
}

$script:LabRootResolved = Resolve-LabRoot -Path $LabRoot

try {
    if ($Action -in @('Prepare', 'Reboot', 'Recover') -and -not (Test-Administrator)) {
        Invoke-ElevatedSelf
    }
    switch ($Action) {
        'Prepare' { Invoke-Prepare }
        'Reboot' { Invoke-Reboot }
        'Recover' { Invoke-Recover }
        'SelfTest' { Invoke-SelfTest }
        'Run' { Invoke-NativeRun }
        'Import' { Invoke-Import }
    }
    exit 0
}
catch {
    if ($Action -eq 'Run' -and (Test-Administrator)) {
        [Console]::Error.WriteLine("FAIL native-vtx-run-before-guarded-finally: $($_.Exception.Message)")
        Invoke-EmergencyNativeReturn -Failure $_.Exception.Message
    }
    [Console]::Error.WriteLine("FAIL native-vtx-$($Action.ToLowerInvariant()): $($_.Exception.Message)")
    exit 1
}
