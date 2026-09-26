[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('PrepareDryRun', 'Resume', 'ProbePrerequisites', 'VerifyDryRun', 'SelfTest')]
    [string]$Action,
    [string]$LabRoot = 'C:\ecommerce-lab',
    [string]$SourceSha = '',
    [string]$PayloadRoot = '',
    [string]$StateRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$TaskName = 'Ecommerce-VirtualBox-Native-Startup-DryRun'
$PrerequisiteTaskName = 'Ecommerce-VirtualBox-Native-Boot-Prerequisites'
$Phases = @(
    'PREPARED', 'BOOT_RESUME_ARMED', 'NATIVE_BOOT_PENDING', 'NATIVE_BOOTED',
    'CONTROLLER_START', 'QUALIFICATION_RUNNING', 'QUALIFICATION_COMPLETE',
    'RESTORE_PENDING', 'RESTORED', 'COMPLETE', 'FAILED'
)

function Write-JsonAtomic {
    param([string]$Path, $Value)
    $parent = Split-Path -Parent $Path
    [void](New-Item -ItemType Directory -Path $parent -Force)
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 20) + "`n", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-Json {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required state file is absent: $Path" }
    return [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json
}

function Get-Sha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required payload file is absent: $Path" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-HostMutationSnapshot {
    $bcd = & (Join-Path $env:SystemRoot 'System32\bcdedit.exe') /enum all /v 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Read-only BCD snapshot failed' }
    $bcdText = ($bcd | Out-String).Trim()
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $bcdDigest = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($bcdText)))).Replace('-','').ToLowerInvariant() }
    finally { $hasher.Dispose() }
    $vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
    $machines = & $vbox list vms 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Read-only VirtualBox inventory failed' }
    return [ordered]@{
        bcd_sha256=$bcdDigest
        last_boot_up_time=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        hypervisor_present=[bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
        registered_vms=(($machines | Out-String).Trim())
    }
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-StateRoot {
    param([string]$Root, [string]$Lab, [string]$Sha)
    if ($Sha -notmatch '^[0-9a-f]{40}$') { throw 'Exact source SHA is invalid' }
    $expected = [IO.Path]::GetFullPath((Join-Path $Lab "startup-dry-run\$Sha")).TrimEnd('\')
    $actual = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($actual -ine $expected) { throw 'Startup state root is outside the exact-SHA dry-run location' }
    return $actual
}

function Assert-SystemPrincipal {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne 'S-1-5-18') {
        throw "Startup resume requires SYSTEM; observed $($identity.Name)"
    }
    if (-not (Test-Administrator)) { throw 'SYSTEM startup resume lacks an elevated administrator token' }
    return $identity
}

function Invoke-ExplicitTool {
    param([string]$Path, [string[]]$Arguments, [string]$Expected)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required Windows executable is absent: $Path" }
    $output = & $Path @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Windows executable failed: $Path" }
    $version = (($output | Out-String).Trim())
    if ($version -ne $Expected) { throw "Windows executable version differs: $Path expected=$Expected observed=$version" }
    return $version
}

function Get-PrincipalEvidence {
    $identity = Assert-SystemPrincipal
    return [ordered]@{
        name = $identity.Name
        sid = $identity.User.Value
        pid = $PID
        session_id = (Get-Process -Id $PID).SessionId
        timestamp = [DateTime]::UtcNow.ToString('o')
    }
}

function Assert-StartupPrerequisites {
    param($State, [string]$Root)
    $payload = Join-Path $Root 'payload'
    $manifestPath = Join-Path $payload 'payload.json'
    if ((Get-Sha256 $manifestPath) -ne [string]$State.payload_manifest_sha256) { throw 'Persistent payload manifest digest differs' }
    $manifest = Read-Json $manifestPath
    if ($manifest.source_sha -ne $State.source_sha) { throw 'Persistent payload source SHA differs' }
    if (@($manifest.files.PSObject.Properties).Count -lt 5) { throw 'Persistent payload manifest is incomplete' }
    foreach ($file in $manifest.files.PSObject.Properties) {
        $relative = [string]$file.Name
        if ($relative -match '(^|/|\\)\.\.($|/|\\)' -or [IO.Path]::IsPathRooted($relative)) { throw 'Unsafe payload manifest path' }
        if ([string]$file.Value -notmatch '^[0-9a-f]{64}$') { throw 'Payload manifest digest is invalid' }
        $path = [IO.Path]::GetFullPath((Join-Path $payload $relative))
        if (-not $path.StartsWith(([IO.Path]::GetFullPath($payload).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Payload manifest path escapes the governed copy'
        }
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Payload contains a reparse point' }
        if ((Get-Sha256 $path) -ne [string]$file.Value) { throw "Persistent payload file digest differs: $relative" }
    }
    $tools = $State.tools
    $versions = [ordered]@{
        powershell = Invoke-ExplicitTool -Path ([string]$tools.powershell) -Arguments @('-NoProfile','-NonInteractive','-Command','$PSVersionTable.PSVersion.ToString()') -Expected ([string]$tools.powershell_version)
        virtualbox = Invoke-ExplicitTool -Path ([string]$tools.virtualbox) -Arguments @('--version') -Expected '7.2.18r175117'
        packer = Invoke-ExplicitTool -Path ([string]$tools.packer) -Arguments @('version') -Expected 'Packer v1.16.1'
        vagrant = Invoke-ExplicitTool -Path ([string]$tools.vagrant) -Arguments @('--version') -Expected 'Vagrant 2.4.9'
    }
    $adapter = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -eq 'VirtualBox Host-Only Ethernet Adapter' })
    if ($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Up') { throw 'SYSTEM cannot observe the owned host-only adapter' }
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter[0].ifIndex -ErrorAction Stop)
    if (@($addresses | Where-Object { $_.IPAddress -eq '192.168.22.1' -and $_.PrefixLength -eq 24 }).Count -ne 1) {
        throw 'SYSTEM cannot observe the owned host-only IPv4 network'
    }
    foreach ($directory in @($Root, (Join-Path $Root 'evidence'), (Join-Path $Root 'payload'))) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "SYSTEM cannot read required Windows directory: $directory" }
    }
    $writeProbe = Join-Path $Root 'evidence\write-probe.tmp'
    try { [IO.File]::WriteAllText($writeProbe, 'SYSTEM', [Text.Encoding]::ASCII) }
    finally { Remove-Item -LiteralPath $writeProbe -Force -ErrorAction SilentlyContinue }
    return [ordered]@{
        powershell = $versions.powershell
        virtualbox = $versions.virtualbox
        packer = $versions.packer
        vagrant = $versions.vagrant
        payload_files = @($manifest.files.PSObject.Properties).Count
        payload_manifest_sha256 = $State.payload_manifest_sha256
        host_only_network = '192.168.22.1/24'
        state_directory = 'PASS'
        evidence_writable = 'PASS'
    }
}

function Move-Phase {
    param($State, [string]$Next)
    $current = [array]::IndexOf($Phases, [string]$State.phase)
    $nextIndex = [array]::IndexOf($Phases, $Next)
    $failure = $Next -eq 'FAILED' -and $State.phase -notin @('COMPLETE','FAILED') -and $current -ge 0
    if (-not $failure -and ($current -lt 0 -or $State.phase -eq 'FAILED' -or $nextIndex -ne ($current + 1))) {
        throw "Non-monotone startup state transition: $($State.phase) -> $Next"
    }
    $State.phase = $Next
    $State.history += [pscustomobject]@{ phase=$Next; at=[DateTime]::UtcNow.ToString('o') }
}

function Invoke-Resume {
    $root = Assert-StateRoot -Root $StateRoot -Lab $LabRoot -Sha $SourceSha
    $evidenceRoot = Join-Path $root 'evidence'
    $lockPath = Join-Path $root 'resume.lock'
    $principal = Get-PrincipalEvidence
    $lock = $null
    $lockStarted = [DateTime]::UtcNow
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try { $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); break }
        catch [IO.IOException] { Start-Sleep -Milliseconds 500 }
    }
    if ($null -eq $lock) {
        Write-JsonAtomic -Path (Join-Path $evidenceRoot 'lock-rejected.json') -Value ([ordered]@{
            schema=1; status='PASS'; classification='CONCURRENCY_LOCK'; principal=$principal
            waited_ms=([DateTime]::UtcNow - $lockStarted).TotalMilliseconds
            rejected_at=[DateTime]::UtcNow.ToString('o')
        })
        exit 75
    }
    $state = $null
    try {
        $statePath = Join-Path $root 'state.json'
        $state = Read-Json $statePath
        if ($state.source_sha -ne $SourceSha -or $state.mode -ne 'DRY_RUN') { throw 'Persistent startup state binding is invalid' }
        if ($state.phase -notin @('BOOT_RESUME_ARMED','COMPLETE')) { throw "Startup state is not resumable: $($state.phase)" }
        $before = @($state.history).Count
        $preconditions = Assert-StartupPrerequisites -State $state -Root $root
        $idempotent = $state.phase -eq 'COMPLETE'
        if (-not $idempotent) {
            foreach ($phase in $Phases[2..($Phases.Count - 2)]) { Move-Phase -State $state -Next $phase }
            Write-JsonAtomic -Path $statePath -Value $state
        }
        $run = [ordered]@{
            schema=1; status='PASS'; mode='DRY_RUN'; source_sha=$SourceSha
            principal=$principal; phase_before=if ($idempotent) { 'COMPLETE' } else { 'BOOT_RESUME_ARMED' }
            phase_after=$state.phase; idempotent=$idempotent
            history_before=$before; history_after=@($state.history).Count
            preconditions=$preconditions; completed_at=[DateTime]::UtcNow.ToString('o')
        }
        $name = if ($idempotent) { 'second-run.json' } else { 'first-run.json' }
        Write-JsonAtomic -Path (Join-Path $evidenceRoot $name) -Value $run
        Write-Output "PASS native-startup-resume mode=DRY_RUN phase=$($state.phase) idempotent=$idempotent"
    }
    catch {
        if ($null -ne $state -and $state.mode -eq 'DRY_RUN' -and $state.source_sha -eq $SourceSha -and $state.phase -notin @('COMPLETE','FAILED')) {
            Move-Phase -State $state -Next 'FAILED'
            Write-JsonAtomic -Path (Join-Path $root 'state.json') -Value $state
        }
        Write-JsonAtomic -Path (Join-Path $evidenceRoot 'failure.json') -Value ([ordered]@{
            schema=1; status='FAIL'; source_sha=$SourceSha; principal=$principal
            error=$_.Exception.Message; failed_at=[DateTime]::UtcNow.ToString('o')
        })
        throw
    }
    finally { $lock.Dispose() }
}

function Invoke-PrerequisiteProbe {
    $root = Assert-StateRoot -Root $StateRoot -Lab $LabRoot -Sha $SourceSha
    $principal = Get-PrincipalEvidence
    try {
        $state = Read-Json (Join-Path $root 'state.json')
        if ($state.mode -ne 'DRY_RUN' -or $state.source_sha -ne $SourceSha) { throw 'Boot prerequisite state binding is invalid' }
        $checks = Assert-StartupPrerequisites -State $state -Root $root
        Write-JsonAtomic -Path (Join-Path $root 'evidence\boot-prerequisites.json') -Value ([ordered]@{
            schema=1; status='PASS'; source_sha=$SourceSha; principal=$principal
            checks=$checks; completed_at=[DateTime]::UtcNow.ToString('o')
        })
        Write-Output "PASS native-boot-prerequisites sha=$SourceSha"
    }
    catch {
        Write-JsonAtomic -Path (Join-Path $root 'evidence\failure.json') -Value ([ordered]@{
            schema=1; status='FAIL'; source_sha=$SourceSha; principal=$principal
            error=$_.Exception.Message; failed_at=[DateTime]::UtcNow.ToString('o')
        })
        throw
    }
}

function Wait-TaskResult {
    param([string]$EvidencePath, [string]$Name = $TaskName, [int]$Seconds = 600, [int]$ExpectedExitCode = 0, [DateTime]$TriggeredAt)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $failurePath = Join-Path (Split-Path -Parent $EvidencePath) 'failure.json'
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
        if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
            $failure = Read-Json $failurePath
            throw "SYSTEM startup task failed: $($failure.error)"
        }
        Start-Sleep -Seconds 1
    }
    if (-not (Test-Path -LiteralPath $EvidencePath -PathType Leaf)) { throw "SYSTEM task evidence timed out: $EvidencePath" }
    $completionDeadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Get-ScheduledTask -TaskName $Name -ErrorAction Stop).State -eq 'Running' -and [DateTime]::UtcNow -lt $completionDeadline) {
        Start-Sleep -Milliseconds 250
    }
    $taskInfo = Get-ScheduledTaskInfo -TaskName $Name -ErrorAction Stop
    if ($taskInfo.LastTaskResult -ne $ExpectedExitCode) { throw "SYSTEM task exit code differs: expected=$ExpectedExitCode observed=$($taskInfo.LastTaskResult)" }
    if ($taskInfo.LastRunTime.ToUniversalTime() -lt $TriggeredAt.AddSeconds(-2)) { throw 'SYSTEM task LastRunTime predates manual trigger' }
    $evidence = Read-Json $EvidencePath
    return [pscustomobject]@{ TaskInfo=$taskInfo; Evidence=$evidence }
}

function Invoke-PrepareDryRun {
    if (-not (Test-Administrator)) { throw 'Startup dry-run preparation requires administrator PowerShell' }
    if ($SourceSha -notmatch '^[0-9a-f]{40}$') { throw 'Exact source SHA is invalid' }
    $root = Assert-StateRoot -Root (Join-Path $LabRoot "startup-dry-run\$SourceSha") -Lab $LabRoot -Sha $SourceSha
    if (Test-Path -LiteralPath (Join-Path $root 'state.json') -PathType Leaf) { throw 'Existing startup dry-run state requires explicit inspection' }
    if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { throw 'Existing startup dry-run task requires explicit inspection' }
    if ($null -ne (Get-ScheduledTask -TaskName $PrerequisiteTaskName -ErrorAction SilentlyContinue)) { throw 'Existing boot prerequisite task requires explicit inspection' }
    $hostBefore = Get-HostMutationSnapshot
    $sourcePayload = [IO.Path]::GetFullPath($PayloadRoot)
    $sourceManifest = Read-Json (Join-Path $sourcePayload 'payload.json')
    if ($sourceManifest.source_sha -ne $SourceSha) { throw 'Dry-run payload source SHA differs' }
    [void](New-Item -ItemType Directory -Path $root -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'evidence') -Force)
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $root 'native-startup-resume.ps1')
    $copyJob = Start-Job -ScriptBlock {
        param([string]$Source, [string]$Destination)
        Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -ErrorAction Stop
    } -ArgumentList $sourcePayload, (Join-Path $root 'payload')
    try {
        if ($null -eq (Wait-Job -Job $copyJob -Timeout 1800)) {
            Stop-Job -Job $copyJob
            throw 'Exact-SHA payload copy exceeded its 30-minute preparation deadline'
        }
        Receive-Job -Job $copyJob -ErrorAction Stop
    }
    finally { Remove-Job -Job $copyJob -Force }
    $payloadManifestSha = Get-Sha256 (Join-Path $root 'payload\payload.json')
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
    $vagrant = Join-Path $env:ProgramFiles 'Vagrant\bin\vagrant.exe'
    $packer = (Get-Command 'packer.exe' -CommandType Application -ErrorAction Stop).Source
    $state = [ordered]@{
        schema=1; mode='DRY_RUN'; source_sha=$SourceSha; phase='PREPARED'
        payload_manifest_sha256=$payloadManifestSha
        tools=[ordered]@{
            powershell=$powershell; powershell_version=$PSVersionTable.PSVersion.ToString()
            virtualbox=$vbox; packer=$packer; vagrant=$vagrant
        }
        history=@([ordered]@{phase='PREPARED';at=[DateTime]::UtcNow.ToString('o')})
    }
    $statePath = Join-Path $root 'state.json'
    Write-JsonAtomic -Path $statePath -Value $state
    $runner = Join-Path $root 'native-startup-resume.ps1'
    $arguments = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $runner + '"'),'-Action','Resume','-LabRoot',('"' + $LabRoot + '"'),'-StateRoot',('"' + $root + '"'),'-SourceSha',$SourceSha) -join ' '
    $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances Parallel
    [void](Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings)
    try {
        $registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $registeredIdentity = [string]$registered.Principal.UserId
        $registeredSid = if ($registeredIdentity -match '^S-1-') { $registeredIdentity } else {
            ([Security.Principal.NTAccount]::new($registeredIdentity)).Translate([Security.Principal.SecurityIdentifier]).Value
        }
        if ($registeredSid -ne 'S-1-5-18' -or [string]$registered.Principal.LogonType -ne 'ServiceAccount' -or [string]$registered.Principal.RunLevel -ne 'Highest') {
            throw 'Registered startup task principal differs from SYSTEM Highest'
        }
        if ([string]$registered.Actions[0].Execute -ine $powershell -or [string]$registered.Actions[0].Arguments -ne $arguments) { throw 'Registered startup task action differs' }
        if ([string]$registered.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger') { throw 'Registered startup task trigger is not AtStartup' }
        if ([string]$registered.Principal.LogonType -eq 'Password') { throw 'Startup task stores user credentials' }
        Move-Phase -State $state -Next 'BOOT_RESUME_ARMED'
        Write-JsonAtomic -Path $statePath -Value $state
        $firstTrigger = [DateTime]::UtcNow
        Start-ScheduledTask -TaskName $TaskName
        $first = Wait-TaskResult -EvidencePath (Join-Path $root 'evidence\first-run.json') -TriggeredAt $firstTrigger
        if ($first.Evidence.status -ne 'PASS' -or $first.Evidence.principal.sid -ne 'S-1-5-18' -or $first.Evidence.phase_after -ne 'COMPLETE') { throw 'First SYSTEM task resume did not PASS' }
        $secondTrigger = [DateTime]::UtcNow
        Start-ScheduledTask -TaskName $TaskName
        $second = Wait-TaskResult -EvidencePath (Join-Path $root 'evidence\second-run.json') -TriggeredAt $secondTrigger
        if ($second.Evidence.status -ne 'PASS' -or -not $second.Evidence.idempotent -or $second.Evidence.history_after -ne $first.Evidence.history_after) { throw 'Second SYSTEM task resume is not idempotent' }
        $probeArguments = $arguments.Replace('-Action Resume', '-Action ProbePrerequisites')
        $probeAction = New-ScheduledTaskAction -Execute $powershell -Argument $probeArguments
        [void](Register-ScheduledTask -TaskName $PrerequisiteTaskName -Action $probeAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings)
        $probeTrigger = [DateTime]::UtcNow
        Start-ScheduledTask -TaskName $PrerequisiteTaskName
        $prerequisites = Wait-TaskResult -Name $PrerequisiteTaskName -EvidencePath (Join-Path $root 'evidence\boot-prerequisites.json') -TriggeredAt $probeTrigger
        if ($prerequisites.Evidence.status -ne 'PASS' -or $prerequisites.Evidence.principal.sid -ne 'S-1-5-18' -or $prerequisites.Evidence.checks.virtualbox -ne '7.2.18r175117') {
            throw 'Second SYSTEM task boot prerequisite probe did not PASS'
        }
        $lock = [IO.File]::Open((Join-Path $root 'resume.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $lockTrigger = [DateTime]::UtcNow
            Start-ScheduledTask -TaskName $TaskName
            $locked = Wait-TaskResult -EvidencePath (Join-Path $root 'evidence\lock-rejected.json') -Seconds 45 -ExpectedExitCode 75 -TriggeredAt $lockTrigger
            if ($locked.Evidence.classification -ne 'CONCURRENCY_LOCK' -or $locked.Evidence.principal.sid -ne 'S-1-5-18' -or $locked.Evidence.waited_ms -lt 4500 -or $locked.Evidence.waited_ms -gt 15000) { throw 'SYSTEM task did not reject concurrent resume within its timeout' }
        }
        finally { $lock.Dispose() }
        $hostAfter = Get-HostMutationSnapshot
        if ($hostAfter.bcd_sha256 -ne $hostBefore.bcd_sha256 -or $hostAfter.last_boot_up_time -ne $hostBefore.last_boot_up_time -or
            $hostAfter.hypervisor_present -ne $hostBefore.hypervisor_present -or $hostAfter.registered_vms -ne $hostBefore.registered_vms) {
            throw 'Startup dry-run changed BCD, host hypervisor, reboot state or VirtualBox machine inventory'
        }
        $payloadCopy = [IO.Path]::GetFullPath((Join-Path $root 'payload'))
        if (-not $payloadCopy.StartsWith(($root.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Dry-run payload cleanup path escapes the governed state root'
        }
        Remove-Item -LiteralPath $payloadCopy -Recurse -Force
        $summary = [ordered]@{
            schema=1; status='PASS'; source_sha=$SourceSha
            startup_task_registered='PASS'; startup_task_principal='SYSTEM'; stored_user_credentials=$false
            manual_task_trigger='PASS'; resume_state_read='PASS'; resume_state_transition='PASS'
            resume_idempotency='PASS'; concurrency_lock='PASS'; resume_evidence='PASS'
            boot_prerequisites='PASS'; vboxmanage_system_context='PASS'; bcd_mutated=$false; reboot_occurred=$false
            temporary_payload_cleanup='PASS'
            bcd_sha256=$hostAfter.bcd_sha256; hypervisor_present=$hostAfter.hypervisor_present
            first_pid=$first.Evidence.principal.pid; second_pid=$second.Evidence.principal.pid
            first_timestamp=$first.Evidence.principal.timestamp; second_timestamp=$second.Evidence.principal.timestamp
            completed_at=[DateTime]::UtcNow.ToString('o')
        }
        Write-JsonAtomic -Path (Join-Path $root 'evidence\summary.json') -Value $summary
        Write-Output ($summary | ConvertTo-Json -Compress)
    }
    finally {
        Unregister-ScheduledTask -TaskName $PrerequisiteTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

switch ($Action) {
    'PrepareDryRun' { Invoke-PrepareDryRun }
    'Resume' { Invoke-Resume }
    'ProbePrerequisites' { Invoke-PrerequisiteProbe }
    'VerifyDryRun' {
        $root = Assert-StateRoot -Root $StateRoot -Lab $LabRoot -Sha $SourceSha
        $summary = Read-Json (Join-Path $root 'evidence\summary.json')
        if ($summary.status -ne 'PASS') { throw 'Startup dry-run summary is not PASS' }
        Write-Output ($summary | ConvertTo-Json -Compress)
    }
    'SelfTest' {
        $state = [pscustomobject]@{ phase='PREPARED'; history=@([pscustomobject]@{phase='PREPARED';at='fixture'}) }
        foreach ($phase in $Phases[1..($Phases.Count - 2)]) { Move-Phase -State $state -Next $phase }
        if ($state.phase -ne 'COMPLETE' -or @($state.history).Count -ne ($Phases.Count - 1)) { throw 'Startup state-machine transition self-test failed' }
        $rejected = $false
        try { Move-Phase -State $state -Next 'NATIVE_BOOT_PENDING' }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Non-monotone startup transition was accepted' }
        $failed = [pscustomobject]@{ phase='PREPARED'; history=@([pscustomobject]@{phase='PREPARED';at='fixture'}) }
        Move-Phase -State $failed -Next 'FAILED'
        $resurrected = $false
        try { Move-Phase -State $failed -Next 'BOOT_RESUME_ARMED' }
        catch { $resurrected = $true }
        if ($failed.phase -ne 'FAILED' -or -not $resurrected) { throw 'Failed startup state was resumed' }
        Write-Output 'PASS native-startup-resume-self-test monotone transitions and stale phase rejection'
    }
}
