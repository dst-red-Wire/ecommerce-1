[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Run', 'Resume', 'Clean')][string]$Action,
    [Parameter(Mandatory = $true)][string]$StageRoot,
    [string]$RunnerSourceSha = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
. (Join-Path $PSScriptRoot 'NativeVagrantSshSmoke.ps1')
. (Join-Path $PSScriptRoot 'LabNetworkSeed.ps1')
Set-PipelineUtf8

function Assert-LabStage {
    param([string]$Root)
    $stage = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $base = [IO.Path]::GetFullPath('C:\ecommerce-lab\network-smoke').TrimEnd('\') + '\'
    if (-not $stage.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Network smoke stage is outside the governed laboratory path'
    }
    $manifest = Join-Path $stage 'SHA256SUMS'
    foreach ($line in [IO.File]::ReadAllLines($manifest, [Text.Encoding]::UTF8)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$') { throw 'Network smoke staging manifest is invalid' }
        $expected = $Matches[1]
        $relative = $Matches[2]
        $candidate = [IO.Path]::GetFullPath((Join-Path $stage $relative.Replace('/', '\')))
        if (-not $candidate.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $candidate -PathType Leaf) -or (Get-FileSha256 -Path $candidate) -ne $expected) {
            throw "Network smoke staged input differs: $relative"
        }
    }
    return $stage
}

function Get-LabBackend {
    param([string]$LogPath)
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) { return 'UNKNOWN' }
    $content = [IO.File]::ReadAllText($LogPath, [Text.Encoding]::UTF8)
    if ($content -match '(?im)Attempting fall back to NEM|\bNEM:|WHvCapabilityCodeHypervisorPresent') { return 'NEM' }
    if ($content -match '(?im)\bHM:.*(?:VT-x|AMD-V)') { return 'NATIVE_VTX' }
    return 'UNKNOWN'
}

$stage = Assert-LabStage -Root $StageRoot
$prepared = Read-JsonFile (Join-Path $stage 'prepared.json')
if ($prepared.schema -ne 1 -or $prepared.status -ne 'PREPARED' -or
    [IO.Path]::GetFileName($stage) -ne [string]$prepared.campaign_id -or
    [string]$prepared.box_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Network smoke prepared binding is invalid'
}
$retainVm = $prepared.PSObject.Properties.Name -contains 'retain_vm' -and $prepared.retain_vm -eq $true
$diagnosticNem = $prepared.PSObject.Properties.Name -contains 'diagnostic_nem' -and $prepared.diagnostic_nem -eq $true
$smokeRoot = Join-Path $stage 'smoke-run'
$evidenceRoot = Join-Path 'C:\ecommerce-lab\evidence\network-smoke' ([string]$prepared.campaign_id)
$resultPath = Join-Path $evidenceRoot 'result.json'
$vagrant = Resolve-WindowsTool -Name 'vagrant.exe' -FallbackPaths @('C:\Program Files\Vagrant\bin\vagrant.exe')
$vbox = Resolve-WindowsTool -Name 'VBoxManage.exe' -FallbackPaths @('C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
$ssh = Resolve-WindowsTool -Name 'ssh.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'))
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$privateKey = 'C:\ecommerce-lab\identity\id_ed25519'
$publicKeyPath = "$privateKey.pub"
$seedServer = Join-Path $PSScriptRoot 'local-services-seed-server.ps1'

if ($Action -eq 'Clean') {
    try {
        $cleanLock = [IO.File]::Open('C:\ecommerce-lab\network-smoke\.runtime.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] { throw 'BLOCKED_RUNTIME another network smoke holds the laboratory runtime lock' }
    $result = Read-JsonFile $resultPath
    if ($result.status -in @('CLEANED_AFTER_DIAGNOSTIC','CLEANED_AFTER_RETAINED') -and $result.cleanup.vm_preserved -eq $false -and
        $result.cleanup.status -eq 'PASS') {
        $cleanLock.Dispose()
        [Console]::WriteLine("PASS lab-network-clean already-clean campaign=$($prepared.campaign_id)")
        exit 0
    }
    if ($result.status -notin @('DIAGNOSTIC_PRESERVED','PASS','BLOCKED_RUNTIME') -or $result.campaign_id -ne $prepared.campaign_id -or
        $result.cleanup.vm_preserved -ne $true -or $result.cleanup.vm_name -ne $result.vm_name -or
        $result.vm_name -notmatch '^ecommerce-rocky-10-2-smoke-[0-9a-f]{12}$' -or
        $result.cleanup.vm_id -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'No owned preserved network-smoke VM is recorded for this campaign'
    }
    $runtime = Read-JsonFile (Join-Path $smokeRoot 'runtime.json')
    if ($runtime.name -ne $result.vm_name -or $runtime.box_name -ne $result.box_name) {
        throw 'Preserved VM binding differs from the recorded campaign'
    }
    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
    $environment = @{ VAGRANT_HOME = (Join-Path $smokeRoot 'vagrant-home'); VAGRANT_CHECKPOINT_DISABLE = '1'; VAGRANT_DEFAULT_PROVIDER = 'virtualbox'; VAGRANT_NO_PLUGINS = '1' }
    if ($machines.ContainsKey([string]$result.vm_name)) {
        $machineIdPath = Join-Path $smokeRoot '.vagrant\machines\default\virtualbox\id'
        if (-not (Test-Path -LiteralPath $machineIdPath -PathType Leaf) -or
            [IO.File]::ReadAllText($machineIdPath).Trim().Trim('{}') -ine ([string]$result.cleanup.vm_id) -or
            ([string]$machines[[string]$result.vm_name]).Trim('{}') -ine ([string]$result.cleanup.vm_id)) {
            throw 'Preserved Vagrant machine ID differs from the owned VirtualBox VM'
        }
        $destroy = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('destroy', '--force') -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $environment
        if ($destroy.ExitCode -ne 0) {
            [void](Remove-OwnedVirtualMachine -Name ([string]$result.vm_name) -InitialMachines @{} -VBoxManage $vbox -WorkingDirectory $smokeRoot)
        }
    }
    $boxRemove = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box', 'remove', '--force', [string]$result.box_name) -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $environment
    Assert-ProcessSuccess -Result $boxRemove -Operation 'owned preserved network-smoke box removal'
    $result.cleanup.vm_preserved = $false
    $result.cleanup.reason = $null
    $result.cleanup.status = 'PASS'
    $result.status = if ($result.status -eq 'PASS') { 'CLEANED_AFTER_RETAINED' } else { 'CLEANED_AFTER_DIAGNOSTIC' }
    Write-Utf8Json -InputObject $result -Path $resultPath
    $cleanLock.Dispose()
    [Console]::WriteLine("PASS lab-network-clean campaign=$($prepared.campaign_id)")
    exit 0
}

if ($Action -eq 'Resume') {
    if ($RunnerSourceSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Network SSH resume requires the exact clean runner source SHA'
    }
    $result = Read-JsonFile $resultPath
    if ($result.campaign_id -ne $prepared.campaign_id -or
        $result.status -notin @('DIAGNOSTIC_PRESERVED','PASS','BLOCKED_RUNTIME') -or
        $result.cleanup.vm_preserved -ne $true -or
        $result.vm_name -notmatch '^ecommerce-rocky-10-2-smoke-[0-9a-f]{12}$' -or
        $result.cleanup.vm_id -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'Network SSH resume requires an owned preserved VM and matching campaign'
    }
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent -and -not $diagnosticNem) {
        throw 'BLOCKED_RUNTIME native VT-x is unavailable for network SSH resume in this Windows boot'
    }
    $box = [IO.Path]::GetFullPath([string]$prepared.box_path)
    if ((Get-FileSha256 -Path $box) -ne [string]$prepared.box_sha256 -or
        (Get-FileSha256 -Path (Join-Path (Split-Path -Parent $box) 'manifest.json')) -ne [string]$prepared.box_manifest_sha256) {
        throw 'Network SSH resume box digest or provenance changed'
    }
    $runtime = Read-JsonFile (Join-Path $smokeRoot 'runtime.json')
    if ($runtime.name -ne $result.vm_name -or $runtime.box_name -ne $result.box_name -or
        [IO.Path]::GetFullPath([string]$runtime.private_key) -ine [IO.Path]::GetFullPath($privateKey)) {
        throw 'Network SSH resume runtime binding changed'
    }
    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
    $machineIdPath = Join-Path $smokeRoot '.vagrant\machines\default\virtualbox\id'
    if (-not $machines.ContainsKey([string]$result.vm_name) -or
        -not (Test-Path -LiteralPath $machineIdPath -PathType Leaf) -or
        [IO.File]::ReadAllText($machineIdPath).Trim().Trim('{}') -ine [string]$result.cleanup.vm_id -or
        ([string]$machines[[string]$result.vm_name]).Trim('{}') -ine [string]$result.cleanup.vm_id) {
        throw 'Network SSH resume VM identity differs from the retained checkpoint'
    }
    $environment = @{ VAGRANT_HOME = (Join-Path $smokeRoot 'vagrant-home'); VAGRANT_CHECKPOINT_DISABLE = '1'; VAGRANT_DEFAULT_PROVIDER = 'virtualbox'; VAGRANT_NO_PLUGINS = '1' }
    $status = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('status','--machine-readable') -TimeoutSeconds 45 -WorkingDirectory $smokeRoot -Environment $environment
    if ($status.ExitCode -ne 0) { throw 'Network SSH resume could not read Vagrant VM state' }
    $vmState = if ($status.StdOut -match '(?m),default,state,([a-z_]+)\s*$') { $Matches[1] } else { '' }
    $resumeSeedRoot = Join-Path $smokeRoot 'seed'
    $resumeSeedStarted = $false
    $resumeSeedStatus = 'NOT_REQUIRED'
    try {
        if ($vmState -in @('poweroff','saved','aborted')) {
            if (-not ($runtime.PSObject.Properties.Name -contains 'seed_port') -or
                [int]$runtime.seed_port -lt 1024 -or [int]$runtime.seed_port -gt 65535) {
                throw 'Network SSH resume requires the retained NoCloud seed port'
            }
            $seedStart = Invoke-BoundedProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Start','-SeedRoot',$resumeSeedRoot,'-Port',[string]$runtime.seed_port) -TimeoutSeconds 30 -WorkingDirectory $stage
            Assert-ProcessSuccess -Result $seedStart -Operation 'retained NoCloud seed server start'
            $resumeSeedStarted = $true
            $start = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('up','--provider','virtualbox','--no-provision') -TimeoutSeconds 900 -WorkingDirectory $smokeRoot -Environment $environment
            Assert-ProcessSuccess -Result $start -Operation 'restart the retained network-smoke VM'
            $afterStart = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
            if (-not $afterStart.ContainsKey([string]$result.vm_name) -or
                ([string]$afterStart[[string]$result.vm_name]).Trim('{}') -ine [string]$result.cleanup.vm_id) {
                throw 'Network SSH resume changed the retained VirtualBox VM identity'
            }
            $vmRestart = 'EXECUTED_EXISTING_VM'
        }
        elseif ($vmState -eq 'running') { $vmRestart = 'NOT_REQUIRED' }
        else { throw "Network SSH resume refuses Vagrant VM state $vmState" }
        if ($result.PSObject.Properties.Name -contains 'vm_restart') { $result.vm_restart = $vmRestart }
        else { $result | Add-Member -NotePropertyName vm_restart -NotePropertyValue $vmRestart }
        $attempt = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        Write-Utf8Json -InputObject $result -Path (Join-Path $evidenceRoot "result-before-resume-$attempt.json")
        $network = New-NativeSshSmokeEvidence -VmName $result.vm_name -User 'packer' -EvidenceDirectory (Join-Path $stage "logs\ssh-resume-$attempt")
        $network.vagrant_up_started_at = [DateTime]::UtcNow.ToString('o')
        $network.vagrant_ready = 'PASS'
        $network.vagrant_ready_at = $network.vagrant_up_started_at
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        foreach ($delay in @(2,3,5,8,10,10,10,10)) {
            Update-NativeSshSmokeEvidence -Evidence $network -VBoxManage $vbox -VmName $result.vm_name -WorkingDirectory $smokeRoot -PrivateKey $privateKey -SshExecutable $ssh
            if ($network.ssh_auth_ready -eq 'PASS' -or [DateTime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Seconds $delay
        }
        Complete-NativeSshSmokeEvidence -Evidence $network -VBoxManage $vbox -Vagrant $vagrant -VmName $result.vm_name -WorkingDirectory $smokeRoot -Environment $environment -PrivateKey $privateKey -SshExecutable $ssh -VagrantUpResult $null
    }
    finally {
        if ($resumeSeedStarted) {
            $seedStop = Invoke-BoundedProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Stop','-SeedRoot',$resumeSeedRoot,'-Port',[string]$runtime.seed_port) -TimeoutSeconds 30 -WorkingDirectory $stage
            Assert-ProcessSuccess -Result $seedStop -Operation 'retained NoCloud seed server stop'
            $resumeSeedStatus = 'PASS'
        }
    }
    if ($result.PSObject.Properties.Name -contains 'resume_seed_server') { $result.resume_seed_server = $resumeSeedStatus }
    else { $result | Add-Member -NotePropertyName resume_seed_server -NotePropertyValue $resumeSeedStatus }
    $result.virtualbox_backend = Get-LabBackend -LogPath (Join-Path $network.diagnostics_directory 'VBox.log')
    $result.network_smoke = $network
    if ($result.PSObject.Properties.Name -contains 'resume_runner_source_sha') {
        $result.resume_runner_source_sha = $RunnerSourceSha
    }
    else { $result | Add-Member -NotePropertyName resume_runner_source_sha -NotePropertyValue $RunnerSourceSha }
    $result.checkpoints.'03-vm-smoke' = 'PASS'
    $result.checkpoints.'04-network-ssh' = if ($network.remote_command_ready -eq 'PASS') { 'PASS' } else { 'FAIL' }
    $result.checkpoints.'05-rocky-runtime' = if ($network.rocky_runtime -eq 'PASS') { 'PASS' } else { 'NOT_EXECUTED' }
    $result.resume_from = if ($network.remote_command_ready -ne 'PASS') { '04-network-ssh' } elseif ($network.rocky_runtime -ne 'PASS') { '05-rocky-runtime' } else { 'downstream-qualification' }
    $result.vm_recreate = 'NOT_REQUIRED'
    $result.status = if ($network.failure_stage) { 'DIAGNOSTIC_PRESERVED' } elseif ($result.virtualbox_backend -ne 'NATIVE_VTX' -or (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent) { 'BLOCKED_RUNTIME' } else { 'PASS' }
    $result.error = if ($network.failure_stage) { "$($network.failure_code): $($network.failure_reason)" } elseif ($result.status -eq 'BLOCKED_RUNTIME') { "VirtualBox backend $($result.virtualbox_backend); native VT-x qualification remains pending" } else { $null }
    $result.cleanup.reason = $result.error
    $result.completed_at = [DateTime]::UtcNow.ToString('o')
    Write-Utf8Json -InputObject $result -Path $resultPath
    [Console]::WriteLine("LAB_NETWORK_RESUME=$($result.status) campaign=$($prepared.campaign_id) evidence=$resultPath")
    if ($result.status -eq 'PASS') { exit 0 }
    if ($result.status -eq 'BLOCKED_RUNTIME') { exit 2 }
    exit 1
}

if (Test-Path -LiteralPath $resultPath -PathType Leaf) { throw 'Network smoke campaign was already attempted; prepare a new campaign' }
[void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
$result = [ordered]@{
    schema = 1; status = 'FAIL'; campaign_id = [string]$prepared.campaign_id
    source_git_sha = [string]$prepared.source_sha; source_tree_sha = [string]$prepared.source_tree_sha
    packer = [ordered]@{ status = 'REUSED'; build = 'NOT_EXECUTED'; inputs_digest = [string]$prepared.inputs_digest }
    box_digest = [string]$prepared.box_sha256; box_digest_verified = 'NOT_EXECUTED'
    ssh_identity = [ordered]@{ source = 'controller_persistent'; private_key_present = $false; public_key_fingerprint = $null; private_key_in_box = $null }
    vm_name = $null; box_name = $null; virtualbox_backend = 'UNKNOWN'
    network_smoke = $null
    checkpoints = [ordered]@{ '03-vm-smoke' = 'NOT_EXECUTED'; '04-network-ssh' = 'NOT_EXECUTED'; '05-rocky-runtime' = 'NOT_EXECUTED' }
    resume_from = '03-vm-smoke'; vm_recreate = 'REQUIRED_MISSING_VM'
    resume_runner_source_sha = $null; vm_restart = 'NOT_EXECUTED'
    timings = [ordered]@{ box_import_seconds = $null; vm_boot_seconds = $null; network_readiness_seconds = $null; ssh_readiness_seconds = $null; cleanup_seconds = $null }
    guest_security = 'NOT_EXECUTED'
    cleanup = [ordered]@{ policy = if ($retainVm) { 'retain_until_explicit_clean' } elseif ($prepared.keep_failed_vm) { 'preserve_on_failure' } else { 'destroy_always' }; status = 'NOT_EXECUTED'; vm_preserved = $false; vm_name = $null; vm_id = $null; reason = $null; seed_server = 'NOT_EXECUTED'; lock = 'NOT_EXECUTED' }
    started_at = [DateTime]::UtcNow.ToString('o'); completed_at = $null
    error = $null
}
$environment = @{}
$seedRoot = $null
$boxAdded = $false
$vmName = $null
$campaignLock = $null
$initial = @{}
try {
    try {
        $campaignLock = [IO.File]::Open('C:\ecommerce-lab\network-smoke\.runtime.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] { throw 'BLOCKED_RUNTIME another network smoke holds the laboratory runtime lock' }
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $processors = @(Get-CimInstance -ClassName Win32_Processor)
    $firmwareStates = @($processors | ForEach-Object { $_.VirtualizationFirmwareEnabled -eq $true })
    if (-not (Test-LabVirtualizationReady -HypervisorPresent $computer.HypervisorPresent -DiagnosticNem $diagnosticNem -FirmwareEnabled $firmwareStates)) {
        throw 'BLOCKED_RUNTIME native VT-x is unavailable in this Windows boot'
    }
    $identity = Invoke-BoundedProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'LabSshIdentity.ps1'),'-Action','Verify') -TimeoutSeconds 30 -WorkingDirectory $stage
    Assert-ProcessSuccess -Result $identity -Operation 'persistent laboratory SSH identity verification'
    if ($identity.StdOut -notmatch 'FINGERPRINT=(SHA256:[A-Za-z0-9+/]+)') { throw 'Persistent laboratory SSH fingerprint is absent' }
    $result.ssh_identity.private_key_present = $true
    $result.ssh_identity.public_key_fingerprint = $Matches[1]
    $box = [IO.Path]::GetFullPath([string]$prepared.box_path)
    if (-not (Test-Path -LiteralPath $box -PathType Leaf) -or (Get-FileSha256 -Path $box) -ne [string]$prepared.box_sha256) {
        throw 'Verified box digest differs before network smoke'
    }
    $boxManifest = Join-Path (Split-Path -Parent $box) 'manifest.json'
    if ((Get-FileSha256 -Path $boxManifest) -ne [string]$prepared.box_manifest_sha256) { throw 'Verified box provenance manifest changed' }
    $result.box_digest_verified = 'PASS'
    $vagrantVersion = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('--version') -TimeoutSeconds 15 -WorkingDirectory $stage
    if ($vagrantVersion.ExitCode -ne 0 -or $vagrantVersion.StdOut.Trim() -ne "Vagrant $($prepared.vagrant_version)") { throw 'Vagrant version differs from prepared exact toolchain' }
    $vboxVersion = Invoke-BoundedProcess -FilePath $vbox -Arguments @('--version') -TimeoutSeconds 15 -WorkingDirectory $stage
    if ($vboxVersion.ExitCode -ne 0 -or $vboxVersion.StdOut -notmatch '^([0-9]+\.[0-9]+\.[0-9]+)r' -or $Matches[1] -ne [string]$prepared.virtualbox_version) {
        throw 'VirtualBox version differs from prepared exact toolchain'
    }
    [void](New-Item -ItemType Directory -Path $smokeRoot -Force)
    Copy-Item -LiteralPath (Join-Path $stage 'platform\vagrant\rocky-image-smoke\Vagrantfile') -Destination $smokeRoot
    $campaignHash = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$prepared.campaign_id))
    $suffix = ([BitConverter]::ToString($campaignHash).Replace('-', '').ToLowerInvariant()).Substring(0, 12)
    $vmName = "ecommerce-rocky-10-2-smoke-$suffix"
    $digestPrefix = ([string]$prepared.box_sha256).Substring(0, 12)
    $boxName = "ecommerce/rocky-10.2-rke2-$digestPrefix"
    $result.vm_name = $vmName
    $result.box_name = $boxName
    $ports = @((Get-LabPort), (Get-LabPort))
    if ($ports[0] -eq $ports[1]) { throw 'Seed and SSH host ports unexpectedly collide' }
    $publicKey = [IO.File]::ReadAllText($publicKeyPath, [Text.Encoding]::UTF8).Trim()
    $seedRoot = Write-LabSeed -Root $smokeRoot -Campaign ([string]$prepared.campaign_id) -PublicKey $publicKey
    Write-Utf8Json -InputObject ([ordered]@{
        name = $vmName; box_name = $boxName; vagrant_version = [string]$prepared.vagrant_version
        private_key = $privateKey; boot_timeout_seconds = [int]$prepared.global_deadline_seconds
        ssh_timeout_seconds = 10; memory_mib = 4096; cpus = 4; nic_type = 'virtio'
        seed_port = [int]$ports[0]; ssh_host_port = [int]$ports[1]
    }) -Path (Join-Path $smokeRoot 'runtime.json')
    $environment = @{ VAGRANT_HOME = (Join-Path $smokeRoot 'vagrant-home'); VAGRANT_CHECKPOINT_DISABLE = '1'; VAGRANT_DEFAULT_PROVIDER = 'virtualbox'; VAGRANT_NO_PLUGINS = '1' }
    $initial = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
    if ($initial.ContainsKey($vmName)) { throw "Owned smoke VM already exists: $vmName" }
    $seedStart = Invoke-BoundedProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Start','-SeedRoot',$seedRoot,'-Port',[string]$ports[0]) -TimeoutSeconds 30 -WorkingDirectory $stage
    Assert-ProcessSuccess -Result $seedStart -Operation 'NoCloud network-smoke seed server start'
    $result.cleanup.seed_server = 'RUNNING'
    $boxClock = [Diagnostics.Stopwatch]::StartNew()
    $boxAdd = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box','add','--name',$boxName,'--provider','virtualbox','--checksum-type','sha256','--checksum',[string]$prepared.box_sha256,$box) -TimeoutSeconds 600 -WorkingDirectory $smokeRoot -Environment $environment
    $boxClock.Stop()
    $result.timings.box_import_seconds = [Math]::Round($boxClock.Elapsed.TotalSeconds, 3)
    Assert-ProcessSuccess -Result $boxAdd -Operation 'verified network-smoke Vagrant box add'
    $boxAdded = $true
    $network = New-NativeSshSmokeEvidence -VmName $vmName -User 'packer' -EvidenceDirectory (Join-Path $stage 'logs\ssh-smoke')
    $network.vagrant_up_deadline_seconds = [int]$prepared.global_deadline_seconds
    $result.network_smoke = $network
    $network.vagrant_up_started_at = [DateTime]::UtcNow.ToString('o')
    $up = $null
    $upError = $null
    try {
        $up = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('up','--provider','virtualbox','--no-provision') -TimeoutSeconds ([int]$prepared.global_deadline_seconds) -WorkingDirectory $smokeRoot -Environment $environment -OnPoll {
            try { Update-NativeSshSmokeEvidence -Evidence $network -VBoxManage $vbox -VmName $vmName -WorkingDirectory $smokeRoot -PrivateKey $privateKey -SshExecutable $ssh }
            catch { $network.last_ssh_error = $_.Exception.Message }
        } -PollIntervalSeconds 5
    }
    catch { $upError = $_.Exception.Message }
    Complete-NativeSshSmokeEvidence -Evidence $network -VBoxManage $vbox -Vagrant $vagrant -VmName $vmName -WorkingDirectory $smokeRoot -Environment $environment -PrivateKey $privateKey -SshExecutable $ssh -VagrantUpResult $up
    $result.checkpoints.'03-vm-smoke' = if ($network.vm_running -eq 'PASS' -and $network.vagrant_ready -eq 'PASS') { 'PASS' } else { 'FAIL' }
    $result.checkpoints.'04-network-ssh' = if ($network.remote_command_ready -eq 'PASS') { 'PASS' } else { 'NOT_EXECUTED' }
    $result.checkpoints.'05-rocky-runtime' = if ($network.rocky_runtime -eq 'PASS') { 'PASS' } else { 'NOT_EXECUTED' }
    $result.resume_from = if ($network.vm_running -ne 'PASS') { '03-vm-smoke' } elseif ($network.remote_command_ready -ne 'PASS') { '04-network-ssh' } elseif ($network.rocky_runtime -ne 'PASS') { '05-rocky-runtime' } else { 'downstream-qualification' }
    $result.vm_recreate = 'EXECUTED'
    $result.timings.vm_boot_seconds = Get-NativeSshSeconds -Start $network.vagrant_up_started_at -End $network.vm_running_at
    $result.timings.network_readiness_seconds = Get-NativeSshSeconds -Start $network.vm_running_at -End $network.tcp_22_ready_at
    $result.timings.ssh_readiness_seconds = Get-NativeSshSeconds -Start $network.tcp_22_ready_at -End $network.ssh_auth_ready_at
    $result.virtualbox_backend = Get-LabBackend -LogPath (Join-Path $stage 'logs\ssh-smoke\VBox.log')
    if ($result.virtualbox_backend -ne 'NATIVE_VTX' -and -not ($diagnosticNem -and $result.virtualbox_backend -eq 'NEM')) {
        throw "BLOCKED_RUNTIME VirtualBox backend is $($result.virtualbox_backend)"
    }
    if ($upError) { throw "Network smoke vagrant up failed at $($network.failure_stage): $upError" }
    if ($up.ExitCode -ne 0 -or $network.failure_stage) { throw "Network smoke failed at $($network.failure_stage): $($network.failure_reason)" }
    $security = Invoke-NativeDirectSshProbe -SshExecutable $ssh -Address $network.address -Port $network.port -User $network.user -PrivateKey $privateKey -WorkingDirectory $smokeRoot -TimeoutSeconds 30 -Command 'test "$(stat -c %a ~/.ssh)" = 700 && test "$(stat -c %a ~/.ssh/authorized_keys)" = 600 && test "$(stat -c %U ~/.ssh/authorized_keys)" = packer && sudo -n sshd -T | grep -qx "pubkeyauthentication yes" && { sudo -n grep -R -l "BEGIN OPENSSH PRIVATE KEY" /home/packer /root >/dev/null 2>&1; test $? -eq 1; }'
    Assert-ProcessSuccess -Result $security -Operation 'guest SSH key ownership, mode, cloud-init and sshd security'
    $result.guest_security = 'PASS'
    $result.ssh_identity.private_key_in_box = $false
    $result.status = if ($result.virtualbox_backend -eq 'NATIVE_VTX') { 'PASS' } else { 'BLOCKED_RUNTIME' }
    if ($result.status -eq 'BLOCKED_RUNTIME') { $result.error = 'NEM diagnostic only; native VT-x qualification remains pending' }
}
catch {
    $result.error = $_.Exception.Message
    if ($result.error.StartsWith('BLOCKED_RUNTIME ', [StringComparison]::Ordinal)) { $result.status = 'BLOCKED_RUNTIME' }
    if ($null -eq $result.network_smoke) {
        $result.network_smoke = [ordered]@{ failure_stage = 'preflight'; failure_code = if ($result.status -eq 'BLOCKED_RUNTIME') { 'BLOCKED_RUNTIME' } else { 'PREFLIGHT_FAILED' }; failure_reason = $result.error }
    }
}
finally {
    $cleanupClock = [Diagnostics.Stopwatch]::StartNew()
    if ($null -ne $seedRoot) {
        try {
            $seedStop = Invoke-BoundedProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Stop','-SeedRoot',$seedRoot,'-Port',[string]$ports[0]) -TimeoutSeconds 30 -WorkingDirectory $stage
            Assert-ProcessSuccess -Result $seedStop -Operation 'NoCloud network-smoke seed server stop'
            $result.cleanup.seed_server = 'PASS'
        }
        catch { $result.cleanup.seed_server = 'FAIL'; $result.status = 'FAIL'; $result.error = "Seed server cleanup failed: $($_.Exception.Message)" }
    }
    $vmExists = $false
    $ownedVmId = $null
    $inventoryFailed = $false
    try {
        if ($vmName) {
            $ownedMachines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $stage
            $vmExists = $ownedMachines.ContainsKey($vmName)
            if ($vmExists) { $ownedVmId = ([string]$ownedMachines[$vmName]).Trim('{}') }
        }
    }
    catch {
        $inventoryFailed = $true
        $result.cleanup.status = 'FAIL'
        $result.status = 'FAIL'
        $result.error = "VirtualBox ownership check failed: $($_.Exception.Message); prior error: $($result.error)"
    }
    $preserve = (($result.status -in @('FAIL','BLOCKED_RUNTIME') -and ($prepared.keep_failed_vm -eq $true -or $retainVm)) -or
        ($result.status -eq 'PASS' -and $retainVm)) -and $vmExists -and $boxAdded
    if ($preserve) {
        if ($result.status -eq 'FAIL') { $result.status = 'DIAGNOSTIC_PRESERVED' }
        $result.cleanup.vm_preserved = $true
        $result.cleanup.vm_name = $vmName
        $result.cleanup.vm_id = $ownedVmId
        $result.cleanup.reason = $result.error
        $result.cleanup.status = 'PASS'
    }
    elseif (Test-Path -LiteralPath (Join-Path $smokeRoot 'runtime.json') -PathType Leaf) {
        try {
            if ($vmExists -or $inventoryFailed) {
                $destroy = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('destroy','--force') -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $environment
                if ($destroy.ExitCode -ne 0 -and $vmExists -and -not $inventoryFailed) {
                    [void](Remove-OwnedVirtualMachine -Name $vmName -InitialMachines $initial -VBoxManage $vbox -WorkingDirectory $smokeRoot)
                }
                else { Assert-ProcessSuccess -Result $destroy -Operation 'network-smoke VM cleanup' }
            }
            if ($boxAdded) {
                $boxRemove = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box','remove','--force',[string]$result.box_name) -TimeoutSeconds 300 -WorkingDirectory $smokeRoot -Environment $environment
                Assert-ProcessSuccess -Result $boxRemove -Operation 'network-smoke box cache cleanup'
            }
            if (-not $inventoryFailed) { $result.cleanup.status = 'PASS' }
        }
        catch { $result.cleanup.status = 'FAIL'; $result.status = 'FAIL'; $result.error = "Network-smoke cleanup failed: $($_.Exception.Message); prior error: $($result.error)" }
    }
    else { $result.cleanup.status = 'PASS' }
    if ($null -ne $campaignLock) { $campaignLock.Dispose() }
    $result.cleanup.lock = 'PASS'
    $cleanupClock.Stop()
    $result.timings.cleanup_seconds = [Math]::Round($cleanupClock.Elapsed.TotalSeconds, 3)
    $result.completed_at = [DateTime]::UtcNow.ToString('o')
    Write-Utf8Json -InputObject $result -Path $resultPath
}
[Console]::WriteLine("LAB_NETWORK_SMOKE=$($result.status) campaign=$($prepared.campaign_id) evidence=$resultPath")
if ($result.status -eq 'PASS') { exit 0 }
if ($result.status -eq 'BLOCKED_RUNTIME') { exit 2 }
exit 1
