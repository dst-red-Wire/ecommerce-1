[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory = $true)][string]$WslDistribution,
    [Parameter(Mandatory = $true)][string]$WslRepoRoot,
    [switch]$Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$root = $null
$artifactRoot = $null
$evidenceRoot = $null
$stageRoot = $null
$pipelineRoot = $null
$initialMachines = @{}
$vbox = $null
$buildCompleted = $false
$cleanupStatus = 'NOT_EXECUTED'
$artifactSource = $null
$artifactSha256 = $null
$gitState = $null
$serialLog = $null
$packerLog = $null
$evidence = [ordered]@{
    schema = 1
    image = 'rocky-10.2'
    profile = 'rke2'
    builder = 'packer'
    hypervisor = 'virtualbox'
    status = 'FAIL'
    source_sha = $null
    source_clean = $false
    artifact = 'rocky-10.2-rke2-virtualbox.box'
    sha256 = $null
    packer_version = $null
    virtualbox_version = $null
    vagrant_version = $null
    preflight = 'NOT_EXECUTED'
    packer_init = 'NOT_EXECUTED'
    packer_fmt = 'NOT_EXECUTED'
    packer_validate = 'NOT_EXECUTED'
    packer_build = 'NOT_EXECUTED'
    checksum = 'NOT_EXECUTED'
    cleanup = 'NOT_EXECUTED'
    qualification_key = 'NOT_CREATED'
    resources = $null
    storage = $null
    milestones = [ordered]@{
        T0_PACKER_START = $null
        T1_VM_CREATED = $null
        T2_ISO_BOOT = $null
        T3_KICKSTART_START = $null
        T4_NETWORK_READY = $null
        T5_RPM_INSTALLATION_START = $null
        T6_RPM_INSTALLATION_END = $null
        T7_FIRST_REBOOT = $null
        T8_INSTALLED_OS_BOOT = $null
        T9_SSHD_READY = $null
        T10_PACKER_SSH_CONNECTION = $null
        T11_PROVISIONING_COMPLETE = $null
        T12_SHUTDOWN = $null
        T13_ARTIFACT_EXPORT_COMPLETE = $null
    }
    telemetry = [ordered]@{
        serial_log = 'NOT_CAPTURED'
        serial_log_sha256 = $null
        packer_log = 'NOT_CAPTURED'
        packer_log_sha256 = $null
    }
    started_at = [DateTime]::UtcNow.ToString('o')
    completed_at = $null
    error = $null
}

try {
    if ($WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or -not $WslRepoRoot.StartsWith('/')) {
        throw 'Invalid WSL distribution or repository path'
    }
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    $artifactRoot = Join-Path $root '.artifacts\packer\rocky-10.2\windows'
    $evidenceRoot = Join-Path $root '.context\evidence\rocky-image\rocky-10.2\windows'
    [void](New-Item -ItemType Directory -Path $artifactRoot -Force)
    [void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
    $preflightEvidence = Join-Path $evidenceRoot 'preflight.json'
    $preflight = Invoke-BoundedProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $PSScriptRoot 'packer-preflight.ps1'),
        '-RepoRoot', $root,
        '-WslDistribution', $WslDistribution,
        '-WslRepoRoot', $WslRepoRoot,
        '-EvidencePath', $preflightEvidence
    ) -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $preflight -Operation 'Windows Packer preflight'
    $preflightDocument = Read-JsonFile $preflightEvidence
    if ($preflightDocument.status -ne 'PASS') {
        throw 'Windows Packer preflight evidence is not PASS'
    }
    $evidence.preflight = 'PASS'
    $evidence.packer_version = $preflightDocument.tools.packer.actual_version
    $evidence.virtualbox_version = $preflightDocument.tools.virtualbox.actual_version
    $evidence.vagrant_version = $preflightDocument.tools.vagrant.actual_version
    $packer = [string]$preflightDocument.tools.packer.executable
    $vbox = [string]$preflightDocument.tools.virtualbox.executable

    $gitState = Get-GitState -Distribution $WslDistribution -WslRepoRoot $WslRepoRoot
    if ($gitState.Head -notmatch '^[0-9a-f]{40}$') {
        throw 'Git HEAD is not a full commit SHA'
    }
    $evidence.source_sha = $gitState.Head
    $evidence.source_clean = $gitState.Clean

    $pipelineRoot = Get-LocalPipelineRoot
    [void](New-Item -ItemType Directory -Path $pipelineRoot -Force)
    $stageRoot = Join-Path $pipelineRoot ("build-{0}-{1}" -f $gitState.Head.Substring(0, 12), [Guid]::NewGuid().ToString('N'))
    $stageRoot = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath $stageRoot
    [void](New-Item -ItemType Directory -Path $stageRoot)
    $sourceRoot = Join-Path $stageRoot 'source'
    $buildArtifacts = Join-Path $stageRoot 'artifacts'
    [void](New-Item -ItemType Directory -Path $sourceRoot)
    [void](New-Item -ItemType Directory -Path $buildArtifacts)
    foreach ($definition in @('rocky-10.2.pkr.hcl', 'variables.pkr.hcl')) {
        Copy-Item -LiteralPath (Join-Path $root "platform\packer\rocky-10.2\$definition") -Destination $sourceRoot
    }
    Copy-Item -LiteralPath (Join-Path $root 'platform\packer\rocky-10.2\http') -Destination $sourceRoot -Recurse
    $initialMachines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $stageRoot
    $ownedBuildVm = 'ecommerce-rocky-10-2-build-rke2'
    if ($initialMachines.ContainsKey($ownedBuildVm)) {
        throw "Refusing build because the deterministic Packer VM already exists: $ownedBuildVm"
    }

    $init = Invoke-BoundedProcess -FilePath $packer -Arguments @('init', $sourceRoot) -TimeoutSeconds 300 -WorkingDirectory $stageRoot
    Assert-ProcessSuccess -Result $init -Operation 'packer init'
    $evidence.packer_init = 'PASS'

    $fmt = Invoke-BoundedProcess -FilePath $packer -Arguments @('fmt', '-check', $sourceRoot) -TimeoutSeconds 120 -WorkingDirectory $stageRoot
    Assert-ProcessSuccess -Result $fmt -Operation 'packer fmt -check'
    $evidence.packer_fmt = 'PASS'

    $stageWsl = Convert-ToWslPath -WindowsPath $stageRoot -Distribution $WslDistribution -TimeoutSeconds 15
    $offlineBundleWsl = "$stageWsl/offline"
    $materializeArguments = @(
        'scripts/materialize_packer_rpm_repo.py',
        '--contract', 'config/contracts/machine-image-lock.yaml',
        '--package-lock', 'config/artifacts/rocky-10.2-base-packages.lock.json',
        '--toolchain-lock', 'config/contracts/toolchain-lock.json',
        '--cache', '.context/cache/packer',
        '--output', $offlineBundleWsl
    )
    if ($Offline.IsPresent) {
        $materializeArguments += '--offline'
    }
    $materialize = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments $materializeArguments -TimeoutSeconds 7200
    Assert-ProcessSuccess -Result $materialize -Operation 'checksum-locked Packer input materialization'

    $sshKeygen = Resolve-WindowsTool -Name 'ssh-keygen.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'))
    $privateKey = Join-Path $stageRoot 'qualification-key'
    $keygen = Invoke-BoundedProcess -FilePath $sshKeygen -Arguments @('-q', '-t', 'ed25519', '-N', '', '-C', 'ecommerce-rocky-image-qualification', '-f', $privateKey) -TimeoutSeconds 30 -WorkingDirectory $stageRoot
    Assert-ProcessSuccess -Result $keygen -Operation 'ephemeral image qualification key generation'
    $evidence.qualification_key = 'CREATED_WINDOWS_LOCAL_ONLY'

    $varFileWsl = "$stageWsl/rocky-10.2.auto.pkrvars.hcl"
    $runtimeContractWsl = "$stageWsl/runtime-contract.json"
    $render = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments @(
        'scripts/render_packer_vars.py',
        '--contract', 'config/contracts/machine-image-lock.yaml',
        '--bundle', $offlineBundleWsl,
        '--build-public-key-file', "$stageWsl/qualification-key.pub",
        '--build-private-key-file', "$stageWsl/qualification-key",
        '--artifact-dir', "$stageWsl/artifacts",
        '--target-platform', 'windows',
        '--runtime-contract-output', $runtimeContractWsl,
        '--output', $varFileWsl
    ) -TimeoutSeconds 300
    Assert-ProcessSuccess -Result $render -Operation 'Packer Windows variable rendering'
    $varFile = Join-Path $stageRoot 'rocky-10.2.auto.pkrvars.hcl'
    $runtimeContract = Read-JsonFile (Join-Path $stageRoot 'runtime-contract.json')
    $evidence.resources = $runtimeContract.resources
    $evidence.storage = $runtimeContract.storage

    $validate = Invoke-BoundedProcess -FilePath $packer -Arguments @('validate', "-var-file=$varFile", $sourceRoot) -TimeoutSeconds 120 -WorkingDirectory $stageRoot
    Assert-ProcessSuccess -Result $validate -Operation 'packer validate'
    $evidence.packer_validate = 'PASS'

    $serialLog = Join-Path $buildArtifacts 'virtualbox-serial.log'
    $packerLog = Join-Path $stageRoot 'packer-build.log'
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
    $evidence.milestones.T0_PACKER_START = [DateTime]::UtcNow.ToString('o')
    $observeProgress = {
        $observedAt = [DateTime]::UtcNow.ToString('o')
        if ($null -eq $evidence.milestones.T1_VM_CREATED) {
            try {
                $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $stageRoot
                if ($machines.ContainsKey($ownedBuildVm)) {
                    $evidence.milestones.T1_VM_CREATED = $observedAt
                }
            }
            catch {
                # Telemetry probes must not replace the bounded Packer result.
            }
        }
        if (Test-Path -LiteralPath $serialLog -PathType Leaf) {
            $serialInfo = Get-Item -LiteralPath $serialLog
            if ($serialInfo.Length -gt 0 -and $null -eq $evidence.milestones.T2_ISO_BOOT) {
                $evidence.milestones.T2_ISO_BOOT = $observedAt
            }
            $serial = [System.IO.File]::ReadAllText($serialLog, [System.Text.Encoding]::UTF8)
            foreach ($name in $milestoneTokens.Keys) {
                if ($null -eq $evidence.milestones[$name] -and $serial.Contains($milestoneTokens[$name])) {
                    $evidence.milestones[$name] = $observedAt
                }
            }
        }
    }.GetNewClosure()
    $build = Invoke-BoundedProcess -FilePath $packer -Arguments @('build', '-only=rocky-10.2-base.virtualbox-iso.base', "-var-file=$varFile", '-var=image_profile=rke2', $sourceRoot) -TimeoutSeconds 7200 -WorkingDirectory $stageRoot -Environment @{
        PACKER_LOG = '1'
        PACKER_LOG_PATH = $packerLog
    } -OnPoll $observeProgress -PollIntervalSeconds 5
    Assert-ProcessSuccess -Result $build -Operation 'packer build'
    $evidence.packer_build = 'PASS'
    $artifactSource = Join-Path $buildArtifacts 'rocky-10.2-rke2-virtualbox.box'
    if (-not (Test-Path -LiteralPath $artifactSource -PathType Leaf)) {
        throw "Packer did not produce the contracted box: $artifactSource"
    }
    $artifactSha256 = Get-FileSha256 -Path $artifactSource
    if ($artifactSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Packer artifact SHA-256 is invalid'
    }
    $evidence.sha256 = $artifactSha256
    $evidence.checksum = 'PASS'
    $evidence.milestones.T13_ARTIFACT_EXPORT_COMPLETE = [DateTime]::UtcNow.ToString('o')
    $missingMilestones = @($evidence.milestones.Keys | Where-Object { $null -eq $evidence.milestones[$_] })
    if ($missingMilestones.Count -gt 0) {
        throw "Packer telemetry is incomplete: $($missingMilestones -join ', ')"
    }
    $buildCompleted = $true
}
catch {
    $evidence.error = $_.Exception.Message
}

if ($null -ne $vbox -and $null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot -PathType Container)) {
    try {
        $cleanupStatus = Remove-OwnedVirtualMachine -Name 'ecommerce-rocky-10-2-build-rke2' -InitialMachines $initialMachines -VBoxManage $vbox -WorkingDirectory $stageRoot
    }
    catch {
        $cleanupStatus = 'FAIL'
        if ($null -eq $evidence.error) {
            $evidence.error = $_.Exception.Message
        }
    }
}
$evidence.cleanup = $cleanupStatus

if ($null -ne $evidenceRoot) {
    foreach ($telemetrySource in @(
        [pscustomobject]@{ Source = $serialLog; Name = 'build-serial.log'; Status = 'serial_log'; Digest = 'serial_log_sha256' },
        [pscustomobject]@{ Source = $packerLog; Name = 'build-packer.log'; Status = 'packer_log'; Digest = 'packer_log_sha256' }
    )) {
        if ($null -ne $telemetrySource.Source -and (Test-Path -LiteralPath $telemetrySource.Source -PathType Leaf)) {
            $telemetryTarget = Join-Path $evidenceRoot $telemetrySource.Name
            Copy-Item -LiteralPath $telemetrySource.Source -Destination $telemetryTarget -Force
            $evidence.telemetry[$telemetrySource.Status] = $telemetrySource.Name
            $evidence.telemetry[$telemetrySource.Digest] = Get-FileSha256 -Path $telemetryTarget
        }
    }
}

if ($buildCompleted -and $cleanupStatus -ne 'FAIL') {
    $promotionStarted = $false
    $storedPrivateKey = $null
    $storedPublicKey = $null
    try {
        $targetArtifact = Join-Path $artifactRoot 'rocky-10.2-rke2-virtualbox.box'
        $temporaryArtifact = Join-Path $artifactRoot ("rocky-10.2-rke2-virtualbox.box.{0}.tmp" -f [Guid]::NewGuid().ToString('N'))
        Copy-Item -LiteralPath $artifactSource -Destination $temporaryArtifact
        if ((Get-FileSha256 -Path $temporaryArtifact) -ne $artifactSha256) {
            throw 'Artifact digest changed while promoting it into the repository artifact directory'
        }
        Move-Item -LiteralPath $temporaryArtifact -Destination $targetArtifact -Force
        [System.IO.File]::WriteAllText((Join-Path $artifactRoot 'SHA256SUMS'), "$artifactSha256  rocky-10.2-rke2-virtualbox.box`n", (New-Object System.Text.UTF8Encoding($false)))
        foreach ($stale in @('qualification.json', 'release.json')) {
            $stalePath = Join-Path $evidenceRoot $stale
            if (Test-Path -LiteralPath $stalePath -PathType Leaf) {
                Remove-Item -LiteralPath $stalePath -Force
            }
        }

        $keyRoot = Join-Path $pipelineRoot 'keys'
        [void](New-Item -ItemType Directory -Path $keyRoot -Force)
        $storedPrivateKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$artifactSha256.key")
        $storedPublicKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$artifactSha256.key.pub")
        if ((Test-Path -LiteralPath $storedPrivateKey) -or (Test-Path -LiteralPath $storedPublicKey)) {
            throw 'Qualification key destination already exists; refusing to overwrite it'
        }
        $promotionStarted = $true
        Move-Item -LiteralPath (Join-Path $stageRoot 'qualification-key') -Destination $storedPrivateKey -Force
        Move-Item -LiteralPath (Join-Path $stageRoot 'qualification-key.pub') -Destination $storedPublicKey -Force
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetOwner($identity)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
        [void]$acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $storedPrivateKey -AclObject $acl
        $evidence.qualification_key = 'STORED_WINDOWS_LOCAL_ONLY'
        $evidence.status = 'PASS'
    }
    catch {
        $evidence.status = 'FAIL'
        $evidence.error = $_.Exception.Message
        if ($promotionStarted) {
            foreach ($storedKey in @($storedPrivateKey, $storedPublicKey)) {
                try {
                    if (Test-Path -LiteralPath $storedKey) {
                        Remove-Item -LiteralPath $storedKey -Force
                    }
                }
                catch {
                    $evidence.error += "; qualification key rollback failed: $($_.Exception.Message)"
                }
            }
        }
    }
}

if ($null -ne $pipelineRoot -and $null -ne $stageRoot) {
    try { Remove-SafeTree -BasePath $pipelineRoot -CandidatePath $stageRoot } catch {
        $evidence.status = 'FAIL'
        $evidence.cleanup = 'FAIL'
        if ($null -eq $evidence.error) { $evidence.error = $_.Exception.Message }
    }
}

$evidence.completed_at = [DateTime]::UtcNow.ToString('o')
if ($null -ne $evidenceRoot) {
    Write-Utf8Json -InputObject $evidence -Path (Join-Path $evidenceRoot 'build.json')
}
if ($evidence.status -eq 'PASS') {
    [Console]::WriteLine("PASS rocky-image-build sha256=$artifactSha256")
    exit 0
}
[Console]::Error.WriteLine("FAIL rocky-image-build: $($evidence.error)")
exit 1
