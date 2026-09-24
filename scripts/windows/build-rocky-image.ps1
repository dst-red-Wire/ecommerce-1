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
    $render = Invoke-WslProcess -Distribution $WslDistribution -WslWorkingDirectory $WslRepoRoot -Command 'python3' -Arguments @(
        'scripts/render_packer_vars.py',
        '--contract', 'config/contracts/machine-image-lock.yaml',
        '--bundle', $offlineBundleWsl,
        '--build-public-key-file', "$stageWsl/qualification-key.pub",
        '--build-private-key-file', "$stageWsl/qualification-key",
        '--artifact-dir', "$stageWsl/artifacts",
        '--target-platform', 'windows',
        '--output', $varFileWsl
    ) -TimeoutSeconds 300
    Assert-ProcessSuccess -Result $render -Operation 'Packer Windows variable rendering'
    $varFile = Join-Path $stageRoot 'rocky-10.2.auto.pkrvars.hcl'

    $validate = Invoke-BoundedProcess -FilePath $packer -Arguments @('validate', "-var-file=$varFile", $sourceRoot) -TimeoutSeconds 120 -WorkingDirectory $stageRoot
    Assert-ProcessSuccess -Result $validate -Operation 'packer validate'
    $evidence.packer_validate = 'PASS'

    $build = Invoke-BoundedProcess -FilePath $packer -Arguments @('build', '-only=rocky-10.2-base.virtualbox-iso.base', "-var-file=$varFile", '-var=image_profile=rke2', $sourceRoot) -TimeoutSeconds 7200 -WorkingDirectory $stageRoot
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

if ($buildCompleted -and $cleanupStatus -ne 'FAIL') {
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
