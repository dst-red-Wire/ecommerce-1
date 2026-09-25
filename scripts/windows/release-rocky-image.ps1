[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [Parameter(Mandatory = $true)][string]$WslDistribution,
    [Parameter(Mandatory = $true)][string]$WslRepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
Set-PipelineUtf8

$root = $null
$artifactRoot = $null
$evidenceRoot = $null
$evidence = [ordered]@{
    schema = 1
    image = 'rocky-10.2'
    artifact = 'rocky-10.2-rke2-virtualbox.box'
    artifact_sha256 = $null
    source_sha = $null
    status = 'FAIL'
    remote_publication = 'NOT_PERFORMED'
    checks = [ordered]@{
        preflight = 'NOT_EXECUTED'
        exact_source_sha = 'NOT_EXECUTED'
        clean_source = 'NOT_EXECUTED'
        build_evidence = 'NOT_EXECUTED'
        checksum = 'NOT_EXECUTED'
        qualification_evidence = 'NOT_EXECUTED'
        cleanup = 'NOT_EXECUTED'
        ephemeral_key_absent = 'NOT_EXECUTED'
        sbom = 'NOT_EXECUTED'
        package_manifest = 'NOT_EXECUTED'
        profile_inventory = 'NOT_EXECUTED'
    }
    completed_at = $null
    error = $null
}

try {
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    $artifactRoot = Join-Path $root '.artifacts\packer\rocky-10.2\windows'
    $evidenceRoot = Join-Path $root '.context\evidence\rocky-image\rocky-10.2\windows'
    [void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
    $preflightPath = Join-Path $evidenceRoot 'preflight.json'
    $preflight = Invoke-BoundedProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $PSScriptRoot 'packer-preflight.ps1'),
        '-RepoRoot', $root,
        '-WslDistribution', $WslDistribution,
        '-WslRepoRoot', $WslRepoRoot,
        '-EvidencePath', $preflightPath
    ) -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $preflight -Operation 'Windows release preflight'
    if ((Read-JsonFile $preflightPath).status -ne 'PASS') {
        throw 'Release preflight evidence is not PASS'
    }
    $evidence.checks.preflight = 'PASS'

    $build = Read-JsonFile (Join-Path $evidenceRoot 'build.json')
    foreach ($field in @('preflight', 'packer_init', 'packer_fmt', 'packer_validate', 'packer_build', 'checksum', 'cleanup')) {
        if ($build.$field -ne 'PASS' -and -not ($field -eq 'cleanup' -and $build.$field -eq 'NOT_NEEDED')) {
            throw "Build evidence field is not PASS: $field"
        }
    }
    if ($build.status -ne 'PASS') {
        throw 'Build evidence status is not PASS'
    }
    $evidence.checks.build_evidence = 'PASS'
    $evidence.source_sha = [string]$build.source_sha

    $gitState = Get-GitState -Distribution $WslDistribution -WslRepoRoot $WslRepoRoot
    if (-not $gitState.Clean -or $build.source_clean -ne $true) {
        throw 'Release requires build evidence from a clean worktree'
    }
    $evidence.checks.clean_source = 'PASS'
    if ($gitState.Head -ne [string]$build.source_sha) {
        throw 'Release candidate source SHA differs from the current exact SHA'
    }
    $evidence.checks.exact_source_sha = 'PASS'

    $artifact = Join-Path $artifactRoot 'rocky-10.2-rke2-virtualbox.box'
    $sha256 = Get-FileSha256 -Path $artifact
    $checksumLine = [System.IO.File]::ReadAllText((Join-Path $artifactRoot 'SHA256SUMS'), [System.Text.Encoding]::UTF8).Trim()
    if ($sha256 -ne [string]$build.sha256 -or $checksumLine -ne "$sha256  rocky-10.2-rke2-virtualbox.box") {
        throw 'Release artifact checksum does not match its build evidence and checksum manifest'
    }
    $evidence.artifact_sha256 = $sha256
    $evidence.checks.checksum = 'PASS'

    $qualification = Read-JsonFile (Join-Path $evidenceRoot 'qualification.json')
    if ($qualification.status -ne 'PASS' -or [string]$qualification.artifact_sha256 -ne $sha256) {
        throw 'Qualification evidence is not PASS for the exact artifact SHA-256'
    }
    foreach ($field in @('preflight', 'checksum', 'box_add', 'boot', 'ssh', 'rocky_release', 'kernel', 'architecture_cpu', 'systemd', 'disk', 'network', 'fundamental_tools', 'rke2_prerequisites', 'security')) {
        if ($qualification.qualification.$field -ne 'PASS') {
            throw "Qualification evidence field is not PASS: $field"
        }
    }
    $evidence.checks.qualification_evidence = 'PASS'
    $packageLock = Read-JsonFile (Join-Path $root 'config\artifacts\rocky-10.2-base-packages.lock.json')
    $requiredPackages = @($packageLock.profiles.base.roots) + @($packageLock.profiles.rke2.roots)
    Assert-ImageSupplyChainEvidence -Evidence $qualification.supply_chain -ArtifactSha256 $sha256 -RequiredPackages $requiredPackages
    $evidence.checks.sbom = 'PASS'
    $evidence.checks.package_manifest = 'PASS'
    $evidence.checks.profile_inventory = 'PASS'
    if ($qualification.qualification.cleanup -ne 'PASS' -or $qualification.qualification.key_cleanup -ne 'PASS') {
        throw 'Qualification cleanup evidence is not PASS'
    }
    $evidence.checks.cleanup = 'PASS'

    $pipelineRoot = Get-LocalPipelineRoot
    $keyRoot = Join-Path $pipelineRoot 'keys'
    $privateKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$sha256.key")
    $publicKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$sha256.key.pub")
    if ((Test-Path -LiteralPath $privateKey) -or (Test-Path -LiteralPath $publicKey)) {
        throw 'Ephemeral qualification key remains present; release is forbidden'
    }
    $evidence.checks.ephemeral_key_absent = 'PASS'
    $evidence.status = 'PASS'
}
catch {
    $evidence.error = $_.Exception.Message
}

$evidence.completed_at = [DateTime]::UtcNow.ToString('o')
if ($null -ne $evidenceRoot) {
    Write-Utf8Json -InputObject $evidence -Path (Join-Path $evidenceRoot 'release.json')
}
if ($evidence.status -eq 'PASS') {
    [Console]::WriteLine("PASS rocky-image-release sha256=$($evidence.artifact_sha256) publication=NOT_PERFORMED")
    exit 0
}
[Console]::Error.WriteLine("FAIL rocky-image-release: $($evidence.error)")
exit 1
