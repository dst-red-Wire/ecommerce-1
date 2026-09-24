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
$pipelineRoot = $null
$stageRoot = $null
$vagrant = $null
$vbox = $null
$environment = @{}
$initialMachines = @{}
$vmName = $null
$boxName = $null
$privateKey = $null
$publicKey = $null
$qualificationPassed = $false
$evidence = [ordered]@{
    schema = 1
    image = 'rocky-10.2'
    artifact = 'rocky-10.2-rke2-virtualbox.box'
    artifact_sha256 = $null
    source_sha = $null
    status = 'FAIL'
    qualification = [ordered]@{
        preflight = 'NOT_EXECUTED'
        checksum = 'NOT_EXECUTED'
        box_add = 'NOT_EXECUTED'
        boot = 'NOT_EXECUTED'
        ssh = 'NOT_EXECUTED'
        rocky_release = 'NOT_EXECUTED'
        kernel = 'NOT_EXECUTED'
        architecture_cpu = 'NOT_EXECUTED'
        systemd = 'NOT_EXECUTED'
        disk = 'NOT_EXECUTED'
        network = 'NOT_EXECUTED'
        fundamental_tools = 'NOT_EXECUTED'
        rke2_prerequisites = 'NOT_EXECUTED'
        security = 'NOT_EXECUTED'
        cleanup = 'NOT_EXECUTED'
        key_cleanup = 'NOT_EXECUTED'
    }
    observations = [ordered]@{}
    started_at = [DateTime]::UtcNow.ToString('o')
    completed_at = $null
    error = $null
}

function Invoke-SmokeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$TimeoutSeconds = 120
    )
    $result = Invoke-BoundedProcess -FilePath $script:vagrant -Arguments @('ssh', '-c', $Command) -TimeoutSeconds $TimeoutSeconds -WorkingDirectory $script:stageRoot -Environment $script:environment
    Assert-ProcessSuccess -Result $result -Operation "Vagrant smoke check $Name"
    $script:evidence.qualification[$Name] = 'PASS'
    return $result.StdOut.Trim()
}

try {
    if ($WslDistribution -notmatch '^[A-Za-z0-9._-]+$' -or -not $WslRepoRoot.StartsWith('/')) {
        throw 'Invalid WSL distribution or repository path'
    }
    $root = Get-RepositoryRoot -RequestedRoot $RepoRoot
    $artifactRoot = Join-Path $root '.artifacts\packer\rocky-10.2\windows'
    $evidenceRoot = Join-Path $root '.context\evidence\rocky-image\rocky-10.2\windows'
    [void](New-Item -ItemType Directory -Path $evidenceRoot -Force)
    $buildEvidencePath = Join-Path $evidenceRoot 'build.json'
    $buildEvidence = Read-JsonFile $buildEvidencePath
    if ($buildEvidence.status -ne 'PASS' -or $buildEvidence.packer_build -ne 'PASS' -or $buildEvidence.checksum -ne 'PASS') {
        throw 'Build evidence is absent or not PASS'
    }
    $evidence.source_sha = [string]$buildEvidence.source_sha
    $artifact = Join-Path $artifactRoot 'rocky-10.2-rke2-virtualbox.box'
    $actualSha256 = Get-FileSha256 -Path $artifact
    if ($actualSha256 -ne [string]$buildEvidence.sha256) {
        throw 'Artifact SHA-256 does not match build evidence'
    }
    $evidence.artifact_sha256 = $actualSha256
    $evidence.qualification.checksum = 'PASS'

    $preflightEvidence = Join-Path $evidenceRoot 'preflight.json'
    $preflight = Invoke-BoundedProcess -FilePath 'powershell.exe' -Arguments @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $PSScriptRoot 'packer-preflight.ps1'),
        '-RepoRoot', $root,
        '-WslDistribution', $WslDistribution,
        '-WslRepoRoot', $WslRepoRoot,
        '-EvidencePath', $preflightEvidence
    ) -TimeoutSeconds 60 -WorkingDirectory $env:SystemRoot
    Assert-ProcessSuccess -Result $preflight -Operation 'Windows image qualification preflight'
    $preflightDocument = Read-JsonFile $preflightEvidence
    if ($preflightDocument.status -ne 'PASS') {
        throw 'Windows image qualification preflight evidence is not PASS'
    }
    $evidence.qualification.preflight = 'PASS'
    $vagrant = [string]$preflightDocument.tools.vagrant.executable
    $vbox = [string]$preflightDocument.tools.virtualbox.executable

    $pipelineRoot = Get-LocalPipelineRoot
    [void](New-Item -ItemType Directory -Path $pipelineRoot -Force)
    $keyRoot = Join-Path $pipelineRoot 'keys'
    $privateKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$actualSha256.key")
    $publicKey = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath (Join-Path $keyRoot "$actualSha256.key.pub")
    if (-not (Test-Path -LiteralPath $privateKey -PathType Leaf) -or -not (Test-Path -LiteralPath $publicKey -PathType Leaf)) {
        throw 'Ephemeral qualification key is missing; rebuild the image candidate'
    }

    $stageRoot = Join-Path $pipelineRoot ("qualify-{0}-{1}" -f $actualSha256.Substring(0, 12), [Guid]::NewGuid().ToString('N'))
    $stageRoot = Assert-SafeChildPath -BasePath $pipelineRoot -CandidatePath $stageRoot
    [void](New-Item -ItemType Directory -Path $stageRoot)
    Copy-Item -LiteralPath (Join-Path $root 'platform\vagrant\rocky-image-smoke\Vagrantfile') -Destination $stageRoot
    $vmName = "ecommerce-rocky-10-2-smoke-$($actualSha256.Substring(0, 12))"
    $boxName = "ecommerce/rocky-10.2-rke2-$($actualSha256.Substring(0, 12))"
    $runtime = [ordered]@{
        name = $vmName
        box_name = $boxName
        vagrant_version = [string]$preflightDocument.tools.vagrant.actual_version
        private_key = $privateKey
        boot_timeout_seconds = 900
        ssh_timeout_seconds = 30
        cpus = 2
        memory_mib = 4096
    }
    Write-Utf8Json -InputObject $runtime -Path (Join-Path $stageRoot 'runtime.json')
    $environment = @{
        VAGRANT_HOME = (Join-Path $stageRoot 'vagrant-home')
        VAGRANT_CHECKPOINT_DISABLE = '1'
        VAGRANT_DEFAULT_PROVIDER = 'virtualbox'
        VAGRANT_NO_PLUGINS = '1'
    }
    $initialMachines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $stageRoot
    if ($initialMachines.ContainsKey($vmName)) {
        throw "Refusing qualification because the deterministic smoke VM already exists: $vmName"
    }

    $boxAdd = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box', 'add', '--name', $boxName, '--provider', 'virtualbox', '--checksum-type', 'sha256', '--checksum', $actualSha256, $artifact) -TimeoutSeconds 600 -WorkingDirectory $stageRoot -Environment $environment
    Assert-ProcessSuccess -Result $boxAdd -Operation 'Vagrant local box add'
    $evidence.qualification.box_add = 'PASS'

    $up = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('up', '--provider', 'virtualbox', '--no-provision') -TimeoutSeconds 900 -WorkingDirectory $stageRoot -Environment $environment
    Assert-ProcessSuccess -Result $up -Operation 'Vagrant smoke VM boot'
    $evidence.qualification.boot = 'PASS'

    $sshReady = $false
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $probe = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('ssh', '-c', 'true') -TimeoutSeconds 30 -WorkingDirectory $stageRoot -Environment $environment
        if ($probe.ExitCode -eq 0) {
            $sshReady = $true
            break
        }
        if ($attempt -lt 12) {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $sshReady) {
        throw 'Vagrant SSH did not become ready within 12 bounded attempts'
    }
    $evidence.qualification.ssh = 'PASS'

    $release = Invoke-SmokeCommand -Name 'rocky_release' -Command "grep -Fx 'Rocky Linux release 10.2 (Red Quartz)' /etc/rocky-release"
    $evidence.observations.rocky_release = $release
    $kernel = Invoke-SmokeCommand -Name 'kernel' -Command 'uname -r'
    $evidence.observations.kernel = $kernel
    $architecture = Invoke-SmokeCommand -Name 'architecture_cpu' -Command "test \"`$(uname -m)\" = x86_64 && test \"`$(getconf _NPROCESSORS_ONLN)\" -ge 2 && uname -m && getconf _NPROCESSORS_ONLN"
    $evidence.observations.architecture_cpu = $architecture
    $systemd = Invoke-SmokeCommand -Name 'systemd' -Command "state=`$(systemctl is-system-running --wait || true); test \"`$state\" = running; test -z \"`$(systemctl --failed --no-legend --plain)\"; printf '%s' \"`$state\""
    $evidence.observations.systemd = $systemd
    $disk = Invoke-SmokeCommand -Name 'disk' -Command "available=`$(df --output=avail -BM / | tail -1 | tr -dc '0-9'); test \"`$available\" -ge 1024; printf '%s MiB' \"`$available\""
    $evidence.observations.disk_available = $disk
    $network = Invoke-SmokeCommand -Name 'network' -Command "ip -4 -o addr show scope global | grep -q .; ip -4 route show default | grep -q '^default '; ip -4 -o addr show scope global; ip -4 route show default"
    $evidence.observations.network = $network
    $tools = Invoke-SmokeCommand -Name 'fundamental_tools' -Command "for tool in python3 curl tar gzip xz zstd rsync unzip openssl nft ip ss systemctl; do command -v \"`$tool\" >/dev/null; done; printf 'required-tools-present'"
    $evidence.observations.fundamental_tools = $tools
    $rke2 = Invoke-SmokeCommand -Name 'rke2_prerequisites' -Command "test -z \"`$(swapon --noheadings --show)\"; test \"`$(stat -fc %T /sys/fs/cgroup)\" = cgroup2fs; for module in overlay br_netfilter nf_conntrack vxlan; do sudo -n modprobe \"`$module\"; done; test \"`$(sysctl -n net.ipv4.ip_forward)\" = 1; test \"`$(sysctl -n net.bridge.bridge-nf-call-iptables)\" = 1; test -d /sys/fs/bpf; printf 'rke2-prerequisites-present'"
    $evidence.observations.rke2_prerequisites = $rke2
    $security = Invoke-SmokeCommand -Name 'security' -Command "test \"`$(getenforce)\" = Enforcing; sudo -n sshd -T | grep -qx 'permitrootlogin no'; sudo -n sshd -T | grep -qx 'passwordauthentication no'; command -v oscap >/dev/null; test -r /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml; test ! -e /root/.config/gh/hosts.yml; test ! -e /etc/rancher/rke2/config.yaml; printf 'security-baseline-present'"
    $evidence.observations.security = $security
    $qualificationPassed = $true
}
catch {
    $evidence.error = $_.Exception.Message
}

$cleanupFailed = $false
if ($null -ne $vagrant -and $null -ne $stageRoot -and (Test-Path -LiteralPath $stageRoot -PathType Container)) {
    try {
        $destroy = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('destroy', '--force') -TimeoutSeconds 300 -WorkingDirectory $stageRoot -Environment $environment
        if ($destroy.ExitCode -ne 0 -and $null -ne $vbox -and $null -ne $vmName) {
            [void](Remove-OwnedVirtualMachine -Name $vmName -InitialMachines $initialMachines -VBoxManage $vbox -WorkingDirectory $stageRoot)
        }
        if ($null -ne $boxName) {
            $boxRemove = Invoke-BoundedProcess -FilePath $vagrant -Arguments @('box', 'remove', '--force', $boxName) -TimeoutSeconds 300 -WorkingDirectory $stageRoot -Environment $environment
            if ($boxRemove.ExitCode -ne 0 -and $evidence.qualification.box_add -eq 'PASS') {
                throw 'Failed to remove the isolated Vagrant box'
            }
        }
        if ($null -ne $vbox -and $null -ne $vmName) {
            $remaining = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $stageRoot
            if ($remaining.ContainsKey($vmName)) {
                throw "Owned smoke VM remains registered after cleanup: $vmName"
            }
        }
        $evidence.qualification.cleanup = 'PASS'
    }
    catch {
        $cleanupFailed = $true
        $evidence.qualification.cleanup = 'FAIL'
        if ($null -eq $evidence.error) { $evidence.error = $_.Exception.Message }
    }
}

try {
    foreach ($keyPath in @($privateKey, $publicKey)) {
        if ($null -ne $keyPath -and (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
            Remove-Item -LiteralPath $keyPath -Force
        }
    }
    $evidence.qualification.key_cleanup = 'PASS'
}
catch {
    $cleanupFailed = $true
    $evidence.qualification.key_cleanup = 'FAIL'
    if ($null -eq $evidence.error) { $evidence.error = $_.Exception.Message }
}

if ($null -ne $pipelineRoot -and $null -ne $stageRoot) {
    try { Remove-SafeTree -BasePath $pipelineRoot -CandidatePath $stageRoot } catch {
        $cleanupFailed = $true
        $evidence.qualification.cleanup = 'FAIL'
        if ($null -eq $evidence.error) { $evidence.error = $_.Exception.Message }
    }
}

if ($qualificationPassed -and -not $cleanupFailed -and $evidence.qualification.cleanup -eq 'PASS' -and $evidence.qualification.key_cleanup -eq 'PASS') {
    $evidence.status = 'PASS'
}
$evidence.completed_at = [DateTime]::UtcNow.ToString('o')
if ($null -ne $evidenceRoot) {
    Write-Utf8Json -InputObject $evidence -Path (Join-Path $evidenceRoot 'qualification.json')
}
if ($evidence.status -eq 'PASS') {
    [Console]::WriteLine("PASS rocky-image-qualification sha256=$($evidence.artifact_sha256)")
    exit 0
}
[Console]::Error.WriteLine("FAIL rocky-image-qualification: $($evidence.error)")
exit 1
