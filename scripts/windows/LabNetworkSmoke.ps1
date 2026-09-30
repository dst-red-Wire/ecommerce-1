[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Run', 'Resume', 'Clean', 'SelfTest')][string]$Action,
    [Parameter(Mandatory = $true)][string]$StageRoot,
    [string]$RunnerSourceSha = '',
    [string]$ShadowRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NativeShadowLayout {
    param([string]$Root, [string]$Stage, [string]$Sha, [string]$Runner)
    $campaign = [IO.Path]::GetFileName([IO.Path]::GetFullPath($Stage).TrimEnd('\'))
    if ($campaign -notmatch '^\d{8}T\d{6}Z-[0-9a-f]{12}$' -or $Sha -notmatch '^[0-9a-f]{40}$') {
        throw 'Native shadow requires an exact campaign and source SHA'
    }
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not $programFiles) { throw 'Native shadow requires the Windows Program Files root' }
    $expected = [IO.Path]::GetFullPath((Join-Path (Join-Path $programFiles 'EcommerceNativeSmoke') "$campaign-$Sha")).TrimEnd('\')
    $actual = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $expectedStage = [IO.Path]::GetFullPath((Join-Path $expected $campaign)).TrimEnd('\')
    $expectedRunner = [IO.Path]::GetFullPath((Join-Path $expected "runner-$Sha\scripts\windows")).TrimEnd('\')
    if ($actual -ine $expected -or [IO.Path]::GetFullPath($Stage).TrimEnd('\') -ine $expectedStage -or
        [IO.Path]::GetFullPath($Runner).TrimEnd('\') -ine $expectedRunner) {
        throw 'Native Resume runner, stage or shadow root differs from the exact protected layout'
    }
    return $actual
}

$shadow = ''
if ($Action -eq 'Resume') {
    $shadow = Assert-NativeShadowLayout -Root $ShadowRoot -Stage $StageRoot -Sha $RunnerSourceSha -Runner $PSScriptRoot
}
elseif ($ShadowRoot) { throw 'ShadowRoot is valid only for native Resume' }

Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force
. (Join-Path $PSScriptRoot 'NativeVagrantSshSmoke.ps1')
. (Join-Path $PSScriptRoot 'LabNetworkSeed.ps1')
Set-PipelineUtf8

function Assert-LabStage {
    param([string]$Root, [string]$ProtectedRoot = '')
    $stage = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $base = if ($ProtectedRoot) { [IO.Path]::GetFullPath($ProtectedRoot).TrimEnd('\') + '\' }
            else { [IO.Path]::GetFullPath('C:\ecommerce-lab\network-smoke').TrimEnd('\') + '\' }
    if (-not $stage.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Network smoke stage is outside the governed runtime path'
    }
    $manifest = Join-Path $stage 'SHA256SUMS'
    foreach ($path in @($base.TrimEnd('\'), $stage, $manifest)) {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Network smoke stage traverses a reparse point: $path"
        }
    }
    foreach ($line in [IO.File]::ReadAllLines($manifest, [Text.Encoding]::UTF8)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$') { throw 'Network smoke staging manifest is invalid' }
        $expected = $Matches[1]
        $relative = $Matches[2]
        $candidate = [IO.Path]::GetFullPath((Join-Path $stage $relative.Replace('/', '\')))
        if (-not $candidate.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Network smoke staged input escapes its campaign: $relative"
        }
        $ancestor = $candidate
        while ($ancestor.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $item = Get-Item -LiteralPath $ancestor -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Network smoke staged input traverses a reparse point: $relative"
            }
            $ancestor = Split-Path -Parent $ancestor
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
            (Get-FileSha256 -Path $candidate) -ne $expected) {
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

function Assert-LabGuestSecurity {
    param([string]$SshExecutable, [object]$Network, [string]$PrivateKey, [string]$WorkingDirectory)
    $security = Invoke-NativeDirectSshProbe -SshExecutable $SshExecutable -Address $Network.address -Port $Network.port -User $Network.user -PrivateKey $PrivateKey -WorkingDirectory $WorkingDirectory -TimeoutSeconds 30 -Command 'test "$(stat -c %a ~/.ssh)" = 700 && test "$(stat -c %a ~/.ssh/authorized_keys)" = 600 && test "$(stat -c %U ~/.ssh/authorized_keys)" = packer && sudo -n sshd -T | grep -qx "pubkeyauthentication yes" && { sudo -n grep -R -l "BEGIN OPENSSH PRIVATE KEY" /home/packer /root >/dev/null 2>&1; test $? -eq 1; }'
    Assert-ProcessSuccess -Result $security -Operation 'guest SSH key ownership, mode, cloud-init and sshd security'
}

function Invoke-LabImageProbe {
    param(
        [System.Collections.IDictionary]$Qualification,
        [string]$Name, [string]$Command,
        [string]$SshExecutable, [object]$Network,
        [string]$PrivateKey, [string]$WorkingDirectory
    )
    $commandText = "set -eu; set -o pipefail; $Command"
    try {
        $probe = Invoke-NativeDirectSshProbe -SshExecutable $SshExecutable -Address $Network.address -Port $Network.port -User $Network.user -PrivateKey $PrivateKey -WorkingDirectory $WorkingDirectory -TimeoutSeconds 45 -Command $commandText
    }
    catch {
        $Qualification.checks[$Name] = 'FAIL'
        $message = [string]$_.Exception.Message
        $Qualification.observations[$Name] = [ordered]@{
            status='FAIL'; exit_code=$null; stdout=''; stderr=$message.Substring(0,[Math]::Min(1024,$message.Length))
            stdout_truncated=$false
        }
        throw
    }
    $stdout = [string]$probe.StdOut
    $stderr = [string]$probe.StdErr
    $passed = $probe.ExitCode -eq 0
    $Qualification.checks[$Name] = if ($passed) { 'PASS' } else { 'FAIL' }
    $Qualification.observations[$Name] = [ordered]@{
        status=if ($passed) { 'PASS' } else { 'FAIL' }
        exit_code=[int]$probe.ExitCode
        stdout=$stdout.Substring(0,[Math]::Min(4096,$stdout.Length))
        stderr=$stderr.Substring(0,[Math]::Min(1024,$stderr.Length))
        stdout_truncated=$stdout.Length -gt 4096
    }
    if (-not $passed) { throw "Native image qualification probe failed: $Name (exit $($probe.ExitCode))" }
    return $stdout.Trim()
}

function Invoke-LabImageQualification {
    param(
        [string]$SshExecutable, [object]$Network, [string]$PrivateKey,
        [string]$WorkingDirectory, [string]$PackageLockPath,
        [string]$SourceSha, [string]$SourceTreeSha, [string]$BoxSha256,
        [string]$VmId, [string]$VirtualBoxBackend,
        [string]$VirtualBoxLogRelative, [string]$VirtualBoxLogSha256
    )
    $qualification = [ordered]@{
        status='FAIL'; source_sha=$SourceSha; source_tree_sha=$SourceTreeSha
        box_sha256=$BoxSha256; vm_id=$VmId; virtualbox_backend=$VirtualBoxBackend
        virtualbox_log_relative=$VirtualBoxLogRelative
        virtualbox_log_sha256=$VirtualBoxLogSha256
        package_lock_sha256=(Get-FileSha256 -Path $PackageLockPath)
        checks=[ordered]@{}; observations=[ordered]@{}; supply_chain=$null
        started_at=[DateTime]::UtcNow.ToString('o'); completed_at=$null; error=$null
    }
    try {
        if ($VirtualBoxBackend -cne 'NATIVE_VTX' -or
            $VirtualBoxLogSha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Native image qualification requires observed VT-x and its protected log digest'
        }
        $packageLock = Read-JsonFile $PackageLockPath
        $packages = @($packageLock.profiles.base.roots) + @($packageLock.profiles.rke2.roots)
        if ($packages.Count -lt 10 -or
            @($packages | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[A-Za-z0-9+_.][A-Za-z0-9+_.-]*$' }).Count -gt 0 -or
            @($packages | Sort-Object -Unique).Count -ne $packages.Count) {
            throw 'Native image qualification RKE2 package roots are invalid'
        }
        $parameters = @{
            Qualification=$qualification; SshExecutable=$SshExecutable
            Network=$Network; PrivateKey=$PrivateKey; WorkingDirectory=$WorkingDirectory
        }
        $checks = @(
            @{ Name='rocky_release'; Command='grep -Fx ''Rocky Linux release 10.2 (Red Quartz)'' /etc/rocky-release' }
            @{ Name='kernel'; Command='kernel=$(uname -r); test -n "$kernel"; printf ''%s\n'' "$kernel"' }
            @{ Name='architecture_cpu'; Command='arch=$(uname -m); cpus=$(getconf _NPROCESSORS_ONLN); test "$arch" = x86_64; test "$cpus" -eq 4; printf ''%s %s\n'' "$arch" "$cpus"' }
            @{ Name='memory'; Command='memory=$(awk ''$1 == "MemTotal:" {print $2}'' /proc/meminfo); test -n "$memory"; test "$memory" -ge 3500000; printf ''%s KiB\n'' "$memory"' }
            @{ Name='disk'; Command='size=$(lsblk -b -dn -o SIZE /dev/sda); test "$size" -ge 34359738368; printf ''%s bytes\n'' "$size"' }
            @{ Name='xfs'; Command='filesystem=$(findmnt -n -o FSTYPE /); test "$filesystem" = xfs; printf ''%s\n'' "$filesystem"' }
            @{ Name='lvm_absent'; Command='types=$(lsblk -n -o TYPE); ! printf ''%s\n'' "$types" | grep -qx lvm; printf ''no-lvm\n''' }
            @{ Name='swap_absent'; Command='swap=$(swapon --noheadings --show); test -z "$swap"; printf ''no-swap\n''' }
            @{ Name='systemd'; Command='state=$(systemctl is-system-running --wait); test "$state" = running; failed=$(systemctl --failed --no-legend --plain); test -z "$failed"; printf ''%s\n'' "$state"' }
            @{ Name='network'; Command='addresses=$(ip -4 -o addr show scope global); test -n "$addresses"; gateway=$(ip -4 route show default); test -n "$gateway"; printf ''%s\n%s\n'' "$addresses" "$gateway"' }
            @{ Name='fundamental_tools'; Command='for tool in python3 curl tar gzip xz zstd rsync unzip openssl nft ip ss systemctl; do command -v "$tool" >/dev/null; done; printf ''required-tools-present\n''' }
            @{ Name='rke2_prerequisites'; Command='test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs; for module in overlay br_netfilter nf_conntrack vxlan; do sudo -n modprobe "$module"; done; test "$(sysctl -n net.ipv4.ip_forward)" = 1; test "$(sysctl -n net.bridge.bridge-nf-call-iptables)" = 1; test -d /sys/fs/bpf; printf ''rke2-prerequisites-present\n''' }
            @{ Name='security'; Command='cloud-init status --wait >/dev/null; test "$(getenforce)" = Enforcing; settings=$(sudo -n sshd -T); printf ''%s\n'' "$settings" | grep -x "permitrootlogin no" >/dev/null; printf ''%s\n'' "$settings" | grep -x "passwordauthentication no" >/dev/null; printf ''%s\n'' "$settings" | grep -x "pubkeyauthentication yes" >/dev/null; command -v oscap >/dev/null; test -r /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml; sudo -n test ! -e /root/.config/gh/hosts.yml; sudo -n test ! -e /etc/rancher/rke2/config.yaml; if sudo -n grep -R -l "BEGIN OPENSSH PRIVATE KEY" /home/packer /root >/dev/null 2>&1; then exit 1; else test "$?" -eq 1; fi; printf ''security-baseline-present\n''' }
        )
        foreach ($check in $checks) {
            [void](Invoke-LabImageProbe @parameters -Name $check.Name -Command $check.Command)
        }
        $profileCommand = 'rpm -q ' + ($packages -join ' ')
        [void](Invoke-LabImageProbe @parameters -Name 'rpm_profile' -Command $profileCommand)
        $inventory = Invoke-LabImageProbe @parameters -Name 'package_inventory' -Command 'rpm -qa --qf ''%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'' | LC_ALL=C sort'
        $qualification.checks.supply_chain = 'FAIL'
        $qualification.supply_chain = New-ImageSupplyChainEvidence -ArtifactSha256 $BoxSha256 -RpmInventory $inventory -RequiredPackages $packages
        Assert-ImageSupplyChainEvidence -Evidence $qualification.supply_chain -ArtifactSha256 $BoxSha256 -RequiredPackages $packages
        $qualification.checks.supply_chain = 'PASS'
        $qualification.observations.supply_chain = [ordered]@{
            status='PASS'; exit_code=0
            stdout="packages=$(@($qualification.supply_chain.package_manifest.packages).Count) artifact_sha256=$BoxSha256"
            stderr=''; stdout_truncated=$false
        }
        $qualification.status = 'PASS'
    }
    catch {
        $qualification.error = [string]$_.Exception.Message
        if (-not $qualification.checks.Contains('supply_chain')) {
            $qualification.checks.supply_chain = 'NOT_EXECUTED'
        }
        elseif ($qualification.checks.supply_chain -eq 'FAIL') {
            $message = $qualification.error
            $qualification.observations.supply_chain = [ordered]@{
                status='FAIL'; exit_code=$null; stdout=''
                stderr=$message.Substring(0,[Math]::Min(1024,$message.Length))
                stdout_truncated=$false
            }
        }
    }
    $qualification.completed_at = [DateTime]::UtcNow.ToString('o')
    return $qualification
}

function Assert-NativeBootLeaseState {
    param($State, [string]$Operation, [string]$Id, [string]$Sha, [string]$OwnerSid, [bool]$HypervisorPresent)
    if ($null -eq $State -or $State.schema -ne 1 -or $State.mode -ne 'NETWORK_SMOKE_NATIVE' -or
        $State.phase -notin @('PREPARED','BOOT_PENDING','RUNNING','RETURN_PENDING','FAILED','RECOVERED') -or
        [string]$State.campaign_id -notmatch '^\d{8}T\d{6}Z-[0-9a-f]{12}$' -or
        [string]$State.source_sha -notmatch '^[0-9a-f]{40}$' -or
        [string]$State.owner_sid -notmatch '^S-\d+(?:-\d+)+$') {
        throw 'BLOCKED_RUNTIME native smoke boot lease is invalid'
    }
    if ($State.phase -eq 'RECOVERED' -and $Operation -ne 'Resume') { return }
    if ($Operation -eq 'Resume' -and $State.phase -eq 'RUNNING' -and
        $State.campaign_id -eq $Id -and $State.source_sha -eq $Sha -and
        $State.owner_sid -eq $OwnerSid -and -not $HypervisorPresent) {
        return
    }
    throw "BLOCKED_RUNTIME native smoke boot lease is active: $($State.phase)"
}

function Assert-NativeShadowInput {
    param([string]$Root, [string]$Path)
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not $candidate.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Native shadow input escapes the protected root: $Path"
    }
    while ($candidate.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $candidate -ieq $base) {
        $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Native shadow input traverses a reparse point: $Path"
        }
        if ($candidate -ieq $base) { break }
        $candidate = Split-Path -Parent $candidate
    }
}

function New-NativeProtectedEvidenceAcl {
    param([bool]$Directory = $false)
    $admin = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
    $system = [Security.Principal.SecurityIdentifier]'S-1-5-18'
    $users = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
    $ownerRights = [Security.Principal.SecurityIdentifier]'S-1-3-4'
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity }
           else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($admin)
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($entry in @(
        @($admin,[Security.AccessControl.FileSystemRights]::FullControl),
        @($system,[Security.AccessControl.FileSystemRights]::FullControl),
        @($users,[Security.AccessControl.FileSystemRights]::ReadAndExecute),
        @($ownerRights,[Security.AccessControl.FileSystemRights]::ReadAndExecute)
    )) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $entry[0],$entry[1],$inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-NativeProtectedEvidenceAcl {
    param([string]$Path, [bool]$Directory = $false)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Native proof is redirected or has the wrong type: $Path"
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $expected = @{
        'S-1-5-32-544'=[Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-18'=[Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-545'=([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize)
        'S-1-3-4'=([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize)
    }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or
        -not $acl.AreAccessRulesProtected) {
        throw "Native proof ACL owner or inheritance differs: $Path"
    }
    $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne $expected.Count) { throw "Native proof ACL rule set differs: $Path" }
    $inherit = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
               else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid) -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne $expected[$sid] -or
            $rule.InheritanceFlags -ne $inherit -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Native proof ACL grants unexpected rights: $Path"
        }
    }
}

function Write-NativeProtectedResult {
    param($InputObject, [string]$Path, [string]$Root)
    Assert-NativeShadowInput -Root $Root -Path $Path
    Assert-NativeProtectedEvidenceAcl -Path $Path
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $json = ($InputObject | ConvertTo-Json -Depth 20) + [Environment]::NewLine
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.File]::Create($temporary,4096,[IO.FileOptions]::None,(New-NativeProtectedEvidenceAcl))
    try {
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    try {
        Assert-NativeProtectedEvidenceAcl -Path $temporary
        [IO.File]::Replace($temporary,$Path,$null)
        Assert-NativeProtectedEvidenceAcl -Path $Path
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-NativeBootLease {
    param([string]$Operation, [string]$Id, [string]$Sha = '', [string]$ProtectedRoot = '')
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($ProtectedRoot) {
        $path = Join-Path $ProtectedRoot 'native-boot.json'
        Assert-NativeShadowInput -Root $ProtectedRoot -Path $path
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'BLOCKED_RUNTIME protected native smoke boot lease is not a regular file'
        }
        $state = Read-JsonFile $path
        Assert-NativeBootLeaseState -State $state -Operation $Operation -Id $Id -Sha $Sha -OwnerSid $ownerSid -HypervisorPresent ([bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent)
        if ([IO.Path]::GetFullPath([string]$state.shadow_root).TrimEnd('\') -ine $ProtectedRoot) {
            throw 'BLOCKED_RUNTIME protected native smoke boot lease has another shadow root'
        }
        return $state
    }
    $legacy = 'C:\ecommerce-lab\network-smoke\native-boot.json'
    if (Test-Path -LiteralPath $legacy) {
        $item = Get-Item -LiteralPath $legacy -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'BLOCKED_RUNTIME legacy native smoke boot lease is not a regular file'
        }
        $oldState = Read-JsonFile $legacy
        Assert-NativeBootLeaseState -State $oldState -Operation 'Run' -Id $Id -Sha '' -OwnerSid $ownerSid -HypervisorPresent $false
    }
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $shadowBase = Join-Path $programFiles 'EcommerceNativeSmoke'
    if (-not (Test-Path -LiteralPath $shadowBase)) { return }
    $baseItem = Get-Item -LiteralPath $shadowBase -ErrorAction Stop
    if (-not $baseItem.PSIsContainer -or ($baseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'BLOCKED_RUNTIME protected native smoke root is invalid'
    }
    foreach ($directory in @(Get-ChildItem -LiteralPath $shadowBase -Directory -Force)) {
        if ($directory.Name -notmatch '^\d{8}T\d{6}Z-[0-9a-f]{12}-[0-9a-f]{40}$') { continue }
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'BLOCKED_RUNTIME protected native smoke campaign is a reparse point'
        }
        $path = Join-Path $directory.FullName 'native-boot.json'
        if (-not (Test-Path -LiteralPath $path)) {
            throw 'BLOCKED_RUNTIME protected native smoke campaign has no boot lease'
        }
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'BLOCKED_RUNTIME protected native smoke boot lease is not a regular file'
        }
        $state = Read-JsonFile $path
        Assert-NativeBootLeaseState -State $state -Operation $Operation -Id $Id -Sha $Sha -OwnerSid $ownerSid -HypervisorPresent $false
    }
}

function Invoke-NativeBootLeaseSelfTest {
    $id = '20260929T163821Z-9da62296f3d5'
    $sha = 'a' * 40
    $root = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'EcommerceNativeSmoke') "$id-$sha"
    $stage = Join-Path $root $id
    $runner = Join-Path $root "runner-$sha\scripts\windows"
    if ((Assert-NativeShadowLayout -Root $root -Stage $stage -Sha $sha -Runner $runner) -ine $root) {
        throw 'Native shadow layout did not accept the exact protected path'
    }
    foreach ($candidate in @(
        @{ Root='C:\ecommerce-lab\network-smoke'; Stage=$stage; Runner=$runner },
        @{ Root=$root; Stage='C:\ecommerce-lab\network-smoke\20260929T163821Z-9da62296f3d5'; Runner=$runner },
        @{ Root=$root; Stage=$stage; Runner='C:\ecommerce-lab\network-smoke\runner-unsafe\scripts\windows' }
    )) {
        $rejected = $false
        try { [void](Assert-NativeShadowLayout -Root $candidate.Root -Stage $candidate.Stage -Sha $sha -Runner $candidate.Runner) }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'Native shadow layout accepted an unprotected path' }
    }
    $ownerSid = 'S-1-5-21-111-222-333-1001'
    $state = [pscustomobject]@{
        schema=1; mode='NETWORK_SMOKE_NATIVE'; phase='RUNNING'
        campaign_id=$id; source_sha=$sha; owner_sid=$ownerSid
    }
    Assert-NativeBootLeaseState -State $state -Operation 'Resume' -Id $id -Sha $sha -OwnerSid $ownerSid -HypervisorPresent $false
    foreach ($case in @('Run','Clean','WrongSha','Hypervisor','MalformedRecovered')) {
        $state.phase = 'RUNNING'
        $state.owner_sid = $ownerSid
        $operation = 'Resume'; $candidateSha = $sha; $hypervisor = $false
        switch ($case) {
            Run { $operation = 'Run' }
            Clean { $operation = 'Clean' }
            WrongSha { $candidateSha = 'b' * 40 }
            Hypervisor { $hypervisor = $true }
            MalformedRecovered { $state.phase = 'RECOVERED'; $state.owner_sid = 'invalid' }
        }
        $rejected = $false
        try { Assert-NativeBootLeaseState -State $state -Operation $operation -Id $id -Sha $candidateSha -OwnerSid $ownerSid -HypervisorPresent $hypervisor }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Native boot lease accepted an unsafe fixture: $case" }
    }
    $state.phase = 'RECOVERED'; $state.owner_sid = $ownerSid
    Assert-NativeBootLeaseState -State $state -Operation 'Run' -Id $id -Sha '' -OwnerSid $ownerSid -HypervisorPresent $false
    $rejected = $false
    try { Assert-NativeBootLeaseState -State $state -Operation 'Resume' -Id $id -Sha $sha -OwnerSid $ownerSid -HypervisorPresent $false }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Native Resume accepted an already recovered lease' }
    function Invoke-NativeDirectSshProbe {
        param($SshExecutable, $Address, $Port, $User, $PrivateKey, $WorkingDirectory, $TimeoutSeconds, $Command)
        $stdout = if ($Command -like '*rpm -qa --qf*') { $script:ImageProbeTestInventory }
                  else { $script:ImageProbeTestOutput }
        return [pscustomobject]@{ ExitCode=$script:ImageProbeTestExit; StdOut=$stdout; StdErr='' }
    }
    $script:ImageProbeTestExit = 0
    $script:ImageProbeTestOutput = 'x' * 5000
    $script:ImageProbeTestInventory = ''
    $imageTest = [ordered]@{ checks=[ordered]@{}; observations=[ordered]@{} }
    $probeArgs = @{
        Qualification=$imageTest; Name='bounded-output'; Command='true'
        SshExecutable='ssh.exe'; Network=[pscustomobject]@{ address='127.0.0.1'; port=22; user='packer' }
        PrivateKey='fixture'; WorkingDirectory='C:\fixture'
    }
    [void](Invoke-LabImageProbe @probeArgs)
    if ($imageTest.checks.'bounded-output' -ne 'PASS' -or
        $imageTest.observations.'bounded-output'.exit_code -ne 0 -or
        $imageTest.observations.'bounded-output'.stdout.Length -ne 4096 -or
        -not $imageTest.observations.'bounded-output'.stdout_truncated) {
        throw 'Native image probe did not record a bounded successful observation'
    }
    $script:ImageProbeTestExit = 1
    $rejected = $false
    try { [void](Invoke-LabImageProbe @probeArgs) } catch { $rejected = $true }
    if (-not $rejected -or $imageTest.checks.'bounded-output' -ne 'FAIL' -or
        $imageTest.observations.'bounded-output'.exit_code -ne 1) {
        throw 'Native image probe accepted a failed SSH command'
    }
    $script:ImageProbeTestExit = 0
    $script:ImageProbeTestOutput = 'observed'
    $roots = @(1..50 | ForEach-Object { "pkg$_" })
    $script:ImageProbeTestInventory = (@($roots | ForEach-Object { "$_|0:1-1.x86_64" }) -join [Environment]::NewLine)
    $testLock = [IO.Path]::GetTempFileName()
    try {
        Write-Utf8Json -InputObject ([ordered]@{
            profiles=[ordered]@{
                base=[ordered]@{ roots=@($roots[0..47]) }
                rke2=[ordered]@{ roots=@($roots[48..49]) }
            }
        }) -Path $testLock
        $imageArgs = @{
            SshExecutable='ssh.exe'; Network=$probeArgs.Network
            PrivateKey='fixture'; WorkingDirectory='C:\fixture'
            PackageLockPath=$testLock; SourceSha=$sha; SourceTreeSha=('b' * 40)
            BoxSha256=('c' * 64); VmId='e80d60f3-a12e-4734-a654-0cd24dce0fa1'
            VirtualBoxBackend='NATIVE_VTX'; VirtualBoxLogRelative='logs/fixture/VBox.log'
            VirtualBoxLogSha256=('d' * 64)
        }
        $qualified = Invoke-LabImageQualification @imageArgs
        if ($qualified.status -ne 'PASS' -or $qualified.checks.Count -ne 16 -or
            $qualified.checks.supply_chain -ne 'PASS' -or
            @($qualified.supply_chain.package_manifest.packages).Count -ne 50) {
            throw "Native image qualification did not require its probes and supply chain: $($qualified.error)"
        }
        $script:ImageProbeTestExit = 1
        $failed = Invoke-LabImageQualification @imageArgs
        if ($failed.status -ne 'FAIL' -or $failed.checks.rocky_release -ne 'FAIL') {
            throw 'Native image qualification accepted a failed guest probe'
        }
    }
    finally { Remove-Item -LiteralPath $testLock -Force -ErrorAction SilentlyContinue }
    Remove-Variable -Name ImageProbeTestExit -Scope Script
    Remove-Variable -Name ImageProbeTestOutput -Scope Script
    Remove-Variable -Name ImageProbeTestInventory -Scope Script
    [Console]::WriteLine('PASS lab-network-native-lease-self-test')
}

if ($Action -eq 'SelfTest') { Invoke-NativeBootLeaseSelfTest; exit 0 }

$stage = Assert-LabStage -Root $StageRoot -ProtectedRoot $shadow
$prepared = Read-JsonFile (Join-Path $stage 'prepared.json')
if ($prepared.schema -ne 1 -or $prepared.status -ne 'PREPARED' -or
    [IO.Path]::GetFileName($stage) -ne [string]$prepared.campaign_id -or
    [string]$prepared.box_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Network smoke prepared binding is invalid'
}
$retainVm = $prepared.PSObject.Properties.Name -contains 'retain_vm' -and $prepared.retain_vm -eq $true
$diagnosticNem = $prepared.PSObject.Properties.Name -contains 'diagnostic_nem' -and $prepared.diagnostic_nem -eq $true
$smokeRoot = Join-Path $stage 'smoke-run'
Set-NativeSmokeProcessEnvironment -VagrantHome (Join-Path $smokeRoot 'vagrant-home')
$evidenceRoot = if ($Action -eq 'Resume') { Join-Path $shadow "evidence\network-smoke\$($prepared.campaign_id)" }
                else { Join-Path 'C:\ecommerce-lab\evidence\network-smoke' ([string]$prepared.campaign_id) }
$resultPath = Join-Path $evidenceRoot 'result.json'
$vagrant = Resolve-WindowsTool -Name 'vagrant.exe' -FallbackPaths @('C:\Program Files\Vagrant\bin\vagrant.exe')
$vbox = Resolve-WindowsTool -Name 'VBoxManage.exe' -FallbackPaths @('C:\Program Files\Oracle\VirtualBox\VBoxManage.exe')
$ssh = Resolve-WindowsTool -Name 'ssh.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'))
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$privateKey = if ($Action -eq 'Resume') { Join-Path $shadow 'identity\id_ed25519' }
              else { 'C:\ecommerce-lab\identity\id_ed25519' }
$publicKeyPath = "$privateKey.pub"
$seedServer = Join-Path $PSScriptRoot 'local-services-seed-server.ps1'

if ($Action -eq 'Clean') {
    try {
        $cleanLock = [IO.File]::Open('C:\ecommerce-lab\network-smoke\.runtime.lock', [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] { throw 'BLOCKED_RUNTIME another network smoke holds the laboratory runtime lock' }
    Assert-NativeBootLease -Operation 'Clean' -Id ([string]$prepared.campaign_id)
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
    $globalResumeLock = $null
    $resumeLock = $null
    $result = $null
    $resumeInProgress = $false
    try {
    $globalLockPath = 'C:\ecommerce-lab\network-smoke\.runtime.lock'
    foreach ($path in @('C:\', 'C:\ecommerce-lab', 'C:\ecommerce-lab\network-smoke', $globalLockPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($path -eq $globalLockPath -and $item.PSIsContainer) -or
            ($path -ne $globalLockPath -and -not $item.PSIsContainer)) {
            throw "BLOCKED_RUNTIME laboratory runtime lock path is redirected or malformed: $path"
        }
    }
    try {
        $globalResumeLock = [IO.File]::Open($globalLockPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    }
    catch [IO.IOException] { throw 'BLOCKED_RUNTIME another network smoke holds the laboratory runtime lock' }
    Assert-NativeShadowInput -Root $shadow -Path (Join-Path $shadow '.runtime.lock')
    try {
        $resumeLock = [IO.File]::Open((Join-Path $shadow '.runtime.lock'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch [IO.IOException] { throw 'BLOCKED_RUNTIME another native smoke task holds the protected runtime lock' }
    if ($RunnerSourceSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Network SSH resume requires the exact clean runner source SHA'
    }
    $bootState = Assert-NativeBootLease -Operation 'Resume' -Id ([string]$prepared.campaign_id) -Sha $RunnerSourceSha -ProtectedRoot $shadow
    foreach ($path in @($evidenceRoot, $resultPath, $smokeRoot, $privateKey, "$privateKey.pub")) {
        Assert-NativeShadowInput -Root $shadow -Path $path
    }
    $result = Read-JsonFile $resultPath
    if ($result.campaign_id -ne $prepared.campaign_id -or
        $result.status -notin @('DIAGNOSTIC_PRESERVED','PASS','BLOCKED_RUNTIME') -or
        $result.cleanup.vm_preserved -ne $true -or
        $result.vm_name -notmatch '^ecommerce-rocky-10-2-smoke-[0-9a-f]{12}$' -or
        $result.cleanup.vm_id -notmatch '^[0-9a-fA-F-]{36}$' -or
        [string]$result.cleanup.vm_id -ine [string]$bootState.vm_id -or
        [string]$result.vm_name -ne [string]$bootState.vm_name -or
        [string]$prepared.box_sha256 -ne [string]$bootState.box_sha256) {
        throw 'Network SSH resume requires an owned preserved VM and matching campaign'
    }
    $runnerNames = @('LabNativeBoot.ps1','LabNetworkSmoke.ps1','RockyImagePipeline.psm1','NativeVagrantSshSmoke.ps1','LabNetworkSeed.ps1','LabSshIdentity.ps1','local-services-seed-server.ps1')
    $runnerManifestPath = Join-Path $shadow "runner-$RunnerSourceSha\runner.json"
    Assert-NativeShadowInput -Root $shadow -Path $runnerManifestPath
    $runnerManifestItem = Get-Item -LiteralPath $runnerManifestPath -ErrorAction Stop
    if ($runnerManifestItem.PSIsContainer -or ($runnerManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileSha256 -Path $runnerManifestPath) -ne [string]$bootState.runner_manifest_sha256) {
        throw 'Network SSH resume exact-SHA runner manifest differs from the protected boot state'
    }
    $runnerManifest = Read-JsonFile $runnerManifestPath
    if ($runnerManifest.campaign_id -ne $prepared.campaign_id -or
        $runnerManifest.source_sha -ne $RunnerSourceSha -or
        $runnerManifest.source_tree_sha -ne [string]$bootState.source_tree_sha -or
        @($runnerManifest.runner_files.PSObject.Properties.Name).Count -ne $runnerNames.Count) {
        throw 'Network SSH resume exact-SHA runner binding is invalid'
    }
    $packageRelative = 'config/artifacts/rocky-10.2-base-packages.lock.json'
    $packageLockPath = Join-Path $stage $packageRelative.Replace('/', '\')
    Assert-NativeShadowInput -Root $shadow -Path $packageLockPath
    $packageDigest = [string]$runnerManifest.package_lock_sha256
    if ($packageDigest -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileSha256 -Path $packageLockPath) -ne $packageDigest -or
        @( [IO.File]::ReadAllLines((Join-Path $stage 'SHA256SUMS'), [Text.Encoding]::UTF8) |
            Where-Object { $_ -ceq "$packageDigest  $packageRelative" } ).Count -ne 1) {
        throw 'Network SSH resume RKE2 package lock differs from the exact runner'
    }
    $runnerFiles = @{}
    foreach ($name in $runnerNames) {
        $runnerFile = Join-Path $PSScriptRoot $name
        Assert-NativeShadowInput -Root $shadow -Path $runnerFile
        $item = Get-Item -LiteralPath $runnerFile -ErrorAction Stop
        $expectedRunnerDigest = [string]$runnerManifest.runner_files.$name
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $expectedRunnerDigest -notmatch '^[0-9a-f]{64}$' -or
            (Get-FileSha256 -Path $runnerFile) -ne $expectedRunnerDigest) {
            throw "Network SSH resume runner input differs from the protected manifest: $name"
        }
        $runnerFiles[$name] = $expectedRunnerDigest
    }
    $stagedVagrantfile = Join-Path $stage 'platform\vagrant\rocky-image-smoke\Vagrantfile'
    $runtimeVagrantfile = Join-Path $smokeRoot 'Vagrantfile'
    Assert-NativeShadowInput -Root $shadow -Path $runtimeVagrantfile
    $vagrantfileDigest = Get-FileSha256 -Path $stagedVagrantfile
    if ($vagrantfileDigest -ne [string]$runnerManifest.vagrantfile_sha256 -or
        ((Get-Item -LiteralPath $runtimeVagrantfile -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileSha256 -Path $runtimeVagrantfile) -ne $vagrantfileDigest -or
        (Test-Path -LiteralPath (Join-Path $smokeRoot 'vagrant-home\Vagrantfile'))) {
        throw 'Network SSH resume VM Vagrantfile differs from the verified campaign input'
    }
    $attempt = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    Write-Utf8Json -InputObject $result -Path (Join-Path $evidenceRoot "result-before-resume-$attempt.json")
    $result.status = 'DIAGNOSTIC_PRESERVED'
    $result.guest_security = 'NOT_EXECUTED'
    $result.checkpoints.'04-network-ssh' = 'NOT_EXECUTED'
    $result.checkpoints.'05-rocky-runtime' = 'NOT_EXECUTED'
    $result.checkpoints | Add-Member -NotePropertyName '06-image-qualification' -NotePropertyValue 'NOT_EXECUTED' -Force
    $result.resume_from = '04-network-ssh'
    if ($result.PSObject.Properties.Name -contains 'resume_runner_source_sha') { $result.resume_runner_source_sha = $RunnerSourceSha }
    else { $result | Add-Member -NotePropertyName resume_runner_source_sha -NotePropertyValue $RunnerSourceSha }
    if ($result.PSObject.Properties.Name -contains 'resume_vagrantfile_sha256') { $result.resume_vagrantfile_sha256 = $vagrantfileDigest }
    else { $result | Add-Member -NotePropertyName resume_vagrantfile_sha256 -NotePropertyValue $vagrantfileDigest }
    if ($result.PSObject.Properties.Name -contains 'resume_runner_files') { $result.resume_runner_files = $runnerFiles }
    else { $result | Add-Member -NotePropertyName resume_runner_files -NotePropertyValue $runnerFiles }
    $imagePending = [ordered]@{
        status='NOT_EXECUTED'; source_sha=$RunnerSourceSha
        source_tree_sha=[string]$bootState.source_tree_sha
        box_sha256=[string]$prepared.box_sha256; vm_id=[string]$result.cleanup.vm_id
        virtualbox_backend='UNKNOWN'; package_lock_sha256=$packageDigest
        virtualbox_log_relative=$null; virtualbox_log_sha256=$null
        checks=[ordered]@{}; observations=[ordered]@{}; supply_chain=$null
        started_at=$null; completed_at=$null; error=$null
    }
    if ($result.PSObject.Properties.Name -contains 'image_qualification') { $result.image_qualification = $imagePending }
    else { $result | Add-Member -NotePropertyName image_qualification -NotePropertyValue $imagePending }
    $result.completed_at = $null
    $result.error = 'Network SSH resume pending guest security verification'
    $result.cleanup.reason = $result.error
    $resumeInProgress = $true
    Write-NativeProtectedResult -InputObject $result -Path $resultPath -Root $shadow
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent -and -not $diagnosticNem) {
        throw 'BLOCKED_RUNTIME native VT-x is unavailable for network SSH resume in this Windows boot'
    }
    $box = Join-Path $shadow 'box\source.box'
    Assert-NativeShadowInput -Root $shadow -Path $box
    $boxItem = Get-Item -LiteralPath $box -ErrorAction Stop
    if ($boxItem.PSIsContainer -or ($boxItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileSha256 -Path $box) -ne [string]$prepared.box_sha256) {
        throw 'Network SSH resume protected box digest changed'
    }
    $runtimePath = Join-Path $smokeRoot 'runtime.json'
    Assert-NativeShadowInput -Root $shadow -Path $runtimePath
    $runtime = Read-JsonFile $runtimePath
    if ($runtime.name -ne $result.vm_name -or $runtime.box_name -ne $result.box_name -or
        [IO.Path]::GetFullPath([string]$runtime.private_key) -ine [IO.Path]::GetFullPath($privateKey)) {
        throw 'Network SSH resume runtime binding changed'
    }
    $machines = Get-VBoxMachines -VBoxManage $vbox -WorkingDirectory $smokeRoot
    $machineIdPath = Join-Path $smokeRoot '.vagrant\machines\default\virtualbox\id'
    Assert-NativeShadowInput -Root $shadow -Path $machineIdPath
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
        Complete-NativeSshSmokeEvidence -Evidence $network -VBoxManage $vbox -Vagrant $vagrant -VmName $result.vm_name -WorkingDirectory $smokeRoot -Environment $environment -PrivateKey $privateKey -SshExecutable $ssh -VagrantUpResult $null -ProtectedRoot $shadow
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
    $virtualBoxLogRelative = "logs/ssh-resume-$attempt/VBox.log"
    $virtualBoxLog = Join-Path $stage $virtualBoxLogRelative.Replace('/', '\')
    $virtualBoxLogSha256 = $null
    if ($result.virtualbox_backend -eq 'NATIVE_VTX') {
        Assert-NativeShadowInput -Root $shadow -Path $virtualBoxLog
        $virtualBoxLogSha256 = Get-FileSha256 -Path $virtualBoxLog
    }
    if (-not $network.failure_stage -and $network.remote_command_ready -eq 'PASS' -and $network.rocky_runtime -eq 'PASS') {
        $result.guest_security = 'FAIL'
        Assert-LabGuestSecurity -SshExecutable $ssh -Network $network -PrivateKey $privateKey -WorkingDirectory $smokeRoot
        $result.guest_security = 'PASS'
        $result.ssh_identity.private_key_in_box = $false
    }
    if (-not $network.failure_stage -and $result.guest_security -eq 'PASS' -and
        $result.virtualbox_backend -eq 'NATIVE_VTX' -and
        -not (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent) {
        $result.image_qualification = Invoke-LabImageQualification -SshExecutable $ssh -Network $network -PrivateKey $privateKey -WorkingDirectory $smokeRoot -PackageLockPath $packageLockPath -SourceSha $RunnerSourceSha -SourceTreeSha ([string]$bootState.source_tree_sha) -BoxSha256 ([string]$prepared.box_sha256) -VmId ([string]$result.cleanup.vm_id) -VirtualBoxBackend ([string]$result.virtualbox_backend) -VirtualBoxLogRelative $virtualBoxLogRelative -VirtualBoxLogSha256 $virtualBoxLogSha256
    }
    $result.checkpoints.'03-vm-smoke' = 'PASS'
    $result.checkpoints.'04-network-ssh' = if ($network.remote_command_ready -eq 'PASS' -and $result.guest_security -eq 'PASS') { 'PASS' } else { 'FAIL' }
    $result.checkpoints.'05-rocky-runtime' = if ($network.rocky_runtime -eq 'PASS' -and $result.guest_security -eq 'PASS') { 'PASS' } else { 'NOT_EXECUTED' }
    $result.checkpoints.'06-image-qualification' = if ($result.image_qualification.status -eq 'PASS') { 'PASS' } elseif ($result.image_qualification.status -eq 'FAIL') { 'FAIL' } else { 'NOT_EXECUTED' }
    $result.resume_from = if ($result.checkpoints.'04-network-ssh' -ne 'PASS') { '04-network-ssh' } elseif ($result.checkpoints.'05-rocky-runtime' -ne 'PASS') { '05-rocky-runtime' } elseif ($result.checkpoints.'06-image-qualification' -ne 'PASS') { 'image-qualification' } else { 'downstream-qualification' }
    $result.vm_recreate = 'NOT_REQUIRED'
    $result.status = if ($network.failure_stage -or $result.guest_security -ne 'PASS') { 'DIAGNOSTIC_PRESERVED' } elseif ($result.virtualbox_backend -ne 'NATIVE_VTX' -or (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent) { 'BLOCKED_RUNTIME' } elseif ($result.image_qualification.status -ne 'PASS') { 'DIAGNOSTIC_PRESERVED' } else { 'PASS' }
    $result.error = if ($network.failure_stage) { "$($network.failure_code): $($network.failure_reason)" } elseif ($result.guest_security -ne 'PASS') { 'Guest SSH security baseline did not pass' } elseif ($result.status -eq 'BLOCKED_RUNTIME') { "VirtualBox backend $($result.virtualbox_backend); native VT-x qualification remains pending" } elseif ($result.image_qualification.status -ne 'PASS') { "Native image guest qualification failed: $($result.image_qualification.error)" } else { $null }
    $result.cleanup.reason = $result.error
    $result.completed_at = [DateTime]::UtcNow.ToString('o')
    foreach ($name in $runnerNames) {
        if ((Get-FileSha256 -Path (Join-Path $PSScriptRoot $name)) -ne $runnerFiles[$name]) {
            throw "Network SSH resume runner input changed during execution: $name"
        }
    }
    if ((Get-FileSha256 -Path $stagedVagrantfile) -ne $vagrantfileDigest -or
        (Get-FileSha256 -Path $runtimeVagrantfile) -ne $vagrantfileDigest) {
        throw 'Network SSH resume VM Vagrantfile changed during execution'
    }
    Write-NativeProtectedResult -InputObject $result -Path $resultPath -Root $shadow
    $resumeExitCode = if ($result.status -eq 'PASS') { 0 } elseif ($result.status -eq 'BLOCKED_RUNTIME') { 2 } else { 1 }
    }
    catch {
        if ($resumeInProgress) {
            $result.error = $_.Exception.Message
            $result.status = if ($result.error.StartsWith('BLOCKED_RUNTIME ', [StringComparison]::Ordinal)) { 'BLOCKED_RUNTIME' } else { 'DIAGNOSTIC_PRESERVED' }
            $result.guest_security = if ($result.guest_security -eq 'FAIL') { 'FAIL' } else { 'NOT_EXECUTED' }
            $result.checkpoints.'04-network-ssh' = 'FAIL'
            $result.checkpoints.'05-rocky-runtime' = 'NOT_EXECUTED'
            $result.resume_from = '04-network-ssh'
            $result.cleanup.reason = $result.error
            $result.completed_at = [DateTime]::UtcNow.ToString('o')
            Write-NativeProtectedResult -InputObject $result -Path $resultPath -Root $shadow
        }
        throw
    }
    finally {
        if ($null -ne $resumeLock) { $resumeLock.Dispose() }
        if ($null -ne $globalResumeLock) { $globalResumeLock.Dispose() }
    }
    [Console]::WriteLine("LAB_NETWORK_RESUME=$($result.status) campaign=$($prepared.campaign_id) evidence=$resultPath")
    exit $resumeExitCode
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
    Assert-NativeBootLease -Operation 'Run' -Id ([string]$prepared.campaign_id)
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
    Assert-LabGuestSecurity -SshExecutable $ssh -Network $network -PrivateKey $privateKey -WorkingDirectory $smokeRoot
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
