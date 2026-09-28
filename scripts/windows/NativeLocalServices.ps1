# Loaded by native-vtx-cycle.ps1 after the exact-SHA staging manifest verifies.
function Invoke-LocalTool {
    param([string]$Tool, [string[]]$Arguments, [string]$Directory, [int]$Timeout = 900, [hashtable]$Environment = @{})
    $execution = Invoke-BoundedProcess -FilePath $Tool -Arguments $Arguments -TimeoutSeconds $Timeout -WorkingDirectory $Directory -Environment $Environment
    Assert-ProcessSuccess -Result $execution -Operation "$Tool $($Arguments[0])"
    return $execution.StdOut.Trim()
}

function Get-LocalEphemeralPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return [int]$listener.LocalEndpoint.Port }
    finally { $listener.Stop() }
}

function Assert-LocalHostOnlyNetwork {
    $adapter = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -eq 'VirtualBox Host-Only Ethernet Adapter' })
    if ($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Up') { throw 'Owned VirtualBox host-only adapter is absent or down' }
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter[0].ifIndex -ErrorAction Stop)
    if (@($addresses | Where-Object { $_.IPAddress -eq '192.168.22.1' -and $_.PrefixLength -eq 24 }).Count -ne 1) {
        throw 'Owned VirtualBox host-only adapter differs from 192.168.22.1/24'
    }
    foreach ($address in @('192.168.22.241', '192.168.22.242')) {
        if (@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object IPAddress -eq $address).Count -gt 0) {
            throw "Reserved local-service address already belongs to the host: $address"
        }
        $ping = Test-Connection -ComputerName $address -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) { throw "Reserved local-service address already answers: $address" }
    }
}

function Write-LocalSeed {
    param([string]$Directory, [string]$Role, [string]$Sha, [string]$PublicKey, [string]$Address, [string]$Mac)
    $seed = Join-Path $Directory 'seed'
    [void](New-Item -ItemType Directory -Path $seed -Force)
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'), "instance-id: ecommerce-$Role-$($Sha.Substring(0,12))`nlocal-hostname: $Role-local`n", [Text.UTF8Encoding]::new($false))
    $userData = @"
#cloud-config
disable_root: true
ssh_pwauth: false
ssh_deletekeys: true
ssh_genkeytypes: [ed25519]
users:
  - name: qualifier
    gecos: Ecommerce local qualification
    groups: [wheel]
    lock_passwd: true
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - $PublicKey
package_update: false
package_upgrade: false
runcmd:
  - [restorecon, -RF, /home/qualifier/.ssh]
  - [touch, /var/lib/ecommerce-first-boot-ready]
"@
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'), $userData + "`n", [Text.UTF8Encoding]::new($false))
    $macColon = (($Mac -split '(..)' | Where-Object { $_ }) -join ':').ToLowerInvariant()
    $network = @"
version: 2
ethernets:
  hostonly:
    match:
      macaddress: $macColon
    set-name: enp0s8
    dhcp4: false
    dhcp6: false
    addresses: [$Address/24]
"@
    [IO.File]::WriteAllText((Join-Path $seed 'network-config'), $network + "`n", [Text.UTF8Encoding]::new($false))
}

function Invoke-LocalSsh {
    param([string]$Ssh, [string]$Identity, [string]$KnownHosts, [string]$Address, [string]$Command, [string]$Directory, [int]$Timeout = 300, [switch]$AllowNewHost)
    $policy = if ($AllowNewHost) { 'accept-new' } else { 'yes' }
    return Invoke-LocalTool -Tool $Ssh -Directory $Directory -Timeout $Timeout -Arguments @(
        '-o', "UserKnownHostsFile=$KnownHosts", '-o', "StrictHostKeyChecking=$policy",
        '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-i', $Identity,
        "qualifier@$Address", $Command
    )
}

function Get-LocalVmLogPath {
    param([string]$VBoxManage, [string]$Name, [string]$Directory)
    $details = Invoke-LocalTool -Tool $VBoxManage -Directory $Directory -Timeout 30 -Arguments @('showvminfo',$Name,'--machinereadable')
    $logFolder = [regex]::Match($details, '(?m)^LogFldr="(?<path>[^"]+)"$')
    if ($logFolder.Success) { return Join-Path $logFolder.Groups['path'].Value 'VBox.log' }
    $configuration = [regex]::Match($details, '(?m)^CfgFile="(?<path>[^"]+)"$')
    if (-not $configuration.Success) { throw "Cannot locate registered VirtualBox log: $Name" }
    return Join-Path ([IO.Path]::GetDirectoryName($configuration.Groups['path'].Value)) 'Logs\VBox.log'
}

function Wait-LocalSsh {
    param([string]$Ssh, [string]$Identity, [string]$KnownHosts, [string]$Address, [string]$Directory)
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        try {
            $answer = Invoke-LocalSsh -Ssh $Ssh -Identity $Identity -KnownHosts $KnownHosts -Address $Address -Directory $Directory -AllowNewHost -Timeout 25 -Command 'cloud-init status --wait >/dev/null && test -f /var/lib/ecommerce-first-boot-ready && getenforce'
            if ($answer -eq 'Enforcing') { return }
        }
        catch { }
        Start-Sleep -Seconds 3
    }
    throw "NoCloud SSH readiness timed out: $Address"
}

function Invoke-NativeLocalServices {
    param($Prepared, $Result, [string]$Stage, [string]$Artifact, [string]$Vagrant, [string]$VBoxManage)
    Assert-LocalHostOnlyNetwork
    $sha = [string]$Prepared.source_git_sha
    $runtimeRoot = Join-Path $Stage 'local-services-run'
    [void](New-Item -ItemType Directory -Path $runtimeRoot -Force)
    $foreignRunning = Invoke-LocalTool -Tool $VBoxManage -Directory $runtimeRoot -Timeout 30 -Arguments @('list','runningvms')
    if (-not [string]::IsNullOrWhiteSpace($foreignRunning)) { throw 'Native service campaign requires no pre-existing running VirtualBox VM' }
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $scp = Join-Path $env:SystemRoot 'System32\OpenSSH\scp.exe'
    $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    foreach ($executable in @($ssh, $scp, $keygen, $powershell)) {
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "Required Windows OpenSSH executable is absent: $executable" }
    }
    $identity = Join-Path $runtimeRoot 'controller-key'
    $serviceIdentity = Join-Path $runtimeRoot 'service-key'
    foreach ($key in @($identity, $serviceIdentity)) {
        [void](Invoke-LocalTool -Tool $keygen -Directory $runtimeRoot -Timeout 30 -Arguments @('-q','-t','ed25519','-N','','-f',$key))
    }
    $controllerKnown = Join-Path $runtimeRoot 'controller-known-hosts'
    $controllerIp = '192.168.22.241'
    $serviceIp = '192.168.22.242'
    $campaign = [Guid]::NewGuid().ToString('N')
    $Result.local_services.campaign_id = $campaign
    $boxName = "ecommerce/native-local-$($sha.Substring(0,12))"
    $environment = @{ VAGRANT_HOME = (Join-Path $runtimeRoot 'vagrant-home'); VAGRANT_CHECKPOINT_DISABLE='1'; VAGRANT_DEFAULT_PROVIDER='virtualbox'; VAGRANT_NO_PLUGINS='1' }
    $seedServer = Join-Path $Stage 'runner\local-services\local-services-seed-server.ps1'
    $fixture = Join-Path $Stage 'runner\local-services\Vagrantfile'
    $roles = @('controller','gitea','harbor')
    $owned = @{}
    $controllerLogSha256 = $null
    $active = $null
    try {
        [void](Invoke-LocalTool -Tool $Vagrant -Directory $runtimeRoot -Environment $environment -Timeout 900 -Arguments @('box','add','--name',$boxName,'--provider','virtualbox','--checksum-type','sha256','--checksum',[string]$Result.artifact_sha256,$Artifact))
        foreach ($role in $roles) {
            $roleRoot = Join-Path $runtimeRoot $role
            [void](New-Item -ItemType Directory -Path $roleRoot -Force)
            Copy-Item -LiteralPath $fixture -Destination (Join-Path $roleRoot 'Vagrantfile')
            $mac = if ($role -eq 'controller') { '02EECC0000F1' } else { '02EECC0000F2' }
            $address = if ($role -eq 'controller') { $controllerIp } else { $serviceIp }
            $publicKey = if ($role -eq 'controller') { [IO.File]::ReadAllText("$identity.pub").Trim() } else { [IO.File]::ReadAllText("$serviceIdentity.pub").Trim() }
            $memory = if ($role -eq 'controller') { 2048 } elseif ($role -eq 'gitea') { 3072 } else { 6144 }
            $cpus = if ($role -eq 'harbor') { 4 } else { 2 }
            $vmName = "ecommerce-local-$role-$($sha.Substring(0,12))"
            Write-Utf8Json -Path (Join-Path $roleRoot 'runtime.json') -InputObject ([ordered]@{
                name=$vmName; box_name=$boxName; vagrant_version=[string]$Prepared.tools.vagrant.actual_version
                ssh_host_port=(Get-LocalEphemeralPort); seed_port=(Get-LocalEphemeralPort)
                memory_mib=$memory; cpus=$cpus; host_only_adapter='VirtualBox Host-Only Ethernet Adapter'; host_only_mac=$mac
            })
            Write-LocalSeed -Directory $roleRoot -Role $role -Sha $sha -PublicKey $publicKey -Address $address -Mac $mac
            $owned[$role] = [pscustomobject]@{ Root=$roleRoot; Name=$vmName; Address=$address }
        }
        foreach ($role in $roles) {
            $state = $owned[$role]
            $configuration = Read-JsonFile (Join-Path $state.Root 'runtime.json')
            [void](Invoke-LocalTool -Tool $powershell -Directory $state.Root -Timeout 30 -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Start','-SeedRoot',(Join-Path $state.Root 'seed'),'-Port',[string]$configuration.seed_port))
            $active = $role
            try {
                [void](Invoke-LocalTool -Tool $Vagrant -Directory $state.Root -Environment $environment -Timeout 900 -Arguments @('up','--provider','virtualbox','--no-provision'))
                $machine = (Get-VBoxMachines -VBoxManage $VBoxManage -WorkingDirectory $state.Root)
                if (-not $machine.ContainsKey($state.Name)) { throw "Expected owned VM is missing: $($state.Name)" }
                $logPath = Get-LocalVmLogPath -VBoxManage $VBoxManage -Name $state.Name -Directory $state.Root
                $backend = 'UNKNOWN'
                for ($logAttempt = 0; $logAttempt -lt 30; $logAttempt++) {
                    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
                        $log = Read-SharedUtf8Text -Path $logPath
                        $backend = Get-VirtualBoxBackendFromLog -Text $log
                        if ($backend -ne 'UNKNOWN') { break }
                    }
                    Start-Sleep -Seconds 1
                }
                if ($backend -ne 'NATIVE_VTX') { throw "Local $role VirtualBox backend is $backend" }
                $capturedLog = Join-Path $Stage "logs\local-$role-VBox.log"
                [IO.File]::WriteAllText($capturedLog, $log, [Text.UTF8Encoding]::new($false))
                $Result.local_services.backend_logs[$role] = Get-FileSha256 -Path $capturedLog
                if ($role -eq 'controller') { $controllerLogSha256 = [string]$Result.local_services.backend_logs[$role] }
                $key = if ($role -eq 'controller') { $identity } else { $serviceIdentity }
                $known = if ($role -eq 'controller') { $controllerKnown } else { Join-Path $runtimeRoot "$role-known-hosts" }
                Wait-LocalSsh -Ssh $ssh -Identity $key -KnownHosts $known -Address $state.Address -Directory $runtimeRoot
                [void](Invoke-LocalTool -Tool $VBoxManage -Directory $state.Root -Timeout 60 -Arguments @('controlvm',$state.Name,'nic1','null'))
                [void](Invoke-LocalTool -Tool $powershell -Directory $state.Root -Timeout 30 -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Stop','-SeedRoot',(Join-Path $state.Root 'seed'),'-Port',[string]$configuration.seed_port))
                if ($role -eq 'controller') {
                    $payload = Join-Path $Stage 'controller'
                    $remote = 'qualifier@192.168.22.241:'
                    [void](Invoke-LocalTool -Tool $scp -Directory $runtimeRoot -Timeout 3600 -Arguments @('-B','-r','-o',"UserKnownHostsFile=$controllerKnown",'-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-i',$identity,$payload,($remote + '/home/qualifier/payload')))
                    [void](Invoke-LocalSsh -Ssh $ssh -Identity $identity -KnownHosts $controllerKnown -Address $controllerIp -Directory $runtimeRoot -Timeout 1800 -Command "python3 /home/qualifier/payload/bootstrap.py --payload /home/qualifier/payload --destination /home/qualifier/native-qualification --source-sha $sha")
                    $Result.local_services.controller = 'PASS'
                    [void](Invoke-LocalSsh -Ssh $ssh -Identity $identity -KnownHosts $controllerKnown -Address $controllerIp -Directory $runtimeRoot -Command 'mkdir -p /home/qualifier/native-qualification/repo/.artifacts/packer/rocky-10.2/windows /home/qualifier/native-qualification/repo/.context/evidence/rocky-image/rocky-10.2/windows')
                    $release = Join-Path $runtimeRoot 'release.json'
                    Write-Utf8Json -Path $release -InputObject ([ordered]@{schema=1;image='rocky-10.2';artifact='rocky-10.2-rke2-virtualbox.box';artifact_sha256=[string]$Result.artifact_sha256;source_sha=$sha;status='PASS';remote_publication='NOT_PERFORMED';qualification_phase='native-artifact-and-smoke-passed';completed_at=(Get-UtcTimestamp);error=$null})
                    $sum = Join-Path $runtimeRoot 'SHA256SUMS'
                    [IO.File]::WriteAllText($sum, "$($Result.artifact_sha256)  rocky-10.2-rke2-virtualbox.box`n",[Text.UTF8Encoding]::new($false))
                    $releaseTarget = $remote + '/home/qualifier/native-qualification/repo/.context/evidence/rocky-image/rocky-10.2/windows/release.json'
                    $artifactTarget = $remote + '/home/qualifier/native-qualification/repo/.artifacts/packer/rocky-10.2/windows/'
                    foreach ($transfer in @(@($release,$releaseTarget),@($Artifact,$artifactTarget),@($sum,$artifactTarget),@($serviceIdentity,$remote + '/home/qualifier/native-qualification/service-key'))) {
                        [void](Invoke-LocalTool -Tool $scp -Directory $runtimeRoot -Timeout 3600 -Arguments @('-B','-o',"UserKnownHostsFile=$controllerKnown",'-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-i',$identity,[string]$transfer[0],[string]$transfer[1]))
                    }
                    [void](Invoke-LocalSsh -Ssh $ssh -Identity $identity -KnownHosts $controllerKnown -Address $controllerIp -Directory $runtimeRoot -Command 'chmod 600 /home/qualifier/native-qualification/service-key')
                    continue
                }
                $input = Join-Path $runtimeRoot 'controller-input.json'
                Write-Utf8Json -Path $input -InputObject ([ordered]@{
                    source_sha=$sha;campaign_id=$campaign;controller='virtualbox-linux';target_ip=$serviceIp
                    service_identity='/home/qualifier/native-qualification/service-key'
                    service_virtualbox_log_sha256=[string]$Result.local_services.backend_logs[$role]
                    runtime=[ordered]@{hypervisor_present=$false;hardware_virtualization=$true;virtualbox_backend='NATIVE_VTX';nem_detected=$false;virtualbox_log_sha256=$controllerLogSha256}
                })
                $remoteInput = 'qualifier@192.168.22.241:/home/qualifier/native-qualification/input.json'
                [void](Invoke-LocalTool -Tool $scp -Directory $runtimeRoot -Timeout 120 -Arguments @('-B','-o',"UserKnownHostsFile=$controllerKnown",'-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-i',$identity,$input,$remoteInput))
                $phase = "controller-$role"
                [void](Invoke-LocalSsh -Ssh $ssh -Identity $identity -KnownHosts $controllerKnown -Address $controllerIp -Directory $runtimeRoot -Timeout 3600 -Command "cd /home/qualifier/native-qualification/repo && .venv/qualification/bin/python scripts/local_services_qualification.py $phase --input /home/qualifier/native-qualification/input.json")
                $evidenceRemote = 'qualifier@192.168.22.241:/home/qualifier/native-qualification/repo/.context/evidence/local-services-vm/qualification.json'
                [void](Invoke-LocalTool -Tool $scp -Directory $runtimeRoot -Timeout 120 -Arguments @('-B','-o',"UserKnownHostsFile=$controllerKnown",'-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-i',$identity,$evidenceRemote,(Join-Path $Stage 'evidence/local-services-qualification.json')))
                $observed = Read-JsonFile (Join-Path $Stage 'evidence/local-services-qualification.json')
                $expected = if ($role -eq 'gitea') { 'GITEA_PASS' } else { 'PASS' }
                if ($observed.status -ne $expected -or $observed.source_sha -ne $sha -or $observed.campaign_id -ne $campaign) { throw "Native $role evidence is incomplete or stale" }
                $Result.local_services[$role] = $expected
                if ($role -eq 'harbor') { $Result.local_services.evidence_sha256 = Get-FileSha256 -Path (Join-Path $Stage 'evidence/local-services-qualification.json') }
            }
            finally {
                try { [void](Invoke-LocalTool -Tool 'powershell.exe' -Directory $state.Root -Timeout 30 -Arguments @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$seedServer,'-Action','Stop','-SeedRoot',(Join-Path $state.Root 'seed'),'-Port',[string]$configuration.seed_port)) } catch { }
                if ($role -ne 'controller') {
                    [void](Invoke-LocalTool -Tool $Vagrant -Directory $state.Root -Environment $environment -Timeout 300 -Arguments @('destroy','--force'))
                    $active = $null
                }
            }
        }
        $Result.local_services.status = 'PASS'
    }
    finally {
        foreach ($role in @('harbor','gitea','controller')) {
            if ($owned.ContainsKey($role)) {
                $state = $owned[$role]
                try { [void](Invoke-LocalTool -Tool $Vagrant -Directory $state.Root -Environment $environment -Timeout 300 -Arguments @('destroy','--force')) } catch { $Result.local_services.cleanup = 'FAIL' }
            }
        }
        try { [void](Invoke-LocalTool -Tool $Vagrant -Directory $runtimeRoot -Environment $environment -Timeout 300 -Arguments @('box','remove','--force',$boxName)) } catch { $Result.local_services.cleanup = 'FAIL' }
        foreach ($key in @($identity,$serviceIdentity)) { Remove-Item -LiteralPath $key,"$key.pub" -Force -ErrorAction SilentlyContinue }
        if ($Result.local_services.cleanup -ne 'FAIL') { $Result.local_services.cleanup = 'PASS' }
    }
}
