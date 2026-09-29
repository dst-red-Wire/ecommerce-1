Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\scripts\windows\NativeVagrantSshSmoke.ps1')

function Invoke-BoundedProcess {
    param($FilePath, $Arguments, $TimeoutSeconds, $WorkingDirectory, $Environment)
    switch ([string]$Arguments[0]) {
        'showvminfo' {
            return [pscustomobject]@{
                ExitCode = 0
                StdOut = if ($script:FixtureMode -eq 'vm_stopped') { 'VMState="poweroff"' } else { "VMState=`"running`"`nVMStateChangeTime=`"2026-09-26T21:00:00.106000000`"`nForwarding(0)=`"ssh,tcp,127.0.0.1,2222,,22`"" }
                StdErr = ''
            }
        }
        'guestproperty' {
            return [pscustomobject]@{ ExitCode = 0; StdOut = 'Name: /VirtualBox/GuestInfo/Net/0/V4/IP, value: 10.0.2.15, timestamp: 1'; StdErr = '' }
        }
        'ssh-config' {
            return [pscustomobject]@{ ExitCode = 0; StdOut = "Host default`n HostName 127.0.0.1`n User packer`n Port 2222`n IdentityFile $script:FixtureKey"; StdErr = '' }
        }
        'ssh' {
            if ($TimeoutSeconds -ne 20) { throw 'Optional Vagrant SSH wrapper timeout is not bounded at 20 seconds' }
            $script:VagrantAttempts++
            throw 'Synthetic Vagrant SSH wrapper timeout'
        }
        default {
            if ($Arguments -contains 'StrictHostKeyChecking=yes') {
                $script:DirectAttempts++
                if ($Arguments[-1] -eq 'printf "REMOTE_COMMAND_OK\n"') {
                    return [pscustomobject]@{ ExitCode = 0; StdOut = 'REMOTE_COMMAND_OK'; StdErr = '' }
                }
                if ($Arguments[-1] -eq 'cat /etc/os-release') {
                    return [pscustomobject]@{ ExitCode = 0; StdOut = "ID=rocky`nVERSION_ID=`"10.2`""; StdErr = '' }
                }
                throw 'Unexpected direct SSH command'
            }
            $script:HandshakeAttempts++
            if ($Arguments -notcontains 'StrictHostKeyChecking=accept-new' -or
                -not @($Arguments | Where-Object { $_ -like 'UserKnownHostsFile=*' }).Count) {
                throw 'SSH probe does not pin the observed guest host key'
            }
            if ($script:FixtureMode -eq 'acl_failure') {
                return [pscustomobject]@{ ExitCode = 255; StdOut = ''; StdErr = 'WARNING: UNPROTECTED PRIVATE KEY FILE! Key ignored.' }
            }
            return [pscustomobject]@{ ExitCode = 0; StdOut = '2: enp0s3 inet 10.0.2.15/24 scope global'; StdErr = '' }
        }
    }
}

function Test-NativeTcpPort { param($Address, $Port, [ref]$ErrorClass) if ($script:FixtureMode -eq 'tcp_unavailable') { $ErrorClass.Value = 'CONNECTION_REFUSED'; return $false }; return $true }

$script:FixtureRoot = Join-Path $env:TEMP ('native-ssh-smoke-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $script:FixtureRoot -Force)
$script:FixtureKey = Join-Path $script:FixtureRoot 'id_ed25519'
[IO.File]::WriteAllText($script:FixtureKey, 'fixture')
[IO.File]::WriteAllText((Join-Path $script:FixtureRoot 'ssh_known_hosts'), 'fixture')
$script:FixtureMode = 'success'
$script:HandshakeAttempts = 0
$evidence = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
Update-NativeSshSmokeEvidence -Evidence $evidence -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $script:FixtureRoot -PrivateKey $script:FixtureKey -SshExecutable 'ssh.exe'
foreach ($field in @('vm_running', 'ip_ready', 'tcp_22_ready', 'ssh_auth_ready')) {
    if ($evidence[$field] -ne 'PASS') { throw "Synthetic native SSH state failed: $field" }
}
if ($evidence.address -ne '127.0.0.1' -or $evidence.port -ne 2222 -or $evidence.guest_ip -ne '10.0.2.15') {
    throw 'VirtualBox NAT or guest IP parsing failed'
}
if ($evidence.vm_running_observation -ne 'virtualbox_state_change_time' -or $evidence.ssh_probe_count -ne 1) {
    throw 'VM timestamp or bounded SSH probe count is wrong'
}
if ($evidence.vm_running_at -ne '2026-09-26T21:00:00.1060000Z' -or
    (Convert-VBoxStateTimeToUtc '2026-09-26T23:00:00+02:00') -ne '2026-09-26T21:00:00.0000000Z') {
    throw 'VirtualBox state change time was not interpreted as UTC'
}
if ((Get-NativeSshSeconds '2026-09-26T21:00:00Z' '2026-09-26T21:00:10Z') -ne 10) {
    throw 'SSH timing calculation is wrong'
}

$script:VagrantAttempts = 0
$script:DirectAttempts = 0
$evidence.diagnostics_directory = Join-Path $script:FixtureRoot 'diagnostics'
Complete-NativeSshSmokeEvidence -Evidence $evidence -VBoxManage 'VBoxManage' -Vagrant 'vagrant.exe' -VmName 'fixture' -WorkingDirectory $script:FixtureRoot -Environment @{} -PrivateKey $script:FixtureKey -SshExecutable 'ssh.exe' -VagrantUpResult ([pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' })
if ($evidence.ssh_config -ne 'PASS' -or $evidence.remote_command_ready -ne 'PASS' -or
    $evidence.rocky_runtime -ne 'PASS' -or $evidence.rocky_version -ne '10.2' -or
    $evidence.vagrant_ssh_command -ne 'FAIL_NON_BLOCKING' -or $evidence.vagrant_ssh_command_attempts -ne 1 -or
    $script:VagrantAttempts -ne 1 -or $script:DirectAttempts -ne 2 -or $evidence.failure_stage) {
    throw 'Direct SSH and Rocky runtime must pass when only the Vagrant wrapper times out'
}
$wrapperLog = Get-Content -LiteralPath (Join-Path $evidence.diagnostics_directory 'vagrant-ssh-command.txt') -Raw
if ($wrapperLog -notmatch 'Synthetic Vagrant SSH wrapper timeout') {
    throw 'Optional Vagrant SSH wrapper failure was not retained'
}

$script:FixtureMode = 'vm_stopped'
$stopped = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
$beforeHandshake = $script:HandshakeAttempts
Update-NativeSshSmokeEvidence -Evidence $stopped -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $script:FixtureRoot -PrivateKey $script:FixtureKey -SshExecutable 'ssh.exe'
if ($stopped.vm_running -ne 'FAIL' -or $stopped.ssh_probe_count -ne 0 -or $script:HandshakeAttempts -ne $beforeHandshake) {
    throw 'Stopped VM incorrectly proceeded to SSH'
}

$script:FixtureMode = 'tcp_unavailable'
$noTcp = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
Update-NativeSshSmokeEvidence -Evidence $noTcp -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $script:FixtureRoot -PrivateKey $script:FixtureKey -SshExecutable 'ssh.exe'
if ($noTcp.vm_running -ne 'PASS' -or $noTcp.tcp_22_ready -ne 'FAIL' -or
    $noTcp.tcp_probe_count -ne 1 -or $noTcp.tcp_last_error -ne 'CONNECTION_REFUSED' -or
    $noTcp.ssh_probe_count -ne 0 -or $script:HandshakeAttempts -ne $beforeHandshake) {
    throw 'Unavailable TCP port incorrectly proceeded to SSH'
}

$script:FixtureMode = 'acl_failure'
$failure = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
Update-NativeSshSmokeEvidence -Evidence $failure -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $script:FixtureRoot -PrivateKey $script:FixtureKey -SshExecutable 'ssh.exe'
if ($failure.tcp_22_ready -ne 'PASS' -or $failure.ssh_auth_ready -ne 'FAIL' -or $failure.ssh_probe_count -ne 1) {
    throw 'TCP readiness and authentication failure were conflated'
}
if (-not $failure.Contains('terminal_auth_error') -or $failure.last_ssh_error -notmatch 'UNPROTECTED PRIVATE KEY FILE') {
    throw 'Private key ACL failure was not preserved precisely'
}
if ((Get-NativeSshFailureCode -Stage 'ssh_auth_ready' -Detail $failure.last_ssh_error) -ne 'SSH_AUTH_FAILED' -or
    (Get-NativeSshFailureCode -Stage 'ssh_auth_ready' -Detail 'Host key verification failed.') -ne 'SSH_HOST_KEY_FAILED' -or
    (Get-NativeSshFailureCode -Stage 'tcp_22_ready' -Detail 'VirtualBox NAT SSH forwarding is absent') -ne 'VBOX_NETWORK_ERROR') {
    throw 'SSH authentication and VirtualBox network failure codes are not distinct'
}
Write-Output 'PASS NativeVagrantSshSmoke synthetic VM, TCP, authentication, UTC timing, direct SSH, Rocky runtime and optional Vagrant wrapper evidence'
