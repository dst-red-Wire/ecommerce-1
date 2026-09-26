Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\scripts\windows\NativeVagrantSshSmoke.ps1')

function Invoke-BoundedProcess {
    param($FilePath, $Arguments, $TimeoutSeconds, $WorkingDirectory)
    switch ([string]$Arguments[0]) {
        'showvminfo' {
            return [pscustomobject]@{
                ExitCode = 0
                StdOut = "VMState=`"running`"`nVMStateChangeTime=`"2026-09-26T21:00:00Z`"`nForwarding(0)=`"ssh,tcp,127.0.0.1,2222,,22`""
                StdErr = ''
            }
        }
        'guestproperty' {
            return [pscustomobject]@{ ExitCode = 0; StdOut = 'Name: /VirtualBox/GuestInfo/Net/0/V4/IP, value: 10.0.2.15, timestamp: 1'; StdErr = '' }
        }
        default {
            if ($script:FixtureMode -eq 'acl_failure') {
                return [pscustomobject]@{ ExitCode = 255; StdOut = ''; StdErr = 'WARNING: UNPROTECTED PRIVATE KEY FILE! Key ignored.' }
            }
            return [pscustomobject]@{ ExitCode = 0; StdOut = '2: enp0s3 inet 10.0.2.15/24 scope global'; StdErr = '' }
        }
    }
}

function Test-NativeTcpPort { param($Address, $Port) return $true }

$script:FixtureMode = 'success'
$evidence = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
Update-NativeSshSmokeEvidence -Evidence $evidence -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $PSScriptRoot -PrivateKey 'unused' -SshExecutable 'ssh.exe'
foreach ($field in @('vm_running', 'ip_ready', 'tcp_22_ready', 'ssh_auth_ready')) {
    if ($evidence[$field] -ne 'PASS') { throw "Synthetic native SSH state failed: $field" }
}
if ($evidence.address -ne '127.0.0.1' -or $evidence.port -ne 2222 -or $evidence.guest_ip -ne '10.0.2.15') {
    throw 'VirtualBox NAT or guest IP parsing failed'
}
if ($evidence.vm_running_observation -ne 'virtualbox_state_change_time' -or $evidence.ssh_probe_count -ne 1) {
    throw 'VM timestamp or bounded SSH probe count is wrong'
}
if ((Get-NativeSshSeconds '2026-09-26T21:00:00Z' '2026-09-26T21:00:10Z') -ne 10) {
    throw 'SSH timing calculation is wrong'
}

$script:FixtureMode = 'acl_failure'
$failure = New-NativeSshSmokeEvidence -VmName 'fixture' -User 'packer' -EvidenceDirectory 'unused'
Update-NativeSshSmokeEvidence -Evidence $failure -VBoxManage 'VBoxManage' -VmName 'fixture' -WorkingDirectory $PSScriptRoot -PrivateKey 'unused' -SshExecutable 'ssh.exe'
if ($failure.tcp_22_ready -ne 'PASS' -or $failure.ssh_auth_ready -ne 'FAIL' -or $failure.ssh_probe_count -ne 1) {
    throw 'TCP readiness and authentication failure were conflated'
}
if (-not $failure.Contains('terminal_auth_error') -or $failure.last_ssh_error -notmatch 'UNPROTECTED PRIVATE KEY FILE') {
    throw 'Private key ACL failure was not preserved precisely'
}
Write-Output 'PASS NativeVagrantSshSmoke synthetic NAT, IP, TCP, authentication and ACL evidence'
