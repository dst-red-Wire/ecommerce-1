function New-NativeSshSmokeEvidence {
    param([string]$VmName, [string]$User, [string]$EvidenceDirectory)
    return [ordered]@{
        vm_name = $VmName; vm_running = 'FAIL'; ip_ready = 'FAIL'
        tcp_22_ready = 'FAIL'; ssh_auth_ready = 'FAIL'; vagrant_ready = 'FAIL'
        address = $null; port = $null; user = $User; guest_ip = $null
        ip_observation = $null
        vm_running_observation = $null
        timing_semantics = 'first_observed_state; guest_ip_without_guest_additions_is_observed_after_ssh_auth'
        vagrant_up_started_at = $null; vm_running_at = $null; ip_ready_at = $null
        tcp_22_ready_at = $null; ssh_auth_ready_at = $null; vagrant_ready_at = $null
        first_ssh_probe_at = $null; first_ssh_probe_delay_seconds = $null
        ssh_probe_count = 0; ssh_probe_timeout_seconds = 10
        tcp_probe_count = 0; tcp_last_error = $null
        ssh_exit_code = $null; ssh_failure_class = $null
        ssh_poll_interval_seconds = 5; vagrant_up_deadline_seconds = 900
        vagrant_ssh_command = 'NOT_EXECUTED'
        vagrant_ssh_command_attempts = 0; vagrant_ssh_command_timeout_seconds = 20
        ssh_config = 'NOT_EXECUTED'; remote_command_ready = 'NOT_EXECUTED'
        rocky_runtime = 'NOT_EXECUTED'; rocky_version = $null
        remote_command_at = $null; rocky_runtime_at = $null
        ssh_to_remote_command_seconds = $null; boot_to_remote_command_seconds = $null
        total_smoke_seconds = $null
        boot_to_ip_seconds = $null; ip_to_tcp22_seconds = $null
        tcp22_to_ssh_auth_seconds = $null; ssh_auth_to_vagrant_ready_seconds = $null
        boot_to_vagrant_ready_seconds = $null
        failure_stage = $null; failure_code = $null; failure_reason = $null; last_ssh_error = $null
        last_vagrant_error = $null
        diagnostics_directory = $EvidenceDirectory
    }
}

function Get-NativeSshSeconds {
    param($Start, $End)
    if ($null -eq $Start -or $null -eq $End) { return $null }
    $seconds = ([DateTime]::Parse([string]$End).ToUniversalTime() - [DateTime]::Parse([string]$Start).ToUniversalTime()).TotalSeconds
    if ($seconds -lt 0) { return $null }
    return [Math]::Round($seconds, 3)
}

function Convert-VBoxStateTimeToUtc {
    param([string]$Value)
    $timestamp = if ($Value -match '(?:Z|[+-][0-9]{2}:[0-9]{2})$') { $Value } else { "${Value}Z" }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($timestamp, [ref]$parsed)) { return $null }
    return $parsed.UtcDateTime.ToString('o')
}

function Test-LabVirtualizationReady {
    param([bool]$HypervisorPresent, [bool]$DiagnosticNem, [bool[]]$FirmwareEnabled)
    if ($FirmwareEnabled.Count -eq 0) { return $false }
    if ($HypervisorPresent) { return $DiagnosticNem }
    return @($FirmwareEnabled | Where-Object { -not $_ }).Count -eq 0
}

function Get-NativeLastErrorLine {
    param([string]$StdErr, [string]$StdOut)
    $source = if ($StdErr.Trim()) { $StdErr } else { $StdOut }
    $lines = @($source -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0) { return 'Process failed without diagnostic output' }
    return [string]$lines[-1]
}

function Get-NativeSshFailureCode {
    param([string]$Stage, [string]$Detail)
    switch ($Stage) {
        'vm_running' { return 'VM_NOT_RUNNING' }
        'ip_ready' { return 'IP_NOT_OBSERVABLE' }
        'tcp_22_ready' {
            if ($Detail -match 'NAT SSH forwarding is absent') { return 'VBOX_NETWORK_ERROR' }
            return 'TCP22_NOT_READY'
        }
        'vagrant_ready' { return 'VAGRANT_NOT_READY' }
        'vagrant_ssh_command' { return 'VAGRANT_NOT_READY' }
        'ssh_config' { return 'SSH_CONFIG_INVALID' }
        'remote_command_ready' { return 'REMOTE_COMMAND_FAILED' }
        'rocky_runtime' { return 'ROCKY_RUNTIME_INVALID' }
        'ssh_auth_ready' {
            if ($Detail -match 'Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED') { return 'SSH_HOST_KEY_FAILED' }
            if ($Detail -match 'Permission denied|UNPROTECTED PRIVATE KEY FILE|bad permissions|Identity file') { return 'SSH_AUTH_FAILED' }
            if ($Detail -match 'kex_exchange_identification|banner exchange|Unable to negotiate') { return 'SSH_HANDSHAKE_FAILED' }
            return 'SSH_AUTH_FAILED'
        }
    }
    return 'GLOBAL_DEADLINE_EXCEEDED'
}

function Test-NativeTcpPort {
    param([string]$Address, [int]$Port, [ref]$ErrorClass)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(1500)) { $ErrorClass.Value = 'TIMEOUT'; return $false }
        $client.EndConnect($pending)
        $client.ReceiveTimeout = 2500
        $buffer = New-Object byte[] 64
        $read = $client.GetStream().Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { $ErrorClass.Value = 'NO_SSH_BANNER'; return $false }
        if (-not [Text.Encoding]::ASCII.GetString($buffer, 0, $read).StartsWith('SSH-')) {
            $ErrorClass.Value = 'NO_SSH_BANNER'
            return $false
        }
        return $true
    }
    catch [System.Net.Sockets.SocketException] {
        $ErrorClass.Value = switch ($_.Exception.SocketErrorCode) {
            'ConnectionRefused' { 'CONNECTION_REFUSED' }
            'TimedOut' { 'TIMEOUT' }
            'NetworkUnreachable' { 'NO_ROUTE' }
            'HostNotFound' { 'DNS_ERROR' }
            default { 'TCP_ERROR' }
        }
        return $false
    }
    catch { $ErrorClass.Value = 'TCP_ERROR'; return $false }
    finally { $client.Close() }
}

function Invoke-NativeDirectSshProbe {
    param(
        [string]$SshExecutable, [string]$Address, [int]$Port,
        [string]$User, [string]$PrivateKey, [string]$WorkingDirectory,
        [string]$Command, [int]$TimeoutSeconds = 15
    )
    $knownHosts = Join-Path $WorkingDirectory 'ssh_known_hosts'
    if (-not (Test-Path -LiteralPath $knownHosts -PathType Leaf)) { throw 'Pinned SSH known_hosts is absent' }
    return Invoke-BoundedProcess -FilePath $SshExecutable -Arguments @(
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts",
        '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1',
        '-o', 'NumberOfPasswordPrompts=0', '-i', $PrivateKey,
        '-p', [string]$Port, "$User@$Address", $Command
    ) -TimeoutSeconds $TimeoutSeconds -WorkingDirectory $WorkingDirectory
}

function Update-NativeSshSmokeEvidence {
    param(
        [System.Collections.IDictionary]$Evidence, [string]$VBoxManage,
        [string]$VmName, [string]$WorkingDirectory, [string]$PrivateKey,
        [string]$SshExecutable
    )
    $info = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('showvminfo', $VmName, '--machinereadable') -TimeoutSeconds 10 -WorkingDirectory $WorkingDirectory
    if ($info.ExitCode -ne 0) { return }
    if ($info.StdOut -match '(?m)^VMState="running"\s*$') {
        if ($Evidence.vm_running -ne 'PASS') {
            $Evidence.vm_running = 'PASS'
            $Evidence.vm_running_at = [DateTime]::UtcNow.ToString('o')
            $Evidence.vm_running_observation = 'first_showvminfo_poll'
            if ($info.StdOut -match '(?m)^VMStateChangeTime="([^"]+)"\s*$') {
                $stateChange = Convert-VBoxStateTimeToUtc -Value $Matches[1]
                if ($null -ne $stateChange) {
                    $Evidence.vm_running_at = $stateChange
                    $Evidence.vm_running_observation = 'virtualbox_state_change_time'
                }
            }
        }
    }
    else { return }

    foreach ($line in ($info.StdOut -split "`r?`n")) {
        if ($line -notmatch '^Forwarding\(\d+\)="([^"]+)"') { continue }
        $fields = $Matches[1] -split ',', 6
        if ($fields.Count -ne 6 -or $fields[1] -ne 'tcp' -or $fields[5] -ne '22') { continue }
        if ($fields[3] -notmatch '^\d+$') { continue }
        $Evidence.address = if ($fields[2]) { $fields[2] } else { '127.0.0.1' }
        $Evidence.port = [int]$fields[3]
        break
    }

    if ($Evidence.ip_ready -ne 'PASS') {
        $properties = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments @('guestproperty', 'enumerate', $VmName) -TimeoutSeconds 10 -WorkingDirectory $WorkingDirectory
        if ($properties.ExitCode -eq 0 -and $properties.StdOut -match '(?m)Name: /VirtualBox/GuestInfo/Net/\d+/V4/IP, value: ((?:\d{1,3}\.){3}\d{1,3})') {
            $Evidence.guest_ip = $Matches[1]
            $Evidence.ip_ready = 'PASS'
            $Evidence.ip_ready_at = [DateTime]::UtcNow.ToString('o')
            $Evidence.ip_observation = 'virtualbox_guestproperty'
        }
        elseif ($null -eq $Evidence.ip_observation) { $Evidence.ip_observation = 'guestproperty_ipv4_unavailable' }
    }
    if ($null -eq $Evidence.address -or $null -eq $Evidence.port) { return }
    if ($Evidence.tcp_22_ready -ne 'PASS') {
        $Evidence.tcp_probe_count = [int]$Evidence.tcp_probe_count + 1
        $tcpError = $null
        if (-not (Test-NativeTcpPort -Address $Evidence.address -Port $Evidence.port -ErrorClass ([ref]$tcpError))) {
            $Evidence.tcp_last_error = $tcpError
            return
        }
        $Evidence.tcp_22_ready = 'PASS'
        $Evidence.tcp_last_error = $null
        $Evidence.tcp_22_ready_at = [DateTime]::UtcNow.ToString('o')
    }
    if ($Evidence.ssh_auth_ready -eq 'PASS' -or $Evidence.Contains('terminal_auth_error')) { return }
    if ($null -eq $Evidence.first_ssh_probe_at) {
        $Evidence.first_ssh_probe_at = [DateTime]::UtcNow.ToString('o')
        $Evidence.first_ssh_probe_delay_seconds = Get-NativeSshSeconds -Start $Evidence.vm_running_at -End $Evidence.first_ssh_probe_at
    }
    $Evidence.ssh_probe_count = [int]$Evidence.ssh_probe_count + 1
    $knownHosts = Join-Path $WorkingDirectory 'ssh_known_hosts'
    $ssh = Invoke-BoundedProcess -FilePath $SshExecutable -Arguments @(
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=accept-new', '-o', "UserKnownHostsFile=$knownHosts",
        '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=0',
        '-i', $PrivateKey, '-p', [string]$Evidence.port,
        "$($Evidence.user)@$($Evidence.address)", 'ip -4 -o addr show scope global'
    ) -TimeoutSeconds 10 -WorkingDirectory $WorkingDirectory
    $Evidence.ssh_exit_code = $ssh.ExitCode
    if ($ssh.ExitCode -eq 0) {
        $Evidence.ssh_auth_ready = 'PASS'
        $Evidence.ssh_auth_ready_at = [DateTime]::UtcNow.ToString('o')
        $Evidence.last_ssh_error = $null
        if ($Evidence.ip_ready -ne 'PASS' -and $ssh.StdOut -match '\binet\s+((?:\d{1,3}\.){3}\d{1,3})/') {
            $Evidence.guest_ip = $Matches[1]
            $Evidence.ip_ready = 'PASS'
            $Evidence.ip_ready_at = $Evidence.ssh_auth_ready_at
            $Evidence.ip_observation = 'guest_ip_command_after_ssh_auth'
        }
    }
    else {
        $Evidence.last_ssh_error = Get-NativeLastErrorLine -StdErr $ssh.StdErr -StdOut $ssh.StdOut
        if ($ssh.StdErr -match 'UNPROTECTED PRIVATE KEY FILE|bad permissions|Load key .*Permission denied|Identity file .*not accessible') {
            $Evidence.last_ssh_error = $ssh.StdErr.Trim()
            $Evidence.terminal_auth_error = $true
        }
    }
}

function Complete-NativeSshSmokeEvidence {
    param(
        [System.Collections.IDictionary]$Evidence, [string]$VBoxManage,
        [string]$Vagrant, [string]$VmName, [string]$WorkingDirectory,
        [hashtable]$Environment, [string]$PrivateKey, [string]$SshExecutable,
        $VagrantUpResult
    )
    $diagnostics = [string]$Evidence.diagnostics_directory
    [void](New-Item -ItemType Directory -Path $diagnostics -Force)
    try {
        $acl = Get-Acl -LiteralPath $PrivateKey -ErrorAction Stop
        [IO.File]::WriteAllText((Join-Path $diagnostics 'private-key-acl.txt'), ($acl | Format-List Owner,AccessToString | Out-String))
    }
    catch { [IO.File]::WriteAllText((Join-Path $diagnostics 'private-key-acl.txt'), $_.Exception.Message) }
    if ($null -ne $VagrantUpResult -and $VagrantUpResult.ExitCode -eq 0 -and $Evidence.vagrant_ready -ne 'PASS') {
        $Evidence.vagrant_ready = 'PASS'
        $Evidence.vagrant_ready_at = [DateTime]::UtcNow.ToString('o')
    }
    foreach ($entry in @(
        @{ Name = 'showvminfo.txt'; Args = @('showvminfo', $VmName, '--machinereadable') },
        @{ Name = 'guestproperty.txt'; Args = @('guestproperty', 'enumerate', $VmName) },
        @{ Name = 'hostonlyifs.txt'; Args = @('list', 'hostonlyifs') },
        @{ Name = 'hostonlynets.txt'; Args = @('list', 'hostonlynets') },
        @{ Name = 'natnets.txt'; Args = @('list', 'natnets') }
    )) {
        try {
            $capture = Invoke-BoundedProcess -FilePath $VBoxManage -Arguments $entry.Args -TimeoutSeconds 15 -WorkingDirectory $WorkingDirectory
            [IO.File]::WriteAllText((Join-Path $diagnostics $entry.Name), "exit=$($capture.ExitCode)`n$($capture.StdOut)`n$($capture.StdErr)")
        }
        catch { [IO.File]::WriteAllText((Join-Path $diagnostics $entry.Name), $_.Exception.Message) }
    }
    $machineInfoPath = Join-Path $diagnostics 'showvminfo.txt'
    if ((Test-Path -LiteralPath $machineInfoPath) -and [IO.File]::ReadAllText($machineInfoPath) -match '(?m)^LogFldr="([^"]+)"') {
        $vboxLogPath = Join-Path $Matches[1] 'VBox.log'
        if (Test-Path -LiteralPath $vboxLogPath -PathType Leaf) {
            try { Copy-Item -LiteralPath $vboxLogPath -Destination (Join-Path $diagnostics 'VBox.log') }
            catch { [IO.File]::WriteAllText((Join-Path $diagnostics 'VBox-log-copy-error.txt'), $_.Exception.Message) }
        }
    }
    if ($null -ne $VagrantUpResult) {
        [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-up.txt'), "exit=$($VagrantUpResult.ExitCode)`n$($VagrantUpResult.StdOut)`n$($VagrantUpResult.StdErr)")
        if ($VagrantUpResult.ExitCode -ne 0) { $Evidence.last_vagrant_error = Get-NativeLastErrorLine -StdErr $VagrantUpResult.StdErr -StdOut $VagrantUpResult.StdOut }
    }
    try {
        $config = Invoke-BoundedProcess -FilePath $Vagrant -Arguments @('ssh-config') -TimeoutSeconds 30 -WorkingDirectory $WorkingDirectory -Environment $Environment
        [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-config.txt'), "exit=$($config.ExitCode)`n$($config.StdOut)`n$($config.StdErr)")
        if ($config.ExitCode -eq 0) {
            $hostName = if ($config.StdOut -match '(?m)^\s*HostName\s+(\S+)') { $Matches[1] } else { '' }
            $portText = if ($config.StdOut -match '(?m)^\s*Port\s+(\d+)') { $Matches[1] } else { '' }
            $sshUser = if ($config.StdOut -match '(?m)^\s*User\s+(\S+)') { $Matches[1] } else { '' }
            $identity = if ($config.StdOut -match '(?m)^\s*IdentityFile\s+([^\r\n]+)') { $Matches[1].Trim().Trim('"') } else { '' }
            if ($hostName -eq $Evidence.address -and $portText -eq [string]$Evidence.port -and
                $sshUser -eq $Evidence.user -and $identity -and
                [IO.Path]::GetFullPath($identity) -ieq [IO.Path]::GetFullPath($PrivateKey)) {
                $Evidence.ssh_config = 'PASS'
                [IO.File]::WriteAllText((Join-Path $diagnostics 'ssh-target.json'),
                    ([ordered]@{ host=$hostName; port=[int]$portText; user=$sshUser; identity_file=$identity } | ConvertTo-Json -Compress))
            }
            else { $Evidence.last_ssh_error = 'Vagrant SSH config differs from observed NAT endpoint or owned identity' }
        }
        else { $Evidence.last_ssh_error = Get-NativeLastErrorLine -StdErr $config.StdErr -StdOut $config.StdOut }
    }
    catch {
        $Evidence.last_ssh_error = $_.Exception.Message
        [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-config.txt'), $Evidence.last_ssh_error)
    }
    if ($Evidence.vm_running -eq 'PASS' -and $Evidence.ssh_auth_ready -ne 'PASS') {
        try { Update-NativeSshSmokeEvidence -Evidence $Evidence -VBoxManage $VBoxManage -VmName $VmName -WorkingDirectory $WorkingDirectory -PrivateKey $PrivateKey -SshExecutable $SshExecutable }
        catch { $Evidence.last_ssh_error = $_.Exception.Message }
    }
    if ($Evidence.ssh_auth_ready -eq 'PASS' -and $Evidence.ssh_config -eq 'PASS') {
        try {
            $remote = Invoke-NativeDirectSshProbe -SshExecutable $SshExecutable -Address $Evidence.address -Port $Evidence.port -User $Evidence.user -PrivateKey $PrivateKey -WorkingDirectory $WorkingDirectory -Command 'printf "REMOTE_COMMAND_OK\n"'
            [IO.File]::WriteAllText((Join-Path $diagnostics 'remote-command.txt'), "exit=$($remote.ExitCode)`n$($remote.StdOut)`n$($remote.StdErr)")
            if ($remote.ExitCode -eq 0 -and $remote.StdOut.Trim() -eq 'REMOTE_COMMAND_OK') {
                $Evidence.remote_command_ready = 'PASS'
                $Evidence.remote_command_at = [DateTime]::UtcNow.ToString('o')
            }
            else { $Evidence.last_ssh_error = Get-NativeLastErrorLine -StdErr $remote.StdErr -StdOut $remote.StdOut }
        }
        catch { $Evidence.last_ssh_error = $_.Exception.Message }
    }
    if ($Evidence.remote_command_ready -eq 'PASS') {
        try {
            $os = Invoke-NativeDirectSshProbe -SshExecutable $SshExecutable -Address $Evidence.address -Port $Evidence.port -User $Evidence.user -PrivateKey $PrivateKey -WorkingDirectory $WorkingDirectory -Command 'cat /etc/os-release'
            [IO.File]::WriteAllText((Join-Path $diagnostics 'os-release.txt'), "exit=$($os.ExitCode)`n$($os.StdOut)`n$($os.StdErr)")
            if ($os.ExitCode -eq 0 -and $os.StdOut -match '(?m)^ID=rocky\s*$' -and
                $os.StdOut -match '(?m)^VERSION_ID="?10\.2"?\s*$') {
                $Evidence.rocky_runtime = 'PASS'
                $Evidence.rocky_version = '10.2'
                $Evidence.rocky_runtime_at = [DateTime]::UtcNow.ToString('o')
            }
            else { $Evidence.last_ssh_error = 'Guest /etc/os-release does not prove Rocky Linux 10.2' }
        }
        catch { $Evidence.last_ssh_error = $_.Exception.Message }
    }
    if ($Evidence.rocky_runtime -eq 'PASS') {
        $Evidence.vagrant_ssh_command_attempts = 1
        try {
            $wrapper = Invoke-BoundedProcess -FilePath $Vagrant -Arguments @('ssh', '-c', 'true') -TimeoutSeconds 20 -WorkingDirectory $WorkingDirectory -Environment $Environment
            $Evidence.vagrant_ssh_command = if ($wrapper.ExitCode -eq 0) { 'PASS' } else { 'FAIL_NON_BLOCKING' }
            [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-command.txt'), "exit=$($wrapper.ExitCode)`n$($wrapper.StdOut)`n$($wrapper.StdErr)")
        }
        catch {
            $Evidence.vagrant_ssh_command = 'FAIL_NON_BLOCKING'
            [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-command.txt'), $_.Exception.Message)
        }
    }
    $Evidence.boot_to_ip_seconds = Get-NativeSshSeconds $Evidence.vm_running_at $Evidence.ip_ready_at
    $Evidence.ip_to_tcp22_seconds = Get-NativeSshSeconds $Evidence.ip_ready_at $Evidence.tcp_22_ready_at
    $Evidence.tcp22_to_ssh_auth_seconds = Get-NativeSshSeconds $Evidence.tcp_22_ready_at $Evidence.ssh_auth_ready_at
    $Evidence.ssh_auth_to_vagrant_ready_seconds = Get-NativeSshSeconds $Evidence.ssh_auth_ready_at $Evidence.vagrant_ready_at
    $Evidence.boot_to_vagrant_ready_seconds = Get-NativeSshSeconds $Evidence.vm_running_at $Evidence.vagrant_ready_at
    $Evidence.ssh_to_remote_command_seconds = Get-NativeSshSeconds $Evidence.ssh_auth_ready_at $Evidence.remote_command_at
    $Evidence.boot_to_remote_command_seconds = Get-NativeSshSeconds $Evidence.vm_running_at $Evidence.remote_command_at
    $Evidence.total_smoke_seconds = Get-NativeSshSeconds $Evidence.vagrant_up_started_at ([DateTime]::UtcNow.ToString('o'))
    if ($Evidence.tcp_22_ready -eq 'PASS' -and $Evidence.ssh_auth_ready -ne 'PASS' -and $Evidence.last_ssh_error) {
        $Evidence.failure_stage = 'ssh_auth_ready'
        $Evidence.failure_reason = [string]$Evidence.last_ssh_error
    }
    foreach ($stage in @('vm_running','tcp_22_ready','ssh_auth_ready','ip_ready','vagrant_ready','ssh_config','remote_command_ready','rocky_runtime')) {
        if ($Evidence.failure_stage) { break }
        if ($Evidence[$stage] -ne 'PASS') {
            $Evidence.failure_stage = $stage
            $Evidence.failure_reason = if ($stage -in @('ssh_auth_ready','ssh_config','remote_command_ready','rocky_runtime') -and $Evidence.last_ssh_error) { [string]$Evidence.last_ssh_error } elseif ($stage -eq 'vagrant_ready' -and $Evidence.last_vagrant_error) { [string]$Evidence.last_vagrant_error } elseif ($stage -eq 'ip_ready') { 'Guest IPv4 is not exposed by VirtualBox guestproperty and could not be read through authenticated SSH' } elseif ($stage -eq 'tcp_22_ready' -and ($null -eq $Evidence.address -or $null -eq $Evidence.port)) { 'VirtualBox NAT SSH forwarding is absent from showvminfo' } elseif ($stage -eq 'tcp_22_ready') { "No SSH banner was observed at $($Evidence.address):$($Evidence.port) before the global deadline" } else { "Stage $stage did not pass; inspect $diagnostics" }
            break
        }
    }
    if ($Evidence.Contains('terminal_auth_error')) { $Evidence.Remove('terminal_auth_error') }
    if ($Evidence.failure_stage) {
        $Evidence.failure_code = Get-NativeSshFailureCode -Stage ([string]$Evidence.failure_stage) -Detail ([string]$Evidence.failure_reason)
        if ($Evidence.failure_stage -eq 'tcp_22_ready' -and $Evidence.tcp_last_error) {
            $Evidence.failure_code = [string]$Evidence.tcp_last_error
        }
        if ($Evidence.failure_stage -eq 'ssh_auth_ready') { $Evidence.ssh_failure_class = $Evidence.failure_code }
    }
}
