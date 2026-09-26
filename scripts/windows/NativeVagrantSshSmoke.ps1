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
        ssh_poll_interval_seconds = 5; vagrant_up_deadline_seconds = 900
        vagrant_ssh_command = 'NOT_EXECUTED'
        boot_to_ip_seconds = $null; ip_to_tcp22_seconds = $null
        tcp22_to_ssh_auth_seconds = $null; ssh_auth_to_vagrant_ready_seconds = $null
        boot_to_vagrant_ready_seconds = $null
        failure_stage = $null; failure_reason = $null; last_ssh_error = $null
        last_vagrant_error = $null; private_key_path = $null
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

function Get-NativeLastErrorLine {
    param([string]$StdErr, [string]$StdOut)
    $source = if ($StdErr.Trim()) { $StdErr } else { $StdOut }
    $lines = @($source -split "`r?`n" | Where-Object { $_.Trim() })
    if ($lines.Count -eq 0) { return 'Process failed without diagnostic output' }
    return [string]$lines[-1]
}

function Test-NativeTcpPort {
    param([string]$Address, [int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(1500)) { return $false }
        $client.EndConnect($pending)
        $client.ReceiveTimeout = 2500
        $buffer = New-Object byte[] 64
        $read = $client.GetStream().Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return $false }
        return [Text.Encoding]::ASCII.GetString($buffer, 0, $read).StartsWith('SSH-')
    }
    catch { return $false }
    finally { $client.Close() }
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
                $stateChange = [DateTime]::MinValue
                if ([DateTime]::TryParse($Matches[1], [ref]$stateChange)) {
                    $Evidence.vm_running_at = $stateChange.ToUniversalTime().ToString('o')
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
    }
    if ($null -eq $Evidence.address -or $null -eq $Evidence.port) { return }
    if ($Evidence.tcp_22_ready -ne 'PASS') {
        if (-not (Test-NativeTcpPort -Address $Evidence.address -Port $Evidence.port)) { return }
        $Evidence.tcp_22_ready = 'PASS'
        $Evidence.tcp_22_ready_at = [DateTime]::UtcNow.ToString('o')
    }
    if ($Evidence.ssh_auth_ready -eq 'PASS' -or $Evidence.Contains('terminal_auth_error')) { return }
    if ($null -eq $Evidence.first_ssh_probe_at) {
        $Evidence.first_ssh_probe_at = [DateTime]::UtcNow.ToString('o')
        $Evidence.first_ssh_probe_delay_seconds = Get-NativeSshSeconds -Start $Evidence.vm_running_at -End $Evidence.first_ssh_probe_at
    }
    $Evidence.ssh_probe_count = [int]$Evidence.ssh_probe_count + 1
    $ssh = Invoke-BoundedProcess -FilePath $SshExecutable -Arguments @(
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
        '-o', 'ConnectTimeout=5', '-o', 'NumberOfPasswordPrompts=0',
        '-i', $PrivateKey, '-p', [string]$Evidence.port,
        "$($Evidence.user)@$($Evidence.address)", 'ip -4 -o addr show scope global'
    ) -TimeoutSeconds 10 -WorkingDirectory $WorkingDirectory
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
    $Evidence.private_key_path = $PrivateKey
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
            if ($config.StdOut -match '(?m)^\s*HostName\s+(\S+)') { $Evidence.address = $Matches[1] }
            if ($config.StdOut -match '(?m)^\s*Port\s+(\d+)') { $Evidence.port = [int]$Matches[1] }
            if ($config.StdOut -match '(?m)^\s*User\s+(\S+)') { $Evidence.user = $Matches[1] }
        }
    }
    catch { [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-config.txt'), $_.Exception.Message) }
    if ($Evidence.vm_running -eq 'PASS' -and $Evidence.ssh_auth_ready -ne 'PASS') {
        try { Update-NativeSshSmokeEvidence -Evidence $Evidence -VBoxManage $VBoxManage -VmName $VmName -WorkingDirectory $WorkingDirectory -PrivateKey $PrivateKey -SshExecutable $SshExecutable }
        catch { $Evidence.last_ssh_error = $_.Exception.Message }
    }
    if ($Evidence.ssh_auth_ready -eq 'PASS') {
        try {
            $command = Invoke-BoundedProcess -FilePath $Vagrant -Arguments @('ssh', '-c', 'true') -TimeoutSeconds 20 -WorkingDirectory $WorkingDirectory -Environment $Environment
            [IO.File]::WriteAllText((Join-Path $diagnostics 'vagrant-ssh-command.txt'), "exit=$($command.ExitCode)`n$($command.StdOut)`n$($command.StdErr)")
            if ($command.ExitCode -eq 0) { $Evidence.vagrant_ssh_command = 'PASS' }
            else { $Evidence.last_ssh_error = Get-NativeLastErrorLine -StdErr $command.StdErr -StdOut $command.StdOut }
        }
        catch { $Evidence.last_ssh_error = $_.Exception.Message }
    }
    $Evidence.boot_to_ip_seconds = Get-NativeSshSeconds $Evidence.vm_running_at $Evidence.ip_ready_at
    $Evidence.ip_to_tcp22_seconds = Get-NativeSshSeconds $Evidence.ip_ready_at $Evidence.tcp_22_ready_at
    $Evidence.tcp22_to_ssh_auth_seconds = Get-NativeSshSeconds $Evidence.tcp_22_ready_at $Evidence.ssh_auth_ready_at
    $Evidence.ssh_auth_to_vagrant_ready_seconds = Get-NativeSshSeconds $Evidence.ssh_auth_ready_at $Evidence.vagrant_ready_at
    $Evidence.boot_to_vagrant_ready_seconds = Get-NativeSshSeconds $Evidence.vm_running_at $Evidence.vagrant_ready_at
    if ($Evidence.tcp_22_ready -eq 'PASS' -and $Evidence.ssh_auth_ready -ne 'PASS' -and $Evidence.last_ssh_error) {
        $Evidence.failure_stage = 'ssh_auth_ready'
        $Evidence.failure_reason = [string]$Evidence.last_ssh_error
    }
    foreach ($stage in @('vm_running','ip_ready','tcp_22_ready','ssh_auth_ready','vagrant_ready','vagrant_ssh_command')) {
        if ($Evidence.failure_stage) { break }
        if ($Evidence[$stage] -ne 'PASS') {
            $Evidence.failure_stage = $stage
            $Evidence.failure_reason = if ($stage -in @('ssh_auth_ready','vagrant_ssh_command') -and $Evidence.last_ssh_error) { [string]$Evidence.last_ssh_error } elseif ($stage -eq 'vagrant_ready' -and $Evidence.last_vagrant_error) { [string]$Evidence.last_vagrant_error } else { "Stage $stage did not pass; inspect $diagnostics" }
            break
        }
    }
    if ($Evidence.Contains('terminal_auth_error')) { $Evidence.Remove('terminal_auth_error') }
}
