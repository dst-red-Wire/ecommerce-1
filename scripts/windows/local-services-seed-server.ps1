[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Serve', 'Stop')]
    [string]$Action,
    [Parameter(Mandatory = $true)][string]$SeedRoot,
    [Parameter(Mandatory = $true)][ValidateRange(1024, 65535)][int]$Port
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$seed = [IO.Path]::GetFullPath($SeedRoot)
$pidPath = Join-Path $seed 'seed-server.pid'
$readyPath = Join-Path $seed 'seed-server.ready'
$stopPath = Join-Path $seed 'seed-server.stop'

function ConvertTo-SingleQuotedPowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-ServeEncodedCommand {
    $command = @(
        '&', (ConvertTo-SingleQuotedPowerShellLiteral $PSCommandPath),
        '-Action', "'Serve'",
        '-SeedRoot', (ConvertTo-SingleQuotedPowerShellLiteral $seed),
        '-Port', "'$Port'"
    ) -join ' '
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
}

if ($Action -eq 'Start') {
    foreach ($required in @('meta-data', 'user-data')) {
        if (-not (Test-Path -LiteralPath (Join-Path $seed $required) -PathType Leaf)) {
            throw "NoCloud seed file is absent: $required"
        }
    }
    if (Test-Path -LiteralPath $pidPath -PathType Leaf) {
        $stalePid = [int]([IO.File]::ReadAllText($pidPath, [Text.Encoding]::UTF8).Trim())
        if (Get-Process -Id $stalePid -ErrorAction SilentlyContinue) {
            throw 'Refusing to overwrite the PID of an active NoCloud seed server candidate'
        }
        Remove-Item -LiteralPath $pidPath -Force
    }
    Remove-Item -LiteralPath $readyPath, $stopPath -Force -ErrorAction SilentlyContinue
    $encoded = Get-ServeEncodedCommand
    $process = Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded
    )
    [IO.File]::WriteAllText($pidPath, [string]$process.Id, [Text.UTF8Encoding]::new($false))
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
            if ($process.HasExited) { throw 'NoCloud seed server exited before readiness' }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { throw 'NoCloud seed server readiness timed out' }
    } catch {
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        Remove-Item -LiteralPath $pidPath, $readyPath, $stopPath -Force -ErrorAction SilentlyContinue
        throw
    }
    Write-Output 'NOCLOUD_SEED_SERVER: PASS'
    exit 0
}

if ($Action -eq 'Stop') {
    if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) {
        Remove-Item -LiteralPath $readyPath, $stopPath -Force -ErrorAction SilentlyContinue
        Write-Output 'NOCLOUD_SEED_SERVER_STOP: PASS'
        exit 0
    }
    $ownedPid = [int]([IO.File]::ReadAllText($pidPath, [Text.Encoding]::UTF8).Trim())
    [IO.File]::WriteAllText($stopPath, 'stop', [Text.UTF8Encoding]::new($false))
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline -and (Get-Process -Id $ownedPid -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 100
    }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid" -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $expectedEncoded = Get-ServeEncodedCommand
        if ([string]$process.CommandLine -notlike "*$expectedEncoded*") {
            throw 'Refusing to stop a process that is not the owned NoCloud seed server'
        }
        Stop-Process -Id $ownedPid -Force
    }
    Remove-Item -LiteralPath $pidPath, $readyPath, $stopPath -Force -ErrorAction SilentlyContinue
    Write-Output 'NOCLOUD_SEED_SERVER_STOP: PASS'
    exit 0
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
try {
    $listener.Start()
    [IO.File]::WriteAllText($readyPath, 'ready', [Text.UTF8Encoding]::new($false))
    while (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 100
            continue
        }
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 4096, $true)
            $requestLine = $reader.ReadLine()
            while (($line = $reader.ReadLine()) -ne $null -and $line.Length -gt 0) { }
            $match = [regex]::Match([string]$requestLine, '^GET /(?<name>meta-data|user-data|vendor-data|network-config) HTTP/1\.[01]$')
            if ($match.Success) {
                $name = $match.Groups['name'].Value
                $path = Join-Path $seed $name
                $body = if (Test-Path -LiteralPath $path -PathType Leaf) { [IO.File]::ReadAllBytes($path) } else { [byte[]]@() }
                $header = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
            } else {
                $body = [Text.Encoding]::UTF8.GetBytes("not found`n")
                $header = "HTTP/1.1 404 Not Found`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
            }
            $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
            $stream.Write($headerBytes, 0, $headerBytes.Length)
            $stream.Write($body, 0, $body.Length)
            $stream.Flush()
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
    Remove-Item -LiteralPath $readyPath -Force -ErrorAction SilentlyContinue
}
