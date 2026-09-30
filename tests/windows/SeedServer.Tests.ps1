Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$server = Join-Path $PSScriptRoot '..\..\scripts\windows\local-services-seed-server.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$seed = Join-Path $tempRoot ('ecommerce-seed-regression-' + [Guid]::NewGuid().ToString('N'))
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
try {
    [void](New-Item -ItemType Directory -Path $seed)
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'), "instance-id: regression`n")
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'), "#cloud-config`n")
    $listener.Start()
    $port = [int]$listener.LocalEndpoint.Port
    $listener.Stop()

    $started = & $server -Action Start -SeedRoot $seed -Port $port
    if ($LASTEXITCODE -ne 0 -or $started -ne 'NOCLOUD_SEED_SERVER: PASS') {
        throw 'NoCloud seed server did not start'
    }
    foreach ($name in @('vendor-data', 'network-config')) {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$port/$name" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -ne 200 -or $response.RawContentLength -ne 0) {
            throw "Empty optional NoCloud response is invalid: $name"
        }
        $serverPid = [int]([IO.File]::ReadAllText((Join-Path $seed 'seed-server.pid')).Trim())
        if (-not (Get-Process -Id $serverPid -ErrorAction SilentlyContinue)) {
            throw "NoCloud seed server exited after empty optional response: $name"
        }
    }
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$port/meta-data" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -ne 200 -or $response.Content -ne "instance-id: regression`n") {
        throw 'NoCloud seed server did not serve required metadata after an empty response'
    }
    [Console]::WriteLine('PASS NoCloud empty optional responses preserve the server')
}
finally {
    $listener.Stop()
    if (Test-Path -LiteralPath (Join-Path $seed 'seed-server.pid')) {
        & $server -Action Stop -SeedRoot $seed -Port $port | Out-Null
    }
    $resolved = [IO.Path]::GetFullPath($seed)
    if ($resolved.StartsWith($tempRoot + '\ecommerce-seed-regression-', [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolved -PathType Container)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
