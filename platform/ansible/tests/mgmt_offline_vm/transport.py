"""Windows IPC adapters only; Ansible owns VM/guest lifecycle and configuration."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
PS = r"""
param([string]$Request)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$r = Get-Content -Raw -LiteralPath $Request | ConvertFrom-Json
if ($r.mode -eq "vagrant") {
  Set-Location -LiteralPath $r.directory
  $env:VAGRANT_HOME = Join-Path $r.directory "vagrant-home"
  $env:VAGRANT_CHECKPOINT_DISABLE = "1"
  $env:VAGRANT_DEFAULT_PROVIDER = "virtualbox"
  $env:VAGRANT_EXPERIMENTAL = "none_communicator"
  $env:VAGRANT_NO_PLUGINS = "1"
  & $r.executable @($r.arguments)
  exit $LASTEXITCODE
}
if ($r.mode -eq "proxy") {
  $client = [Net.Sockets.TcpClient]::new()
  $connecting = $client.ConnectAsync($r.address, 22)
  if (-not $connecting.Wait(10000)) { $client.Dispose(); throw "Timed out connecting to owned VM SSH" }
  $connecting.GetAwaiter().GetResult()
  $stream = $client.GetStream()
  $readTask = $stream.CopyToAsync([Console]::OpenStandardOutput())
  $writeTask = [Console]::OpenStandardInput().CopyToAsync($stream)
  try {
    $completed = [Threading.Tasks.Task]::WhenAny([Threading.Tasks.Task[]]@($readTask, $writeTask)).GetAwaiter().GetResult()
    $completed.GetAwaiter().GetResult()
  } finally { $client.Dispose() }
  exit 0
}
if ($r.mode -eq "console") {
  $pipe = [IO.Pipes.NamedPipeClientStream]::new(".", $r.name, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
  $pipe.Connect(10000)
  function Send-Line([string]$line) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($line + "`r")
    $pipe.Write($bytes, 0, $bytes.Length)
    $pipe.Flush()
  }
  function Read-Until([string]$pattern) {
    $buffer = New-Object byte[] 16384
    $text = ""
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    while ([DateTime]::UtcNow -lt $deadline) {
      $task = $pipe.ReadAsync($buffer, 0, $buffer.Length)
      if (-not $task.Wait(180000)) { throw "Timed out waiting for isolated VM console" }
      if ($task.Result -eq 0) { throw "Console disconnected" }
      $text += [Text.Encoding]::UTF8.GetString($buffer, 0, $task.Result)
      if ($text -match $pattern) { return $text }
    }
    throw "Expected console prompt missing"
  }
  try {
    Send-Line ""
    $initial = Read-Until 'login:|\]\$ '
    if ($initial -notmatch '\]\$ ') {
      Send-Line "vagrant"
      $null = Read-Until "Password:"
      # Public image-fixture login, never a host/operator credential.
      Send-Line "vagrant"
      $null = Read-Until '\]\$ '
    }
    Send-Line ("printf %s " + $r.payload + " | base64 -d | sudo -n /bin/bash")
    $output = Read-Until 'MGMT_CONSOLE_RESULT:[0-9]+'
    [Console]::Write($output)
    if ($output -notmatch 'MGMT_CONSOLE_RESULT:0') { exit 1 }
  } finally { $pipe.Dispose() }
  exit 0
}
throw "Unsupported transport mode"
"""


def windows_path(path: Path) -> str:
    return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("vagrant", "console", "proxy"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--script", type=Path)
    args, arguments = parser.parse_known_args()
    if args.mode != "vagrant" and arguments:
        parser.error("unexpected transport arguments")
    state = args.state.resolve()
    runtime = json.loads((state / "runtime.json").read_text())
    if not re.fullmatch(r"ecommerce-mgmt-test-[a-z0-9-]+", runtime["name"]):
        raise ValueError("refuse non-test VM identity")
    address = ipaddress.IPv4Address(runtime["address"])
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError("private host-only test address required")
    request = {"mode": args.mode, "name": runtime["name"]}
    if args.mode == "vagrant":
        request.update(
            directory=windows_path(state),
            executable=runtime["vagrant_windows"],
            arguments=[item for item in arguments if item != "--"],
        )
    elif args.mode == "proxy":
        request["address"] = str(address)
    else:
        if args.script is None:
            raise ValueError("console guest script required")
        # Exit status marker is encoded too, so input echo cannot impersonate it.
        payload = "(\n" + args.script.read_text() + "\n)\nresult=$?\nprintf 'MGMT_CONSOLE_RESULT:%s\\n' \"$result\"\n"
        request["payload"] = base64.b64encode(payload.encode()).decode()
        if len(request["payload"]) > 3700:
            raise ValueError("guest console payload exceeds safe terminal line budget")
    bridge = state / "ipc-transport.ps1"
    if not bridge.exists() or bridge.read_text() != PS:
        bridge.write_text(PS)
    request_path = state / f"ipc-{args.mode}.json"
    contents = json.dumps(request)
    if not request_path.exists() or request_path.read_text() != contents:
        request_path.write_text(contents)
    return subprocess.call(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            windows_path(bridge),
            "-Request",
            windows_path(request_path),
        ]
    )


if __name__ == "__main__":
    sys.exit(main())
