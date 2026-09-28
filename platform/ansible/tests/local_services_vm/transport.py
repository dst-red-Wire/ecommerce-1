#!/usr/bin/env python3
"""Bridge WSL automation to the native Windows Vagrant and SSH endpoints."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
PS = r'''
param([string]$Request)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$r = Get-Content -Raw -LiteralPath $Request | ConvertFrom-Json
if ($r.mode -eq "vagrant") {
  Set-Location -LiteralPath $r.directory
  $env:VAGRANT_HOME = $r.vagrant_home
  $env:VAGRANT_CHECKPOINT_DISABLE = "1"
  $env:VAGRANT_DEFAULT_PROVIDER = "virtualbox"
  $env:VAGRANT_EXPERIMENTAL = "none_communicator"
  $env:VAGRANT_NO_PLUGINS = "1"
  & $r.executable @($r.arguments)
  exit $LASTEXITCODE
}
if ($r.mode -eq "proxy") {
  $client = [Net.Sockets.TcpClient]::new()
  $connecting = $client.ConnectAsync("127.0.0.1", [int]$r.port)
  if (-not $connecting.Wait(10000)) { $client.Dispose(); throw "Timed out connecting to owned VM endpoint" }
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
if ($r.mode -eq "backend") {
  $idPath = Join-Path $r.directory '.vagrant\machines\default\virtualbox\id'
  $id = (Get-Content -Raw -LiteralPath $idPath).Trim()
  if ($id -notmatch '^[0-9a-fA-F-]{36}$') { throw "Invalid owned VirtualBox VM identifier" }
  $vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
  $info = & $vbox showvminfo $id --machinereadable
  if ($LASTEXITCODE -ne 0) { throw "Cannot inspect owned VirtualBox VM" }
  $logLine = @($info | Where-Object { $_ -match '^LogFldr="(?<path>[^"\r\n]+)"$' })
  if ($logLine.Count -ne 1) { throw "Cannot locate owned VirtualBox VM log" }
  [void]($logLine[0] -match '^LogFldr="(?<path>[^"\r\n]+)"$')
  $log = Get-Content -Raw -LiteralPath (Join-Path $Matches.path 'VBox.log')
  if ($log -match '(?im)Attempting fall back to NEM|\bNEM:|WHvCapabilityCodeHypervisorPresent') { [Console]::WriteLine('NEM'); exit 0 }
  if ($log -match '(?im)\bHM:.*(?:VT-x|AMD-V)') { [Console]::WriteLine('NATIVE_VTX'); exit 0 }
  [Console]::WriteLine('UNKNOWN')
  exit 0
}
throw "Unsupported transport mode"
'''


def windows_path(path: Path) -> str:
    value = subprocess.check_output(["wslpath", "-w", str(path)], text=True, timeout=15).strip()
    if not value.startswith("\\\\") and not re.fullmatch(r"[A-Za-z]:\\[^\r\n]+", value):
        raise ValueError("path is not available through the Windows bridge")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("vagrant", "proxy", "backend"))
    parser.add_argument("--state", type=Path, required=True)
    args, arguments = parser.parse_known_args()
    state = args.state.resolve()
    users_root = Path("/mnt/c/Users").resolve()
    if not state.is_relative_to(users_root):
        raise ValueError("state is outside the Windows user profiles")
    relative = state.relative_to(users_root).parts
    expected_middle = ("AppData", "Local", "Temp", "ecommerce", ".context", "local-services-vm")
    if (
        len(relative) != 9
        or relative[1:7] != expected_middle
        or re.fullmatch(r"[0-9a-f]{40}", relative[7]) is None
        or relative[8] not in {"gitea", "harbor"}
    ):
        raise ValueError("state is outside the owned local-service runtime layout")
    runtime = json.loads((state / "runtime.json").read_text(encoding="utf-8"))
    expected_name = f"ecommerce-local-{relative[8]}-{relative[7][:12]}"
    if runtime.get("name") != expected_name:
        raise ValueError("refuse non-owned VM identity")
    if runtime.get("vagrant_windows") != r"C:\Program Files\Vagrant\bin\vagrant.exe":
        raise ValueError("refuse non-canonical Vagrant executable")
    vagrant_home = Path(str(runtime.get("vagrant_home", ""))).resolve()
    if vagrant_home != state.parent / "vagrant-home":
        raise ValueError("refuse Vagrant home outside the owned runtime")
    port = int(runtime["ssh_host_port"])
    if not 1024 <= port <= 65535:
        raise ValueError("invalid owned VM SSH port")
    request = {"mode": args.mode}
    if args.mode in {"vagrant", "backend"}:
        request.update(
            directory=windows_path(state),
            vagrant_home=windows_path(vagrant_home),
        )
        if args.mode == "vagrant":
            request.update(executable=runtime["vagrant_windows"], arguments=[item for item in arguments if item != "--"])
        elif arguments:
            parser.error("backend does not accept trailing arguments")
    else:
        if arguments:
            parser.error("proxy does not accept trailing arguments")
        request["port"] = port
    suffix = f"{args.mode}-{os.getpid()}"
    bridge = state / f"ipc-transport-{suffix}.ps1"
    request_path = state / f"ipc-{suffix}.json"
    bridge.write_text(PS, encoding="utf-8")
    request_path.write_text(json.dumps(request), encoding="utf-8")
    try:
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
    finally:
        request_path.unlink(missing_ok=True)
        bridge.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
