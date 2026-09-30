"""Windows IPC adapters only; Ansible owns VM/guest lifecycle and configuration."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import time
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
  $homeRoot = Join-Path $r.directory "vagrant-home"
  $boxCache = Join-Path $homeRoot "boxes"
  foreach ($candidate in @($r.directory, $homeRoot, $boxCache)) {
    if (Test-Path -LiteralPath $candidate) {
      $entry = Get-Item -LiteralPath $candidate -Force
      if (-not $entry.PSIsContainer -or
          ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Vagrant state or box cache is redirected: $candidate"
      }
    }
  }
  if (Test-Path -LiteralPath (Join-Path $homeRoot "Vagrantfile")) {
    throw "Unexpected global Vagrantfile in isolated VM home"
  }
  if ($r.fresh_box -and (Test-Path -LiteralPath $boxCache)) {
    if (@(Get-ChildItem -LiteralPath $boxCache -Force).Count -ne 0) {
      throw "Fresh VM creation requires an empty isolated Vagrant box cache"
    }
  }
  foreach ($name in @("VAGRANT_CWD", "VAGRANT_DOTFILE_PATH", "VAGRANT_VAGRANTFILE",
                     "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH",
                     "BUNDLE_GEMFILE", "BUNDLE_PATH")) {
    [Environment]::SetEnvironmentVariable($name, $null, "Process")
  }
  $env:VAGRANT_HOME = $homeRoot
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
throw "Unsupported transport mode"
"""


def windows_path(path: Path) -> str:
    return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()


def wait_for_bootstrap_marker(state: Path, *, nonce: str, minimum_mtime_ns: int,
                              offset: int, timeout_seconds: int = 300) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", nonce) is None or minimum_mtime_ns <= 0 or offset < 0:
        raise ValueError("invalid serial bootstrap binding")
    serial = state / "bootstrap-serial.log"
    marker = re.compile(
        rf"(?m)^MGMT_BOOTSTRAP_READY:{nonce} "
        r"MGMT_HOST_KEY:(ssh-ed25519 [A-Za-z0-9+/=]+)\r?$"
    )
    failure = re.compile(
        rf"(?m)^MGMT_BOOTSTRAP_FAIL:{nonce} "
        r"stage=([a-z_]+) rc=([1-9][0-9]*)\r?$"
    )
    cursor = offset
    data = ""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            status = serial.stat()
            if status.st_mtime_ns >= minimum_mtime_ns:
                if status.st_size < cursor:
                    # VirtualBox may truncate a prior serial file on an explicit resume.
                    cursor = 0
                    data = ""
                with serial.open("rb") as source:
                    source.seek(cursor)
                    chunk = source.read(65536)
                    cursor = source.tell()
                if chunk:
                    data = (data + chunk.decode("utf-8", errors="replace"))[-131072:]
                    failed = failure.search(data)
                    if failed:
                        diagnostic = [
                            line[:219] for line in data[failed.end():].splitlines()
                            if line.startswith("MGMT_BOOTSTRAP_LOG:")
                        ][:12]
                        detail = " | ".join(diagnostic)
                        raise ValueError(
                            f"NoCloud bootstrap failed at {failed.group(1)} "
                            f"(exit {failed.group(2)})" + (f": {detail}" if detail else "")
                        )
                    match = marker.search(data)
                    if match:
                        return match.group(0).rstrip("\r")
        except (FileNotFoundError, PermissionError):
            pass
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError("fresh NoCloud serial bootstrap marker missing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("vagrant", "console", "proxy"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--nonce")
    parser.add_argument("--minimum-mtime-ns", type=int)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--fresh-box", action="store_true")
    args, arguments = parser.parse_known_args()
    if args.mode != "vagrant" and arguments:
        parser.error("unexpected transport arguments")
    vagrant_args = [item for item in arguments if item != "--"]
    if args.fresh_box and (args.mode != "vagrant" or vagrant_args not in (
        ["validate"], ["up", "--provider", "virtualbox", "--no-provision"],
    )):
        raise ValueError("fresh box cache check is only valid for new VM validation or boot")
    state = args.state.resolve()
    runtime = json.loads((state / "runtime.json").read_text())
    if not re.fullmatch(r"ecommerce-mgmt-test-[a-z0-9-]+", runtime["name"]):
        raise ValueError("refuse non-test VM identity")
    address = ipaddress.IPv4Address(runtime["address"])
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError("private host-only test address required")
    if args.mode == "console":
        if args.nonce is None or args.minimum_mtime_ns is None:
            raise ValueError("serial bootstrap requires seed nonce and boot timestamp")
        print(wait_for_bootstrap_marker(
            state, nonce=args.nonce, minimum_mtime_ns=args.minimum_mtime_ns,
            offset=args.offset,
        ))
        return 0
    request = {"mode": args.mode, "name": runtime["name"]}
    if args.mode == "vagrant":
        request.update(
            directory=windows_path(state),
            executable=runtime["vagrant_windows"],
            arguments=vagrant_args,
            fresh_box=args.fresh_box,
        )
    elif args.mode == "proxy":
        request["address"] = str(address)
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
