"""Fail-closed Windows/WSL2 capacity gate for the local six-VM HA fixture."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from lifecycle_guard import REGISTERED_VM_RE, run_windows_command

WINDOWS_FACTS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$os = Get-CimInstance Win32_OperatingSystem
$memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$computer = Get-CimInstance Win32_ComputerSystem
$pagefiles = @(Get-CimInstance Win32_PageFileUsage)
$wslconfig = Join-Path $env:USERPROFILE '.wslconfig'
$configBytes = if (Test-Path -LiteralPath $wslconfig -PathType Leaf) {
  [System.IO.File]::ReadAllBytes($wslconfig)
} else {
  $null
}
$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
$runningDistributions = @(
  & $wsl --list --running --quiet |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' }
)
$payload = [ordered]@{
  available_memory_mib = [long][Math]::Floor($os.FreePhysicalMemory / 1024)
  committed_mib = [long][Math]::Floor($memory.CommittedBytes / 1MB)
  commit_limit_mib = [long][Math]::Floor($memory.CommitLimit / 1MB)
  commit_headroom_mib = [long][Math]::Floor(($memory.CommitLimit - $memory.CommittedBytes) / 1MB)
  automatic_managed_pagefile = [bool]$computer.AutomaticManagedPagefile
  pagefile_count = [long]$pagefiles.Count
  pagefile_allocated_mib = [long](($pagefiles | Measure-Object -Property AllocatedBaseSize -Sum).Sum)
  process_names = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
  running_wsl_distributions = $runningDistributions
  wslconfig_base64 = if ($null -eq $configBytes) { $null } else { [Convert]::ToBase64String($configBytes) }
}
$payload | ConvertTo-Json -Compress -Depth 4
""".strip()

SIZE_RE = re.compile(r"^(?P<value>[1-9][0-9]*)(?P<unit>KB|MB|GB)$", re.IGNORECASE)


def parse_wslconfig(contents: str) -> dict[str, dict[str, str]]:
    """Parse the strict section/key subset used by the pinned test projection."""
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for number, raw in enumerate(contents.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().casefold()
            if not current or current in sections:
                raise ValueError(
                    f"invalid or duplicate .wslconfig section at line {number}"
                )
            sections[current] = {}
            continue
        if current is None or "=" not in line:
            raise ValueError(f"invalid .wslconfig entry at line {number}")
        key, value = (part.strip() for part in line.split("=", 1))
        normalized_key = key.casefold()
        if not normalized_key or not value or normalized_key in sections[current]:
            raise ValueError(f"invalid or duplicate .wslconfig key at line {number}")
        sections[current][normalized_key] = value.casefold()
    if not sections:
        raise ValueError("empty .wslconfig")
    return sections


def size_mib(value: str) -> int:
    match = SIZE_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"unsupported .wslconfig size: {value}")
    size = int(match.group("value"))
    unit = match.group("unit").upper()
    if unit == "KB":
        if size % 1024:
            raise ValueError(".wslconfig KB size must resolve to whole MiB")
        return size // 1024
    if unit == "GB":
        return size * 1024
    return size


def meminfo_mib(path: Path = Path("/proc/meminfo")) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.split()
        if fields and fields[0].isdigit():
            values[name] = int(fields[0]) // 1024
    return values


def collect_windows_facts(powershell: str) -> dict[str, Any]:
    result = run_windows_command(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", WINDOWS_FACTS_SCRIPT]
    )
    if result.returncode != 0:
        raise RuntimeError("Windows host fact collection failed")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise TypeError("Windows host facts must be a JSON object")
    return payload


def registered_vm_names(vbox: str) -> list[str]:
    result = run_windows_command([vbox, "list", "vms"])
    if result.returncode != 0:
        raise RuntimeError("VirtualBox registration query failed")
    names: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        match = REGISTERED_VM_RE.fullmatch(line)
        if match is None:
            raise RuntimeError("VirtualBox returned an unparseable registration")
        names.append(match.group("name"))
    if len(names) != len(set(names)):
        raise RuntimeError("VirtualBox returned duplicate VM names")
    return sorted(names)


def linux_container_runtime_facts() -> dict[str, Any]:
    """Collect local Linux runtime state without starting a daemon."""
    processes: set[str] = set()
    for candidate in Path("/proc").iterdir():
        if not candidate.name.isdigit():
            continue
        try:
            name = (candidate / "comm").read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name in {"dockerd", "containerd", "rootlesskit", "slirp4netns"} or name.startswith(
            "containerd-shim"
        ):
            processes.add(name)

    def active(command: list[str]) -> bool:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "active"

    docker = shutil.which("docker")
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix:///run/user/{os.getuid()}/docker.sock"
    daemon_reachable = False
    running_container_count = 0
    if docker:
        info = subprocess.run(
            [docker, "info"],
            env=environment,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        daemon_reachable = info.returncode == 0
        if daemon_reachable:
            containers = subprocess.run(
                [docker, "ps", "-q"],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if containers.returncode != 0:
                raise RuntimeError("active Docker daemon container query failed")
            running_container_count = len(
                [line for line in containers.stdout.splitlines() if line.strip()]
            )
    return {
        "daemon_reachable": daemon_reachable,
        "running_container_count": running_container_count,
        "process_names": sorted(processes),
        "user_docker_service_active": active(
            ["systemctl", "--user", "is-active", "docker.service"]
        ),
        "system_docker_service_active": active(
            ["systemctl", "is-active", "docker.service"]
        ),
        "system_containerd_service_active": active(
            ["systemctl", "is-active", "containerd.service"]
        ),
    }


def evaluate(
    *,
    windows: dict[str, Any],
    wsl_runtime: dict[str, int],
    expected_wslconfig: str,
    actual_wslconfig: str,
    registered_vms: list[str],
    campaign_vm_names: list[str],
    minimum_available_mib: int,
    minimum_commit_headroom_mib: int,
    forbidden_docker_processes: list[str],
    forbidden_docker_distributions: list[str],
    linux_container_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expected = parse_wslconfig(expected_wslconfig)
    actual = parse_wslconfig(actual_wslconfig)
    expected_wsl2 = expected.get("wsl2", {})
    expected_memory_mib = size_mib(expected_wsl2.get("memory", ""))
    expected_swap_mib = size_mib(expected_wsl2.get("swap", ""))
    expected_processors = int(expected_wsl2.get("processors", "0"))

    available_mib = int(windows["available_memory_mib"])
    commit_headroom_mib = int(windows["commit_headroom_mib"])
    pagefile_count = int(windows["pagefile_count"])
    pagefile_allocated_mib = int(windows["pagefile_allocated_mib"])
    automatic_pagefile = windows["automatic_managed_pagefile"] is True

    running_processes = {
        str(value).replace("\x00", "").casefold()
        for value in windows.get("process_names", [])
    }
    running_distributions = {
        str(value).replace("\x00", "").casefold()
        for value in windows.get("running_wsl_distributions", [])
    }
    matched_processes = sorted(
        value
        for value in forbidden_docker_processes
        if value.casefold() in running_processes
    )
    matched_distributions = sorted(
        value
        for value in forbidden_docker_distributions
        if value.casefold() in running_distributions
    )
    stale_vms = sorted(set(registered_vms) & set(campaign_vm_names))
    linux_runtime = linux_container_runtime or {}
    linux_runtime_processes = sorted(
        str(value) for value in linux_runtime.get("process_names", [])
    )
    linux_runtime_active = (
        linux_runtime.get("daemon_reachable") is True
        or int(linux_runtime.get("running_container_count", 0)) > 0
        or bool(linux_runtime_processes)
        or linux_runtime.get("user_docker_service_active") is True
        or linux_runtime.get("system_docker_service_active") is True
        or linux_runtime.get("system_containerd_service_active") is True
        or not linux_runtime
    )

    runtime_memory_mib = int(wsl_runtime["memory_mib"])
    runtime_processors = int(wsl_runtime["processors"])
    runtime_swap_mib = int(wsl_runtime["swap_mib"])
    swap_tolerance_mib = 64

    checks = {
        "docker_desktop_stopped": {
            "status": "PASS"
            if not matched_processes and not matched_distributions
            else "FAIL",
            "running_processes": matched_processes,
            "running_distributions": matched_distributions,
        },
        "linux_container_runtime_stopped": {
            "status": "FAIL" if linux_runtime_active else "PASS",
            "daemon_reachable": linux_runtime.get("daemon_reachable"),
            "running_container_count": linux_runtime.get("running_container_count"),
            "process_names": linux_runtime_processes,
            "user_docker_service_active": linux_runtime.get(
                "user_docker_service_active"
            ),
            "system_docker_service_active": linux_runtime.get(
                "system_docker_service_active"
            ),
            "system_containerd_service_active": linux_runtime.get(
                "system_containerd_service_active"
            ),
        },
        "campaign_vms_absent": {
            "status": "PASS" if not stale_vms else "FAIL",
            "registered_campaign_vms": stale_vms,
        },
        "windows_available_memory": {
            "status": "PASS" if available_mib >= minimum_available_mib else "FAIL",
            "actual_mib": available_mib,
            "minimum_mib": minimum_available_mib,
        },
        "windows_commit_headroom": {
            "status": "PASS"
            if commit_headroom_mib >= minimum_commit_headroom_mib
            else "FAIL",
            "actual_mib": commit_headroom_mib,
            "minimum_mib": minimum_commit_headroom_mib,
        },
        "windows_pagefile": {
            "status": (
                "PASS"
                if automatic_pagefile
                and pagefile_count > 0
                and pagefile_allocated_mib > 0
                else "FAIL"
            ),
            "automatic_management": automatic_pagefile,
            "count": pagefile_count,
            "allocated_mib": pagefile_allocated_mib,
        },
        "wslconfig_projection": {
            "status": "PASS" if actual == expected else "FAIL",
            "expected_sha256": hashlib.sha256(
                expected_wslconfig.encode("utf-8")
            ).hexdigest(),
            "actual_sha256": hashlib.sha256(
                actual_wslconfig.encode("utf-8")
            ).hexdigest(),
        },
        "wsl_runtime_limits": {
            "status": (
                "PASS"
                if runtime_memory_mib <= expected_memory_mib
                and runtime_processors == expected_processors
                and abs(runtime_swap_mib - expected_swap_mib) <= swap_tolerance_mib
                else "FAIL"
            ),
            "memory_mib": runtime_memory_mib,
            "maximum_memory_mib": expected_memory_mib,
            "processors": runtime_processors,
            "expected_processors": expected_processors,
            "swap_mib": runtime_swap_mib,
            "expected_swap_mib": expected_swap_mib,
        },
    }
    failures = sorted(
        name for name, check in checks.items() if check["status"] != "PASS"
    )
    return {
        "schema_version": 1,
        "scope": "windows-wsl2-virtualbox-local-ha-test-only",
        "applies_to_preprod": False,
        "status": "PASS" if not failures else "FAIL",
        "checks": checks,
        "failures": failures,
    }


def _json_list(value: str, label: str) -> list[str]:
    parsed = json.loads(value)
    if (
        not isinstance(parsed, list)
        or not parsed
        or any(not isinstance(item, str) for item in parsed)
    ):
        raise ValueError(f"{label} must be a non-empty JSON string array")
    if len(parsed) != len(set(parsed)):
        raise ValueError(f"{label} must not contain duplicates")
    return parsed


def _wslconfig_sections(value: str) -> dict[str, dict[str, str]]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("expected WSL config sections must be a non-empty JSON object")
    normalized: dict[str, dict[str, str]] = {}
    for section, settings in parsed.items():
        if (
            not isinstance(section, str)
            or not isinstance(settings, dict)
            or not settings
        ):
            raise ValueError("expected WSL config contains an invalid section")
        normalized_section = section.casefold()
        normalized[normalized_section] = {}
        for key, setting in settings.items():
            if not isinstance(key, str) or not isinstance(setting, (str, int, bool)):
                raise TypeError("expected WSL config contains an invalid setting")
            normalized[normalized_section][key.casefold()] = str(setting).casefold()
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--powershell", required=True)
    parser.add_argument("--vbox", required=True)
    parser.add_argument("--wslconfig-template", required=True, type=Path)
    parser.add_argument("--expected-wslconfig-json", required=True)
    parser.add_argument("--minimum-available-mib", required=True, type=int)
    parser.add_argument("--minimum-commit-headroom-mib", required=True, type=int)
    parser.add_argument("--campaign-vm-names-json", required=True)
    parser.add_argument("--forbidden-docker-processes-json", required=True)
    parser.add_argument("--forbidden-docker-distributions-json", required=True)
    args = parser.parse_args()

    try:
        if args.minimum_available_mib <= 0 or args.minimum_commit_headroom_mib <= 0:
            raise ValueError("Windows memory thresholds must be positive")
        campaign_vm_names = _json_list(args.campaign_vm_names_json, "campaign VM names")
        forbidden_processes = _json_list(
            args.forbidden_docker_processes_json, "forbidden Docker processes"
        )
        forbidden_distributions = _json_list(
            args.forbidden_docker_distributions_json, "forbidden Docker distributions"
        )
        template = args.wslconfig_template.read_text(encoding="utf-8")
        if parse_wslconfig(template) != _wslconfig_sections(
            args.expected_wslconfig_json
        ):
            raise ValueError(
                "repository WSL projection drifted from the local HA contract"
            )
        windows = collect_windows_facts(args.powershell)
        encoded_config = windows.pop("wslconfig_base64", None)
        if not isinstance(encoded_config, str) or not encoded_config:
            raise ValueError("Windows user .wslconfig is missing")
        actual_config = base64.b64decode(encoded_config, validate=True).decode(
            "utf-8-sig"
        )
        memory = meminfo_mib()
        result = evaluate(
            windows=windows,
            wsl_runtime={
                "memory_mib": memory["MemTotal"],
                "swap_mib": memory["SwapTotal"],
                "processors": os.cpu_count() or 0,
            },
            expected_wslconfig=template,
            actual_wslconfig=actual_config,
            registered_vms=registered_vm_names(args.vbox),
            campaign_vm_names=campaign_vm_names,
            minimum_available_mib=args.minimum_available_mib,
            minimum_commit_headroom_mib=args.minimum_commit_headroom_mib,
            forbidden_docker_processes=forbidden_processes,
            forbidden_docker_distributions=forbidden_distributions,
            linux_container_runtime=linux_container_runtime_facts(),
        )
    except (
        KeyError,
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        json.JSONDecodeError,
    ) as error:
        result = {
            "schema_version": 1,
            "scope": "windows-wsl2-virtualbox-local-ha-test-only",
            "applies_to_preprod": False,
            "status": "FAIL",
            "checks": {},
            "failures": [f"preflight_probe:{error}"],
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
