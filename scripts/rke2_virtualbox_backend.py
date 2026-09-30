"""Observe the actual VirtualBox backend of an owned RKE2 fixture before installation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def _run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    if result.returncode:
        raise ValueError(f"VirtualBox backend probe failed: {argv[0]}")
    return result.stdout.decode("utf-8-sig").strip()


def _field(info: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}="?([^"\r\n]+)"?\r?$', info, re.MULTILINE)
    if not match:
        raise ValueError(f"VirtualBox backend probe lacks {name}")
    return match.group(1)


def classify_log(log: str) -> str:
    if re.search(r"(?im)Attempting fall back to NEM|\bNEM:|WHvCapabilityCodeHypervisorPresent", log):
        return "NEM"
    if re.search(r"(?im)HM: HMR3Init: VT-x w/ nested paging", log):
        return "NATIVE_VTX"
    raise ValueError("VirtualBox backend is unclassified")


def probe(vm_name: str, *, expected_cpus: int, expected_memory: int,
          expected_version: str, minimum_log_mtime: float,
          snapshot_path: Path | None = None) -> dict[str, object]:
    if re.fullmatch(r"ecommerce-mgmt-test-[a-z0-9-]+", vm_name) is None:
        raise ValueError("VirtualBox backend probe requires an owned fixture name")
    info = _run([VBOX, "showvminfo", vm_name, "--machinereadable"])
    vm_uuid = _field(info, "UUID").lower()
    if not UUID.fullmatch(vm_uuid) or _field(info, "VMState") != "running":
        raise ValueError("VirtualBox fixture identity or running state is invalid")
    if int(_field(info, "cpus")) != expected_cpus or int(_field(info, "memory")) != expected_memory:
        raise ValueError("VirtualBox fixture CPU or memory differs from requested runtime")
    version = _run([VBOX, "--version"])
    if not re.fullmatch(re.escape(expected_version) + r"r[0-9]+", version):
        raise ValueError("VirtualBox version differs from the pinned runtime")
    command = (
        "$c=Get-CimInstance Win32_ComputerSystem;"
        "[pscustomobject]@{hypervisor_present=[bool]$c.HypervisorPresent;"
        "logical_processors=[int]$c.NumberOfLogicalProcessors} | ConvertTo-Json -Compress"
    )
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    host = json.loads(_run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]))
    if (type(host.get("hypervisor_present")) is not bool
        or type(host.get("logical_processors")) is not int
        or host["logical_processors"] < expected_cpus):
        raise ValueError("Windows host CPU or hypervisor capacity is invalid")
    folder = Path(_run(["wslpath", "-u", _field(info, "LogFldr")]))
    log = folder / "VBox.log"
    if log.is_symlink() or not log.is_file() or log.stat().st_mtime < minimum_log_mtime - 1:
        raise ValueError("current VirtualBox runtime log is absent or stale")
    if log.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("current VirtualBox runtime log exceeds the 16 MiB evidence bound")
    log_bytes = log.read_bytes()
    if len(log_bytes) > 16 * 1024 * 1024:
        raise ValueError("current VirtualBox runtime log grew beyond the evidence bound")
    backend = classify_log(log_bytes.decode("utf-8", errors="replace"))
    if backend == "NATIVE_VTX" and host["hypervisor_present"]:
        raise ValueError("native VT-x log contradicts the current Windows hypervisor state")
    if snapshot_path is not None:
        snapshot_path = Path(snapshot_path)
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".backend-VBox-", dir=snapshot_path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(log_bytes)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, snapshot_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {
        "schema_version": 1, "status": "PASS", "vm_name": vm_name,
        "vm_uuid": vm_uuid, "virtualbox_version": version,
        "virtualbox_backend": backend,
        "virtualbox_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "hypervisor_present": host["hypervisor_present"],
        "host_logical_processors": host["logical_processors"],
        "vm_cpus": expected_cpus, "vm_memory_mib": expected_memory,
    }
