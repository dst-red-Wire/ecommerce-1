#!/usr/bin/env python3
"""Archive bounded bootstrap diagnostics and retire only an absent owned VM's seed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time


VBOX = Path("/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe")
VM_NAME = re.compile(r"ecommerce-mgmt-test-[a-z0-9-]+\Z")
VM_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
SEED_FILES = {"meta-data", "user-data", "network-config"}
MAX_RESULT_BYTES = 16384
SERIAL_TAIL_BYTES = 32768


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_file(path: Path, root: Path) -> bool:
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError(f"bootstrap cleanup target is redirected: {path.name}")
    if path.exists() and not path.is_file():
        raise ValueError(f"bootstrap cleanup target is not a file: {path.name}")
    return path.is_file()


def checked_state(state: Path, vm_name: str) -> Path:
    if VM_NAME.fullmatch(vm_name) is None or not state.is_absolute():
        raise ValueError("bootstrap cleanup requires an exact owned VM name and absolute state")
    if (state.name, state.parent.name, state.parent.parent.name,
            state.parent.parent.parent.name) != (vm_name, ".context", "ecommerce", "Temp"):
        raise ValueError("bootstrap cleanup state is outside the owned Windows runtime")
    for path in (state, state.parent, state.parent.parent, state.parent.parent.parent):
        if path.is_symlink():
            raise ValueError("bootstrap cleanup state contains a symbolic link")
    if not state.is_dir():
        raise ValueError("bootstrap cleanup state directory is absent")
    state = state.resolve(strict=True)
    runtime = state / "runtime.json"
    if not checked_file(runtime, state):
        raise ValueError("bootstrap cleanup runtime identity is absent")
    identity = json.loads(runtime.read_text(encoding="utf-8"))
    if not isinstance(identity, dict) or identity.get("name") != vm_name:
        raise ValueError("bootstrap cleanup runtime identity differs")
    vagrant_id = state / ".vagrant/machines/default/virtualbox/id"
    if vagrant_id.exists() or vagrant_id.is_symlink():
        raise ValueError("bootstrap cleanup refuses an existing Vagrant VM identity")
    return state


def checked_diagnostics(repo: Path, vm_name: str) -> Path:
    context = repo / ".context"
    parent = context / "mgmt-offline-vm"
    vm_state = parent / vm_name
    diagnostics = vm_state / "bootstrap-diagnostics"
    for path in (context, parent, vm_state, diagnostics):
        if path.is_symlink():
            raise ValueError("bootstrap diagnostics path contains a symbolic link")
    if not vm_state.is_dir():
        raise ValueError("bootstrap diagnostics VM state is absent")
    diagnostics.mkdir(mode=0o700, exist_ok=True)
    if not diagnostics.is_dir():
        raise ValueError("bootstrap diagnostics destination is invalid")
    return diagnostics.resolve(strict=True)


def cleanup(state: Path, vm_name: str, registrations: str, repo: Path,
            vm_uuid: str | None = None) -> dict[str, object]:
    state = checked_state(state, vm_name)
    if vm_uuid is not None and VM_UUID.fullmatch(vm_uuid) is None:
        raise ValueError("bootstrap cleanup owned VM UUID is malformed")
    if re.search(rf'^"{re.escape(vm_name)}"\s+\{{[0-9a-fA-F-]{{36}}\}}$', registrations, re.MULTILINE):
        raise ValueError("bootstrap cleanup refuses a still-registered owned VM")
    if vm_uuid is not None and f"{{{vm_uuid}}}" in registrations:
        raise ValueError("bootstrap cleanup refuses a still-registered owned VM UUID")
    seed = state / "seed"
    if seed.is_symlink() or (seed.exists() and not seed.is_dir()):
        raise ValueError("bootstrap seed directory is redirected")
    seed_files: list[Path] = []
    if seed.is_dir():
        entries = {path.name for path in seed.iterdir()}
        if entries != SEED_FILES:
            raise ValueError("bootstrap seed directory has missing or unexpected entries")
        for name in sorted(SEED_FILES):
            path = seed / name
            if not checked_file(path, state):
                raise ValueError(f"bootstrap seed file is absent: {name}")
            seed_files.append(path)
    iso = state / "seed.iso"
    result = state / "seed-result.json"
    serial = state / "bootstrap-serial.log"
    present = {path.name: checked_file(path, state) for path in (iso, result, serial)}
    if not seed_files and not any(present.values()):
        return {"status": "PASS", "archived": False, "removed": []}
    seed_result: dict[str, object] | None = None
    if present[result.name]:
        if result.stat().st_size > MAX_RESULT_BYTES:
            raise ValueError("bootstrap seed result exceeds the diagnostic bound")
        seed_result = json.loads(result.read_text(encoding="utf-8"))
        if not isinstance(seed_result, dict) or seed_result.get("vm_name") != vm_name:
            raise ValueError("bootstrap seed result VM identity differs")
        if present[iso.name] and seed_result.get("sha256") != sha256(iso):
            raise ValueError("bootstrap ISO changed since its recorded seed result")
    serial_tail = ""
    serial_digest = None
    if present[serial.name]:
        serial_digest = sha256(serial)
        with serial.open("rb") as source:
            source.seek(max(0, serial.stat().st_size - SERIAL_TAIL_BYTES))
            serial_tail = source.read(SERIAL_TAIL_BYTES).decode("utf-8", errors="replace")
    archive = {
        "schema_version": 1,
        "vm_name": vm_name,
        "seed_result": seed_result,
        "serial_sha256": serial_digest,
        "serial_tail": serial_tail,
        "captured_at_ns": time.time_ns(),
    }
    destination = checked_diagnostics(repo, vm_name) / (
        f"bootstrap-{archive['captured_at_ns']}-{secrets.token_hex(6)}.json"
    )
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(archive, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    removed: list[str] = []
    for path in (serial, result, iso, *seed_files):
        if path.is_file():
            path.unlink()
            removed.append(path.name)
    if seed.is_dir():
        seed.rmdir()
        removed.append("seed/")
    return {"status": "PASS", "archived": True, "archive": str(destination), "removed": removed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--vm-uuid")
    args = parser.parse_args()
    try:
        if not VBOX.is_file():
            raise ValueError("VirtualBox executable is absent")
        result = subprocess.run(
            [str(VBOX), "list", "vms"], capture_output=True, text=True,
            check=True, timeout=20,
        )
        repo = Path(__file__).resolve().parents[4]
        print(json.dumps(cleanup(args.state, args.vm_name, result.stdout, repo, args.vm_uuid), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"FAIL bootstrap seed cleanup: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
