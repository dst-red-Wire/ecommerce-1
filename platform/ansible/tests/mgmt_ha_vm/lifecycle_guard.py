"""Fail-closed decisions for the local HA VM create and cleanup wrapper."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

UUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
VM_NAME_RE = re.compile(r"^ecommerce-mgmt-test-ha-(?:cp|worker)-[0-9]{2}$")
REGISTERED_VM_RE = re.compile(r'^"(?P<name>[^"]+)" \{(?P<uuid>[0-9a-f-]+)\}\r?$')
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONSOLE_TIMEOUT_RE = re.compile(
    r"timed\s*out\s+waiting\s+for\s+(?:the\s+)?isolated\s+vm\s+console",
    re.IGNORECASE,
)
CONSOLE_TASK_RE = re.compile(
    r"configure\s+guest\s+exclusively\s+through\s+its\s+private\s+local\s+serial\s+pipe",
    re.IGNORECASE,
)
CONSOLE_COMMAND_RE = re.compile(r"transport\.py.{0,400}\bconsole\b", re.IGNORECASE | re.DOTALL)
ATTACH_TASK_RE = re.compile(
    r"attach\s+only\s+selected\s+existing\s+host-only\s+network\s+after\s+guest\s+output\s+is\s+denied",
    re.IGNORECASE,
)
WSL_INTEROP_RE = re.compile(
    r"utilacceptvsock:\d+:\s*accept4\s+failed\s+110",
    re.IGNORECASE,
)
TRANSIENT_CLEANUP_RE = re.compile(
    r"(?:"
    r"already\s+locked\s+for\s+a\s+session|"
    r"vbox_e_(?:invalid_object_state|object_in_use)|"
    r"verr_resource_busy|"
    r"failed\s+to\s+acquire\s+the\s+virtualbox\s+com\s+object|"
    r"another\s+process\s+is\s+using|"
    r"being\s+used\s+by\s+another\s+process|"
    r"utilacceptvsock:\d+:\s*accept4\s+failed\s+110"
    r")",
    re.IGNORECASE,
)
POSTCONDITION_TASK_RE = re.compile(
    r"verify\s+native\s+selinux,\s+egress\s+denial,\s+exact\s+rpms\s+and\s+staged\s+image\s+hashes",
    re.IGNORECASE,
)
HOST_KEY_RE = re.compile(r"^MGMT_HOST_KEY:(ssh-ed25519 [A-Za-z0-9+/=]+)(?:\s+.*)?$")

WINDOWS_INTEROP_ATTEMPTS = 3
WINDOWS_INTEROP_DELAY_SECONDS = 2
WINDOWS_INTEROP_EXHAUSTED_RC = 75


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected JSON object: {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _result_text(result: dict[str, Any]) -> str:
    fields = (result.get("stdout", ""), result.get("stderr", ""))
    return ANSI_RE.sub("", "\n".join(value for value in fields if isinstance(value, str)))


def _valid_result(result: dict[str, Any]) -> bool:
    return (
        isinstance(result.get("rc"), int)
        and isinstance(result.get("stdout"), str)
        and isinstance(result.get("stderr"), str)
        and isinstance(result.get("cmd"), (str, list))
    )


def create_decision(result: dict[str, Any], ownership: dict[str, Any]) -> dict[str, Any]:
    """Permit one resume only for the exact owned console-timeout failure."""
    if not _valid_result(result):
        return {"classification": "invalid-result", "recovery": "fail", "resume": False}
    if result["rc"] == 0:
        return {"classification": "create-complete", "recovery": "none", "resume": False}

    text = _result_text(result)
    timeout = bool(CONSOLE_TIMEOUT_RE.search(text))
    console_task = bool(CONSOLE_TASK_RE.search(text))
    console_command = bool(CONSOLE_COMMAND_RE.search(text))
    exact_owner = ownership.get("state") == "owned"
    resume = timeout and console_task and console_command and exact_owner
    if resume:
        classification = "owned-console-timeout"
        recovery = "resume-console"
    elif exact_owner and ATTACH_TASK_RE.search(text) and WSL_INTEROP_RE.search(text):
        classification = "owned-wsl-hostonly-attach-failure"
        recovery = "repair-hostonly-attach"
    elif timeout and not exact_owner:
        classification = "console-timeout-without-ownership"
        recovery = "fail"
    elif timeout:
        classification = "unbound-console-timeout"
        recovery = "fail"
    else:
        classification = "non-console-create-failure"
        recovery = "fail"
    return {"classification": classification, "recovery": recovery, "resume": resume}


def cleanup_decision(result: dict[str, Any], ownership: dict[str, Any]) -> dict[str, Any]:
    """Resolve absence or allow one retry only for a proven transient lock."""
    if not _valid_result(result):
        return {"classification": "invalid-result", "resolution": "fail"}
    if result["rc"] == 0:
        return {"classification": "cleanup-complete", "resolution": "pass"}

    state = ownership.get("state")
    if state in {"absent", "stale_identity"}:
        return {"classification": "owned-vm-already-absent", "resolution": "already-absent"}
    if state == "owned" and TRANSIENT_CLEANUP_RE.search(_result_text(result)):
        return {"classification": "transient-virtualbox-vagrant-contention", "resolution": "retry"}
    return {"classification": "unsafe-or-non-transient-cleanup-failure", "resolution": "fail"}


def cold_stage_decision(result: dict[str, Any], ownership: dict[str, Any]) -> dict[str, Any]:
    """Retry only the final postcondition after a demonstrated WSL transport failure."""
    if not _valid_result(result):
        return {"classification": "invalid-result", "resolution": "fail"}
    if result["rc"] == 0:
        return {"classification": "cold-stage-complete", "resolution": "pass"}
    text = _result_text(result)
    if (
        ownership.get("state") == "owned"
        and POSTCONDITION_TASK_RE.search(text)
        and re.search(r"utilacceptvsock:\d+:\s*accept4\s+failed\s+110", text, re.IGNORECASE)
    ):
        return {
            "classification": "wsl-interop-final-postcondition-timeout",
            "resolution": "retry-postcondition",
        }
    return {"classification": "unsafe-or-non-transient-cold-stage-failure", "resolution": "fail"}


def run_windows_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Retry only the demonstrated transient WSL interop launch failure."""
    if not command:
        raise ValueError("Windows command is required")
    result: subprocess.CompletedProcess[str] | None = None
    for attempt in range(WINDOWS_INTEROP_ATTEMPTS):
        raw = subprocess.run(command, capture_output=True, check=False)
        stdout = (
            raw.stdout.decode("utf-8", errors="replace")
            if isinstance(raw.stdout, bytes)
            else raw.stdout
        )
        stderr = (
            raw.stderr.decode("utf-8", errors="replace")
            if isinstance(raw.stderr, bytes)
            else raw.stderr
        )
        result = subprocess.CompletedProcess(raw.args, raw.returncode, stdout, stderr)
        if result.returncode == 0 or WSL_INTEROP_RE.search(result.stderr) is None:
            return result
        if attempt + 1 < WINDOWS_INTEROP_ATTEMPTS:
            time.sleep(WINDOWS_INTEROP_DELAY_SECONDS)
    assert result is not None
    return subprocess.CompletedProcess(
        result.args,
        WINDOWS_INTEROP_EXHAUSTED_RC,
        result.stdout,
        result.stderr,
    )


def preserve_console_proof(console: Path, known_hosts: Path, address: str) -> bool:
    """Materialize an exact host key only after successful private-console bootstrap."""
    parsed_address = ipaddress.IPv4Address(address)
    if not parsed_address.is_private or parsed_address.is_loopback:
        raise ValueError("private non-loopback guest address required")
    if not console.is_file() or console.is_symlink():
        return False
    text = ANSI_RE.sub("", console.read_text(encoding="utf-8", errors="replace"))
    if "MGMT_CONSOLE_RESULT:0" not in text:
        return False
    keys = {
        match.group(1)
        for line in text.splitlines()
        if (match := HOST_KEY_RE.fullmatch(line.strip())) is not None
    }
    if len(keys) != 1:
        return False
    _write_text(known_hosts, f"{parsed_address} {keys.pop()}\n")
    return True


def _write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(contents, encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def destroy_owned(vbox: str, identity: Path, vm_name: str) -> subprocess.CompletedProcess[str]:
    """Delete only the currently UUID-bound owned fixture in one bounded retry."""
    ownership = probe_ownership(vbox, identity, vm_name)
    if ownership["state"] in {"absent", "stale_identity"}:
        if identity.exists() and identity.is_file() and not identity.is_symlink():
            identity.unlink()
        return subprocess.CompletedProcess([vbox], 0, "already absent\n", "")
    if ownership["state"] != "owned":
        return subprocess.CompletedProcess([vbox], 1, "", "ownership mismatch")
    uuid = ownership["uuid"]
    inspected = run_windows_command([vbox, "showvminfo", uuid, "--machinereadable"])
    if inspected.returncode != 0:
        return inspected
    properties = dict(
        line.split("=", 1) for line in inspected.stdout.splitlines() if "=" in line
    )
    if properties.get("VMState") != '"poweroff"':
        stopped = run_windows_command([vbox, "controlvm", uuid, "poweroff"])
        if stopped.returncode != 0:
            return stopped
    removed = run_windows_command([vbox, "unregistervm", uuid, "--delete"])
    if removed.returncode == 0 and identity.is_file() and not identity.is_symlink():
        identity.unlink()
    return removed


def probe_ownership(vbox: str, identity: Path, vm_name: str) -> dict[str, Any]:
    """Classify only the expected Vagrant identity against live VirtualBox registration."""
    if VM_NAME_RE.fullmatch(vm_name) is None:
        raise ValueError("invalid HA fixture VM name")
    listed = run_windows_command([vbox, "list", "vms"])
    if listed.returncode != 0:
        raise RuntimeError("VirtualBox registration query failed")

    registrations: dict[str, str] = {}
    names: dict[str, str] = {}
    for line in listed.stdout.splitlines():
        match = REGISTERED_VM_RE.fullmatch(line)
        if match is None:
            continue
        name = match.group("name")
        uuid = match.group("uuid")
        if UUID_RE.fullmatch(uuid) is None or uuid in registrations or name in names:
            return {"state": "mismatch", "vm_name": vm_name}
        registrations[uuid] = name
        names[name] = uuid

    if not identity.exists():
        return {"state": "absent" if vm_name not in names else "mismatch", "vm_name": vm_name}
    if identity.is_symlink() or not identity.is_file():
        return {"state": "invalid_identity", "vm_name": vm_name}
    uuid = identity.read_text(encoding="utf-8").strip()
    if UUID_RE.fullmatch(uuid) is None:
        return {"state": "invalid_identity", "vm_name": vm_name}
    if uuid not in registrations and vm_name not in names:
        return {"state": "stale_identity", "vm_name": vm_name, "uuid": uuid}
    if registrations.get(uuid) != vm_name or names.get(vm_name) != uuid:
        return {"state": "mismatch", "vm_name": vm_name, "uuid": uuid}

    inspected = run_windows_command([vbox, "showvminfo", uuid, "--machinereadable"])
    if inspected.returncode != 0:
        return {"state": "mismatch", "vm_name": vm_name, "uuid": uuid}
    properties = dict(
        line.split("=", 1) for line in inspected.stdout.splitlines() if "=" in line
    )
    if properties.get("name") != json.dumps(vm_name) or properties.get("UUID") != json.dumps(uuid):
        return {"state": "mismatch", "vm_name": vm_name, "uuid": uuid}
    return {"state": "owned", "vm_name": vm_name, "uuid": uuid}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    probe = subparsers.add_parser("probe")
    probe.add_argument("--vbox", required=True)
    probe.add_argument("--identity", type=Path, required=True)
    probe.add_argument("--vm-name", required=True)
    probe.add_argument("--output", type=Path, required=True)
    windows = subparsers.add_parser("run-windows")
    windows.add_argument("command", nargs=argparse.REMAINDER)
    console = subparsers.add_parser("console-proof")
    console.add_argument("--console", type=Path, required=True)
    console.add_argument("--known-hosts", type=Path, required=True)
    console.add_argument("--address", required=True)
    destroy = subparsers.add_parser("destroy-owned")
    destroy.add_argument("--vbox", required=True)
    destroy.add_argument("--identity", type=Path, required=True)
    destroy.add_argument("--vm-name", required=True)
    for action in ("classify-create", "classify-cleanup", "classify-cold-stage"):
        command = subparsers.add_parser(action)
        command.add_argument("--result", type=Path, required=True)
        command.add_argument("--ownership", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.action == "run-windows":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        result = run_windows_command(command)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    if args.action == "console-proof":
        return 0 if preserve_console_proof(args.console, args.known_hosts, args.address) else 1
    if args.action == "destroy-owned":
        result = destroy_owned(args.vbox, args.identity, args.vm_name)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    if args.action == "probe":
        payload = probe_ownership(args.vbox, args.identity, args.vm_name)
    else:
        result = _read_json(args.result)
        ownership = _read_json(args.ownership)
        if args.action == "classify-create":
            payload = create_decision(result, ownership)
        elif args.action == "classify-cleanup":
            payload = cleanup_decision(result, ownership)
        else:
            payload = cold_stage_decision(result, ownership)
    _write_json(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
