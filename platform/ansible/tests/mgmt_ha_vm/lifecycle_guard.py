"""Fail-closed decisions for the local HA VM create and cleanup wrapper."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
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
TRANSIENT_CLEANUP_RE = re.compile(
    r"(?:"
    r"already\s+locked\s+for\s+a\s+session|"
    r"vbox_e_(?:invalid_object_state|object_in_use)|"
    r"verr_resource_busy|"
    r"failed\s+to\s+acquire\s+the\s+virtualbox\s+com\s+object|"
    r"another\s+process\s+is\s+using|"
    r"being\s+used\s+by\s+another\s+process"
    r")",
    re.IGNORECASE,
)


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
        return {"classification": "invalid-result", "resume": False}
    if result["rc"] == 0:
        return {"classification": "create-complete", "resume": False}

    text = _result_text(result)
    timeout = bool(CONSOLE_TIMEOUT_RE.search(text))
    console_task = bool(CONSOLE_TASK_RE.search(text))
    console_command = bool(CONSOLE_COMMAND_RE.search(text))
    exact_owner = ownership.get("state") == "owned"
    resume = timeout and console_task and console_command and exact_owner
    if resume:
        classification = "owned-console-timeout"
    elif timeout and not exact_owner:
        classification = "console-timeout-without-ownership"
    elif timeout:
        classification = "unbound-console-timeout"
    else:
        classification = "non-console-create-failure"
    return {"classification": classification, "resume": resume}


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


def probe_ownership(vbox: str, identity: Path, vm_name: str) -> dict[str, Any]:
    """Classify only the expected Vagrant identity against live VirtualBox registration."""
    if VM_NAME_RE.fullmatch(vm_name) is None:
        raise ValueError("invalid HA fixture VM name")
    listed = subprocess.run([vbox, "list", "vms"], capture_output=True, text=True, check=False)
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

    inspected = subprocess.run(
        [vbox, "showvminfo", uuid, "--machinereadable"],
        capture_output=True,
        text=True,
        check=False,
    )
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
    for action in ("classify-create", "classify-cleanup"):
        command = subparsers.add_parser(action)
        command.add_argument("--result", type=Path, required=True)
        command.add_argument("--ownership", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.action == "probe":
        payload = probe_ownership(args.vbox, args.identity, args.vm_name)
    else:
        result = _read_json(args.result)
        ownership = _read_json(args.ownership)
        payload = (
            create_decision(result, ownership)
            if args.action == "classify-create"
            else cleanup_decision(result, ownership)
        )
    _write_json(args.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
