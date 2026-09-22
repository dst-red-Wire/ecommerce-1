"""Extract bounded offline-artifact role timings from the native Ansible log."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re

SCHEMA_VERSION = 1
MAX_LOG_BYTES = 16 * 1024 * 1024
PHASE_TASKS = {
    "controller_validation_seconds": "Validate controller bundle before transfer",
    "transfer_seconds": "Transfer approved bundle over existing SSH access",
    "post_transfer_validation_seconds": "Verify transferred bytes before package installation",
    "rpm_signature_validation_seconds": "Verify every local RPM signature against isolated approved keys",
    "rpm_key_import_seconds": "Import only manifest-approved offline RPM signing keys",
    "dnf_install_seconds": "Install complete local RPM set with all repositories disabled",
}
ROLE_END_TASK = "Record verified offline artifacts for subsequent RKE2 plays"
LOG_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"p=\d+ u=\S+ n=ansible [A-Z]+\| (?P<message>[^\r\n]+)$"
)
TASK_BANNER = re.compile(r"^TASK \[(?P<name>[^\]\r\n]+)\] \*+$")
PLAY_RECAP = re.compile(r"^PLAY RECAP \*+$")


def _task_matches(actual: str, expected: str) -> bool:
    return actual == expected or actual.endswith(f" : {expected}")


def _events(log_text: str) -> list[tuple[dt.datetime, str | None]]:
    events: list[tuple[dt.datetime, str | None]] = []
    for line in log_text.splitlines():
        logged = LOG_LINE.fullmatch(line)
        if logged is None:
            continue
        timestamp = dt.datetime.strptime(
            logged.group("timestamp"), "%Y-%m-%d %H:%M:%S,%f"
        )
        message = logged.group("message")
        task = TASK_BANNER.fullmatch(message)
        if task is not None:
            events.append((timestamp, task.group("name")))
        elif PLAY_RECAP.fullmatch(message) is not None:
            events.append((timestamp, None))
    return events


def _target_index(
    events: list[tuple[dt.datetime, str | None]], task_name: str
) -> int | None:
    matches = [
        index
        for index, (_, actual) in enumerate(events)
        if actual is not None and _task_matches(actual, task_name)
    ]
    if len(matches) > 1:
        raise ValueError(f"ambiguous repeated target task: {task_name}")
    return matches[0] if matches else None


def _duration_to_next(
    events: list[tuple[dt.datetime, str | None]], index: int | None
) -> float | None:
    if index is None or index + 1 >= len(events):
        return None
    duration = (events[index + 1][0] - events[index][0]).total_seconds()
    if duration < 0:
        raise ValueError("Ansible task timestamps are not monotonic")
    return round(duration, 3)


def parse_role_timing(log_text: str) -> dict:
    events = _events(log_text)
    phase_indexes = {
        key: _target_index(events, task_name)
        for key, task_name in PHASE_TASKS.items()
    }
    phases = {
        key: _duration_to_next(events, index)
        for key, index in phase_indexes.items()
    }
    start_index = phase_indexes["controller_validation_seconds"]
    end_index = _target_index(events, ROLE_END_TASK)
    role_total = None
    if (
        start_index is not None
        and end_index is not None
        and end_index + 1 < len(events)
    ):
        role_total = (
            events[end_index + 1][0] - events[start_index][0]
        ).total_seconds()
        if role_total < 0:
            raise ValueError("Ansible role timestamps are not monotonic")
        role_total = round(role_total, 3)
    return {"role_total_seconds": role_total, "phases": phases}


def read_log(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Ansible role log is absent: {path}")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Ansible role log must be a regular file: {path}")
    if path.stat().st_size > MAX_LOG_BYTES:
        raise ValueError(f"Ansible role log exceeds {MAX_LOG_BYTES} bytes")
    return path.read_text(encoding="utf-8")


def parse_log(path: Path) -> dict:
    return parse_role_timing(read_log(path))


def bundle_inventory(root: Path) -> dict[str, int]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"bundle must be a real directory: {root}")
    file_count = 0
    byte_count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise ValueError(f"bundle contains a symbolic link: {entry.path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    file_count += 1
                    byte_count += entry.stat(follow_symlinks=False).st_size
                else:
                    raise ValueError(f"bundle contains a non-regular entry: {entry.path}")
    return {"file_count": file_count, "bytes": byte_count}


def build_metrics(log_text: str, bundle: Path) -> dict:
    timing = parse_role_timing(log_text)
    inventory = bundle_inventory(bundle)
    transfer = timing["phases"]["transfer_seconds"]
    role_total = timing["role_total_seconds"]
    transfer_rate = None
    if transfer is not None and transfer > 0:
        transfer_rate = round(inventory["bytes"] / (1024 * 1024) / transfer, 6)
    transfer_share = None
    if transfer is not None and role_total is not None and role_total > 0:
        transfer_share = round(transfer / role_total * 100, 2)
    return {
        "schema_version": SCHEMA_VERSION,
        "role_total_seconds": role_total,
        "bundle": inventory,
        "phases": timing["phases"],
        "transfer_mib_per_second": transfer_rate,
        "transfer_share_percent": transfer_share,
    }


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metrics = build_metrics(read_log(args.log), args.bundle)
    write_json(args.output, metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
