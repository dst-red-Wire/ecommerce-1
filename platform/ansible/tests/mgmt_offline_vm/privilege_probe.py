"""Bounded SSH, sudo, and Ansible-become diagnostics for the owned RKE2 fixture."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import time

CLASSIFICATIONS = {
    "ssh-transport-timeout",
    "sudo-noninteractive-failure",
    "ansible-become-only-timeout",
    "controlpersist-stale",
    "controller-interop-transient",
    "guest-resource-stall",
    "unknown",
}
SUMMARY_PROBES = (
    "ssh_true",
    "sudo_n_true",
    "ansible_no_become",
    "ansible_become",
)
SECRET_VALUE = re.compile(
    r"(?i)((?:[\"']?)(?:token|password|secret|authorization)(?:[\"']?)\s*[:=]\s*)"
    r"(?:[\"'][^\"']*[\"']|\S+)"
)
BEARER_VALUE = re.compile(r"(?i)bearer\s+\S+")


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def sanitize(value: str, limit: int = 12_000) -> str:
    value = SECRET_VALUE.sub(r"\1<redacted>", value)
    return BEARER_VALUE.sub("Bearer <redacted>", value)[-limit:]


def measured(command: list[str], *, timeout: int, environment: dict[str, str] | None = None) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=environment,
        )
        return {
            "rc": result.returncode,
            "duration_seconds": round(time.monotonic() - started, 4),
            "stdout": sanitize(result.stdout or ""),
            "stderr": sanitize(result.stderr or ""),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "rc": 124,
            "duration_seconds": round(time.monotonic() - started, 4),
            "stdout": sanitize(stdout),
            "stderr": sanitize(stderr or f"bounded timeout after {timeout}s"),
            "timed_out": True,
        }


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summarize(samples: list[dict]) -> dict:
    durations = [float(item["duration_seconds"]) for item in samples]
    ordered = sorted(durations)
    middle = len(ordered) // 2
    if not ordered:
        median = None
    elif len(ordered) % 2:
        median = ordered[middle]
    else:
        median = (ordered[middle - 1] + ordered[middle]) / 2
    return {
        "count": len(samples),
        "failures": sum(item["rc"] != 0 for item in samples),
        "min_seconds": round(min(ordered), 4) if ordered else None,
        "median_seconds": round(median, 4) if median is not None else None,
        "p95_seconds": round(percentile(ordered, 0.95), 4) if ordered else None,
        "max_seconds": round(max(ordered), 4) if ordered else None,
    }


def ansible_environment(config: Path) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ANSIBLE_")}
    environment.update(ANSIBLE_CONFIG=str(config), ANSIBLE_FORKS="1")
    return environment


def ssh_command(config: Path, vm: str, remote_command: str) -> list[str]:
    return ["ssh", "-F", str(config), vm, remote_command]


def ansible_command(
    executable: Path,
    inventory: Path,
    vm: str,
    remote_command: str,
    *,
    become: bool,
) -> list[str]:
    command = [
        str(executable),
        "-i",
        str(inventory),
        vm,
        "-m",
        "ansible.builtin.command",
        "-a",
        remote_command,
        "-e",
        f"ansible_become={'true' if become else 'false'}",
        "-o",
    ]
    if become:
        command.append("--become")
    return command


def socket_snapshot(directory: Path, config: Path, vm: str) -> dict:
    entries = []
    if directory.is_dir():
        for path in sorted(directory.iterdir()):
            try:
                is_socket = stat.S_ISSOCK(path.stat().st_mode)
            except FileNotFoundError:
                continue
            check = None
            if is_socket:
                check = measured(
                    ["ssh", "-S", str(path), "-O", "check", "-F", str(config), vm],
                    timeout=5,
                )
            entries.append(
                {
                    "name": path.name,
                    "socket": is_socket,
                    "active_master": bool(check and check["rc"] == 0),
                    "check_rc": check["rc"] if check else None,
                }
            )
    return {
        "directory": str(directory),
        "entries": entries,
        "stale_socket": any(item["socket"] and not item["active_master"] for item in entries),
    }


def effective_settings(args: argparse.Namespace, environment: dict[str, str]) -> dict:
    ssh = measured(["ssh", "-F", str(args.ssh_config), "-G", args.vm], timeout=8)
    selected: dict[str, str] = {}
    for line in ssh["stdout"].splitlines():
        key, _, value = line.partition(" ")
        if key in {
            "hostname",
            "user",
            "controlmaster",
            "controlpersist",
            "controlpath",
            "connecttimeout",
            "proxycommand",
        }:
            selected[key] = value
    config_executable = args.ansible.with_name("ansible-config")
    ansible = measured(
        [
            str(config_executable),
            "dump",
            "-t",
            "connection",
            "ssh",
            "--format",
            "json",
        ],
        timeout=args.command_timeout,
        environment=environment,
    )
    connection = []
    try:
        payload = json.loads(ansible["stdout"])
        connection = payload[0]["ssh"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        pass
    wanted = {"control_path", "control_path_dir", "pipelining", "ssh_args", "timeout"}
    return {
        "ssh_command": ["ssh", "-F", str(args.ssh_config), args.vm],
        "direct_ssh": selected,
        "ansible_connection": [item for item in connection if item.get("name") in wanted],
        "ansible_config_rc": ansible["rc"],
    }


def wait_for_activation(args: argparse.Namespace) -> dict:
    deadline = time.monotonic() + args.wait_timeout
    observations = []
    while time.monotonic() < deadline:
        result = measured(
            ssh_command(args.ssh_config, args.vm, "/usr/bin/systemctl is-active rke2-server.service"),
            timeout=args.command_timeout,
        )
        state = result["stdout"].strip()
        observations.append(
            {
                "timestamp": now(),
                "state": state,
                "rc": result["rc"],
                "duration_seconds": result["duration_seconds"],
            }
        )
        if state == "activating":
            return {"reached": True, "state": state, "observations": observations[-30:]}
        time.sleep(1)
    return {"reached": False, "state": observations[-1]["state"] if observations else None, "observations": observations[-30:]}


def run_suite(args: argparse.Namespace, environment: dict[str, str]) -> dict[str, list[dict]]:
    samples: dict[str, list[dict]] = {
        "ssh_true": [],
        "sudo_n_true": [],
        "sudo_n_id": [],
        "ansible_no_become": [],
        "ansible_become": [],
        "ansible_become_id": [],
    }
    commands = {
        "ssh_true": ssh_command(args.ssh_config, args.vm, "/usr/bin/true"),
        "sudo_n_true": ssh_command(args.ssh_config, args.vm, "sudo -n /usr/bin/true"),
        "sudo_n_id": ssh_command(args.ssh_config, args.vm, "sudo -n /usr/bin/id -u"),
        "ansible_no_become": ansible_command(
            args.ansible, args.inventory, args.vm, "/usr/bin/true", become=False
        ),
        "ansible_become": ansible_command(
            args.ansible, args.inventory, args.vm, "/usr/bin/true", become=True
        ),
        "ansible_become_id": ansible_command(
            args.ansible, args.inventory, args.vm, "/usr/bin/id -u", become=True
        ),
    }
    for _ in range(args.repetitions):
        for name, command in commands.items():
            samples[name].append(
                measured(
                    command,
                    timeout=args.command_timeout,
                    environment=environment if name.startswith("ansible_") else None,
                )
            )
    return samples


def direct_facts(args: argparse.Namespace) -> dict:
    commands = {
        "sudoers": "sudo -n -l",
        "hostname": "/usr/bin/hostname",
        "etc_hostname": "/usr/bin/cat /etc/hostname",
        "etc_hosts": "/usr/bin/cat /etc/hosts",
        "hostname_resolution": "/usr/bin/getent hosts \"$(/usr/bin/hostname)\"",
    }
    return {
        name: measured(ssh_command(args.ssh_config, args.vm, command), timeout=args.command_timeout)
        for name, command in commands.items()
    }


def failure_diagnostics(args: argparse.Namespace) -> dict:
    commands = {
        "date": "date -Ins",
        "uptime": "uptime",
        "free": "free -m",
        "vmstat": "vmstat 1 5",
        "loadavg": "cat /proc/loadavg",
        "processes": "ps -eo pid,ppid,stat,%cpu,%mem,comm,args",
        "sshd_journal": "sudo -n journalctl -u sshd --since '-2 minutes' --no-pager",
        "rke2_journal": "sudo -n journalctl -u rke2-server --since '-2 minutes' --no-pager -n 200",
        "sudo_true": "sudo -n true",
        "sudo_id": "sudo -n id -u",
    }
    return {
        name: measured(ssh_command(args.ssh_config, args.vm, command), timeout=max(args.command_timeout, 12))
        for name, command in commands.items()
    }


def classify(summary: dict, stale_socket: bool) -> str:
    failures = {name: summary[name]["failures"] for name in SUMMARY_PROBES}
    if failures["ssh_true"]:
        return "ssh-transport-timeout"
    if failures["sudo_n_true"]:
        return "sudo-noninteractive-failure"
    if failures["ansible_no_become"]:
        return "controlpersist-stale" if stale_socket else "controller-interop-transient"
    if failures["ansible_become"]:
        return "ansible-become-only-timeout"
    return "unknown"


def root_proofs_pass(samples: dict[str, list[dict]]) -> bool:
    for name in ("sudo_n_id", "ansible_become_id"):
        for item in samples[name]:
            if item["rc"] != 0 or re.search(r"(^|\n)0(\n|$)", item["stdout"].strip()) is None:
                return False
    return True


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("before", "activating", "failure"), required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--ssh-config", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--ansible-config", type=Path, required=True)
    parser.add_argument("--ansible", type=Path, required=True)
    parser.add_argument("--control-path-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--command-timeout", type=int, default=15)
    parser.add_argument("--wait-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.phase in {"before", "activating"} and not 10 <= args.repetitions <= 50:
        parser.error("before/activating probes require 10..50 repetitions")
    if args.phase == "failure" and not 1 <= args.repetitions <= 10:
        parser.error("failure probes require 1..10 repetitions")
    if not 5 <= args.command_timeout <= 30:
        parser.error("command timeout must remain within 5..30 seconds")
    if not 30 <= args.wait_timeout <= 900:
        parser.error("activation wait timeout must remain within 30..900 seconds")
    return args


def main() -> int:
    args = parse_args()
    environment = ansible_environment(args.ansible_config)
    payload = {
        "schema_version": 1,
        "phase": args.phase,
        "started_at": now(),
        "controller_hostname": socket.gethostname(),
        "bounds": {
            "repetitions": args.repetitions,
            "command_timeout_seconds": args.command_timeout,
            "activation_wait_timeout_seconds": args.wait_timeout,
        },
        "settings": effective_settings(args, environment),
        "sockets_before": socket_snapshot(args.control_path_dir, args.ssh_config, args.vm),
    }
    if args.phase == "activating":
        payload["activation_wait"] = wait_for_activation(args)
        if not payload["activation_wait"]["reached"]:
            payload.update(finished_at=now(), classification="unknown", error="activating state not observed")
            write_json(args.output, payload)
            return 1
    samples = run_suite(args, environment)
    payload["samples"] = samples
    payload["summary"] = {name: summarize(values) for name, values in samples.items()}
    payload["direct_facts"] = direct_facts(args)
    if args.phase == "failure":
        payload["diagnostics"] = failure_diagnostics(args)
    payload["sockets_after"] = socket_snapshot(args.control_path_dir, args.ssh_config, args.vm)
    stale = payload["sockets_before"]["stale_socket"] or payload["sockets_after"]["stale_socket"]
    payload["classification"] = classify(payload["summary"], stale)
    payload["root_proofs_pass"] = root_proofs_pass(samples)
    payload["finished_at"] = now()
    write_json(args.output, payload)
    required_failures = sum(payload["summary"][name]["failures"] for name in SUMMARY_PROBES)
    return 0 if required_failures == 0 and payload["root_proofs_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
