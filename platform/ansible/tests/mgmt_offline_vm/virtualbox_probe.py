#!/usr/bin/env python3
"""Fail closed unless a VirtualBox machine matches the fixture isolation contract."""

from __future__ import annotations

import argparse
import json
import sys


def machine_values(document: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in document.splitlines():
        if "=" not in line:
            continue
        key, raw = line.split("=", 1)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = raw
        values[key] = str(value)
    return values


def require_isolated(values: dict[str, str], *, name: str, nic1: str,
                     adapter: str | None = None, mac: str | None = None,
                     cpus: int | None = None, memory: int | None = None,
                     running: bool = False) -> None:
    if values.get("name") != name:
        raise ValueError("VirtualBox machine name differs from the owned fixture")
    if values.get("ioapic") != "on":
        raise ValueError("fixture IO-APIC must remain enabled")
    if values.get("nic1") != nic1:
        raise ValueError("fixture primary adapter differs from the requested isolation mode")
    for index in range(2, 9):
        if values.get(f"nic{index}") != "none":
            raise ValueError(f"fixture adapter {index} must be disconnected")
    if nic1 == "hostonly":
        if values.get("hostonlyadapter1") != adapter:
            raise ValueError("fixture host-only adapter differs from the requested adapter")
        if values.get("macaddress1", "").lower() != (mac or "").lower():
            raise ValueError("fixture MAC differs from the requested MAC")
    if cpus is not None and values.get("cpus") != str(cpus):
        raise ValueError("fixture CPU allocation differs from the requested value")
    if memory is not None and values.get("memory") != str(memory):
        raise ValueError("fixture memory allocation differs from the requested value")
    if running and values.get("VMState") != "running":
        raise ValueError("fixture must be running")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--nic1", required=True, choices=("null", "hostonly"))
    parser.add_argument("--adapter")
    parser.add_argument("--mac")
    parser.add_argument("--cpus", type=int)
    parser.add_argument("--memory", type=int)
    parser.add_argument("--running", action="store_true")
    args = parser.parse_args()
    try:
        require_isolated(
            machine_values(sys.stdin.read()), name=args.name, nic1=args.nic1,
            adapter=args.adapter, mac=args.mac, cpus=args.cpus,
            memory=args.memory, running=args.running,
        )
    except ValueError as error:
        parser.exit(1, f"FAIL: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
