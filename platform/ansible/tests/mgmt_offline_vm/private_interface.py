#!/usr/bin/env python3
"""Resolve one guest interface by the MAC of the owned host-only adapter."""

from __future__ import annotations

import json
import re
import subprocess
import sys


def interface_for_mac(mac: str, links: list[dict]) -> str:
    if re.fullmatch(r"02[0-9A-Fa-f]{10}", mac) is None:
        raise ValueError("owned host-only MAC is invalid")
    colon_mac = ":".join(mac[index:index + 2] for index in range(0, 12, 2)).lower()
    matches = [row.get("ifname") for row in links if isinstance(row, dict)
               and isinstance(row.get("address"), str)
               and row["address"].lower() == colon_mac]
    if len(matches) != 1 or not isinstance(matches[0], str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", matches[0]) is None:
        raise ValueError("owned host-only guest interface is absent or ambiguous")
    return matches[0]


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("owned host-only MAC is required")
    links = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True, timeout=15))
    if not isinstance(links, list):
        raise ValueError("guest interface inventory is malformed")
    print(interface_for_mac(sys.argv[1], links))


if __name__ == "__main__":
    main()
