#!/usr/bin/env python3
"""Validate the Terraform-state identity contract and render safe inventory."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"Terraform state inventory invalid: {message}")


def positive_integer_id(value: Any, field: str) -> int:
    if isinstance(value, bool):
        fail(f"{field} must be a positive integer")
    if isinstance(value, int):
        if value > 0:
            return value
        fail(f"{field} must be a positive integer")
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        try:
            return int(value)
        except ValueError:
            pass
    fail(f"{field} must be a positive integer")


def load_contract(path: str) -> dict[str, Any]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"input is not valid JSON: {exc}")
    if isinstance(parsed, dict) and {"sensitive", "type", "value"} <= set(parsed):
        parsed = parsed["value"]
    if not isinstance(parsed, dict):
        fail("inventory contract must be a JSON object")
    return parsed


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    expected_values = {
        "server_name": "terraform-state-mgmt",
        "hostname": "terraform-state-mgmt",
        "service": "terraform-state-postgresql",
        "postgresql_bind_address": "127.0.0.1",
        "public_postgresql_exposed": False,
        "management_plane_dependency": False,
    }
    for key, expected in expected_values.items():
        if contract.get(key) != expected:
            fail(f"{key} must equal {expected!r}")

    server_id = positive_integer_id(contract.get("server_id"), "server_id")

    try:
        server_ipv4 = str(ipaddress.IPv4Address(contract["server_ipv4"]))
        ansible_host = str(ipaddress.IPv4Address(contract["ansible_host"]))
    except (KeyError, ipaddress.AddressValueError):
        fail("server_ipv4 and ansible_host must be public IPv4 addresses")
    if server_ipv4 != ansible_host:
        fail("server_ipv4 must equal ansible_host")
    if ipaddress.IPv4Address(server_ipv4).is_private:
        fail("server_ipv4 must be directly reachable for the initial SSH bootstrap")

    volume_id = positive_integer_id(
        contract.get("postgresql_volume_id"), "postgresql_volume_id"
    )
    expected_device = f"/dev/disk/by-id/scsi-0HC_Volume_{volume_id}"
    if contract.get("postgresql_volume_device") != expected_device:
        fail("postgresql_volume_device must be derived exactly from postgresql_volume_id")

    cidrs = contract.get("ssh_allowed_ipv4_cidrs")
    if not isinstance(cidrs, list) or not cidrs or len(cidrs) != len(set(cidrs)):
        fail("ssh_allowed_ipv4_cidrs must be a non-empty unique list")
    normalized_cidrs: list[str] = []
    for value in cidrs:
        try:
            network = ipaddress.IPv4Network(value, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            fail("ssh_allowed_ipv4_cidrs contains an invalid IPv4 CIDR")
        if network.prefixlen < 24:
            fail("SSH CIDRs broader than /24 are forbidden")
        normalized_cidrs.append(str(network))

    return {
        "server_id": server_id,
        "server_name": "terraform-state-mgmt",
        "server_ipv4": server_ipv4,
        "hostname": "terraform-state-mgmt",
        "ansible_host": ansible_host,
        "service": "terraform-state-postgresql",
        "postgresql_bind_address": "127.0.0.1",
        "postgresql_volume_device": expected_device,
        "postgresql_volume_id": volume_id,
        "ssh_allowed_ipv4_cidrs": normalized_cidrs,
        "public_postgresql_exposed": False,
        "management_plane_dependency": False,
    }


def validate_known_hosts(path_text: str | None, host: str) -> str:
    if not path_text:
        fail("--known-hosts is required when rendering Ansible inventory")
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", path_text):
        fail("known_hosts path must be an absolute shell-safe WSL path")
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        fail("dedicated known_hosts must be a regular non-symlink file")
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("dedicated known_hosts must be owned by the invoking user with mode 0600")
    resolved = path.resolve()
    repository = Path(__file__).resolve().parents[1]
    if resolved == repository or repository in resolved.parents or "OneDrive" in resolved.parts:
        fail("dedicated known_hosts must remain outside the repository and OneDrive")
    entries = [
        line.split()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(entries) != 1 or len(entries[0]) < 3:
        fail("dedicated known_hosts must contain exactly one pinned host key")
    if entries[0][0] != host or entries[0][1] != "ssh-ed25519":
        fail("dedicated known_hosts does not pin the inventory IPv4 Ed25519 key")
    return str(resolved)


parser = argparse.ArgumentParser()
parser.add_argument(
    "contract",
    nargs="?",
    default="-",
    help="Terraform output JSON file, or - for stdin",
)
parser.add_argument(
    "--output-format",
    choices=("inventory", "json"),
    default="inventory",
    help="validated Ansible inventory or canonical JSON contract",
)
parser.add_argument(
    "--known-hosts",
    help="dedicated pinned known_hosts path required for inventory output",
)
args = parser.parse_args()
contract = validate_contract(load_contract(args.contract))

if args.output_format == "json":
    if args.known_hosts:
        fail("--known-hosts is not accepted for JSON contract output")
    json.dump(contract, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    raise SystemExit(0)

ansible_host = contract["ansible_host"]
known_hosts = validate_known_hosts(args.known_hosts, ansible_host)
server_id = contract["server_id"]
volume_id = contract["postgresql_volume_id"]
device = contract["postgresql_volume_device"]
normalized_cidrs = contract["ssh_allowed_ipv4_cidrs"]

lines = [
    "---",
    "all:",
    "  children:",
    "    terraform_state_bootstrap:",
    "      hosts:",
    "        terraform-state-mgmt:",
    f"          ansible_host: {ansible_host}",
    "          ansible_user: root",
    f"          ansible_ssh_common_args: '-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}'",
    f"          terraform_state_server_id: {server_id}",
    "          terraform_state_server_name: terraform-state-mgmt",
    f"          terraform_state_server_ipv4: {ansible_host}",
    "          service: terraform-state-postgresql",
    "          postgresql_bind_address: 127.0.0.1",
    f"          terraform_state_volume_device: {device}",
    f"          terraform_state_volume_id: {volume_id}",
    f"          postgresql_volume_device: {device}",
    f"          postgresql_volume_id: {volume_id}",
    "          ssh_allowed_ipv4_cidrs:",
]
lines.extend(f"            - {cidr}" for cidr in normalized_cidrs)
lines.extend(
    [
        "          public_postgresql_exposed: false",
        "          management_plane_dependency: false",
    ]
)
sys.stdout.write("\n".join(lines) + "\n")
