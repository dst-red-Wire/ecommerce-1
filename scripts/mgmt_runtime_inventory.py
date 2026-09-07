#!/usr/bin/env python3
"""Build a non-secret Ansible transport overlay from Terraform MGMT outputs.

This command is read-only with respect to Terraform and provider state. It reads the
canonical MGMT inventory plus `terraform output -json servers`, validates exact node
parity, and writes only runtime transport addresses under `.context/`.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml


def load_canonical_nodes(root: Path) -> list[str]:
    doc = yaml.safe_load((root / "config/infrastructure/mgmt-inventory.yaml").read_text(encoding="utf-8"))
    nodes = [*doc["control_planes"].keys(), *doc["workers"].keys()]
    if len(nodes) != len(set(nodes)):
        raise ValueError("canonical MGMT inventory contains duplicate node names")
    return sorted(nodes)


def validate_servers(canonical_nodes: list[str], servers: Any) -> dict[str, str]:
    if not isinstance(servers, dict):
        raise ValueError("Terraform servers output must be a mapping")
    if sorted(servers.keys()) != canonical_nodes:
        raise ValueError(
            f"Terraform servers output node set mismatch: expected {canonical_nodes}, got {sorted(servers.keys())}"
        )

    hosts: dict[str, str] = {}
    for name in canonical_nodes:
        value = servers[name]
        if not isinstance(value, dict):
            raise ValueError(f"Terraform servers output for {name} must be a mapping")
        raw = value.get("ipv4")
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"Terraform servers output for {name} requires non-empty ipv4")
        address = ipaddress.ip_address(raw.strip())
        if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError(f"Terraform servers output for {name} has invalid transport IPv4 {raw!r}")
        hosts[name] = str(address)
    return hosts


def terraform_servers(terraform_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["terraform", f"-chdir={terraform_dir}", "output", "-json", "servers"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        detail = " ".join((proc.stderr or proc.stdout).strip().split())
        raise RuntimeError(f"terraform output servers failed: {detail}")
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"terraform output servers returned invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("terraform output servers must decode to a mapping")
    return value


def write_overlay(output: Path, hosts: dict[str, str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "source": "terraform-output:servers",
        "contains_secrets": False,
        "hosts": hosts,
    }
    temp = output.with_suffix(output.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".context/runtime/mgmt-ansible-transport.json")
    parser.add_argument(
        "--terraform-dir",
        default="platform/terraform/environments/mgmt",
        help="Terraform MGMT root containing the applied state/outputs",
    )
    parser.add_argument(
        "--servers-json",
        help="Offline/test input containing the decoded Terraform `servers` output; skips terraform command",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        canonical_nodes = load_canonical_nodes(root)
        if args.servers_json:
            servers = json.loads(Path(args.servers_json).read_text(encoding="utf-8"))
        else:
            servers = terraform_servers(root / args.terraform_dir)
        hosts = validate_servers(canonical_nodes, servers)
        output = Path(args.output)
        if not output.is_absolute():
            output = root / output
        write_overlay(output, hosts)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f"FAIL mgmt-runtime-inventory: {exc}", file=sys.stderr)
        return 2

    print(f"PASS mgmt-runtime-inventory: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
