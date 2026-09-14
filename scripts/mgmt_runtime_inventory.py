#!/usr/bin/env python3
"""Build the non-secret MGMT Ansible transport overlay from Terraform output."""

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


def load_canonical(root: Path) -> tuple[list[str], str]:
    inventory = yaml.safe_load((root / "config/infrastructure/mgmt-inventory.yaml").read_text())
    access = yaml.safe_load((root / "config/infrastructure/mgmt-access-gateways.yaml").read_text())
    nodes = sorted([*inventory["control_planes"], *inventory["workers"]])
    gateways = list(access["access_gateways"])
    if len(nodes) != 6 or gateways != ["wg-01"]:
        raise ValueError("canonical MGMT transport requires six RKE2 nodes and wg-01")
    return nodes, gateways[0]


def _ipv4(value: Any, label: str, *, public: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} requires a non-empty IPv4 address")
    address = ipaddress.ip_address(value.strip())
    if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError(f"{label} has invalid IPv4 address")
    if public and address.is_private:
        # TEST-NET ranges are classified private by Python; accept only globally
        # routable addresses in real output and explicit documentation ranges in tests.
        if (
            not address in ipaddress.ip_network("192.0.2.0/24")
            and not address in ipaddress.ip_network("198.51.100.0/24")
            and not address in ipaddress.ip_network("203.0.113.0/24")
        ):
            raise ValueError(f"{label} must be a provider public IPv4 address")
    return str(address)


def validate_transport(canonical_nodes: list[str], gateway_name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Terraform runtime_transport output must be a mapping")
    phase = value.get("phase")
    if phase not in {"bootstrap", "steady-state"}:
        raise ValueError("runtime transport phase must be bootstrap or steady-state")
    gateway = value.get("gateway")
    nodes = value.get("nodes")
    if not isinstance(gateway, dict) or gateway.get("name") != gateway_name:
        raise ValueError("runtime transport requires the canonical wg-01 gateway")
    if not isinstance(nodes, dict) or sorted(nodes) != canonical_nodes:
        raise ValueError("runtime transport node set mismatch")

    gateway_public = gateway.get("provider_public")
    bootstrap_ssh = gateway.get("bootstrap_ssh") is True
    if phase == "bootstrap":
        if not bootstrap_ssh:
            raise ValueError("bootstrap phase requires explicit gateway transport")
        gateway_host = _ipv4(gateway_public, "wg-01 provider_public", public=True)
    else:
        if bootstrap_ssh:
            raise ValueError("steady-state transport must not retain public SSH")
        gateway_host = _ipv4(gateway.get("private_address"), "wg-01 private_address")

    hosts: dict[str, Any] = {
        gateway_name: {
            "ansible_host": gateway_host,
            "transport": "temporary-public-ssh" if phase == "bootstrap" else "wireguard-private",
        }
    }
    for name in canonical_nodes:
        node = nodes[name]
        if not isinstance(node, dict) or node.get("gateway") != gateway_name:
            raise ValueError(f"{name} requires gateway transport through wg-01")
        if node.get("provider_public") not in {None, ""}:
            raise ValueError(f"{name} must not use a provider public address")
        private = _ipv4(node.get("private_address"), f"{name} private_address")
        host = {"ansible_host": private, "transport": "wireguard-private"}
        if phase == "bootstrap":
            host["ansible_ssh_common_args"] = (
                f"-o ForwardAgent=no -o ClearAllForwardings=yes -o ProxyJump={gateway_host}"
            )
        hosts[name] = host
    return {"phase": phase, "gateway": gateway_name, "hosts": hosts}


def terraform_transport(terraform_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["terraform", f"-chdir={terraform_dir}", "output", "-json", "runtime_transport"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise RuntimeError("terraform output runtime_transport failed: " + " ".join(proc.stderr.split()))
    return json.loads(proc.stdout)


def write_overlay(output: Path, transport: dict[str, Any], source: str = "terraform-output:runtime_transport") -> None:
    if source not in {"terraform-output:runtime_transport", "transport-json"}:
        raise ValueError("unsupported MGMT transport provenance")
    payload = {"version": 2, "source": source, "contains_secrets": False, **transport}
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(temp, 0o600)
    temp.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".context/runtime/mgmt-ansible-transport.json")
    parser.add_argument("--terraform-dir", default="platform/terraform/environments/mgmt")
    parser.add_argument("--transport-json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        nodes, gateway = load_canonical(root)
        raw = (
            json.loads(Path(args.transport_json).read_text())
            if args.transport_json
            else terraform_transport(root / args.terraform_dir)
        )
        transport = validate_transport(nodes, gateway, raw)
        output = Path(args.output)
        write_overlay(
            output if output.is_absolute() else root / output,
            transport,
            "transport-json" if args.transport_json else "terraform-output:runtime_transport",
        )
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"FAIL mgmt-runtime-inventory: {exc}", file=sys.stderr)
        return 2
    print(f"PASS mgmt-runtime-inventory: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
