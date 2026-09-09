#!/usr/bin/env python3
"""Build a non-secret Ansible transport overlay from Terraform MGMT state.

This command is read-only with respect to Terraform and provider state. By default it
reads the canonical root `terraform output -json servers`. For recovery of an older local
state created before the root output existed, `--terraform-state` reads that state through
`terraform show -json` and extracts only the canonical hcloud_server transport addresses.
It never refreshes, plans, applies, imports, moves, removes, or rewrites Terraform state.
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

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from yaml_loader import load_yaml

MGMT_MODULE_ADDRESS = "module.hcloud_mgmt"
MGMT_SERVER_TYPE = "hcloud_server"
MGMT_SERVER_NAME = "node"
MGMT_PROJECT_LABEL = "ecommerce-1"
MGMT_SITE_LABEL = "mgmt"


def load_canonical_nodes(root: Path) -> list[str]:
    doc = load_yaml(root / "config/infrastructure/mgmt-inventory.yaml")
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


def extract_servers_from_show(show_doc: Any) -> dict[str, Any]:
    if not isinstance(show_doc, dict):
        raise ValueError("terraform show JSON must be a mapping")
    values = show_doc.get("values")
    if not isinstance(values, dict):
        raise ValueError("terraform show JSON requires values mapping")
    root_module = values.get("root_module")
    if not isinstance(root_module, dict):
        raise ValueError("terraform show JSON requires values.root_module mapping")
    children = root_module.get("child_modules")
    if not isinstance(children, list):
        raise ValueError("terraform show JSON requires root child_modules")

    modules = [item for item in children if isinstance(item, dict) and item.get("address") == MGMT_MODULE_ADDRESS]
    if len(modules) != 1:
        raise ValueError(f"terraform show JSON requires exactly one {MGMT_MODULE_ADDRESS}, got {len(modules)}")
    resources = modules[0].get("resources")
    if not isinstance(resources, list):
        raise ValueError(f"{MGMT_MODULE_ADDRESS} requires resources list")

    servers: dict[str, Any] = {}
    for item in resources:
        if not isinstance(item, dict):
            continue
        if (
            item.get("mode") != "managed"
            or item.get("type") != MGMT_SERVER_TYPE
            or item.get("name") != MGMT_SERVER_NAME
        ):
            continue
        index = item.get("index")
        resource_values = item.get("values")
        if not isinstance(index, str) or not index:
            raise ValueError("MGMT hcloud_server resource requires non-empty string index")
        if not isinstance(resource_values, dict):
            raise ValueError(f"MGMT hcloud_server {index} requires values mapping")
        if index in servers:
            raise ValueError(f"duplicate MGMT hcloud_server index {index}")
        resource_name = resource_values.get("name")
        if resource_name != index:
            raise ValueError(
                f"MGMT hcloud_server {index} resource name mismatch: expected {index!r}, got {resource_name!r}"
            )
        labels = resource_values.get("labels")
        if not isinstance(labels, dict):
            raise ValueError(f"MGMT hcloud_server {index} requires labels mapping")
        if labels.get("project") != MGMT_PROJECT_LABEL or labels.get("site") != MGMT_SITE_LABEL:
            raise ValueError(f"MGMT hcloud_server {index} ownership labels do not match ecommerce-1/mgmt")
        ipv4 = resource_values.get("ipv4_address")
        ipv6 = resource_values.get("ipv6_address")
        resource_id = resource_values.get("id")
        if not isinstance(ipv4, str) or not ipv4.strip():
            raise ValueError(f"MGMT hcloud_server {index} requires ipv4_address")
        servers[index] = {
            "id": resource_id,
            "ipv4": ipv4,
            "ipv6": ipv6,
        }
    if not servers:
        raise ValueError("terraform show JSON contains no canonical MGMT hcloud_server resources")
    return servers


def terraform_servers_from_state(terraform_dir: Path, state_path: Path) -> dict[str, Any]:
    if not state_path.is_absolute():
        raise ValueError("Terraform state path must be absolute")
    if not state_path.is_file():
        raise ValueError(f"Terraform state file not found: {state_path}")
    proc = subprocess.run(
        ["terraform", f"-chdir={terraform_dir}", "show", "-json", str(state_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        # Do not include stdout here: terraform show -json can contain sensitive state values.
        detail = " ".join((proc.stderr or "terraform show failed").strip().split())
        raise RuntimeError(f"terraform show state failed: {detail}")
    try:
        show_doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"terraform show state returned invalid JSON: {exc}") from exc
    return extract_servers_from_show(show_doc)


def write_overlay(
    output: Path,
    hosts: dict[str, str],
    source: str = "terraform-output:servers",
) -> None:
    if source not in {"terraform-output:servers", "terraform-state:show", "servers-json"}:
        raise ValueError(f"unsupported MGMT transport provenance source: {source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "source": source,
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
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--servers-json",
        help="Offline/test input containing the decoded Terraform `servers` output; skips terraform command",
    )
    source.add_argument(
        "--terraform-state",
        help="Absolute local state path for read-only recovery through `terraform show -json`",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        canonical_nodes = load_canonical_nodes(root)
        terraform_dir = root / args.terraform_dir
        if args.servers_json:
            servers = json.loads(Path(args.servers_json).read_text(encoding="utf-8"))
            provenance = "servers-json"
        elif args.terraform_state:
            state_path = Path(args.terraform_state).expanduser()
            if not state_path.is_absolute():
                raise ValueError("--terraform-state must be an absolute path")
            servers = terraform_servers_from_state(terraform_dir, state_path.resolve())
            provenance = "terraform-state:show"
        else:
            servers = terraform_servers(terraform_dir)
            provenance = "terraform-output:servers"
        hosts = validate_servers(canonical_nodes, servers)
        output = Path(args.output)
        if not output.is_absolute():
            output = root / output
        write_overlay(output, hosts, provenance)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f"FAIL mgmt-runtime-inventory: {exc}", file=sys.stderr)
        return 2

    print(f"PASS mgmt-runtime-inventory: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
