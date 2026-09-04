#!/usr/bin/env python3
"""Render a non-secret Ansible inventory from Terraform output -json."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path


EXPECTED_HOSTS = {"gitea-mgmt", "harbor-mgmt", "data-mgmt"}


def fail(message: str) -> None:
    raise SystemExit(f"management inventory render failed: {message}")


def output_value(outputs: dict, name: str):
    item = outputs.get(name)
    if not isinstance(item, dict) or "value" not in item:
        fail(f"Terraform output {name!r} is missing")
    return item["value"]


def ipv4(value: object, field: str) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as error:
        fail(f"{field} is not an IP address: {error}")
    if address.version != 4:
        fail(f"{field} must be IPv4")
    return str(address)


def yaml_string(value: str) -> str:
    return json.dumps(value)


parser = argparse.ArgumentParser()
parser.add_argument("--terraform-output", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--ansible-user", default="root")
parser.add_argument("--ssh-private-key-file", default="~/.ssh/id_ed25519")
parser.add_argument("--acme-email", required=True)
args = parser.parse_args()

if not re.fullmatch(r"[^@\s]+@[^@\s]+", args.acme_email):
    fail("--acme-email must be a valid operational email address")
if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", args.ansible_user):
    fail("--ansible-user must be a single safe SSH account name")

outputs = json.loads(args.terraform_output.read_text(encoding="utf-8"))
contract = output_value(outputs, "inventory_contract")
cidrs = output_value(outputs, "management_ssh_allowed_cidrs")
if set(contract) != EXPECTED_HOSTS:
    fail(f"inventory contract hosts must be exactly {sorted(EXPECTED_HOSTS)}")
if not isinstance(cidrs, list) or not cidrs:
    fail("management_ssh_allowed_cidrs must be a non-empty list")
for cidr in cidrs:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as error:
        fail(f"invalid SSH CIDR: {error}")
    if network.version != 4 or network.prefixlen < 24:
        fail("SSH CIDRs must be IPv4 /24 or narrower")

gitea_public = ipv4(contract["gitea-mgmt"]["ansible_host"], "gitea ansible_host")
gitea_private = ipv4(contract["gitea-mgmt"]["private_ip"], "gitea private_ip")
harbor_public = ipv4(contract["harbor-mgmt"]["ansible_host"], "harbor ansible_host")
harbor_private = ipv4(contract["harbor-mgmt"]["private_ip"], "harbor private_ip")
data_private = ipv4(contract["data-mgmt"]["private_ip"], "data private_ip")
if ipv4(contract["data-mgmt"]["ansible_host"], "data ansible_host") != data_private:
    fail("data-mgmt must use its private IP as ansible_host")
if ipv4(contract["data-mgmt"]["bastion"], "data bastion") != gitea_public:
    fail("data-mgmt bastion must be gitea-mgmt public IPv4")
if contract["data-mgmt"].get("egress_proxy_host") != gitea_private:
    fail("data-mgmt egress proxy host must be gitea-mgmt private IPv4")
if contract["data-mgmt"].get("egress_proxy_port") != 3128:
    fail("data-mgmt egress proxy port must be 3128")

lines = [
    "all:",
    "  children:",
    "    management:",
    "      children:",
]
for group, host, public, private in (
    ("gitea_management", "gitea-mgmt", gitea_public, gitea_private),
    ("harbor_management", "harbor-mgmt", harbor_public, harbor_private),
):
    lines.extend(
        [
            f"        {group}:",
            "          hosts:",
            f"            {host}:",
            f"              ansible_host: {public}",
            f"              private_ip: {private}",
        ]
    )
lines.extend(
    [
        "        data_management:",
        "          hosts:",
        "            data-mgmt:",
        f"              ansible_host: {data_private}",
        f"              private_ip: {data_private}",
        "              ansible_ssh_common_args: >-",
        f"                -o ProxyJump={args.ansible_user}@{gitea_public}",
        "      vars:",
        f"        ansible_user: {yaml_string(args.ansible_user)}",
        f"        ansible_ssh_private_key_file: {yaml_string(args.ssh_private_key_file)}",
        "        management_ssh_allowed_ipv4_cidrs:",
    ]
)
lines.extend(f"          - {cidr}" for cidr in cidrs)
lines.extend(
    [
        f"        management_gitea_private_ip: {gitea_private}",
        f"        management_harbor_private_ip: {harbor_private}",
        f"        management_data_private_ip: {data_private}",
        f"        management_egress_proxy_url: http://{gitea_private}:3128",
        f"        management_acme_email: {yaml_string(args.acme_email)}",
        "        management_inventory_status: RENDERED_FROM_TERRAFORM",
        "",
    ]
)

args.output.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary_name = tempfile.mkstemp(prefix=".management-inventory-", dir=args.output.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, args.output)
finally:
    if os.path.exists(temporary_name):
        os.unlink(temporary_name)

print(f"management inventory rendered: {args.output}")
