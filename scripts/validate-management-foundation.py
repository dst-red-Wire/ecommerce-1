#!/usr/bin/env python3
"""Validate the local management foundation without contacting cloud APIs."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"management foundation invalid: {message}")


def read(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        fail(f"required file is missing: {relative}")
    return path.read_text(encoding="utf-8")


def require(content: str, tokens: tuple[str, ...], source: str) -> None:
    for token in tokens:
        if token not in content:
            fail(f"{source} is missing {token!r}")


main_tf = read("infrastructure/hetzner/management/main.tf")
variables_tf = read("infrastructure/hetzner/management/variables.tf")
dns_tf = read("infrastructure/hetzner/management/dns.tf")
outputs_tf = read("infrastructure/hetzner/management/outputs.tf")
playbook = read("infrastructure/ansible/management.yml")
base_tasks = read("infrastructure/ansible/roles/management_base/tasks/main.yml")
postgres_tasks = read(
    "infrastructure/ansible/roles/management_postgresql/tasks/main.yml"
)
management_vars = read("infrastructure/ansible/group_vars/management/vars.yml")
versions = read("versions.mk")

require(
    main_tf,
    (
        'name        = "gitea-mgmt"',
        'name        = "harbor-mgmt"',
        'name        = "data-mgmt"',
        "ipv4_enabled = false",
        "ipv6_enabled = false",
        "delete_protection  = true",
        "rebuild_protection = true",
        "prevent_destroy = true",
        'port        = "2222"',
    ),
    "management/main.tf",
)
for forbidden_port in ('port        = "5432"', 'port        = "6379"'):
    if forbidden_port in main_tf:
        fail(f"Hetzner public firewall exposes forbidden {forbidden_port}")

require(
    variables_tf,
    (
        'var.gitea_server_type == "cpx22"',
        'var.harbor_server_type == "cpx32"',
        'var.data_server_type == "cpx32"',
        'var.location == "nbg1"',
        ">= 24",
    ),
    "management/variables.tf",
)
require(
    dns_tf,
    (
        "prevent_destroy = true",
        'id = var.dns_zone',
        'check "distinct_management_dns_names"',
    ),
    "management/dns.tf",
)
require(
    outputs_tf,
    ("inventory_contract", "egress_proxy_port = 3128", "management_ssh_allowed_cidrs"),
    "management/outputs.tf",
)
if "['x86_64', 'amd64']" not in base_tasks or "aarch64" in base_tasks:
    fail("management hosts must enforce the reviewed x86 architecture")

firewall_contract = json.loads(
    read("infrastructure/hetzner/management/host-firewall.contract.json")
)
if firewall_contract.get("status") != "DEFINED_NOT_PROVEN_RUNTIME":
    fail("host firewall contract must remain runtime-unproven before deployment")
data_rules = firewall_contract["hosts"]["data-mgmt"]["allowedInbound"]
if {(rule["port"], tuple(rule["sourceHosts"])) for rule in data_rules} != {
    (22, ("gitea-mgmt",)),
    (5432, ("gitea-mgmt", "harbor-mgmt")),
}:
    fail("data-mgmt inbound contract differs from the reviewed boundary")
if firewall_contract["redisDecision"]["sharedDataMgmtRedisDeployed"] is not False:
    fail("shared Redis must not be deployed in this milestone")

required_roles = (
    "management_base",
    "management_egress_proxy",
    "management_firewall",
    "management_postgresql",
    "management_gitea",
    "management_harbor",
    "management_reverse_proxy",
    "management_health",
)
for role in required_roles:
    if f"role: {role}" not in playbook:
        fail(f"management playbook does not invoke {role}")
    if not (ROOT / "infrastructure/ansible/roles" / role / "tasks/main.yml").is_file():
        fail(f"role {role} has no tasks/main.yml")

postgres_hba = read(
    "infrastructure/ansible/roles/management_postgresql/templates/pg_hba.conf.j2"
)
require(
    postgres_hba,
    (
        "hostssl",
        "127.0.0.1/32",
        "management_gitea_private_ip",
        "management_harbor_private_ip",
        "hostnossl",
        "reject",
    ),
    "PostgreSQL pg_hba template",
)
if re.search(r"\b(ecommerce|application)[_-]?(database|user)\b", postgres_hba, re.I):
    fail("application database leaked into PostgreSQL management configuration")
if "host={{ management_data_private_ip }}" in postgres_tasks:
    fail("PostgreSQL TLS check must not connect from data-mgmt to its private IP")
require(
    postgres_tasks,
    (
        "host=127.0.0.1",
        "sslmode=require",
        "SELECT ssl AND version IS NOT NULL",
        "current_user",
        "current_database()",
        "management_postgresql_tls_check.stdout | trim != 't'",
    ),
    "PostgreSQL TLS health check",
)

require(
    management_vars,
    ("management_postgresql_filesystem_group: ecommerce-postgresql",),
    "management vars",
)
require(
    base_tasks,
    (
        "Create the dedicated PostgreSQL filesystem access group",
        "management_postgresql_filesystem_group",
        "inventory_hostname == 'data-mgmt'",
        "'0710' if inventory_hostname == 'data-mgmt' else '0750'",
    ),
    "management base filesystem boundaries",
)
require(
    postgres_tasks,
    (
        "Grant PostgreSQL only the dedicated filesystem traversal group",
        "append: true",
        "management_config_root }}/postgresql/tls/server.key",
        'mode: "0600"',
        "management_log_root }}/postgresql",
        'mode: "0750"',
        "Assert PostgreSQL filesystem permissions before configuration restart",
    ),
    "PostgreSQL filesystem permissions",
)

nftables = read(
    "infrastructure/ansible/roles/management_firewall/templates/nftables.conf.j2"
)
require(
    nftables,
    (
        "policy drop",
        "management_data_private_ip",
        "management_postgresql_port",
        "management_egress_proxy_port",
    ),
    "nftables template",
)
if "6379" in nftables:
    fail("host firewall must not expose an unused Redis/Valkey port")

for name in (
    "GITEA_VERSION",
    "GITEA_IMAGE_DIGEST",
    "HARBOR_VERSION",
    "HARBOR_ONLINE_INSTALLER_SHA256",
    "CADDY_VERSION",
    "CADDY_IMAGE_DIGEST",
):
    if not re.search(rf"(?m)^{name}\s*:=\s*\S+$", versions):
        fail(f"versions.mk does not pin {name}")

ansible_requirements = read("requirements/ansible.txt")
for package in ("ansible-core", "ansible-lint"):
    if not re.search(rf"(?m)^{package}==[0-9]+\.[0-9]+\.[0-9]+$", ansible_requirements):
        fail(f"requirements/ansible.txt must pin an exact version of {package}")

ignore = read(".gitignore")
require(
    ignore,
    (
        "infrastructure/ansible/inventory/management.generated.yml",
        "infrastructure/ansible/group_vars/management/secrets.yml",
    ),
    ".gitignore",
)

# Exercise the renderer with Terraform's real output envelope and verify the
# result through ansible-inventory when that executable is available.
fixture = {
    "inventory_contract": {
        "value": {
            "gitea-mgmt": {
                "ansible_host": "192.0.2.10",
                "private_ip": "10.30.0.10",
                "service": "gitea",
            },
            "harbor-mgmt": {
                "ansible_host": "192.0.2.20",
                "private_ip": "10.30.0.20",
                "service": "harbor",
            },
            "data-mgmt": {
                "ansible_host": "10.30.0.30",
                "private_ip": "10.30.0.30",
                "bastion": "192.0.2.10",
                "egress_proxy_host": "10.30.0.10",
                "egress_proxy_port": 3128,
                "service": "postgresql-management",
            },
        }
    },
    "management_ssh_allowed_cidrs": {"value": ["192.0.2.100/32"]},
}
with tempfile.TemporaryDirectory(prefix="management-foundation-") as directory:
    temporary = Path(directory)
    fixture_path = temporary / "outputs.json"
    inventory_path = temporary / "inventory.yml"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render-management-inventory.py"),
            "--terraform-output",
            str(fixture_path),
            "--output",
            str(inventory_path),
            "--acme-email",
            "ops@example.invalid",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = inventory_path.read_text(encoding="utf-8")
    require(
        rendered,
        (
            "-o ProxyJump=root@192.0.2.10",
            "management_data_private_ip: 10.30.0.30",
            "management_inventory_status: RENDERED_FROM_TERRAFORM",
        ),
        "rendered management inventory",
    )
    if "data-mgmt:\n              ansible_host: 192.0.2" in rendered:
        fail("renderer gave data-mgmt a public ansible_host")
    try:
        subprocess.run(
            ["ansible-inventory", "-i", str(inventory_path), "--list"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        pass

    unsafe_user = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render-management-inventory.py"),
            "--terraform-output",
            str(fixture_path),
            "--output",
            str(temporary / "unsafe.yml"),
            "--ansible-user",
            "root -oProxyCommand=invalid",
            "--acme-email",
            "ops@example.invalid",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if unsafe_user.returncode == 0:
        fail("renderer accepted an unsafe ProxyJump SSH account")

print("Management foundation static contract: valid")
