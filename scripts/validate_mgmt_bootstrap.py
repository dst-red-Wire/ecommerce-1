#!/usr/bin/env python3
"""Fail-closed, offline M2.5 contract validator."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def validate_contracts(inventory, network, access, bootstrap, architecture) -> list[str]:
    errors: list[str] = []
    cps, workers = inventory.get("control_planes", {}), inventory.get("workers", {})
    expected_cp = {f"cp-0{i}" for i in range(1, 4)}
    expected_workers = {f"worker-0{i}" for i in range(1, 4)}
    if set(cps) != expected_cp:
        errors.append("exactly three canonical control planes are required")
    if set(workers) != expected_workers:
        errors.append("exactly three canonical workers are required")
    if inventory.get("private_block") != "10.243.0.0/16":
        errors.append("canonical private block changed")
    if inventory.get("private_block") != network.get("address_domains", {}).get("mgmt"):
        errors.append("inventory/network private block drift")
    addresses = []
    for node in [*cps.values(), *workers.values()]:
        addresses.extend(value for key, value in node.items() if key.endswith("_ip"))
    if len(addresses) != len(set(addresses)):
        errors.append("duplicate canonical node IP")
    for value in addresses:
        if ipaddress.ip_address(value) not in ipaddress.ip_network(inventory["private_block"]):
            errors.append(f"node IP outside MGMT block: {value}")
    if architecture.get("platform", {}).get("node_os") != "rocky-linux-9":
        errors.append("MGMT node OS must be Rocky Linux 9")
    services = bootstrap.get("platform_bootstrap", {}).get("services", {})
    required = {"gitea", "harbor", "tekton", "rancher", "rancher-fleet", "openbao-bootstrap", "tetragon"}
    if not required.issubset(services):
        errors.append("platform bootstrap service set incomplete")
    if not services.get("rancher-fleet", {}).get("gitops_authority"):
        errors.append("Fleet must remain canonical GitOps")
    state = bootstrap.get("state", {})
    if state.get("bootstrap", {}).get("availability_dependency") == "post-bootstrap" or state.get("persistent", {}).get("availability_dependency") != "post-bootstrap":
        errors.append("state backend circular dependency")
    if inventory.get("bootstrap", {}).get("human_apply_gate") is not True or access.get("implementation", {}).get("human_apply_gate") is not True:
        errors.append("human apply gate is mandatory")
    deps = architecture.get("milestone_dependencies", {})
    if deps.get("M2-5-persistent-mgmt-bootstrap") != ["M1-monorepo-bootstrap"]:
        errors.append("M2.5 must depend only on M1")
    if deps.get("M3-preprod-infrastructure") != ["M2-5-persistent-mgmt-bootstrap"]:
        errors.append("M3 must depend on M2.5")
    return errors


def validate_repository_text() -> list[str]:
    errors: list[str] = []
    tf = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "platform/terraform").rglob("*.tf"))
    versions = (ROOT / "platform/terraform/environments/mgmt/versions.tf").read_text(encoding="utf-8")
    if 'version = "= 1.68.0"' not in versions:
        errors.append("hcloud provider is not exactly pinned")
    canonical_ip = re.compile(r"10\.243\.\d+\.\d+")
    if canonical_ip.search(tf):
        errors.append("Terraform duplicates canonical MGMT IP constants")
    if re.search(r'port\s*=\s*"22"[\s\S]{0,160}source_ips\s*=\s*\[[^]]*0\.0\.0\.0/0', tf):
        errors.append("unrestricted management SSH")
    forbidden_ownership = re.compile(r"(remote-exec|local-exec|install-rke2|rke2-server\.service)", re.I)
    if forbidden_ownership.search(tf):
        errors.append("Terraform attempts Ansible/RKE2 ownership")
    governed = [
        ROOT / "config/infrastructure/mgmt-bootstrap.yaml",
        ROOT / "platform/terraform/environments/mgmt",
        ROOT / "platform/terraform/modules/hcloud-mgmt",
        ROOT / "platform/ansible/mgmt.yml",
        ROOT / "platform/ansible/roles/wireguard_gateway",
        ROOT / "platform/ansible/roles/rke2_server",
        ROOT / "platform/ansible/roles/rke2_agent",
    ]
    text_files = []
    for base in governed:
        text_files.extend([base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()])
    for path in text_files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT)
        if re.search(r"(?i)(image|tag):\s*[^\n]*:latest\b", text):
            errors.append(f"mutable latest image in {rel}")
        if re.search(r"(?i)\b(fluxcd|woodpecker)\b", text):
            errors.append(f"superseded runtime authority in {rel}")
        if re.search(r"(?i)(private_key|root_token|admin_password|cluster_token):\s*['\"]?(?!runtime-only|runtime-secret-input|forbidden)[A-Za-z0-9+/=]{20,}", text):
            errors.append(f"possible embedded secret in {rel}")
    return errors


def main() -> int:
    errors = validate_contracts(
        load("config/infrastructure/mgmt-inventory.yaml"),
        load("config/infrastructure/network-plan.yaml"),
        load("config/infrastructure/mgmt-access-gateways.yaml"),
        load("config/infrastructure/mgmt-bootstrap.yaml"),
        load("architecture.lock.yaml"),
    ) + validate_repository_text()
    if errors:
        print("M2.5 STATIC VALIDATION: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("M2.5 STATIC VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
