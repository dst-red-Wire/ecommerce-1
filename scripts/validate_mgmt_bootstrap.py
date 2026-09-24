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


def validate_contracts(inventory, network, access, bootstrap, architecture, wireguard=None) -> list[str]:
    errors: list[str] = []
    wireguard = wireguard or load("config/contracts/mgmt-wireguard-access.yaml")
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
    if architecture.get("platform", {}).get("node_os") != "rocky-linux-10.2":
        errors.append("MGMT node OS must be Rocky Linux 10.2")
    services = bootstrap.get("platform_bootstrap", {}).get("services", {})
    required = {
        "gitea",
        "harbor",
        "tekton",
        "rancher",
        "rancher-fleet",
        "cert-manager",
        "kratix",
        "openbao-bootstrap",
        "external-secrets",
        "tetragon",
    }
    if not required.issubset(services):
        errors.append("platform bootstrap service set incomplete")
    if not services.get("rancher-fleet", {}).get("gitops_authority"):
        errors.append("Fleet must remain canonical GitOps")
    kratix = services.get("kratix", {})
    if (
        kratix.get("deployment_owner") != "rancher-fleet"
        or kratix.get("composition") != "kustomize"
        or kratix.get("packages") != "helm"
        or kratix.get("state_store") != "gitea-gitstatestore"
    ):
        errors.append("Kratix must remain Fleet-deployed, Kustomize-composed, Helm-packaged and Gitea-backed")
    if set(kratix.get("activation_dependencies", [])) != {
        "gitea",
        "rancher-fleet",
        "cert-manager",
        "openbao-bootstrap",
        "external-secrets",
    }:
        errors.append("Kratix activation dependencies are incomplete")
    if services.get("external-secrets", {}).get("dependency") != "openbao-initialized-and-scoped-auth-created":
        errors.append("External Secrets must retain its explicit OpenBao dependency")
    authority = bootstrap.get("wireguard_authority", {})
    if authority.get("phase_selector") != "required-runtime-input":
        errors.append("WireGuard authority phase selector is mandatory")
    if authority.get("bootstrap", {}).get("permanent_use") != "forbidden":
        errors.append("bootstrap WireGuard authority must not become permanent")
    if authority.get("steady_state", {}).get("mode") != "runtime-openbao-read":
        errors.append("steady WireGuard authority must use runtime OpenBao reads")
    transition = authority.get("transition", {})
    if transition.get("key_rotation") != "mandatory-replacement-not-copy":
        errors.append("WireGuard transition requires replacement key rotation")
    for field in ("bootstrap_key_cleanup", "bootstrap_peer_staging_cleanup", "bootstrap_public_ssh_cleanup"):
        if transition.get(field) != "mandatory":
            errors.append(f"WireGuard transition requires {field}")
    phases = wireguard.get("phases", {})
    bootstrap_transport = phases.get("bootstrap", {}).get("bootstrap_transport", {})
    if bootstrap_transport.get("public_ssh_node") != "wg-01-only":
        errors.append("bootstrap public SSH must be scoped to wg-01 only")
    if bootstrap_transport.get("global_cidrs") != "forbidden":
        errors.append("globally permissive bootstrap SSH CIDRs are forbidden")
    if bootstrap_transport.get("human_gate") != "required":
        errors.append("bootstrap public SSH requires a human gate")
    steady_transport = phases.get("steady_state", {}).get("persistent_transport", {})
    if steady_transport.get("public_ssh") != "forbidden":
        errors.append("steady state must not retain public SSH")
    policy_transition = wireguard.get("transition", {})
    if policy_transition.get("key_rotation") != "mandatory-replacement-not-copy":
        errors.append("policy requires gateway key rotation rather than bootstrap key copy")
    if policy_transition.get("copying_bootstrap_key_to_openbao") != "forbidden":
        errors.append("copying bootstrap key to OpenBao is forbidden")
    teardown = policy_transition.get("revocation_teardown", {})
    expected_teardown = {
        "bootstrap_gateway_private_key": "delete",
        "bootstrap_peer_staging": "remove",
        "temporary_public_ssh": "remove",
    }
    if teardown != expected_teardown:
        errors.append("WireGuard authority transition teardown is incomplete")
    state = bootstrap.get("state", {})
    if (
        state.get("bootstrap", {}).get("availability_dependency") == "post-bootstrap"
        or state.get("persistent", {}).get("availability_dependency") != "post-bootstrap"
    ):
        errors.append("state backend circular dependency")
    if (
        inventory.get("bootstrap", {}).get("human_apply_gate") is not True
        or access.get("implementation", {}).get("human_apply_gate") is not True
    ):
        errors.append("human apply gate is mandatory")
    deps = architecture.get("milestone_dependencies", {})
    if deps.get("M2-5-persistent-mgmt-bootstrap") != ["M1-monorepo-bootstrap"]:
        errors.append("M2.5 must depend only on M1")
    if deps.get("M3-preprod-infrastructure") != ["M2-5-persistent-mgmt-bootstrap"]:
        errors.append("M3 must depend on M2.5")
    offline = bootstrap.get("offline_installation", {})
    if offline.get("source") != "independently-approved-controller-local-bundle":
        errors.append("bootstrap artifact source must exist independently before Kubernetes")
    if offline.get("manifest_authorization") != "independently-supplied-sha256":
        errors.append("offline manifest requires independent digest authorization")
    net = offline.get("network", {})
    if net.get("artifact_downloads_from_nodes") != "forbidden" or net.get("wireguard_internet_nat") != "forbidden":
        errors.append("node downloads and WireGuard Internet NAT remain forbidden")
    install = offline.get("installation", {})
    if (
        install.get("package_repositories") != "all-disabled"
        or install.get("registry_default_endpoint_fallback") != "disabled"
    ):
        errors.append("offline installation must not fall back to external repositories")
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
    module = (ROOT / "platform/terraform/modules/hcloud-mgmt/main.tf").read_text(encoding="utf-8")
    if "bootstrap_ssh_allowed_cidrs" not in module or 'dynamic "rule"' not in module:
        errors.append("temporary wg-01 bootstrap SSH lifecycle is not modeled")
    if "--add-masquerade" in "\n".join(
        p.read_text(encoding="utf-8") for p in (ROOT / "platform/ansible").rglob("*.yml")
    ):
        errors.append("generic masquerade is forbidden; exact SNAT is required")
    rke2 = (ROOT / "platform/ansible/roles/rke2_server/templates/config.yaml.j2").read_text(encoding="utf-8")
    for field in ("cluster-cidr", "service-cidr"):
        if field not in rke2:
            errors.append(f"RKE2 server template requires {field}")
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
        if re.search(
            r"(?i)(private_key|root_token|admin_password|cluster_token):\s*['\"]?(?!runtime-only|runtime-secret-input|forbidden)[A-Za-z0-9+/=]{20,}",
            text,
        ):
            errors.append(f"possible embedded secret in {rel}")
    return errors


def main() -> int:
    errors = (
        validate_contracts(
            load("config/infrastructure/mgmt-inventory.yaml"),
            load("config/infrastructure/network-plan.yaml"),
            load("config/infrastructure/mgmt-access-gateways.yaml"),
            load("config/infrastructure/mgmt-bootstrap.yaml"),
            load("architecture.lock.yaml"),
            load("config/contracts/mgmt-wireguard-access.yaml"),
        )
        + validate_repository_text()
    )
    if errors:
        print("M2.5 STATIC VALIDATION: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("M2.5 STATIC VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
